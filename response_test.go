package main

// 响应侧守卫测试。
//
// 验收重点（按优先级）：
//  1. 未命中请求：状态码 / header / 字节流与旧实现完全一致（含 SSE 分帧）。
//  2. 命中：B1 阻断（未写出时返回 502）、B1 中途命中断流、B2/F 只告警不改字节。
//  3. E 环形缓冲默认关闭。

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"
)

// --- 测试夹具 --------------------------------------------------------------

type guardEnv struct {
	guard    bool
	peek     int
	leakMin  int
	warnByte int
}

func setupGuard(t *testing.T, rules []Rule, env guardEnv) {
	t.Helper()

	if rules != nil {
		store = testStore(t, rules)
	} else {
		store = testStore(t, nil)
	}

	prevGuard, prevPeek, prevLeak, prevWarn := guardEnabled, peekBytes, leakMinLen, warnScanBytes
	prevBudget := peekBudget
	prevAuditEnabled := audit.isEnabled()

	guardEnabled = env.guard
	if env.peek > 0 {
		peekBytes = env.peek
	}
	if env.leakMin > 0 {
		leakMinLen = env.leakMin
	}
	if env.warnByte > 0 {
		warnScanBytes = env.warnByte
	}
	audit.configure(false, 50, 0)

	t.Cleanup(func() {
		guardEnabled, peekBytes, leakMinLen, warnScanBytes = prevGuard, prevPeek, prevLeak, prevWarn
		peekBudget = prevBudget
		audit.configure(prevAuditEnabled, 50, 0)
		audit.clear()
	})
}

// startGateway 起一个上游 + 一个网关（直接挂 forward）。
func startGateway(t *testing.T, upstream http.HandlerFunc) (gwURL string, upURL string) {
	t.Helper()

	up := httptest.NewServer(upstream)
	prevUp, prevClient := upstreamBase, client
	upstreamBase = up.URL
	client = &http.Client{Transport: &http.Transport{DisableCompression: true}}

	gw := httptest.NewServer(http.HandlerFunc(forward))

	t.Cleanup(func() {
		gw.Close()
		up.Close()
		upstreamBase, client = prevUp, prevClient
	})
	return gw.URL, up.URL
}

func postJSON(t *testing.T, url, body string) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.Post(url+"/v1/chat/completions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, b
}

// ---------------------------------------------------------------------------
// 1. 未命中路径：必须与旧实现完全一致
// ---------------------------------------------------------------------------

func TestForwardNoHitPassthroughNonStream(t *testing.T) {
	setupGuard(t, nil, guardEnv{guard: true})
	want := `{"id":"x","model":"gpt-4o","choices":[{"message":{"content":"hello"}}]}`
	gw, _ := startGateway(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Upstream", "yes")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, want)
	})

	resp, got := postJSON(t, gw, `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if string(got) != want {
		t.Fatalf("body mismatch:\n got %q\nwant %q", got, want)
	}
	if resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("content-type lost: %q", resp.Header.Get("Content-Type"))
	}
	if resp.Header.Get("X-Upstream") != "yes" {
		t.Fatalf("upstream header lost")
	}
}

func TestForwardNoHitPassthroughSSE(t *testing.T) {
	setupGuard(t, nil, guardEnv{guard: true})
	frames := []string{
		`data: {"model":"gpt-4o","choices":[{"delta":{"content":"he"}}]}` + "\n\n",
		`data: {"model":"gpt-4o","choices":[{"delta":{"content":"llo"}}]}` + "\n\n",
		"data: [DONE]\n\n",
	}
	gw, _ := startGateway(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fl := w.(http.Flusher)
		for _, f := range frames {
			_, _ = io.WriteString(w, f)
			fl.Flush()
			time.Sleep(10 * time.Millisecond)
		}
	})

	resp, got := postJSON(t, gw, `{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hi"}]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if string(got) != strings.Join(frames, "") {
		t.Fatalf("SSE bytes changed:\n got %q\nwant %q", got, strings.Join(frames, ""))
	}
	if !strings.Contains(resp.Header.Get("Content-Type"), "event-stream") {
		t.Fatalf("content-type lost: %q", resp.Header.Get("Content-Type"))
	}
}

func TestForwardNoHitPassthroughSSEWithoutContentType(t *testing.T) {
	// 上游没写 Content-Type：靠首 chunk 的 "data:" 前缀识别，不能因此缓冲整个流。
	setupGuard(t, nil, guardEnv{guard: true})
	gw, _ := startGateway(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header()["Content-Type"] = nil // 故意不发
		_, _ = io.WriteString(w, "data: {\"a\":1}\n\n")
		w.(http.Flusher).Flush()
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
		w.(http.Flusher).Flush()
	})
	resp, got := postJSON(t, gw, `{"model":"m","messages":[]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if string(got) != "data: {\"a\":1}\n\ndata: [DONE]\n\n" {
		t.Fatalf("bytes changed: %q", got)
	}
}

func TestForwardLargeBodyStreamsIdentically(t *testing.T) {
	// 超过 peek 上限的非流式响应：只检查前缀，其余正常透传，字节必须一致。
	setupGuard(t, nil, guardEnv{guard: true, peek: 64 << 10})

	big := strings.Repeat("a", 300<<10)
	want := `{"model":"m","choices":[{"message":{"content":"` + big + `"}}]}`
	gw, _ := startGateway(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, want)
	})

	resp, got := postJSON(t, gw, `{"model":"m","messages":[{"role":"user","content":"hi"}]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if len(got) != len(want) || string(got) != want {
		t.Fatalf("large body changed: got %d bytes, want %d", len(got), len(want))
	}
}

func TestForwardGuardDisabledIsPurePassthrough(t *testing.T) {
	// guard 关闭时，即使响应回显了真值也必须原样透传（保持旧行为）。
	setupGuard(t, []Rule{{
		ID: 1, Name: "mask", Enabled: true, Action: ActionMask,
		Pattern: "sk-[a-zA-Z0-9]{20}", Replacement: "[KEY]",
	}}, guardEnv{guard: false})
	secret := "sk-abcdefghijklmnopqrst"
	gw, _ := startGateway(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"echo":"`+secret+`"}`)
	})
	resp, got := postJSON(t, gw, `{"messages":[{"role":"user","content":"`+secret+`"}]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if !strings.Contains(string(got), secret) {
		t.Fatalf("guard disabled must not alter body: %q", got)
	}
}

// ---------------------------------------------------------------------------
// 2. B1：回显检测
// ---------------------------------------------------------------------------

func TestForwardBlocksEchoedSecretNonStream(t *testing.T) {
	setupGuard(t, []Rule{{
		ID: 1, Name: "mask-key", Enabled: true, Action: ActionMask,
		Pattern: "sk-[a-zA-Z0-9]{20}", Replacement: "[KEY]",
	}}, guardEnv{guard: true})
	secret := "sk-abcdefghijklmnopqrst"

	var received string
	gw, _ := startGateway(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		received = string(b)
		// 上游"泄漏"：把收到的原始密钥原样吐回来
		_, _ = io.WriteString(w, `{"echo":"`+secret+`"}`)
	})

	resp, got := postJSON(t, gw, `{"messages":[{"role":"user","content":"key `+secret+`"}]}`)
	if strings.Contains(received, secret) {
		t.Fatalf("request must be masked before leaving the gateway: %s", received)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502; body=%s", resp.StatusCode, got)
	}
	if !strings.Contains(string(got), "leak guard") {
		t.Fatalf("unexpected error body: %s", got)
	}
}

func TestForwardBlocksEchoedSecretInSSEPrefix(t *testing.T) {
	setupGuard(t, []Rule{{
		ID: 1, Name: "mask-key", Enabled: true, Action: ActionMask,
		Pattern: "sk-[a-zA-Z0-9]{20}", Replacement: "[KEY]",
	}}, guardEnv{guard: true})
	secret := "sk-abcdefghijklmnopqrst"

	gw, _ := startGateway(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, `data: {"leak":"`+secret+`"}`+"\n\n")
		w.(http.Flusher).Flush()
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	})

	resp, got := postJSON(t, gw, `{"stream":true,"messages":[{"role":"user","content":"`+secret+`"}]}`)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 (nothing should have been streamed); body=%s", resp.StatusCode, got)
	}
}

func TestForwardAllowsEchoOfReplacement(t *testing.T) {
	// 回显的是替换后的占位符（我们真正发出去的内容），不是真值 → 必须放行。
	setupGuard(t, []Rule{{
		ID: 1, Name: "mask-key", Enabled: true, Action: ActionMask,
		Pattern: "sk-[a-zA-Z0-9]{20}", Replacement: "[KEY]",
	}}, guardEnv{guard: true})

	gw, _ := startGateway(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_, _ = w.Write(b) // 原样回显收到的（已脱敏）请求
	})

	resp, got := postJSON(t, gw, `{"messages":[{"role":"user","content":"key sk-abcdefghijklmnopqrst"}]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, got)
	}
	if strings.Contains(string(got), "sk-abcdefghijklmnopqrst") {
		t.Fatalf("true secret must never reach the client: %s", got)
	}
}

func TestForwardAbortsMidStreamLeak(t *testing.T) {
	setupGuard(t, []Rule{{
		ID: 1, Name: "mask-key", Enabled: true, Action: ActionMask,
		Pattern: "sk-[a-zA-Z0-9]{20}", Replacement: "[KEY]",
	}}, guardEnv{guard: true})
	secret := "sk-abcdefghijklmnopqrst"

	// 干净帧要大于 holdback 窗口（maxLen-1），否则整帧都会被扣留，
	// 无法验证"流式输出已经开始"。
	clean := `data: {"delta":"` + strings.Repeat("h", 200) + `"}` + "\n\n"
	gw, _ := startGateway(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fl := w.(http.Flusher)
		_, _ = io.WriteString(w, clean)
		fl.Flush()
		time.Sleep(150 * time.Millisecond)
		// 第二帧泄漏 → 已经写出响应头，只能断流
		_, _ = io.WriteString(w, `data: {"leak":"`+secret+`"}`+"\n\n")
		fl.Flush()
		time.Sleep(50 * time.Millisecond)
	})

	resp, err := http.Post(gw+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"stream":true,"messages":[{"role":"user","content":"`+secret+`"}]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (stream already started)", resp.StatusCode)
	}
	if !strings.Contains(string(body), `data: {"delta":"hhh`) {
		t.Fatalf("clean prefix should have been streamed before the abort: %q", body)
	}
	if strings.Contains(string(body), secret) {
		t.Fatalf("leaked secret reached the client: %q", body)
	}
	if readErr == nil {
		t.Fatalf("expected the connection to be aborted mid-stream, body=%q", body)
	}
}

func TestHoldbackDetectsCrossChunkNeedle(t *testing.T) {
	var out bytes.Buffer
	w := newLeakGuardWriter(newLeakMatcher([]string{"supersecretvalue"}, 8), func(b []byte) bool {
		out.Write(b)
		return true
	})
	if hit, ok := w.push([]byte("xxx superse")); hit != 0 || !ok {
		t.Fatalf("partial needle must not be flagged (hit=%d ok=%v)", hit, ok)
	}
	if hit, ok := w.push([]byte("cretvalue yyy")); hit != len("supersecretvalue") || ok {
		t.Fatalf("needle split across chunks not found (hit=%d ok=%v)", hit, ok)
	}
	// 关键：被切开的 needle 前缀绝不能已经写出去
	if bytes.Contains(out.Bytes(), []byte("superse")) {
		t.Fatalf("needle prefix leaked to client: %q", out.String())
	}
}

func TestLeakMatcherIgnoresShortNeedles(t *testing.T) {
	if m := newLeakMatcher([]string{"abc"}, 8); m != nil {
		t.Fatal("needles shorter than minLen must be dropped")
	}
}

// ---------------------------------------------------------------------------
// 3. B2 / F：只告警，不改字节
// ---------------------------------------------------------------------------

func TestForwardWarnsOnSensitiveWithoutModifyingBody(t *testing.T) {
	setupGuard(t, []Rule{detectorRule(1, "api_key", ActionMask, "[KEY]")},
		guardEnv{guard: true})
	leaked := "sk-proj-AbCdEfGhIjKlMnOpQrStUvWx"
	want := `{"model":"m","choices":[{"message":{"content":"` + leaked + `"}}]}`

	gw, _ := startGateway(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, want)
	})

	audit.configure(true, 50, 0)
	resp, got := postJSON(t, gw, `{"model":"m","messages":[{"role":"user","content":"hi"}]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if string(got) != want {
		t.Fatalf("warn path must not modify bytes:\n got %q\nwant %q", got, want)
	}
	found := false
	for _, e := range audit.recent(10) {
		if e.Kind == "sensitive" && e.Detector == "api_key" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a sensitive audit event, got %+v", audit.recent(10))
	}
}

func TestForwardWarnsOnModelMismatch(t *testing.T) {
	setupGuard(t, nil, guardEnv{guard: true})
	want := `{"model":"claude-3-5-sonnet","choices":[{"message":{"content":"hi"}}]}`
	gw, _ := startGateway(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, want)
	})

	audit.configure(true, 50, 0)
	resp, got := postJSON(t, gw, `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if string(got) != want {
		t.Fatalf("warn path must not modify bytes: %q", got)
	}
	found := false
	for _, e := range audit.recent(10) {
		if e.Kind == "model_mismatch" && e.Model == "gpt-4o" && e.UpstreamModel == "claude-3-5-sonnet" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a model_mismatch event, got %+v", audit.recent(10))
	}
}

func TestForwardAcceptsCanonicalizedModel(t *testing.T) {
	setupGuard(t, nil, guardEnv{guard: true})
	gw, _ := startGateway(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"model":"gpt-4o-mini","choices":[]}`)
	})
	audit.configure(true, 50, 0)
	postJSON(t, gw, `{"model":"gpt-4o-mini-2024-07-18","messages":[]}`)
	for _, e := range audit.recent(10) {
		if e.Kind == "model_mismatch" {
			t.Fatalf("canonicalized model id must not warn: %+v", e)
		}
	}
}

func TestModelsCompatible(t *testing.T) {
	cases := []struct {
		a, b string
		ok   bool
	}{
		{"gpt-4o", "gpt-4o", true},
		{"gpt-4o-mini-2024-07-18", "gpt-4o-mini", true},
		{"gpt-4o", "claude-3-5-sonnet", false},
		{"", "whatever", true}, // 信息不足时不告警
	}
	for _, c := range cases {
		if got := modelsCompatible(c.a, c.b); got != c.ok {
			t.Fatalf("modelsCompatible(%q,%q) = %v, want %v", c.a, c.b, got, c.ok)
		}
	}
}

// ---------------------------------------------------------------------------
// 4. 请求侧 needles 采集 / 审计环形缓冲
// ---------------------------------------------------------------------------

func TestProtectRequestCollectsNeedles(t *testing.T) {
	store = testStore(t, []Rule{
		{ID: 1, Name: "regex", Enabled: true, Action: ActionMask,
			Pattern: "MICROSECRET-[A-Z0-9]{6}", Replacement: "[R]"},
		detectorRule(2, "api_key", ActionMask, "[K]"),
	})
	in := `{"messages":[{"role":"user","content":"a MICROSECRET-ABC123 b sk-proj-AbCdEfGhIjKlMnOpQrStUvWx"}]}`
	out, meta, rejected, err := protectRequest([]byte(in))
	if err != nil || rejected {
		t.Fatalf("unexpected: rejected=%v err=%v", rejected, err)
	}
	if strings.Contains(string(out), "MICROSECRET-ABC123") || strings.Contains(string(out), "sk-proj-") {
		t.Fatalf("request not masked: %s", out)
	}
	joined := strings.Join(meta.needles, "|")
	for _, want := range []string{"MICROSECRET-ABC123", "sk-proj-AbCdEfGhIjKlMnOpQrStUvWx"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("needle %q not collected: %v", want, meta.needles)
		}
	}
}

func TestProtectRequestNeedlesDisabledWhenGuardOff(t *testing.T) {
	prev := guardEnabled
	guardEnabled = false
	defer func() { guardEnabled = prev }()

	store = testStore(t, []Rule{{
		ID: 1, Name: "r", Enabled: true, Action: ActionMask,
		Pattern: "SECRETVALUE", Replacement: "[R]",
	}})
	_, meta, _, _ := protectRequest([]byte(`{"messages":[{"role":"user","content":"SECRETVALUE"}]}`))
	if len(meta.needles) != 0 {
		t.Fatalf("needles must not be collected when the guard is off: %v", meta.needles)
	}
}

func TestAuditRingDisabledByDefault(t *testing.T) {
	audit.configure(false, 10, 0)
	audit.clear()
	recordEvent(auditEvent{Kind: "leak", Action: "blocked"}, "sensitive-value")
	if got := audit.recent(10); len(got) != 0 {
		t.Fatalf("disabled audit must keep nothing, got %+v", got)
	}
}

func TestAuditRingRecordsWhenEnabled(t *testing.T) {
	audit.configure(true, 3, 0)
	defer audit.configure(false, 50, 0)
	audit.clear()

	recordEvent(auditEvent{Kind: "leak", Action: "blocked", MatchedLen: 26}, "sk-abcdefghijklmnopqrst")
	got := audit.recent(10)
	if len(got) != 1 {
		t.Fatalf("want 1 event, got %d", len(got))
	}
	if got[0].Kind != "leak" || got[0].MatchedLen != 26 {
		t.Fatalf("unexpected event: %+v", got[0])
	}
	if got[0].Hint != "" {
		t.Fatalf("default audit must not keep matched content, got %q", got[0].Hint)
	}

	// ring 上限
	for i := 0; i < 5; i++ {
		recordEvent(auditEvent{Kind: "sensitive"}, "")
	}
	if n := len(audit.recent(10)); n != 3 {
		t.Fatalf("ring size not enforced: %d", n)
	}
}

func TestAuditHintRespectsConfig(t *testing.T) {
	audit.configure(true, 10, 4)
	defer audit.configure(false, 50, 0)
	audit.clear()
	recordEvent(auditEvent{Kind: "leak"}, "sk-abcdefghij")
	got := audit.recent(1)
	if len(got) != 1 || got[0].Hint != "sk-a…" {
		t.Fatalf("hint = %q", got[0].Hint)
	}
}

// ---------------------------------------------------------------------------
// 5. peekUpstream 的边界行为
// ---------------------------------------------------------------------------

func TestPeekUpstreamSSEUsesOneChunk(t *testing.T) {
	// SSE：窥探只取一个 chunk 就返回，不把整个流吸干。
	payload := bytes.Repeat([]byte("data: {}\n\n"), 5000)
	src := newUpstreamStream(bytes.NewReader(payload), 32*1024)
	defer src.close()

	res := peekUpstream(src, 1<<20, time.Second, true, 0)
	if !res.sse {
		t.Fatal("expected sse")
	}
	if res.full {
		t.Fatal("SSE peek must not drain the body")
	}
	if len(res.prefix) > 32*1024 {
		t.Fatalf("SSE peek read %d bytes, want <= one 32KB chunk", len(res.prefix))
	}

	// 窥探停下的位置之后必须还能完整取到剩余字节（无丢失/重复/乱序）。
	var rest bytes.Buffer
	for {
		msg, ok, _ := src.nextChunk(nil)
		if !ok {
			break
		}
		rest.Write(msg.data)
		src.put(msg.data)
		if msg.err != nil {
			break
		}
	}
	if got := append(append([]byte{}, res.prefix...), rest.Bytes()...); !bytes.Equal(got, payload) {
		t.Fatalf("stream bytes lost or reordered: got %d bytes, want %d", len(got), len(payload))
	}
}

func TestPeekUpstreamStopsAtLimit(t *testing.T) {
	src := newUpstreamStream(bytes.NewReader(bytes.Repeat([]byte("x"), 200<<10)), 32*1024)
	defer src.close()
	res := peekUpstream(src, 64<<10, time.Second, false, 0)
	if res.full {
		t.Fatal("body larger than limit must not be treated as complete")
	}
	if len(res.prefix) < 64<<10 {
		t.Fatalf("prefix too small: %d", len(res.prefix))
	}
	if len(res.prefix) > 96<<10 {
		t.Fatalf("prefix too large (must stay bounded): %d", len(res.prefix))
	}
}

// 预算到期：立即返回，已读前缀保留，且流仍然可用（不丢字节）。
func TestPeekUpstreamBudgetExpiresWithoutLosingBytes(t *testing.T) {
	pr, pw := io.Pipe()
	src := newUpstreamStream(pr, 32*1024)
	defer src.close()
	defer pw.Close()

	go func() {
		_, _ = pw.Write([]byte("first-chunk"))
		time.Sleep(400 * time.Millisecond)
		_, _ = pw.Write([]byte("-second-chunk"))
		_ = pw.Close()
	}()

	start := time.Now()
	res := peekUpstream(src, 1<<20, 50*time.Millisecond, false, 0)
	elapsed := time.Since(start)

	if elapsed > 200*time.Millisecond {
		t.Fatalf("peek waited %v despite a 50ms budget", elapsed)
	}
	if res.full {
		t.Fatal("budget expiry must not claim the body is complete")
	}
	if string(res.prefix) != "first-chunk" {
		t.Fatalf("prefix = %q, want %q", res.prefix, "first-chunk")
	}

	// 预算耗尽后继续从同一对象取剩余字节，顺序与内容不变。
	var rest bytes.Buffer
	for {
		msg, ok, _ := src.nextChunk(nil)
		if !ok {
			break
		}
		rest.Write(msg.data)
		src.put(msg.data)
		if msg.err != nil {
			break
		}
	}
	if got := string(res.prefix) + rest.String(); got != "first-chunk-second-chunk" {
		t.Fatalf("bytes lost after budget expiry: %q", got)
	}
}

type countingReader struct {
	data  []byte
	reads int
	off   int
}

func (c *countingReader) Read(p []byte) (int, error) {
	c.reads++
	if c.off >= len(c.data) {
		return 0, io.EOF
	}
	n := copy(p, c.data[c.off:])
	c.off += n
	return n, nil
}

// TestForwardSSEDeliversFirstFrameBeforeStreamEnds 锁定"不为检测而缓存整个响应"：
// 上游在发送第一帧后阻塞，直到客户端确认收到；如果网关缓冲了整个响应，这里会超时。
func TestForwardSSEDeliversFirstFrameBeforeStreamEnds(t *testing.T) {
	setupGuard(t, nil, guardEnv{guard: true})
	release := make(chan struct{})
	upstreamDone := make(chan struct{})

	gw, _ := startGateway(t, func(w http.ResponseWriter, r *http.Request) {
		defer close(upstreamDone)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: one\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-time.After(3 * time.Second):
		}
		_, _ = io.WriteString(w, "data: two\n\n")
		w.(http.Flusher).Flush()
	})

	resp, err := http.Post(gw+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"stream":true,"messages":[]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	type readResult struct {
		n   int
		err error
	}
	first := make(chan readResult, 1)
	go func() {
		buf := make([]byte, len("data: one\n\n"))
		n, err := io.ReadFull(resp.Body, buf)
		first <- readResult{n, err}
	}()

	select {
	case res := <-first:
		if res.err != nil || res.n != len("data: one\n\n") {
			t.Fatalf("first frame not delivered: n=%d err=%v", res.n, res.err)
		}
	case <-time.After(1 * time.Second):
		close(release)
		<-upstreamDone
		t.Fatal("first SSE frame was buffered instead of forwarded (response was fully cached)")
	}

	close(release)
	rest, _ := io.ReadAll(resp.Body)
	if strings.TrimSpace(string(rest)) != "data: two" {
		t.Fatalf("rest of stream = %q", rest)
	}
}

func TestForwardPassesThroughErrorStatusAndBody(t *testing.T) {
	setupGuard(t, nil, guardEnv{guard: true})
	want := `{"error":{"message":"rate limited","type":"rate_limit_error"}}`
	gw, _ := startGateway(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, want)
	})

	resp, got := postJSON(t, gw, `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", resp.StatusCode)
	}
	if string(got) != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// F1：guard=false 必须真正回到旧透传路径（不窥探、不等待）
// F2：窥探的时间预算必须真正限制首字节等待，且不丢字节
// ---------------------------------------------------------------------------

// dripUpstream 每 64KB 停 10ms，共 n 个 chunk。
func dripUpstream(n int, delay time.Duration) http.HandlerFunc {
	chunk := strings.Repeat("a", 64<<10)
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		for i := 0; i < n; i++ {
			_, _ = io.WriteString(w, chunk)
			w.(http.Flusher).Flush()
			time.Sleep(delay)
		}
	}
}

func TestGuardOffDoesNotPeek(t *testing.T) {
	measure := func(guard bool) time.Duration {
		t.Helper()
		var d time.Duration
		// 子测试里注册 cleanup，保证每次迭代后全局变量都被还原。
		t.Run(fmt.Sprintf("guard=%v", guard), func(t *testing.T) {
			setupGuard(t, nil, guardEnv{guard: guard})
			peekBytes = 1 << 20
			peekBudget = 200 * time.Millisecond
			gw, _ := startGateway(t, dripUpstream(48, 10*time.Millisecond))
			d = ttfb(t, gw)
		})
		return d
	}
	off := measure(false)
	on := measure(true)

	// 关闭守卫：不窥探 → 首字节只等第一个 chunk。
	if off > 100*time.Millisecond {
		t.Fatalf("guard=off ttfb=%v, expected ≈ one chunk (10ms): peek must not run", off)
	}
	// 开启守卫：确实会为凑前缀而等待（1MB ≈ 16 chunk ≈ 160ms），
	// 说明上面的断言是有效的（不是因为两边都快）。
	if on < off+80*time.Millisecond {
		t.Fatalf("guard=on ttfb=%v vs off=%v: peek seems not to run, test is not discriminating", on, off)
	}
}

func TestPeekBudgetCapsFirstByteWait(t *testing.T) {
	setupGuard(t, nil, guardEnv{guard: true})
	peekBytes = 1 << 20
	peekBudget = 50 * time.Millisecond

	// 3MB，64KB/20ms → 填满 1MB 需要 ~320ms；预算 50ms 必须更早放行。
	want := strings.Repeat("a", 64<<10)
	gw, _ := startGateway(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		for i := 0; i < 48; i++ {
			_, _ = io.WriteString(w, want)
			w.(http.Flusher).Flush()
			time.Sleep(20 * time.Millisecond)
		}
	})

	start := time.Now()
	resp, err := http.Post(gw+"/v1/chat/completions", "application/json", strings.NewReader(`{"model":"m","messages":[]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	one := make([]byte, 1)
	if _, err := io.ReadFull(resp.Body, one); err != nil {
		t.Fatalf("first byte: %v", err)
	}
	firstByte := time.Since(start)
	body, _ := io.ReadAll(resp.Body)

	if firstByte > 200*time.Millisecond {
		t.Fatalf("ttfb=%v with a 50ms budget (1MB target would be ~320ms)", firstByte)
	}
	// 前缀放行后必须继续完整透传：48 × 64KB，一个字节都不能少/重复。
	if total := 1 + len(body); total != 48*len(want) {
		t.Fatalf("body=%d bytes, want %d", total, 48*len(want))
	}
}

func TestPeekBudgetNoLossOnSmallSlowBody(t *testing.T) {
	// 小于上限但很慢的响应：预算到期后剩下的字节必须原样送达。
	setupGuard(t, nil, guardEnv{guard: true})
	peekBytes = 1 << 20
	peekBudget = 10 * time.Millisecond

	var payload bytes.Buffer
	parts := []string{`{"a":"`, strings.Repeat("x", 5000), `","b":"`, strings.Repeat("y", 5000), `"}`}
	gw, _ := startGateway(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		for _, p := range parts {
			_, _ = io.WriteString(w, p)
			w.(http.Flusher).Flush()
			time.Sleep(30 * time.Millisecond)
		}
	})
	for _, p := range parts {
		payload.WriteString(p)
	}

	resp, got := postJSON(t, gw, `{"model":"m","messages":[]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	if !bytes.Equal(got, payload.Bytes()) {
		t.Fatalf("body mismatch across budget boundary: got %d bytes, want %d", len(got), payload.Len())
	}
}

func TestReadErrorDuringPeek(t *testing.T) {
	// 上游发一半就断开：客户端应拿到已收到的字节 + 读错误，且不挂死。
	setupGuard(t, nil, guardEnv{guard: true})
	peekBudget = time.Second

	gw, _ := startGateway(t, func(w http.ResponseWriter, r *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"))
		_, _ = conn.Write([]byte("5\r\n{\"a\":\r\n"))
		_ = conn.Close() // 硬断
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		resp, err := http.Post(gw+"/v1/chat/completions", "application/json", strings.NewReader(`{"messages":[]}`))
		if err != nil {
			return
		}
		defer resp.Body.Close()
		b, readErr := io.ReadAll(resp.Body)
		if !strings.Contains(string(b), `{"a":`) {
			t.Errorf("partial bytes lost: %q (err=%v)", b, readErr)
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handler hung after upstream read error")
	}
}

func TestNoGoroutineLeakOnBudgetExpiry(t *testing.T) {
	setupGuard(t, nil, guardEnv{guard: true})
	peekBytes = 1 << 20
	peekBudget = 5 * time.Millisecond

	// 每个响应都会让预算到期（peek 提前返回），验证读 goroutine 会退出。
	gw, _ := startGateway(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"a":`)
		w.(http.Flusher).Flush()
		time.Sleep(30 * time.Millisecond)
		_, _ = io.WriteString(w, `1}`)
	})

	// 预热，排除连接建立/服务端首请求 goroutine 的干扰。
	for i := 0; i < 3; i++ {
		resp, body := postJSON(t, gw, `{"messages":[]}`)
		if resp.StatusCode != http.StatusOK || string(body) != `{"a":1}` {
			t.Fatalf("warmup: status=%d body=%q", resp.StatusCode, body)
		}
	}
	time.Sleep(100 * time.Millisecond)
	baseline := runtime.NumGoroutine()

	for i := 0; i < 30; i++ {
		resp, body := postJSON(t, gw, `{"messages":[]}`)
		if resp.StatusCode != http.StatusOK || string(body) != `{"a":1}` {
			t.Fatalf("request %d: status=%d body=%q", i, resp.StatusCode, body)
		}
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= baseline+3 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("goroutine leak: baseline=%d now=%d", baseline, runtime.NumGoroutine())
}

func ttfb(t *testing.T, gwURL string) time.Duration {
	t.Helper()
	start := time.Now()
	resp, err := http.Post(gwURL+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"m","messages":[]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 1)
	if _, err := io.ReadFull(resp.Body, buf); err != nil {
		t.Fatalf("first byte: %v", err)
	}
	elapsed := time.Since(start)
	_, _ = io.Copy(io.Discard, resp.Body)
	return elapsed
}

// TestLeakAfterPeekBudgetAbortsInsteadOfBlocking 明确记录一个**已知边界**：
// 上游首字节晚于窥探预算时，响应头已经提交，B1 只能断流，无法再返回 502。
func TestLeakAfterPeekBudgetAbortsInsteadOfBlocking(t *testing.T) {
	secret := "sk-abcdefghijklmnopqrst"
	setupGuard(t, []Rule{{
		ID: 1, Name: "mask", Enabled: true, Action: ActionMask,
		Pattern: "sk-[a-zA-Z0-9]{20}", Replacement: "[KEY]",
	}}, guardEnv{guard: true})
	peekBudget = 50 * time.Millisecond

	gw, _ := startGateway(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ok","pad":"`+strings.Repeat("p", 100)+`"`)
		w.(http.Flusher).Flush()
		time.Sleep(150 * time.Millisecond) // 超过预算
		_, _ = io.WriteString(w, `,"leak":"`+secret+`"}`)
		w.(http.Flusher).Flush()
	})

	resp, err := http.Post(gw+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"messages":[{"role":"user","content":"`+secret+`"}]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusBadGateway {
		t.Fatal("headers were already committed after the budget expired; 502 is impossible here")
	}
	if strings.Contains(string(body), secret) {
		t.Fatalf("leaked secret reached the client: %q", body)
	}
	if readErr == nil {
		t.Fatalf("expected an aborted stream, got clean EOF: %q", body)
	}
}

// ---------------------------------------------------------------------------
// F3：tail holdback —— 安全边界测试
// ---------------------------------------------------------------------------

// 32KB 写出边界正好落在 needle 中间：前缀必须被扣留，不能发出去。
func TestHoldbackAt32KBBoundary(t *testing.T) {
	secret := "sk-abcdefghijklmnopqrst" // 26B
	var out bytes.Buffer
	w := newLeakGuardWriter(newLeakMatcher([]string{secret}, 8), func(b []byte) bool {
		out.Write(b)
		return true
	})

	head := bytes.Repeat([]byte("a"), 32*1024-10) // 密钥前 10 字节会落在 32KB 边界后
	if hit, ok := w.push(head); hit != 0 || !ok {
		t.Fatalf("clean head should pass (hit=%d ok=%v)", hit, ok)
	}
	if hit, ok := w.push([]byte(secret[:10])); hit != 0 || !ok {
		t.Fatalf("needle prefix alone must not hit (hit=%d ok=%v)", hit, ok)
	}
	// 此刻已写出: len(head) - (maxLen-1) + (maxLen-1+10 - (maxLen-1)) ...
	// 关键断言：密钥前缀不在已发送内容里
	if bytes.Contains(out.Bytes(), []byte(secret[:10])) {
		t.Fatalf("needle prefix was released before the full needle was seen")
	}
	if hit, ok := w.push([]byte(secret[10:])); hit != len(secret) || ok {
		t.Fatalf("needle straddling boundary not detected (hit=%d ok=%v)", hit, ok)
	}
	if bytes.Contains(out.Bytes(), []byte(secret)) {
		t.Fatal("full needle leaked")
	}
	// 已发送的内容必须全部是填充字节（没有密钥的任何字节）
	if bytes.ContainsAny(out.Bytes(), "sk-") {
		t.Fatalf("unexpected bytes released: %q", out.Bytes()[len(out.Bytes())-20:])
	}
}

// 短响应（比 maxLen 还短）：不能无故丢字节。
func TestHoldbackShortResponseKeepsAllBytes(t *testing.T) {
	var out bytes.Buffer
	w := newLeakGuardWriter(newLeakMatcher([]string{strings.Repeat("s", 64)}, 8), func(b []byte) bool {
		out.Write(b)
		return true
	})
	body := []byte(`{"ok":1}`) // 8B < keep(63)
	if hit, ok := w.push(body); hit != 0 || !ok {
		t.Fatalf("push: hit=%d ok=%v", hit, ok)
	}
	if out.Len() != 0 {
		t.Fatalf("nothing should be released before finish, got %q", out.String())
	}
	if hit, ok := w.finish(); hit != 0 || !ok {
		t.Fatalf("finish: hit=%d ok=%v", hit, ok)
	}
	if !bytes.Equal(out.Bytes(), body) {
		t.Fatalf("short response bytes lost: got %q want %q", out.String(), body)
	}
}

// 短响应本身就含完整 needle：finish 不能绕过检查。
func TestHoldbackShortResponseWithNeedle(t *testing.T) {
	secret := "sk-abcdefghijklmnopqrst"
	var out bytes.Buffer
	w := newLeakGuardWriter(newLeakMatcher([]string{secret}, 8), func(b []byte) bool {
		out.Write(b)
		return true
	})
	// 单次 push 已包含完整 needle → 立即命中，一个字节都不发
	if hit, ok := w.push([]byte(secret)); hit != len(secret) || ok {
		t.Fatalf("push: hit=%d ok=%v", hit, ok)
	}
	if out.Len() != 0 {
		t.Fatalf("nothing should be released on hit, got %q", out.String())
	}
}

// EOF / 读错误收尾：扣留的 tail 必须**先检测**再释放。
func TestHoldbackFinishChecksTailThenReleases(t *testing.T) {
	var out bytes.Buffer
	w := newLeakGuardWriter(newLeakMatcher([]string{"sk-abcdefghijklmnopqrst"}, 8), func(b []byte) bool {
		out.Write(b)
		return true
	})
	body := []byte("hello world, nothing secret here")
	if _, ok := w.push(body); !ok {
		t.Fatal("push failed")
	}
	released := out.Len()
	if hit, ok := w.finish(); hit != 0 || !ok {
		t.Fatalf("finish: hit=%d ok=%v", hit, ok)
	}
	if !bytes.Equal(out.Bytes(), body) {
		t.Fatalf("finish must release the withheld tail: got %d bytes want %d", out.Len(), len(body))
	}
	if released >= len(body) {
		t.Fatal("test does not exercise holdback (nothing was withheld)")
	}
}

// 上游读错误：已接收字节必须完整送达（不放水、不丢字节）。
func TestForwardHoldbackReadErrorKeepsReceivedBytes(t *testing.T) {
	setupGuard(t, []Rule{{
		ID: 1, Name: "mask", Enabled: true, Action: ActionMask,
		Pattern: "sk-[a-zA-Z0-9]{20}", Replacement: "[KEY]",
	}}, guardEnv{guard: true})
	peekBudget = time.Second

	payload := `{"a":"` + strings.Repeat("p", 300) + `"`
	gw, _ := startGateway(t, func(w http.ResponseWriter, r *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"))
		_, _ = conn.Write([]byte(fmt.Sprintf("%x\r\n%s\r\n", len(payload), payload)))
		_ = conn.Close() // 没有终止 chunk → 读错误
	})

	resp, err := http.Post(gw+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"messages":[{"role":"user","content":"key sk-abcdefghijklmnopqrst"}]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	// 已知（本轮不改）行为：上游截断在网关侧表现为"正常收尾"——客户端拿到
	// 已完整到达的字节，但看不到错误。旧实现同样如此（F3 不扩大范围）。
	// F3 在这里保证的是：扣留的 tail 经过检测后才释放，且不丢字节。
	if string(body) != payload {
		t.Fatalf("received bytes changed/lost: got %d want %d", len(body), len(payload))
	}
}

// 端到端：上游把 needle 跨两次 flush 切开，客户端不得收到其前缀。
func TestForwardHoldbackNoPrefixLeakE2E(t *testing.T) {
	secret := "sk-abcdefghijklmnopqrst"
	setupGuard(t, []Rule{{
		ID: 1, Name: "mask", Enabled: true, Action: ActionMask,
		Pattern: "sk-[a-zA-Z0-9]{20}", Replacement: "[KEY]",
	}}, guardEnv{guard: true})

	gw, _ := startGateway(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fl := w.(http.Flusher)
		_, _ = io.WriteString(w, "data: "+strings.Repeat("p", 5000)+secret[:10])
		fl.Flush()
		time.Sleep(120 * time.Millisecond)
		_, _ = io.WriteString(w, secret[10:]+"\n\n")
		fl.Flush()
	})

	resp, err := http.Post(gw+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"stream":true,"messages":[{"role":"user","content":"`+secret+`"}]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if bytes.Contains(body, []byte(secret[:10])) {
		t.Fatalf("needle prefix leaked to the client: tail=%q", body[max(0, len(body)-32):])
	}
	if bytes.Contains(body, []byte(secret)) {
		t.Fatal("full needle leaked")
	}
}

// 无命中的正常流：字节必须与上游完全一致，且**持续**输出（不是攒完再发）。
func TestForwardHoldbackCleanStreamIsIdenticalAndIncremental(t *testing.T) {
	setupGuard(t, []Rule{{
		ID: 1, Name: "mask", Enabled: true, Action: ActionMask,
		Pattern: "sk-[a-zA-Z0-9]{20}", Replacement: "[KEY]",
	}}, guardEnv{guard: true})

	release := make(chan struct{})
	upstreamDone := make(chan struct{})
	first := "data: {" + `"delta":"` + strings.Repeat("x", 4000) + `"}` + "\n\n"
	second := "data: [DONE]\n\n"

	gw, _ := startGateway(t, func(w http.ResponseWriter, r *http.Request) {
		defer close(upstreamDone)
		w.Header().Set("Content-Type", "text/event-stream")
		fl := w.(http.Flusher)
		_, _ = io.WriteString(w, first)
		fl.Flush()
		select {
		case <-release:
		case <-time.After(3 * time.Second):
		}
		_, _ = io.WriteString(w, second)
		fl.Flush()
	})

	resp, err := http.Post(gw+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"stream":true,"messages":[{"role":"user","content":"key sk-abcdefghijklmnopqrst"}]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	// 第一帧必须在上游结束之前到达：holdback 只扣留 maxLen-1 字节，不攒整包。
	got := make([]byte, len(first)-64)
	type res struct {
		n   int
		err error
	}
	ch := make(chan res, 1)
	go func() {
		n, err := io.ReadFull(resp.Body, got)
		ch <- res{n, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("first frame read: %v", r.err)
		}
	case <-time.After(1 * time.Second):
		close(release)
		<-upstreamDone
		t.Fatal("holdback buffered the whole response instead of streaming")
	}
	close(release)
	rest, _ := io.ReadAll(resp.Body)

	if full := string(got) + string(rest); full != first+second {
		t.Fatalf("clean stream bytes changed: got %d want %d", len(full), len(first)+len(second))
	}
}

// guard=false 的回退路径不受 holdback 影响（仍然零扣留、逐字节透传）。
func TestHoldbackNotAppliedWhenGuardDisabled(t *testing.T) {
	secret := "sk-abcdefghijklmnopqrst"
	setupGuard(t, []Rule{{
		ID: 1, Name: "mask", Enabled: true, Action: ActionMask,
		Pattern: "sk-[a-zA-Z0-9]{20}", Replacement: "[KEY]",
	}}, guardEnv{guard: false})
	gw, _ := startGateway(t, func(w http.ResponseWriter, r *http.Request) {
		// 故意回显真值：guard 关闭时必须原样透传（包括前缀）
		_, _ = io.WriteString(w, `{"echo":"`+secret+`"}`)
	})
	resp, body := postJSON(t, gw, `{"messages":[{"role":"user","content":"`+secret+`"}]}`)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), secret) {
		t.Fatalf("guard=false must stay pure passthrough: status=%d body=%q", resp.StatusCode, body)
	}
}

// ---------------------------------------------------------------------------
// F4：模型兼容判断 —— 告警准确性测试
// ---------------------------------------------------------------------------

func TestModelsCompatibleExactAndSuffix(t *testing.T) {
	cases := []struct {
		sent, got string
		want      bool
		why       string
	}{
		{"gpt-4o", "gpt-4o-mini", false, "降级必须告警"},
		{"gpt-4o-mini", "gpt-4o", false, "升级同样不是同一模型"},
		{"gpt-4", "gpt-4o", false, "前缀相同不代表兼容"},
		{"gpt-4o", "claude-3-5-sonnet", false, "不同厂商"},
		{"gpt-4o-mini-2024-07-18", "gpt-4o-mini", true, "日期快照后缀"},
		{"gpt-4o-mini", "gpt-4o-mini-2024-07-18", true, "反向日期快照"},
		{"claude-3-5-sonnet-20241022", "claude-3-5-sonnet", true, "紧凑日期后缀"},
		{"gpt-4-0613", "gpt-4", true, "MMDD 后缀"},
		{"gpt-4o-2024-07-18", "gpt-4o-2024-08-06", true, "同一模型不同快照"},
		{"", "gpt-4o", true, "信息不足时不告警"},
		{"gpt-4o", "", true, "信息不足时不告警"},
		{"gpt-4o", "gpt-4o", true, "完全相同"},
		{"gpt-4o-mini", "gpt-4o-mini-2024", true, "YYYY 后缀"},
	}
	for _, c := range cases {
		if got := modelsCompatible(c.sent, c.got); got != c.want {
			t.Fatalf("modelsCompatible(%q,%q) = %v, want %v (%s)", c.sent, c.got, got, c.want, c.why)
		}
	}
}

func TestCanonicalModelOnlyStripsSupportedSuffixes(t *testing.T) {
	cases := map[string]string{
		"gpt-4o-mini-2024-07-18":     "gpt-4o-mini",
		"claude-3-5-sonnet-20241022": "claude-3-5-sonnet",
		"gpt-4-0613":                 "gpt-4",
		"gpt-4o":                     "gpt-4o",      // 无后缀
		"gpt-4o-mini":                "gpt-4o-mini", // 不能把 mini 当版本号剥掉
		"llama-3.1-70b":              "llama-3.1-70b",
		"my-model-2024-07-18-extra":  "my-model-2024-07-18-extra", // 不是锚定后缀
		"model-12345":                "model-12345",               // 5 位数字不剥
	}
	for in, want := range cases {
		if got := canonicalModel(in); got != want {
			t.Fatalf("canonicalModel(%q) = %q, want %q", in, got, want)
		}
	}
}

// 端到端：降级必须产生 model_mismatch 事件，且响应字节不受影响。
func TestForwardModelDowngradeIsWarned(t *testing.T) {
	setupGuard(t, nil, guardEnv{guard: true})
	audit.configure(true, 50, 0)
	want := `{"model":"gpt-4o-mini","choices":[{"message":{"content":"hi"}}]}`
	gw, _ := startGateway(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, want)
	})
	resp, body := postJSON(t, gw, `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`)
	if resp.StatusCode != http.StatusOK || string(body) != want {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}
	for _, e := range audit.recent(10) {
		if e.Kind == "model_mismatch" && e.Model == "gpt-4o" && e.UpstreamModel == "gpt-4o-mini" {
			return
		}
	}
	t.Fatalf("downgrade not warned: %+v", audit.recent(10))
}

// 端到端：快照后缀不算不一致。
func TestForwardModelSnapshotSuffixIsNotWarned(t *testing.T) {
	setupGuard(t, nil, guardEnv{guard: true})
	audit.configure(true, 50, 0)
	gw, _ := startGateway(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"model":"gpt-4o-mini","choices":[]}`)
	})
	postJSON(t, gw, `{"model":"gpt-4o-mini-2024-07-18","messages":[]}`)
	for _, e := range audit.recent(10) {
		if e.Kind == "model_mismatch" {
			t.Fatalf("snapshot suffix must not warn: %+v", e)
		}
	}
}
