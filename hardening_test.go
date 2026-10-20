package main

// F5–F10 收敛轮次的测试。
//
// 分组对应发现编号，避免把"安全边界"（F5/F9）和"告警准确性/可观测性"
// （F6/F7/F8）混在一起验收。

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// F5：长敏感值 —— 不再静默丢弃，必须给出覆盖不完整信号
// ---------------------------------------------------------------------------

func TestCoverageGapForOverlongMatch(t *testing.T) {
	long := "LONGSECRET-" + strings.Repeat("a", 600) // > maxHitTextLen(512)
	rule := Rule{
		ID: 1, Name: "long", Enabled: true, Action: ActionMask,
		Pattern: `LONGSECRET-[a-z]{600}`, Replacement: "[LONG]",
	}

	// 请求侧：命中值被替换，但无法采集为 needle
	store = testStore(t, []Rule{rule})
	out, meta, rejected, err := protectRequest([]byte(`{"messages":[{"role":"user","content":"` + long + `"}]}`))
	if err != nil || rejected {
		t.Fatalf("protect: rejected=%v err=%v", rejected, err)
	}
	if strings.Contains(string(out), long) {
		t.Fatal("long value should still be masked in the request")
	}
	if !meta.coverageGap {
		t.Fatal("coverageGap must be reported when a match exceeds the needle cap")
	}
	if len(meta.needles) != 0 {
		t.Fatalf("overlong match must not become a needle, got %d", len(meta.needles))
	}

	// 端到端：必须通过响应头明确告知覆盖不完整，且**不得**假装能阻断
	setupGuard(t, []Rule{rule}, guardEnv{guard: true})
	audit.configure(true, 50, 0)
	gw, _ := startGateway(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"echo":"`+long+`"}`) // 回显真值
	})
	resp, body := postJSON(t, gw, `{"messages":[{"role":"user","content":"`+long+`"}]}`)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d: an untracked value cannot be blocked, so the response must pass through", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Mask-Guard"); !strings.Contains(got, "coverage-incomplete") {
		t.Fatalf("X-Mask-Guard=%q, want coverage-incomplete", got)
	}
	if !strings.Contains(string(body), long) {
		t.Fatal("test premise broken: expected the untracked echo in the body")
	}
	found := false
	for _, e := range audit.recent(10) {
		if e.Kind == "coverage_gap" {
			found = true
		}
	}
	if !found {
		t.Fatalf("coverage_gap event missing: %+v", audit.recent(10))
	}
}

func TestCoverageGapOnCollectionCapReached(t *testing.T) {
	// 300 个不同命中 → 只采集 maxCollectedHits(256) 个，其余必须计入缺口。
	var sb strings.Builder
	for i := 0; i < 300; i++ {
		fmt.Fprintf(&sb, "TOK%04d ", i)
	}
	store = testStore(t, []Rule{{
		ID: 1, Name: "tok", Enabled: true, Action: ActionMask,
		Pattern: `TOK\d{4}`, Replacement: "[T]",
	}})
	_, meta, _, _ := protectRequest([]byte(`{"messages":[{"role":"user","content":"` + sb.String() + `"}]}`))

	if !meta.coverageGap {
		t.Fatal("hitting the collection cap must be reported as a coverage gap")
	}
	if len(meta.needles) != maxCollectedHits {
		t.Fatalf("needles=%d, want %d", len(meta.needles), maxCollectedHits)
	}
	// 内存预算：条数 × 单条上限
	for _, n := range meta.needles {
		if len(n) > maxHitTextLen {
			t.Fatalf("needle longer than cap: %d", len(n))
		}
	}
	if bound := maxCollectedHits * maxHitTextLen; 128<<10 != bound {
		t.Fatalf("documented memory bound drifted: %d", bound)
	}
}

func TestNoCoverageSignalForNormalValues(t *testing.T) {
	setupGuard(t, []Rule{{
		ID: 1, Name: "mask", Enabled: true, Action: ActionMask,
		Pattern: "sk-[a-zA-Z0-9]{20}", Replacement: "[KEY]",
	}}, guardEnv{guard: true})
	gw, _ := startGateway(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
	resp, _ := postJSON(t, gw, `{"messages":[{"role":"user","content":"sk-abcdefghijklmnopqrst"}]}`)
	if got := resp.Header.Get("X-Mask-Guard"); got != "" {
		t.Fatalf("clean short values must not emit coverage flags, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// F6 + F7：B2 扫描完整性
// ---------------------------------------------------------------------------

func TestWarnScannerCrossChunkOverlap(t *testing.T) {
	key := "sk-proj-AbCdEfGhIjKlMnOpQrStUvWx"
	w := newWarnScanner([]Rule{detectorRule(1, "api_key", ActionMask, "[K]")}, 1<<20)

	if hits := w.Scan([]byte("prefix " + key[:10])); len(hits) != 0 {
		t.Fatalf("partial key must not hit, got %d", len(hits))
	}
	if hits := w.Scan([]byte(key[10:] + " suffix")); len(hits) != 1 {
		t.Fatalf("key split across chunks not detected (hits=%d)", len(hits))
	}
	if w.exhaustedScan() {
		t.Fatal("budget should not be exhausted here")
	}
}

func TestWarnScannerNoFalseHitAcrossBoundary(t *testing.T) {
	w := newWarnScanner([]Rule{detectorRule(1, "api_key", ActionMask, "[K]")}, 1<<20)
	if hits := w.Scan([]byte("nothing to see here sk-proj-")); len(hits) != 0 {
		t.Fatalf("unexpected hit: %d", len(hits))
	}
	if hits := w.Scan([]byte("short suffix, not a key at all")); len(hits) != 0 {
		t.Fatalf("unexpected hit: %d", len(hits))
	}
}

func TestWarnScannerBudgetIsPerResponseAndObservable(t *testing.T) {
	w := newWarnScanner([]Rule{detectorRule(1, "api_key", ActionMask, "[K]")}, 100)
	w.Scan(bytes.Repeat([]byte("a"), 80))
	if w.exhaustedScan() {
		t.Fatal("budget not exhausted yet")
	}
	w.Scan(bytes.Repeat([]byte("a"), 80)) // window 80+overlap > 剩余预算
	if !w.exhaustedScan() {
		t.Fatal("truncated scan must be flagged as exhausted")
	}
	if w.budget != 0 {
		t.Fatalf("budget=%d, want 0 (total scanned bytes must stay within the budget)", w.budget)
	}
	if w.Scan([]byte("x")) != nil || !w.exhaustedScan() {
		t.Fatal("scanning after exhaustion must be a no-op and stay flagged")
	}
}

func TestScanBudgetExhaustionIsObservableE2E(t *testing.T) {
	setupGuard(t, []Rule{detectorRule(1, "api_key", ActionMask, "[K]")},
		guardEnv{guard: true, warnByte: 1000})
	audit.configure(true, 50, 0)

	want := strings.Repeat("x", 200<<10) // 远大于预算
	gw, _ := startGateway(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, want)
	})

	resp, body := postJSON(t, gw, `{"model":"m","messages":[{"role":"user","content":"hi"}]}`)
	if resp.StatusCode != http.StatusOK || string(body) != want {
		t.Fatalf("B2 must never change status/bytes: status=%d len=%d", resp.StatusCode, len(body))
	}
	if got := resp.Header.Get("X-Mask-Guard"); !strings.Contains(got, "scan-partial") {
		t.Fatalf("X-Mask-Guard=%q, want scan-partial", got)
	}
	found := false
	for _, e := range audit.recent(10) {
		if e.Kind == "scan_incomplete" {
			found = true
		}
	}
	if !found {
		t.Fatalf("scan_incomplete event missing: %+v", audit.recent(10))
	}
}

// ---------------------------------------------------------------------------
// F8：日志放大受控，但关键事件不丢
// ---------------------------------------------------------------------------

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func captureLog(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	prevOut, prevLog := log.Writer(), guardLog
	log.SetOutput(buf)
	guardLog = &logLimiter{window: time.Minute, last: map[string]time.Time{}, muted: map[string]int{}}
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		guardLog = prevLog
	})
	return buf
}

func TestLogRateLimitKeepsRingAndCriticalEvents(t *testing.T) {
	buf := captureLog(t)
	audit.configure(true, 50, 0)
	defer audit.configure(false, 50, 0)
	audit.clear()

	// 同一检测器 20 次告警 → stderr 只应有 1 行
	for i := 0; i < 20; i++ {
		recordEvent(auditEvent{Kind: "sensitive", Action: "warned", Detector: "api_key"}, "")
	}
	if n := strings.Count(buf.String(), "kind=sensitive"); n != 1 {
		t.Fatalf("sensitive log lines = %d, want 1 (rate limited)", n)
	}
	// 但环形缓冲一条都不能丢
	if got := len(audit.recent(50)); got != 20 {
		t.Fatalf("audit ring lost events: %d/20", got)
	}

	// B1 泄漏是安全关键事件：永不被限流
	for i := 0; i < 5; i++ {
		recordEvent(auditEvent{Kind: "leak", Action: "blocked", MatchedLen: 26}, "")
	}
	if n := strings.Count(buf.String(), "kind=leak"); n != 5 {
		t.Fatalf("leak log lines = %d, want 5 (never rate limited)", n)
	}
}

func TestLogRateLimitReportsSuppressedCount(t *testing.T) {
	buf := captureLog(t)
	guardLog.window = 20 * time.Millisecond
	for i := 0; i < 3; i++ { // 第 1 条记录，后 2 条被抑制
		recordEvent(auditEvent{Kind: "model_mismatch", Model: "a", UpstreamModel: "b"}, "")
	}
	time.Sleep(30 * time.Millisecond) // 窗口滚动
	recordEvent(auditEvent{Kind: "model_mismatch", Model: "a", UpstreamModel: "b"}, "")
	if !strings.Contains(buf.String(), "suppressed=2") {
		t.Fatalf("suppressed count missing from log: %q", buf.String())
	}
}

func TestLogRateLimitDifferentKeysAreIndependent(t *testing.T) {
	buf := captureLog(t)
	recordEvent(auditEvent{Kind: "sensitive", Detector: "api_key"}, "")
	recordEvent(auditEvent{Kind: "sensitive", Detector: "cn_phone"}, "")
	recordEvent(auditEvent{Kind: "model_mismatch"}, "")
	if n := strings.Count(buf.String(), "response guard:"); n != 3 {
		t.Fatalf("log lines = %d, want 3 (distinct keys)", n)
	}
}

// ---------------------------------------------------------------------------
// F9：诊断接口访问控制
// ---------------------------------------------------------------------------

func adminServer(t *testing.T) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(apiRouter))
	t.Cleanup(s.Close)
	return s
}

func setAdminToken(t *testing.T, token string) {
	t.Helper()
	prev := adminTokenValue
	adminTokenValue = token
	t.Cleanup(func() { adminTokenValue = prev })
}

func TestEventsAPIRequiresConfiguredToken(t *testing.T) {
	setAdminToken(t, "") // 未配置 → fail closed
	srv := adminServer(t)
	audit.configure(true, 10, 0)
	defer audit.configure(false, 50, 0)
	audit.clear()

	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		req, _ := http.NewRequest(method, srv.URL+"/api/events", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", method, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("%s without token configured: status=%d, want 403", method, resp.StatusCode)
		}
	}
}

func TestEventsAPIRejectsUnauthorized(t *testing.T) {
	setAdminToken(t, "s3cret-token")
	srv := adminServer(t)
	audit.configure(true, 10, 0)
	defer audit.configure(false, 50, 0)
	audit.clear()
	recordEvent(auditEvent{Kind: "leak", Action: "blocked"}, "")

	cases := []struct {
		name   string
		header string
		value  string
	}{
		{"no header", "", ""},
		{"wrong token", "Authorization", "Bearer wrong"},
		{"empty bearer", "Authorization", "Bearer "},
		{"prefix only", "Authorization", "Bearer s3cret"},
	}
	for _, c := range cases {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/events", nil)
		if c.header != "" {
			req.Header.Set(c.header, c.value)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s: status=%d, want 401", c.name, resp.StatusCode)
		}
	}

	// DELETE 同样受保护
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/events", nil)
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthorized DELETE: status=%d, want 401", resp.StatusCode)
	}
	if len(audit.recent(10)) == 0 {
		t.Fatal("unauthorized DELETE must not clear events")
	}
}

func TestEventsAPIAuthorized(t *testing.T) {
	setAdminToken(t, "s3cret-token")
	srv := adminServer(t)
	audit.configure(true, 10, 0)
	defer audit.configure(false, 50, 0)
	audit.clear()
	recordEvent(auditEvent{Kind: "leak", Action: "blocked", MatchedLen: 26}, "")

	for _, auth := range []func(*http.Request){
		func(r *http.Request) { r.Header.Set("Authorization", "Bearer s3cret-token") },
		func(r *http.Request) { r.Header.Set("Authorization", "bearer s3cret-token") }, // 大小写不敏感
		func(r *http.Request) { r.Header.Set("X-Admin-Token", "s3cret-token") },
	} {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/events?limit=5", nil)
		auth(req)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status=%d body=%s", resp.StatusCode, body)
		}
		if !strings.Contains(string(body), `"enabled":true`) || !strings.Contains(string(body), `"leak"`) {
			t.Fatalf("unexpected events payload: %s", body)
		}
	}

	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/events", nil)
	req.Header.Set("Authorization", "Bearer s3cret-token")
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authorized DELETE: status=%d", resp.StatusCode)
	}
	if len(audit.recent(10)) != 0 {
		t.Fatal("authorized DELETE should clear events")
	}
}

func TestAuditHintNeverStoresCompleteValue(t *testing.T) {
	audit.configure(true, 10, 0)
	defer audit.configure(false, 50, 0)
	audit.clear()

	secret := "sk-abcdefghijklmnopqrst"
	// 请求长度 >= 值长度：不记录任何内容
	if got := audit.hintValue("sk-short", 16); got != "" {
		t.Fatalf("hint must be empty when the value fits in n, got %q", got)
	}
	// n < 值长度：只保留前缀
	if got := audit.hintValue(secret, 4); got != "sk-a…" {
		t.Fatalf("hint=%q", got)
	}
	// n 超过硬上限：被夹到 maxAuditHintChars —— 因此即使请求 n >= 值长度，
	// 也绝不会等于完整凭证
	got := audit.hintValue(secret, len(secret))
	if got == secret || got == "" || !strings.HasSuffix(got, "…") || len(got) > maxAuditHintChars+3 {
		t.Fatalf("clamped hint must be a strict prefix, got %q", got)
	}
	if h := audit.hintValue(strings.Repeat("z", 40), 1000); h != strings.Repeat("z", maxAuditHintChars)+"…" {
		t.Fatalf("hint clamp failed: %q", h)
	}
	// configure 也会夹紧
	audit.configure(true, 10, 500)
	audit.mu.Lock()
	hc := audit.hintChars
	audit.mu.Unlock()
	if hc != maxAuditHintChars {
		t.Fatalf("hintChars=%d, want clamp to %d", hc, maxAuditHintChars)
	}
}

func TestAuditConcurrentAccess(t *testing.T) {
	audit.configure(true, 32, 0)
	defer audit.configure(false, 50, 0)
	audit.clear()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				recordEvent(auditEvent{Kind: "sensitive", Detector: "api_key"}, "")
				_ = audit.recent(10)
				if j%25 == 0 {
					audit.clear()
				}
			}
		}(i)
	}
	wg.Wait()
	if n := len(audit.recent(100)); n > 32 {
		t.Fatalf("ring exceeded capacity: %d", n)
	}
}

// ---------------------------------------------------------------------------
// F10：并发大响应 —— 峰值内存 / GC / 首字节分位数
// ---------------------------------------------------------------------------

func TestConcurrentLargeResponses(t *testing.T) {
	const (
		concurrency = 8
		bodySize    = 3 << 20
	)
	setupGuard(t, []Rule{{
		ID: 1, Name: "mask", Enabled: true, Action: ActionMask,
		Pattern: "sk-[a-zA-Z0-9]{20}", Replacement: "[KEY]",
	}}, guardEnv{guard: true})
	secret := "sk-abcdefghijklmnopqrst"

	chunk := strings.Repeat("x", 64<<10)
	gw, _ := startGateway(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		for written := 0; written < bodySize; written += len(chunk) {
			_, _ = io.WriteString(w, chunk)
		}
	})

	// 采样堆使用峰值
	stop := make(chan struct{})
	var peak uint64
	var samples int
	var sampling sync.WaitGroup
	sampling.Add(1)
	go func() {
		defer sampling.Done()
		var ms runtime.MemStats
		for {
			select {
			case <-stop:
				return
			case <-time.After(5 * time.Millisecond):
			}
			runtime.ReadMemStats(&ms)
			samples++
			if ms.HeapInuse > peak {
				peak = ms.HeapInuse
			}
		}
	}()

	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)

	ttfbs := make([]time.Duration, concurrency)
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			start := time.Now()
			resp, err := http.Post(gw+"/v1/chat/completions", "application/json",
				strings.NewReader(`{"messages":[{"role":"user","content":"`+secret+`"}]}`))
			if err != nil {
				t.Errorf("post: %v", err)
				return
			}
			defer resp.Body.Close()
			buf := make([]byte, 1)
			if _, err := io.ReadFull(resp.Body, buf); err != nil {
				t.Errorf("first byte: %v", err)
				return
			}
			ttfbs[i] = time.Since(start)
			n, _ := io.Copy(io.Discard, resp.Body)
			if int(n)+1 != bodySize {
				t.Errorf("bytes=%d, want %d", n+1, bodySize)
			}
		}(i)
	}
	wg.Wait()
	close(stop)
	sampling.Wait()

	sort.Slice(ttfbs, func(i, j int) bool { return ttfbs[i] < ttfbs[j] })
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	peakDelta := 0 * uint64(0)
	if peak > base.HeapInuse {
		peakDelta = peak - base.HeapInuse
	}

	t.Logf("concurrency=%d body=%dMB peakHeapDelta=%.1fMB numGC=%d samples=%d",
		concurrency, bodySize>>20, float64(peakDelta)/(1<<20), ms.NumGC-base.NumGC, samples)
	t.Logf("ttfb p50=%v p95=%v max=%v", ttfbs[concurrency/2], ttfbs[(concurrency*95)/100], ttfbs[concurrency-1])

	// 结构性上界：每请求最多缓冲 peekBytes，加上流缓冲与 GC 余量。
	if limit := uint64(concurrency) * uint64(peekBytes) * 6; peakDelta > limit {
		t.Fatalf("peak heap delta %dMB exceeds structural bound %dMB (possible unbounded buffering)",
			peakDelta>>20, limit>>20)
	}
}

// ---------------------------------------------------------------------------
// 基准：三种状态的吞吐（供灰度对比）
// ---------------------------------------------------------------------------

func benchForward(b *testing.B, rules []Rule, guard bool, body string) {
	b.Helper()
	store = testStore(&testing.T{}, rules)
	prevGuard, prevPeek := guardEnabled, peekBytes
	prevUp, prevClient, prevAudit := upstreamBase, client, audit.isEnabled()
	guardEnabled, peekBytes = guard, 1<<20
	client = &http.Client{Transport: &http.Transport{DisableCompression: true}}
	audit.configure(false, 50, 0)
	defer func() {
		guardEnabled, peekBytes, upstreamBase, client = prevGuard, prevPeek, prevUp, prevClient
		audit.configure(prevAudit, 50, 0)
	}()

	payload := strings.Repeat("x", 4<<10)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, payload)
	}))
	defer up.Close()
	upstreamBase = up.URL

	gw := httptest.NewServer(http.HandlerFunc(forward))
	defer gw.Close()

	b.ResetTimer()
	b.SetBytes(int64(len(payload)))
	for i := 0; i < b.N; i++ {
		resp, err := http.Post(gw.URL+"/v1/chat/completions", "application/json", strings.NewReader(body))
		if err != nil {
			b.Fatal(err)
		}
		n, _ := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if n != int64(len(payload)) {
			b.Fatalf("body=%d", n)
		}
	}
}

func BenchmarkForwardGuardOff(b *testing.B) {
	benchForward(b, []Rule{{
		ID: 1, Name: "m", Enabled: true, Action: ActionMask,
		Pattern: "sk-[a-zA-Z0-9]{20}", Replacement: "[K]",
	}}, false, `{"messages":[{"role":"user","content":"sk-abcdefghijklmnopqrst"}]}`)
}

func BenchmarkForwardGuardOnNoNeedles(b *testing.B) {
	benchForward(b, nil, true, `{"messages":[{"role":"user","content":"hello"}]}`)
}

func BenchmarkForwardGuardOnHoldback(b *testing.B) {
	benchForward(b, []Rule{{
		ID: 1, Name: "m", Enabled: true, Action: ActionMask,
		Pattern: "sk-[a-zA-Z0-9]{20}", Replacement: "[K]",
	}}, true, `{"messages":[{"role":"user","content":"sk-abcdefghijklmnopqrst"}]}`)
}

var _ = os.Stderr

// ---------------------------------------------------------------------------
// 来源白名单（-allow-cidr）：默认只允许回环
//
// 目的不是替代鉴权，而是把"能连上端口"这件事本身收窄：WSL 连 Windows 侧网关
// 必须放开端口，但放开的是"这一网段"，不是"整个局域网"。
// ---------------------------------------------------------------------------

func TestRemoteAllowedDefaultsToLoopback(t *testing.T) {
	prev := allowNets
	allowNets = defaultAllowNets()
	defer func() { allowNets = prev }()

	cases := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:5555", true},
		{"[::1]:5555", true},
		{"[::ffff:127.0.0.1]:5555", true}, // Go 在某些平台把 IPv4 报成 4-in-6
		{"192.168.1.9:5555", false},
		{"[fe80::1]:5555", false},
		{"10.0.0.1:5555", false},
		{"", false},        // 解析不出来 → 拒绝，不能当成放行
		{"garbage", false}, // 同上
		{"127.0.0.1", true},
	}
	for _, c := range cases {
		if got := remoteAllowed(c.addr); got != c.want {
			t.Errorf("remoteAllowed(%q) = %v, want %v", c.addr, got, c.want)
		}
	}
}

func TestParseAllowNets(t *testing.T) {
	if got, err := parseAllowNets(nil); err != nil || len(got) != 2 {
		t.Fatalf("empty spec must fall back to loopback, got %v err=%v", got, err)
	}
	if got, err := parseAllowNets([]string{"  "}); err != nil || len(got) != 2 {
		t.Fatalf("blank spec must fall back to loopback, got %v err=%v", got, err)
	}
	// 逗号分隔 + 单主机不带掩码
	got, err := parseAllowNets([]string{"172.28.0.0/16, 10.1.2.3"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 2 || got[0].String() != "172.28.0.0/16" || got[1].String() != "10.1.2.3/32" {
		t.Fatalf("unexpected nets: %v", got)
	}
	// 写错必须报错（启动 fail closed，不静默降级成"全放行"）
	if _, err := parseAllowNets([]string{"172.28.0.0/33"}); err == nil {
		t.Fatal("invalid CIDR must be rejected")
	}
	if _, err := parseAllowNets([]string{"not-an-ip"}); err == nil {
		t.Fatal("invalid IP must be rejected")
	}
}

func TestRestrictRemoteBlocksAndFailsClosed(t *testing.T) {
	prev := allowNets
	allowNets = defaultAllowNets()
	defer func() { allowNets = prev }()

	h := restrictRemote(http.HandlerFunc(route))

	// 局域网来源：直接 403，且不暴露"这个端口上有什么"
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.RemoteAddr = "203.0.113.7:4444"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-allowed source: want 403, got %d (%s)", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "ok") {
		t.Fatalf("blocked request leaked a successful body: %s", rec.Body.String())
	}

	// 回环：正常放行
	req = httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.RemoteAddr = "127.0.0.1:4444"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("loopback: want 200 ok, got %d %q", rec.Code, rec.Body.String())
	}

	// 加了 WSL 网段之后：只在名单里的能进
	nets, err := parseAllowNets([]string{"127.0.0.1/32,172.28.0.0/16"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	allowNets = nets
	req = httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.RemoteAddr = "172.28.240.55:4444" // WSL2 侧地址
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("wsl subnet should be allowed, got %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.RemoteAddr = "172.29.0.1:4444"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("neighbouring subnet must stay blocked, got %d", rec.Code)
	}
}
