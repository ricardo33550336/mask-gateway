package main

import (
	"bytes"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"flag"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

//go:embed static
var staticFS embed.FS

var (
	store        *Store
	upstreamBase string
	client       *http.Client

	// Response guard configuration (set once from flags in main).
	guardEnabled  = true      // B1 blocking + B2/F warnings
	peekBytes     = 1 << 20   // 非流式响应最多预先缓冲多少字节
	leakMinLen    = 8         // B1 最短 needle，太短会误报
	warnScanBytes = 256 << 10 // B2 每条响应最多扫描多少字节
	// peekBudget 是窥探阶段等待上游的总时长上限（不是字节目标）。
	// 到期即放行已读前缀并继续透传，避免慢响应把首字节拖住。
	peekBudget = 200 * time.Millisecond

	// adminTokenValue guards the diagnostics API. Empty = diagnostics over HTTP
	// are disabled entirely (fail closed): the ring may still be enabled for the
	// operator via logs, but it is not readable without a configured token.
	adminTokenValue string
)

func main() {
	addr := flag.String("addr", ":8282", "listen address")
	rulesFile := flag.String("rules", "rules.json", "path to the rules JSON file")
	upstream := flag.String("upstream", os.Getenv("UPSTREAM"), "upstream base URL, e.g. https://api.openai.com")
	developerAsSystem := flag.Bool("developer-as-system", os.Getenv("DEVELOPER_AS_SYSTEM") == "1",
		"map the developer role to system before forwarding (for upstreams that reject developer)")
	responseGuard := flag.Bool("response-guard", os.Getenv("RESPONSE_GUARD") != "0",
		"scan upstream responses: block echoes of masked values, warn on sensitive content / model mismatch")
	peekLimit := flag.Int("peek-bytes", 1<<20,
		"max upstream bytes buffered before the response is committed (streams are peeked for one read only)")
	leakMin := flag.Int("leak-min-len", 8,
		"minimum length of an echoed value for the leak guard to consider it (shorter values are ignored)")
	warnBudget := flag.Int("warn-scan-bytes", 256<<10,
		"per-response byte budget for detector-based response warnings (0 disables them)")
	auditEnabled := flag.Bool("audit", os.Getenv("AUDIT") == "1",
		"keep a small in-memory ring buffer of guard events (no request/response content is stored)")
	auditSize := flag.Int("audit-size", 200, "ring buffer size for -audit")
	auditHint := flag.Int("audit-hint-chars", 0,
		"how many leading bytes of a matched value to keep in audit events (0 = none, recommended)")
	adminToken := flag.String("admin-token", os.Getenv("ADMIN_TOKEN"),
		"bearer token required by the diagnostics API (/api/events); when empty the API is disabled")
	flag.Parse()

	normalizeDeveloperToSystem = *developerAsSystem
	guardEnabled = *responseGuard
	peekBytes = *peekLimit
	leakMinLen = *leakMin
	warnScanBytes = *warnBudget
	audit.configure(*auditEnabled, *auditSize, *auditHint)
	adminTokenValue = *adminToken

	var err error
	store, err = NewStore(*rulesFile)
	if err != nil {
		log.Fatalf("load rules store: %v", err)
	}

	upstreamBase = strings.TrimRight(*upstream, "/")

	client = &http.Client{
		Transport: &http.Transport{
			// Forward upstream bytes verbatim (SSE-safe); do not let Go
			// transparently gzip/decompress which would corrupt the pass-through.
			DisableCompression:    true,
			ResponseHeaderTimeout: 120 * time.Second,
		},
	}

	http.HandleFunc("/", route)

	log.Printf("mask gateway listening on %s (upstream=%q, rules=%s, response-guard=%v, peek=%dB, audit=%v)",
		*addr, upstreamBase, *rulesFile, guardEnabled, peekBytes, audit.isEnabled())
	log.Fatal(http.ListenAndServe(*addr, nil))
}

// route dispatches between the admin UI, the admin API and the forwarder.
func route(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path

	switch {
	case p == "/healthz":
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))

	case strings.HasPrefix(p, "/api/"):
		apiRouter(w, r)

	case p == "/" || p == "/index.html":
		serveUI(w, r)

	case strings.HasPrefix(p, "/static/"):
		sub, _ := fs.Sub(staticFS, "static")
		noCache(w)
		http.StripPrefix("/static/", http.FileServer(http.FS(sub))).ServeHTTP(w, r)

	default:
		forward(w, r)
	}
}

func serveUI(w http.ResponseWriter, r *http.Request) {
	sub, _ := fs.Sub(staticFS, "static")
	noCache(w)
	http.FileServer(http.FS(sub)).ServeHTTP(w, r)
}

// noCache 强制浏览器每次回源校验。
// embed.FS 里的文件没有 modtime，http.FileServer 因此不会发 Last-Modified / ETag，
// 浏览器只剩启发式缓存 —— 换了二进制后很可能继续用旧的 app.js（前端页面已经"修好"却看不出来）。
func noCache(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-cache")
}

// ---------------------------------------------------------------------------
// Admin API (REST, plain JSON — no GraphQL/gqlgen needed)
// ---------------------------------------------------------------------------

// requireAdmin guards the diagnostics endpoints.
//
// There is no general auth layer in this project (the rules API is documented as
// needing a fronting gateway), so the diagnostics surface gets its own minimal
// control instead of inheriting "open to everyone":
//
//   - no -admin-token configured → 403, the API is disabled (fail closed)
//   - token configured but missing/wrong → 401
//
// The token is compared in constant time. It is accepted as
// "Authorization: Bearer <token>" or "X-Admin-Token: <token>".
func requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if adminTokenValue == "" {
		apiErr(w, http.StatusForbidden,
			"diagnostics API disabled: start the gateway with -admin-token (or ADMIN_TOKEN) to enable it")
		return false
	}
	got := r.Header.Get("X-Admin-Token")
	if got == "" {
		auth := r.Header.Get("Authorization")
		if len(auth) > 7 && strings.EqualFold(auth[:7], "bearer ") {
			got = strings.TrimSpace(auth[7:])
		}
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(adminTokenValue)) != 1 {
		apiErr(w, http.StatusUnauthorized, "unauthorized")
		return false
	}
	return true
}

func apiRouter(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/api")

	switch {
	case p == "/rules" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, store.List())

	case p == "/rules" && r.Method == http.MethodPost:
		createRule(w, r)

	case strings.HasPrefix(p, "/rules/"):
		ruleItem(w, r, p)

	case p == "/detectors" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, detectors)

	case p == "/events" && r.Method == http.MethodGet:
		if !requireAdmin(w, r) {
			return
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 {
			limit = 50
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled": audit.isEnabled(),
			"events":  audit.recent(limit),
		})

	case p == "/events" && r.Method == http.MethodDelete:
		if !requireAdmin(w, r) {
			return
		}
		audit.clear()
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})

	case p == "/preview" && r.Method == http.MethodPost:
		preview(w, r)

	default:
		apiErr(w, http.StatusNotFound, "not found")
	}
}

func createRule(w http.ResponseWriter, r *http.Request) {
	var input Rule
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		apiErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if err := validateRule(input); err != nil {
		apiErr(w, http.StatusBadRequest, err.Error())
		return
	}
	rule, err := store.Create(input)
	if err != nil {
		apiErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, rule)
}

func ruleItem(w http.ResponseWriter, r *http.Request, p string) {
	// POST /api/rules/{id}/status  {"enabled": true|false}
	if strings.HasSuffix(p, "/status") {
		if r.Method != http.MethodPost {
			apiErr(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		id, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(p, "/rules/"), "/status"))
		if err != nil {
			apiErr(w, http.StatusBadRequest, "invalid id")
			return
		}
		var in struct {
			Enabled bool `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			apiErr(w, http.StatusBadRequest, "invalid json")
			return
		}
		rule, err := store.SetEnabled(id, in.Enabled)
		if err != nil {
			apiErr(w, http.StatusNotFound, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, rule)
		return
	}

	id, err := strconv.Atoi(strings.TrimPrefix(p, "/rules/"))
	if err != nil {
		apiErr(w, http.StatusBadRequest, "invalid id")
		return
	}

	switch r.Method {
	case http.MethodPut:
		var input Rule
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			apiErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
			return
		}
		input.ID = id
		if err := validateRule(input); err != nil {
			apiErr(w, http.StatusBadRequest, err.Error())
			return
		}
		rule, err := store.Update(id, input)
		if err != nil {
			apiErr(w, http.StatusNotFound, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, rule)

	case http.MethodDelete:
		if err := store.Delete(id); err != nil {
			apiErr(w, http.StatusNotFound, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})

	default:
		apiErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// preview lets the user test a pattern or detector without saving a rule.
func preview(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Type        string  `json:"type"`
		Pattern     string  `json:"pattern"`
		Detector    string  `json:"detector"`
		Threshold   float64 `json:"threshold"`
		MinLength   int     `json:"minLength"`
		TestText    string  `json:"testText"`
		Action      Action  `json:"action"`
		Replacement string  `json:"replacement"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		apiErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}

	rule := Rule{
		Type:        in.Type,
		Pattern:     in.Pattern,
		Detector:    in.Detector,
		Threshold:   in.Threshold,
		MinLength:   in.MinLength,
		Action:      in.Action,
		Replacement: in.Replacement,
		Enabled:     true,
	}
	if err := validatePatternAction(rule); err != nil {
		apiErr(w, http.StatusBadRequest, err.Error())
		return
	}

	result, changed, rejected := protectString(in.TestText, valueCtx{loc: FieldContent}, protector{rules: []Rule{rule}})
	hasMatch := changed || rejected
	if rejected {
		result = "reject"
	}

	writeJSON(w, http.StatusOK, map[string]any{"result": result, "hasMatch": hasMatch})
}

// ---------------------------------------------------------------------------
// Forwarding (纯转发)
// ---------------------------------------------------------------------------

// forward masks/rejects the request body, streams it to the upstream, and
// streams the upstream response back (SSE included).
//
// Response side: a bounded prefix is peeked *before* the status/headers are
// committed, so the guard can still refuse the response. If nothing matches,
// the bytes/status/headers are written exactly as before.
func forward(w http.ResponseWriter, r *http.Request) {
	if upstreamBase == "" {
		proxyErr(w, http.StatusBadGateway, "upstream not configured (set -upstream or UPSTREAM env)")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 128<<20))
	if err != nil {
		proxyErr(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	protected, meta, rejected, err := protectRequest(body)
	if err != nil {
		// Masking must never break forwarding: fall back to the original body.
		log.Printf("protect: %v (forwarding original body)", err)
		protected, rejected = body, false
	}

	if rejected {
		log.Printf("prompt protection rejected %s %s", r.Method, r.URL.Path)
		proxyErr(w, http.StatusBadRequest, "request blocked by prompt protection policy")
		return
	}

	target := upstreamBase + r.URL.RequestURI()
	req, err := http.NewRequestWithContext(r.Context(), r.Method, target, bytes.NewReader(protected))
	if err != nil {
		proxyErr(w, http.StatusInternalServerError, "failed to build upstream request")
		return
	}
	copyHeaders(req.Header, r.Header)

	resp, err := client.Do(req)
	if err != nil {
		proxyErr(w, http.StatusBadGateway, "upstream request failed: "+err.Error())
		return
	}
	defer resp.Body.Close()

	// F1：守卫关闭时必须真正回到旧透传路径（不窥探、不缓冲、不检测）。
	if !guardEnabled {
		streamPassthrough(w, resp)
		return
	}

	guardAndStream(w, r, resp, meta)
}

// streamPassthrough is the pre-guard behaviour, byte for byte: no peek, no
// buffering, no detection. -response-guard=false uses this so the fallback
// switch really restores the old latency characteristics.
func streamPassthrough(w http.ResponseWriter, resp *http.Response) {
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	flusher, _ := w.(http.Flusher)
	buf := make([]byte, 32*1024)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if rerr != nil {
			break
		}
	}
}

// guardAndStream peeks a bounded prefix (with a time budget), runs the guard,
// then streams the rest. Bytes/status/headers are unchanged when nothing hits.
func guardAndStream(w http.ResponseWriter, r *http.Request, resp *http.Response, meta requestMeta) {
	leak := newLeakMatcher(meta.needles, leakMinLen)
	warn := newWarnScanner(store.EnabledRules(), warnScanBytes)

	// Single owner of the body: the peek may stop *waiting* at the deadline
	// without losing or duplicating bytes (see upstreamStream).
	stream := newUpstreamStream(resp.Body, 32*1024)
	defer stream.close()

	// F5：请求侧有匹配值因超过采集上限而无法生成 needle → 本次响应的
	// 回显检测覆盖不完整，必须明确告知（审计 + 响应头）。
	if meta.coverageGap {
		recordEvent(auditEvent{
			Kind: "coverage_gap", Action: "warned", Path: r.URL.Path, Model: meta.model,
		}, "")
	}

	// F6：B2 预算可能在窥探阶段就已耗尽，收尾时再检查一次。
	defer func() {
		if warn.exhaustedScan() {
			recordEvent(auditEvent{
				Kind: "scan_incomplete", Action: "warned", Path: r.URL.Path, Model: meta.model,
			}, "")
		}
	}()

	expect := 0
	if n, err := strconv.Atoi(resp.Header.Get("Content-Length")); err == nil && n > 0 {
		expect = n
	}
	peek := peekUpstream(stream, peekBytes, peekBudget,
		isEventStream(resp.Header.Get("Content-Type")) || meta.stream, expect)

	if guardPeek(peek, leak, warn, meta, r) {
		proxyErr(w, http.StatusBadGateway, "upstream response blocked by leak guard")
		return
	}

	copyHeaders(w.Header(), resp.Header)
	if flags := guardSignals(meta, warn); len(flags) > 0 {
		w.Header().Set("X-Mask-Guard", strings.Join(flags, ", "))
	}
	w.WriteHeader(resp.StatusCode)

	flusher, _ := w.(http.Flusher)
	out := func(b []byte) bool {
		if len(b) == 0 {
			return true
		}
		if _, werr := w.Write(b); werr != nil {
			return false
		}
		if flusher != nil {
			flusher.Flush()
		}
		return true
	}

	// F3：发送端扣留 maxLen-1 字节，保证 needle 不会以"已发送前缀"的形式泄漏。
	guardOut := newLeakGuardWriter(leak, out)

	abortWith := func(matched int) {
		recordEvent(auditEvent{
			Kind: "leak", Action: "aborted", Path: r.URL.Path,
			Model: meta.model, MatchedLen: matched,
		}, "")
		abortHandler()
	}

	// 窥探到的前缀已由 guardPeek 检查过；但它的末尾仍要进入 holdback 窗口，
	// 否则 needle 可以跨"前缀 / 后续 chunk"的边界泄漏。
	if !guardOut.pushVerified(peek.prefix) {
		return
	}
	// F10：前缀已经写出（或已进入 holdback 窗口），立刻解除引用，
	// 让长流在后续透传期间不再持有最多 peekBytes 的缓冲。
	peek.prefix = nil

	if peek.err != nil || peek.full {
		if n, ok := guardOut.finish(); !ok {
			abortWith(n)
		}
		return
	}

	for {
		msg, ok, _ := stream.nextChunk(nil)
		if !ok {
			if n, ok := guardOut.finish(); !ok {
				abortWith(n)
			}
			return
		}
		if len(msg.data) > 0 {
			// B2 仍按 chunk 扫描（告警用，不改字节）。
			for _, rule := range warn.Scan(msg.data) {
				recordEvent(auditEvent{
					Kind: "sensitive", Action: "warned", Detector: rule.Detector,
					Rule: rule.Name, Path: r.URL.Path, Model: meta.model,
				}, "")
			}
			n, pushOK := guardOut.push(msg.data)
			stream.put(msg.data)
			if !pushOK {
				abortWith(n)
			}
		}
		if msg.err != nil {
			if n, ok := guardOut.finish(); !ok {
				abortWith(n)
			}
			return
		}
	}
}

// guardSignals returns the machine-readable coverage flags for this response.
//
// It answers "can I trust that this response was fully checked?", not "was it
// blocked": a coverage gap means a matched value was too long to be tracked, and
// scan-partial means the detector budget ran out. Neither implies B1 could have
// blocked anything — only that protection is incomplete and the caller should
// know.
func guardSignals(meta requestMeta, warn *warnScanner) []string {
	var flags []string
	if meta.coverageGap {
		flags = append(flags, "coverage-incomplete")
	}
	if warn.exhaustedScan() {
		flags = append(flags, "scan-partial")
	}
	return flags
}

// guardPeek inspects the peeked prefix before the response is committed.
// Returns block=true when the guard refuses the response.
func guardPeek(peek peekResult, leak *leakMatcher, warn *warnScanner, meta requestMeta, r *http.Request) bool {
	// F: model mismatch (warn only)
	if sent, got := meta.model, extractUpstreamModel(peek.prefix); got != "" && sent != "" && !modelsCompatible(sent, got) {
		recordEvent(auditEvent{
			Kind: "model_mismatch", Action: "warned", Path: r.URL.Path,
			Model: sent, UpstreamModel: got,
		}, "")
	}

	// B2: detector scan (warn only)
	for _, rule := range warn.Scan(peek.prefix) {
		recordEvent(auditEvent{
			Kind: "sensitive", Action: "warned", Detector: rule.Detector,
			Rule: rule.Name, Path: r.URL.Path, Model: meta.model,
		}, "")
	}

	// B1: echo of a value we masked in this very request → block, nothing has
	// been written to the client yet.
	if n := leak.Find(peek.prefix); n > 0 {
		recordEvent(auditEvent{
			Kind: "leak", Action: "blocked", Path: r.URL.Path,
			Model: meta.model, MatchedLen: n,
		}, "")
		return true
	}

	return false
}

// normalizeDeveloperToSystem maps the OpenAI "developer" role to "system"
// before forwarding. Some OpenAI-compatible upstreams reject the developer
// role (e.g. serde-based servers that only accept system/user/assistant/tool).
// Disabled by default to keep pure passthrough.
var normalizeDeveloperToSystem = false

// normalizeDeveloperRoles rewrites role == "developer" to "system" in place.
// Returns true when anything changed.
func normalizeDeveloperRoles(doc map[string]json.RawMessage) bool {
	raw, ok := doc["messages"]
	if !ok {
		return false
	}
	var msgs []json.RawMessage
	if err := json.Unmarshal(raw, &msgs); err != nil {
		return false
	}

	changed := false
	for i, rawMsg := range msgs {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(rawMsg, &m); err != nil {
			continue
		}
		var role string
		if err := json.Unmarshal(m["role"], &role); err != nil || role != "developer" {
			continue
		}
		b, _ := json.Marshal("system")
		m["role"] = b
		updated, err := json.Marshal(m)
		if err != nil {
			continue
		}
		msgs[i] = updated
		changed = true
	}
	if !changed {
		return false
	}
	b, err := json.Marshal(msgs)
	if err != nil {
		return false
	}
	doc["messages"] = b
	return true
}

// requestMeta is what the response guard needs to know about the request.
type requestMeta struct {
	model   string
	stream  bool
	needles []string // 请求里被规则命中的原文（B1 的回显检测针）
	// coverageGap 表示有匹配值因采集上限（长度/条数）没有被采集，
	// 因此本次请求的 B1 回显检测覆盖不完整。
	coverageGap bool
}

// protectBody keeps the historical signature (used by tests and callers that do
// not care about response-side metadata).
func protectBody(body []byte) ([]byte, bool, error) {
	out, _, rejected, err := protectRequest(body)
	return out, rejected, err
}

// protectRequest applies enabled rules to an OpenAI-compatible JSON body and
// returns the metadata needed by the response guard.
//
// Scanned locations (see validFields in protect.go): messages[].content,
// messages[].tool_calls / reasoning*, request.tools[] / functions[], and a few
// top-level string fields. Non-JSON bodies are forwarded unchanged.
func protectRequest(body []byte) (out []byte, meta requestMeta, rejected bool, err error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil {
		return body, meta, false, nil // not JSON (e.g. multipart) → forward as-is
	}

	_ = json.Unmarshal(doc["model"], &meta.model)
	_ = json.Unmarshal(doc["stream"], &meta.stream)

	changed := false

	// 1) Masking / reject (rules match the client's ORIGINAL roles).
	if rules := store.EnabledRules(); len(rules) > 0 {
		var sink *hitSink
		if guardEnabled {
			// Observation only: the collector never affects matching/replacement.
			sink = &hitSink{}
		}
		p := protector{rules: rules, hits: sink}
		c, rej := protectDocument(doc, p)
		if rej {
			return body, meta, true, nil
		}
		changed = c
		if sink != nil {
			meta.needles = sink.needles()
			meta.coverageGap = sink.coverageGap()
		}
	}

	// 2) Role normalization (upstream-compatibility shim, applied last).
	if normalizeDeveloperToSystem {
		changed = normalizeDeveloperRoles(doc) || changed
	}

	if !changed {
		return body, meta, false, nil // nothing changed → keep the original bytes
	}

	out, err = json.Marshal(doc)
	if err != nil {
		return body, meta, false, nil
	}
	return out, meta, false, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func copyHeaders(dst, src http.Header) {
	for k, vv := range src {
		if isHopByHop(k) || k == "Content-Length" {
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func isHopByHop(k string) bool {
	switch http.CanonicalHeaderKey(k) {
	case "Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
		"Te", "Trailer", "Transfer-Encoding", "Upgrade":
		return true
	}
	return false
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// apiErr is used by the admin API.
func apiErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}

// proxyErr returns OpenAI-style errors on the forwarding path.
func proxyErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]any{
			"message": msg,
			"type":    "invalid_request_error",
		},
	})
}
