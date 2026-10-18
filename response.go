package main

// 响应侧守卫（response guard）。
//
// 设计约束（务必保持）：
//
//  1. **不缓存整个响应**。只窥探"必要的首 chunk / 前 N 字节"（SSE 只读一次），
//     命中判断在写响应头之前完成；超长响应退化为"只检查前缀 + 正常透传"。
//  2. **未命中请求的字节流与旧实现完全一致**：同样的 32KB 粒度、同样顺序、
//     同样 header、同样状态码。
//  3. 规则语义不在这里重新实现：B1 用的是"请求侧规则实际命中过的原文"，
//     B2 用的是 detect.go 的检测器，二者都不新增匹配逻辑。
//
// 三条检查：
//
//	B1 leak       请求里被 mask 过的真值在响应里出现 → 阻断（未写出）或断流（已写出）
//	B2 sensitive  响应里出现检测器认得的高危内容 → 仅告警
//	F  model      响应 model 与请求 model 不一致 → 仅告警

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// SSE 判定
// ---------------------------------------------------------------------------

func isEventStream(contentType string) bool {
	return strings.Contains(strings.ToLower(contentType), "event-stream")
}

// looksLikeSSE sniffs the first bytes of a body. Some upstreams / proxies omit
// or mislabel Content-Type; buffering a real SSE stream to discover that would
// destroy TTFB, so we check the frame prefix instead.
func looksLikeSSE(prefix []byte) bool {
	p := bytes.TrimLeft(prefix, "\r\n\t ")
	for _, kw := range []string{"data:", "event:", "id:", "retry:"} {
		if bytes.HasPrefix(p, []byte(kw)) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// 窥探（bounded peek）
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 上游读取（可停止等待的窥探）
// ---------------------------------------------------------------------------
//
// 窥探需要"到点就停止等待"，但同步 Read 一旦阻塞就无法被定时器打断。两条
// 看似更简单的路都走不通（已对照 net/http 源码确认）：
//
//   - 定时器包住同步 Read：到期后 Read 仍阻塞，预算形同虚设。
//   - 对连接 SetReadDeadline：错误会走 persistConn.readLoop → pc.closeLocked，
//     Transport 直接废弃整条连接（bodyEOFSignal.Close 也是 earlyClose），
//     后续字节再也取不回来，"放行前缀后继续透传"无法实现。
//
// 因此由**单个** goroutine 独占 body，chunk 经 channel 交给 forward：
//
//   - 窥探阶段用 select + 单个 time.Timer 等待，到期只"停止等待"，不取消读取
//   - 已到但未消费的 chunk 还在 channel 里，顺序/字节都不会丢或重复
//   - 窥探结束（或超时）后从同一 channel 继续取，直到 EOF
//   - forward 返回时 close(stop) + resp.Body.Close() 让 goroutine 退出（无泄漏）

type streamChunk struct {
	data []byte
	err  error
}

type upstreamStream struct {
	body    io.Reader
	bufSize int

	out  chan streamChunk // 容量 1：最多预读一个 chunk
	free chan []byte      // 缓冲区回收（同样容量 1）
	stop chan struct{}

	stopOnce sync.Once
}

func newUpstreamStream(body io.Reader, bufSize int) *upstreamStream {
	if bufSize <= 0 {
		bufSize = 32 * 1024
	}
	s := &upstreamStream{
		body:    body,
		bufSize: bufSize,
		out:     make(chan streamChunk, 1),
		free:    make(chan []byte, 1),
		stop:    make(chan struct{}),
	}
	go s.run()
	return s
}

func (s *upstreamStream) run() {
	// 安全网：退出即关闭 out，消费者不会因为"最后一条消息丢失"而永久阻塞。
	defer close(s.out)

	for {
		var buf []byte
		select {
		case buf = <-s.free:
		default:
			buf = make([]byte, s.bufSize)
		}

		n, err := s.body.Read(buf)
		msg := streamChunk{err: err}
		if n > 0 {
			msg.data = buf[:n]
		}

		// 交接所有权；无人接收（handler 已返回）就退出。
		select {
		case s.out <- msg:
		case <-s.stop:
			return
		}
		if n == 0 {
			s.put(buf)
		}
		if err != nil {
			return
		}
	}
}

// close asks the reader goroutine to exit. resp.Body.Close() (deferred by the
// caller) unblocks a pending Read, so the goroutine cannot be left behind.
func (s *upstreamStream) close() {
	s.stopOnce.Do(func() { close(s.stop) })
}

// put returns a consumed buffer for reuse.
func (s *upstreamStream) put(buf []byte) {
	if cap(buf) != s.bufSize {
		return
	}
	select {
	case s.free <- buf[:s.bufSize]:
	default:
	}
}

// nextChunk waits for the next chunk.
//
//	wait == nil → block until data / EOF / close
//	wait fires  → timedOut=true and **nothing is consumed**: the stream stays
//	              usable, so the caller can drain it later without loss.
func (s *upstreamStream) nextChunk(wait <-chan time.Time) (msg streamChunk, ok, timedOut bool) {
	select {
	case msg, open := <-s.out:
		if !open {
			return streamChunk{}, false, false
		}
		return msg, true, false
	case <-wait:
		return streamChunk{}, false, true
	case <-s.stop:
		return streamChunk{}, false, false
	}
}

// peekResult is the bounded prefix of the upstream response that the guard is
// allowed to inspect before committing the response.
type peekResult struct {
	prefix []byte // bytes already read from upstream
	full   bool   // prefix is the whole body (EOF reached within the limit)
	sse    bool   // response looks like server-sent events
	err    error  // read error encountered during the peek, if any
}

// peekUpstream reads at most `limit` bytes, and for SSE only a single chunk.
//
// `budget` bounds the total *waiting* time, not the byte count: limit is a
// ceiling, never a target to fill. When the budget expires, whatever has
// arrived is returned with full=false and the stream is left intact — the
// remaining bytes are streamed normally afterwards.
func peekUpstream(src *upstreamStream, limit int, budget time.Duration, hintSSE bool, expect int) peekResult {
	if limit <= 0 {
		limit = 1 << 20
	}

	var buf bytes.Buffer
	// 只做**有界**预分配：Content-Length 可能撒谎或很大，所以先夹到 limit。
	if expect > 0 {
		if expect > limit {
			expect = limit
		}
		buf.Grow(expect)
	}
	res := peekResult{}
	firstRead := true

	var wait <-chan time.Time
	if budget > 0 {
		timer := time.NewTimer(budget)
		defer timer.Stop()
		wait = timer.C
	}

	for {
		msg, ok, timedOut := src.nextChunk(wait)
		if timedOut {
			break // 预算到期：不丢已读前缀，剩下的交给后续透传
		}
		if !ok {
			res.full = true
			break
		}
		if len(msg.data) > 0 {
			if firstRead {
				res.sse = hintSSE || looksLikeSSE(msg.data)
				firstRead = false
			}
			_, _ = buf.Write(msg.data)
			src.put(msg.data) // 已拷贝进 buf，可以归还
		}
		// 必须先处理 err 再判断"够了"：Read 允许 (n>0, io.EOF) 同时返回，
		// 若在 sse/limit 处先 break，就会把这个 chunk 携带的 EOF/错误丢掉，
		// 后续 drain 会永远等不到结尾（配合 upstreamStream 时表现为 hang）。
		if msg.err != nil {
			if errors.Is(msg.err, io.EOF) {
				res.full = true
			} else {
				res.err = msg.err
			}
			break
		}
		if res.sse || buf.Len() >= limit {
			break
		}
	}
	res.prefix = buf.Bytes()
	return res
}

// ---------------------------------------------------------------------------
// B1：请求侧真值回显检测
// ---------------------------------------------------------------------------

// leakMatcher holds the exact values this request already sent upstream.
//
// Matching is stateless: the caller passes a window that already contains the
// overlap it cares about (leakGuardWriter keeps the tail). Keeping the overlap
// in the writer — instead of inside the matcher — is what allows holdback: the
// tail is both "matched against" and "withheld from the client" from the same
// buffer, so a needle can never be half-released before it is checked.
type leakMatcher struct {
	needles [][]byte
	maxLen  int
}

// newLeakMatcher builds a matcher from the values matched by request-side rules.
// Values shorter than minLen are ignored: short needles (a word, a number) would
// produce false positives on normal model output.
func newLeakMatcher(needles []string, minLen int) *leakMatcher {
	if len(needles) == 0 {
		return nil
	}
	m := &leakMatcher{}
	seen := make(map[string]bool, len(needles))
	for _, n := range needles {
		if len(n) < minLen {
			continue
		}
		for _, v := range needleVariants(n) {
			if seen[v] {
				continue
			}
			seen[v] = true
			m.needles = append(m.needles, []byte(v))
			if len(v) > m.maxLen {
				m.maxLen = len(v)
			}
		}
	}
	if len(m.needles) == 0 {
		return nil
	}
	return m
}

// needleVariants also matches the JSON-escaped form: a secret containing quotes
// or backslashes appears escaped inside JSON / SSE payloads.
func needleVariants(s string) []string {
	out := []string{s}
	b, err := json.Marshal(s)
	if err != nil || len(b) < 2 {
		return out
	}
	if esc := string(b[1 : len(b)-1]); esc != s {
		out = append(out, esc)
	}
	return out
}

// Find returns the length of the first needle found in window (0 = no hit).
func (m *leakMatcher) Find(window []byte) int {
	if m == nil || len(window) == 0 {
		return 0
	}
	for _, n := range m.needles {
		if bytes.Contains(window, n) {
			return len(n)
		}
	}
	return 0
}

// holdbackBytes is how many trailing bytes must be withheld until the next
// chunk arrives: a needle of length maxLen can only be complete after seeing
// maxLen bytes.
func (m *leakMatcher) holdbackBytes() int {
	if m == nil || m.maxLen <= 1 {
		return 0
	}
	return m.maxLen - 1
}

// ---------------------------------------------------------------------------
// B1 发送端：tail holdback
// ---------------------------------------------------------------------------
//
// 没有 holdback 时：一个 26 字节的密钥被上游切成 "前 10 字节 / 其余 16 字节"
// 两个 chunk，前 10 字节会被直接写出，客户端就拿到了密钥前缀。
//
// 有了 holdback（扣留 maxLen-1 字节）后，每次发送前都在"上一轮扣留的 tail +
// 新 chunk"这个窗口上做检测，只有窗口剩余的安全前缀才会被写出：
//
//	pending(≤maxLen-1) + chunk ──▶ Find(window)
//	                                 ├─ 命中 → 整个 window 都不发送（调用方终止）
//	                                 └─ 未命中 → 写出 window[:len-keep]，扣留尾部
//
// 因此任何 needle 的前缀都不会在"包含它的窗口被检查之前"发出去。收尾（EOF /
// 读错误）时 pending 会再检测一次才释放，绝不因为收尾而绕过检查。
type leakGuardWriter struct {
	matcher *leakMatcher
	keep    int
	pending []byte
	buf     []byte
	out     func([]byte) bool
}

func newLeakGuardWriter(m *leakMatcher, out func([]byte) bool) *leakGuardWriter {
	return &leakGuardWriter{matcher: m, keep: m.holdbackBytes(), out: out}
}

// push appends chunk to the holdback window, checks it, and releases the safe
// prefix. hit>0 means a needle was found and nothing from this window was
// written. ok=false means the underlying writer failed.
func (w *leakGuardWriter) push(chunk []byte) (hit int, ok bool) {
	if len(chunk) == 0 {
		return 0, true
	}
	if w.matcher == nil { // 无 needle：直接透传，零拷贝
		return 0, w.out(chunk)
	}

	w.buf = append(w.buf[:0], w.pending...)
	w.buf = append(w.buf, chunk...)
	window := w.buf

	if n := w.matcher.Find(window); n > 0 {
		return n, false
	}
	return 0, w.release(window)
}

// pushVerified is for bytes the caller has already checked (the peeked prefix):
// it only updates the holdback window, skipping the redundant scan.
func (w *leakGuardWriter) pushVerified(chunk []byte) bool {
	if len(chunk) == 0 {
		return true
	}
	if w.matcher == nil {
		return w.out(chunk)
	}
	w.buf = append(w.buf[:0], w.pending...)
	w.buf = append(w.buf, chunk...)
	return w.release(w.buf)
}

// release writes window[:len-keep] and keeps the tail.
func (w *leakGuardWriter) release(window []byte) bool {
	keep := w.keep
	if keep > len(window) {
		keep = len(window)
	}
	safe := window[:len(window)-keep]
	w.pending = append(w.pending[:0], window[len(window)-keep:]...)
	if len(safe) == 0 {
		return true
	}
	return w.out(safe)
}

// finish checks the remaining tail one last time and releases it. It must be
// called on EOF *and* on read errors: pending bytes are checked, never dropped
// blindly or released without inspection.
func (w *leakGuardWriter) finish() (hit int, ok bool) {
	if len(w.pending) == 0 {
		return 0, true
	}
	if n := w.matcher.Find(w.pending); n > 0 {
		return n, false
	}
	tail := w.pending
	w.pending = nil
	if len(tail) == 0 {
		return 0, true
	}
	return 0, w.out(tail)
}

// ---------------------------------------------------------------------------
// B2：响应内容告警扫描（只告警，不改字节）
// ---------------------------------------------------------------------------

// warnScanner runs detector rules against response bytes with a hard byte
// budget, so a huge stream cannot turn into a CPU sink. Only detector rules are
// used (they carry checksum/entropy validation), which keeps the warn path from
// spamming on ordinary prose.
const (
	// warnOverlapBytes 是 B2 跨 chunk 检测用的有界重叠窗口：一个高危串即使
	// 被切成两个 chunk 也能命中。重叠部分同样计入预算。
	warnOverlapBytes = 4096
)

type warnScanner struct {
	rules     []Rule
	budget    int // 每条响应允许交给检测器的总字节数
	overlap   int
	tail      []byte
	buf       []byte
	seen      map[string]bool
	exhausted bool // 预算耗尽 / 被截断：本次响应只扫了一部分
}

func newWarnScanner(rules []Rule, budget int) *warnScanner {
	var dets []Rule
	for _, r := range rules {
		if r.Enabled && r.effectiveType() == RuleTypeDetector {
			dets = append(dets, r)
		}
	}
	if len(dets) == 0 || budget <= 0 {
		return nil
	}
	return &warnScanner{
		rules:   dets,
		budget:  budget,
		overlap: warnOverlapBytes,
		seen:    map[string]bool{},
	}
}

// Scan returns detector rules that matched (each rule is reported once per
// response).
//
// The scanned window is `previous tail + chunk`, so a pattern straddling a chunk
// boundary still hits. The window length counts against the per-response budget:
// when it runs out, scanning stops and exhausted is set (surfaced as a
// scan_incomplete event) instead of silently going quiet.
func (w *warnScanner) Scan(chunk []byte) []Rule {
	if w == nil || len(chunk) == 0 {
		return nil
	}
	if w.budget <= 0 {
		w.exhausted = true
		return nil
	}

	w.buf = append(w.buf[:0], w.tail...)
	w.buf = append(w.buf, chunk...)
	window := w.buf
	if len(window) > w.budget {
		window = window[:w.budget]
		w.exhausted = true
	}
	w.budget -= len(window)
	s := string(window)

	var hits []Rule
	for _, r := range w.rules {
		if w.seen[r.Detector] {
			continue
		}
		if len(detectIn(r, s)) == 0 {
			continue
		}
		w.seen[r.Detector] = true
		hits = append(hits, r)
	}

	// 重叠窗口只保留**实际扫描过**的尾部，保证下一次 window 连续。
	if keep := w.overlap; keep > 0 && len(window) > 0 {
		if keep > len(window) {
			keep = len(window)
		}
		w.tail = append(w.tail[:0], window[len(window)-keep:]...)
	}
	return hits
}

// exhaustedScan reports whether part of the response was not scanned.
func (w *warnScanner) exhaustedScan() bool {
	return w != nil && w.exhausted
}

// ---------------------------------------------------------------------------
// F：模型一致性
// ---------------------------------------------------------------------------

var upstreamModelRe = regexp.MustCompile(`"model"\s*:\s*"([^"]{1,128})"`)

// extractUpstreamModel pulls the model field out of the peeked bytes. It works
// for both plain JSON bodies and `data: {...}` SSE frames, without parsing.
func extractUpstreamModel(prefix []byte) string {
	m := upstreamModelRe.FindSubmatch(prefix)
	if m == nil {
		return ""
	}
	return string(m[1])
}

// modelVersionSuffix matches only the explicit snapshot suffix shapes we
// support: -YYYY-MM-DD, -YYYYMMDD, -YYYY (e.g. gpt-4-0613 uses -MMDD, which is
// covered by the 4-digit form).
var modelVersionSuffix = regexp.MustCompile(`-(?:\d{4}-\d{2}-\d{2}|\d{8}|\d{4})$`)

// canonicalModel strips a supported snapshot suffix. Anything that is not an
// anchored date/number suffix is left untouched — no fuzzy matching.
func canonicalModel(s string) string {
	return modelVersionSuffix.ReplaceAllString(s, "")
}

// modelsCompatible reports whether two model ids refer to the same model.
// Upstreams routinely canonicalize ids (gpt-4o-mini-2024-07-18 → gpt-4o-mini),
// which is why a supported snapshot suffix is stripped before an *exact*
// comparison. A genuine downgrade (gpt-4o → gpt-4o-mini, gpt-4 → gpt-4o) must
// never be treated as compatible, so prefix relationships are not accepted.
func modelsCompatible(sent, got string) bool {
	if sent == "" || got == "" {
		return true
	}
	return canonicalModel(sent) == canonicalModel(got)
}

// ---------------------------------------------------------------------------
// E：诊断事件环形缓冲（默认关闭）
//
// 关闭时 record 直接丢弃：既不落盘也不保留请求/响应内容。
// ---------------------------------------------------------------------------

type auditEvent struct {
	Time          time.Time `json:"time"`
	Kind          string    `json:"kind"`   // leak | sensitive | model_mismatch
	Action        string    `json:"action"` // blocked | aborted | warned
	Rule          string    `json:"rule,omitempty"`
	Detector      string    `json:"detector,omitempty"`
	Path          string    `json:"path,omitempty"`
	Model         string    `json:"model,omitempty"`
	UpstreamModel string    `json:"upstreamModel,omitempty"`
	MatchedLen    int       `json:"matchedLen,omitempty"`
	Hint          string    `json:"hint,omitempty"` // 仅当 hintChars > 0 才有内容
}

type auditLog struct {
	mu        sync.Mutex
	events    []auditEvent // ring
	next      int
	full      bool
	enabled   bool
	hintChars int
}

var audit = &auditLog{events: make([]auditEvent, 200)}

func (a *auditLog) configure(enabled bool, size, hintChars int) {
	if size <= 0 {
		size = 200
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enabled = enabled
	if hintChars > maxAuditHintChars {
		hintChars = maxAuditHintChars
	}
	a.hintChars = hintChars
	if len(a.events) != size {
		a.events = make([]auditEvent, size)
		a.next, a.full = 0, false
	}
}

func (a *auditLog) isEnabled() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.enabled
}

func (a *auditLog) record(e auditEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.enabled || len(a.events) == 0 {
		return
	}
	e.Time = time.Now()
	a.events[a.next] = e
	a.next = (a.next + 1) % len(a.events)
	if a.next == 0 {
		a.full = true
	}
}

// maxAuditHintChars caps -audit-hint-chars so a misconfiguration cannot turn
// the diagnostics ring into a credential store.
const maxAuditHintChars = 16

// hintValue redacts a matched value down to its first n bytes.
//
// It never returns the complete value: if the value is not longer than n, no
// content is recorded at all (only the length, which the event already carries).
func (a *auditLog) hintValue(s string, n int) string {
	a.mu.Lock()
	if n <= 0 {
		n = a.hintChars
	}
	a.mu.Unlock()
	if n <= 0 || s == "" {
		return ""
	}
	if n > maxAuditHintChars {
		n = maxAuditHintChars
	}
	if len(s) <= n { // 完整值绝不写入事件
		return ""
	}
	return s[:n] + "…"
}

func (a *auditLog) recent(n int) []auditEvent {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.enabled || len(a.events) == 0 || n <= 0 {
		return []auditEvent{}
	}
	total := a.next
	if a.full {
		total = len(a.events)
	}
	if n > total {
		n = total
	}
	out := make([]auditEvent, 0, n)
	for i := 1; i <= n; i++ {
		idx := (a.next - i + len(a.events)) % len(a.events)
		out = append(out, a.events[idx])
	}
	return out
}

func (a *auditLog) clear() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = make([]auditEvent, len(a.events))
	a.next, a.full = 0, false
}

// guardLogWindow is how often the same non-critical event may be logged.
// Critical events (B1 leak) bypass it entirely.
var guardLogWindow = time.Minute

type logLimiter struct {
	mu     sync.Mutex
	window time.Duration
	last   map[string]time.Time
	muted  map[string]int
}

var guardLog = &logLimiter{window: time.Minute, last: map[string]time.Time{}, muted: map[string]int{}}

// allow reports whether this key may be logged now, plus how many occurrences
// were suppressed since it was last logged.
func (l *logLimiter) allow(key string) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	window := l.window
	if window <= 0 {
		window = time.Minute
	}
	now := time.Now()
	if t, ok := l.last[key]; ok && now.Sub(t) < window {
		l.muted[key]++
		return false, 0
	}
	suppressed := l.muted[key]
	l.muted[key] = 0
	l.last[key] = now
	return true, suppressed
}

// recordEvent logs to stderr and to the ring buffer (when enabled).
//
// Logging policy (F8): B1 leak events are security-critical and always logged;
// everything else (B2 detector hits, model mismatch, coverage gaps) is rate
// limited per key so bulk traffic cannot flood stderr. The ring buffer is
// unaffected by the limiter, so -audit never loses an event.
// No request/response content is ever logged, only rule/detector names.
func recordEvent(e auditEvent, matched string) {
	if audit.isEnabled() {
		e.Hint = audit.hintValue(matched, 0)
		audit.record(e)
	}

	line := func(suppressed int) {
		extra := ""
		if suppressed > 0 {
			extra = fmt.Sprintf(" suppressed=%d window=%s", suppressed, guardLogWindow)
		}
		log.Printf("response guard: kind=%s action=%s rule=%q detector=%q path=%s model=%q upstream=%q matched=%dB%s",
			e.Kind, e.Action, e.Rule, e.Detector, e.Path, e.Model, e.UpstreamModel, e.MatchedLen, extra)
	}

	if e.Kind == "leak" { // 安全关键事件：永不限流
		line(0)
		return
	}
	key := e.Kind + "|" + e.Detector + "|" + e.Rule + "|" + e.UpstreamModel
	if ok, suppressed := guardLog.allow(key); ok {
		line(suppressed)
	}
}

// abortHandler panics with ErrAbortHandler, which makes net/http close the
// client connection without logging it. Used for mid-stream aborts: the client
// must see a failed/truncated stream rather than a silently short answer.
func abortHandler() {
	panic(http.ErrAbortHandler)
}
