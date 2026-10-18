// Package main implements a minimal forwarding gateway with prompt protection
// (脱敏/reject) rules borrowed from AxonHub's Prompt Protection feature.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/dlclark/regexp2/v2"
)

// Action is the operation applied when a rule matches.
type Action string

const (
	ActionMask   Action = "mask"   // replace matched content with Replacement
	ActionReject Action = "reject" // block the whole request
)

// Rule types: "regex" (user supplied regexp2 pattern) or "detector" (built-in
// checksum/entropy-validated detector from detect.go).
const (
	RuleTypeRegex    = "regex"
	RuleTypeDetector = "detector"
)

// validScopes are the message roles a rule may apply to.
var validScopes = []string{"system", "developer", "user", "assistant", "tool"}

// validFields are the locations a rule may be applied to. Empty means "all".
//
//	content    → messages[].content (plain string, or the "text" parts of an array)
//	tool_calls → messages[].tool_calls[].function.arguments, reasoning_content, reasoning
//	tools      → request.tools[] / functions[] (function description + parameters, not name)
//	top        → top-level request strings (prompt, input, user, metadata, system, instruction)
var validFields = []string{FieldContent, FieldToolCalls, FieldTools, FieldTop}

const (
	FieldContent   = "content"
	FieldToolCalls = "tool_calls"
	FieldTools     = "tools"
	FieldTop       = "top"
)

// Rule is a prompt protection rule (modeled after AxonHub's PromptProtectionRule).
type Rule struct {
	ID          int     `json:"id"`
	Name        string  `json:"name"`
	Description string  `json:"description,omitempty"`
	Type        string  `json:"type,omitempty"`      // "" / "regex" | "detector"
	Pattern     string  `json:"pattern,omitempty"`   // regex source (regex rules)
	Detector    string  `json:"detector,omitempty"`  // detector name (detector rules)
	Threshold   float64 `json:"threshold,omitempty"` // detector: high_entropy 熵阈值
	MinLength   int     `json:"minLength,omitempty"` // detector: high_entropy 最小长度
	Enabled     bool    `json:"enabled"`
	Action      Action  `json:"action"`
	Replacement string  `json:"replacement,omitempty"`
	// 不用 omitempty：空数组也返回 []，避免前端拿到 undefined
	Scopes []string `json:"scopes"`
	// 同上：留空 = 扫描所有位置
	Fields []string `json:"fields"`
}

// ErrRejected signals that a request must be blocked.
var ErrRejected = errors.New("prompt protection rejected request")

// ---------------------------------------------------------------------------
// Observation side-channel (response leak guard).
//
// hitSink records the ORIGINAL text that a rule matched while the request body
// was being protected. The response guard uses those exact values as needles to
// detect an upstream echoing them back. It is pure observation: recording never
// changes which rules match, in what order, or what the protected body looks
// like.
// ---------------------------------------------------------------------------

// B1 needle collection limits. They bound per-request memory (see the docs):
//
//	maxCollectedHits * maxHitTextLen = 256 * 512B = 128KB worst case
//
// Longer matches are NOT collected: an exact-match needle of that size is
// useless for echo detection and would only cost memory. Dropping is never
// silent — hitSink counts it and requestMeta.coverageGap surfaces it (response
// header + audit event), because B1 cannot protect what it did not collect.
const (
	maxCollectedHits = 256
	maxHitTextLen    = 512
)

type hit struct {
	rule string
	text string
}

type hitSink struct {
	hits []hit
	// dropped counts matches we could not track (too long, or cap reached).
	dropped int
}

func (h *hitSink) add(rule Rule, text string) {
	if h == nil || text == "" {
		return
	}
	if len(text) > maxHitTextLen || len(h.hits) >= maxCollectedHits {
		h.dropped++
		return
	}
	name := rule.Name
	if name == "" {
		name = rule.Detector
	}
	h.hits = append(h.hits, hit{rule: name, text: text})
}

// coverageGap reports that at least one matched value could not be turned into
// a needle, so response-side echo detection for this request is incomplete.
func (h *hitSink) coverageGap() bool {
	return h != nil && h.dropped > 0
}

// protector bundles the enabled rules with the optional hit sink so the whole
// scan pipeline stays single-source-of-truth for "what counts as a match".
type protector struct {
	rules []Rule
	hits  *hitSink
}

// effectiveType infers the rule type; legacy rules (no type) are regex rules
// unless they set a detector name.
func (r Rule) effectiveType() string {
	if r.Type == RuleTypeDetector {
		return RuleTypeDetector
	}
	if r.Type == "" && r.Detector != "" {
		return RuleTypeDetector
	}
	return RuleTypeRegex
}

// ---------------------------------------------------------------------------
// Regex compilation cache (same idea as AxonHub's promptProtectionRegexCache).
// regexp2 is used instead of the stdlib regexp because it supports lookahead /
// lookbehind, which is needed for realistic sensitive-data patterns.
// ---------------------------------------------------------------------------

type patternCache struct {
	re         *regexp2.Regexp
	compileErr bool
	err        error
}

var (
	regexCache = map[string]*patternCache{}
	regexMu    sync.RWMutex
)

func compilePattern(pattern string) (*regexp2.Regexp, error) {
	regexMu.RLock()
	cached, ok := regexCache[pattern]
	regexMu.RUnlock()
	if ok {
		if cached.compileErr {
			return nil, cached.err
		}
		return cached.re, nil
	}

	re, err := regexp2.Compile(pattern, regexp2.None)

	regexMu.Lock()
	regexCache[pattern] = &patternCache{re: re, compileErr: err != nil, err: err}
	regexMu.Unlock()

	return re, err
}

func matchPattern(pattern, content string) bool {
	re, err := compilePattern(pattern)
	if err != nil {
		return false
	}
	ok, err := re.MatchString(content)
	return err == nil && ok
}

func replacePattern(pattern, content, replacement string) string {
	re, err := compilePattern(pattern)
	if err != nil {
		return content
	}
	out, err := re.Replace(content, replacement, -1, -1)
	if err != nil {
		return content
	}
	return out
}

// ruleAppliesToRole mirrors AxonHub's promptProtectionRuleAppliesToRole:
// an empty scope list means "apply to all roles".
func ruleAppliesToRole(scopes []string, role string) bool {
	if len(scopes) == 0 {
		return true
	}
	r := strings.ToLower(role)
	for _, s := range scopes {
		if s == r {
			return true
		}
	}
	return false
}

// ruleAppliesToField: an empty field list means "apply everywhere".
func ruleAppliesToField(fields []string, loc string) bool {
	if len(fields) == 0 {
		return true
	}
	return slices.Contains(fields, loc)
}

// validateRule mirrors AxonHub's ValidateSettings (full rule, incl. name).
func validateRule(r Rule) error {
	if strings.TrimSpace(r.Name) == "" {
		return errors.New("name is required")
	}
	return validatePatternAction(r)
}

// validatePatternAction validates everything except the name (used by preview).
func validatePatternAction(r Rule) error {
	switch r.effectiveType() {
	case RuleTypeDetector:
		if !validDetector(r.Detector) {
			return fmt.Errorf("unknown detector: %q", r.Detector)
		}
		if strings.TrimSpace(r.Pattern) != "" {
			return errors.New("pattern must be empty for detector rules")
		}
		if r.Threshold != 0 && (r.Threshold < 1 || r.Threshold > 8) {
			return errors.New("threshold must be between 1 and 8")
		}
		if r.MinLength != 0 && (r.MinLength < 4 || r.MinLength > 1024) {
			return errors.New("minLength must be between 4 and 1024")
		}
	default: // regex
		if r.Detector != "" {
			return errors.New("detector must be empty for regex rules")
		}
		if strings.TrimSpace(r.Pattern) == "" {
			return errors.New("pattern is required")
		}
		if _, err := compilePattern(r.Pattern); err != nil {
			return fmt.Errorf("invalid regex pattern: %w", err)
		}
	}

	if r.Action != ActionMask && r.Action != ActionReject {
		return fmt.Errorf("invalid action: %s", r.Action)
	}
	if r.Action == ActionMask && r.Replacement == "" {
		return errors.New("replacement is required for mask action")
	}
	for _, sc := range r.Scopes {
		if !slices.Contains(validScopes, sc) {
			return fmt.Errorf("invalid scope: %s", sc)
		}
	}
	for _, f := range r.Fields {
		if !slices.Contains(validFields, f) {
			return fmt.Errorf("invalid field: %s", f)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Core masking logic.
//
// Rules are processed in order (by ID). Mask rules stack: each replacement is
// applied to the result of the previous rule. The first reject match stops the
// request immediately.
// ---------------------------------------------------------------------------

// protectDocument applies rules to every protected location of a parsed
// request body, mutating doc in place. Returns whether anything changed and
// whether the request must be rejected.
func protectDocument(doc map[string]json.RawMessage, p protector) (changed, rejected bool) {
	for _, fn := range []func(map[string]json.RawMessage, protector) (bool, bool){
		protectMessagesField,
		protectToolsField,
		protectTopLevelFields,
	} {
		c, rej := fn(doc, p)
		if rej {
			return changed, true
		}
		changed = changed || c
	}
	return changed, false
}

// protectMessagesField walks doc["messages"].
func protectMessagesField(doc map[string]json.RawMessage, p protector) (bool, bool) {
	raw, ok := doc["messages"]
	if !ok {
		return false, false
	}
	var msgs []json.RawMessage
	if err := json.Unmarshal(raw, &msgs); err != nil {
		return false, false
	}

	changed := false
	for i, msg := range msgs {
		updated, c, rej := protectMessage(msg, p)
		if rej {
			return changed, true
		}
		if c {
			msgs[i] = updated
			changed = true
		}
	}
	if !changed {
		return false, false
	}
	b, err := json.Marshal(msgs)
	if err != nil {
		return false, false
	}
	doc["messages"] = b
	return true, false
}

// protectMessage handles one message object, preserving all untouched fields
// byte-for-byte (they stay in m as json.RawMessage).
func protectMessage(raw json.RawMessage, p protector) (json.RawMessage, bool, bool) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return raw, false, false
	}

	var role string
	_ = json.Unmarshal(m["role"], &role)
	ctx := valueCtx{loc: FieldContent, role: strings.ToLower(role)}
	_, ctx.hasRole = m["role"]

	// Content needs its own handling (never touch image parts).
	changed := false
	if content, ok := m["content"]; ok {
		updated, c, rej := protectContent(content, ctx, p)
		if rej {
			return raw, changed, true
		}
		if c {
			m["content"] = updated
			changed = true
		}
	}

	// Extra text locations that used to be forwarded verbatim.
	for _, key := range []string{"tool_calls", "reasoning_content", "reasoning"} {
		v, ok := m[key]
		if !ok {
			continue
		}
		updated, c, rej := protectRawValue(v, valueCtx{loc: FieldToolCalls, role: ctx.role, hasRole: ctx.hasRole}, p)
		if rej {
			return raw, changed, true
		}
		if c {
			m[key] = updated
			changed = true
		}
	}

	if !changed {
		return raw, false, false
	}
	out, err := json.Marshal(m)
	if err != nil {
		return raw, false, false
	}
	return out, true, false
}

// valueCtx describes where a string sits in the request, so rules can decide
// whether they apply (field selection + role scoping).
type valueCtx struct {
	loc     string
	role    string
	hasRole bool // true when the value lives inside a message / role object
}

// protectContent handles both content formats:
//
//	"content": "plain string"
//	"content": [{"type":"text","text":"..."}, {"type":"image_url",...}]
//
// Only "text" parts are rewritten: image_url / input_image / file payloads are
// left alone (masking base64 images would corrupt the request).
func protectContent(raw json.RawMessage, ctx valueCtx, p protector) (json.RawMessage, bool, bool) {
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		out, changed, rejected := protectString(text, ctx, p)
		if rejected || !changed {
			return raw, false, rejected
		}
		b, _ := json.Marshal(out)
		return b, true, false
	}

	var parts []json.RawMessage
	if err := json.Unmarshal(raw, &parts); err != nil {
		return raw, false, false
	}

	changed := false
	for i, partRaw := range parts {
		var part map[string]json.RawMessage
		if err := json.Unmarshal(partRaw, &part); err != nil {
			continue
		}
		var typ string
		_ = json.Unmarshal(part["type"], &typ)
		if typ != "" && !strings.EqualFold(typ, "text") {
			continue
		}
		textRaw, ok := part["text"]
		if !ok {
			continue
		}
		var partText string
		if err := json.Unmarshal(textRaw, &partText); err != nil || partText == "" {
			continue
		}
		out, c, rej := protectString(partText, ctx, p)
		if rej {
			return raw, changed, true
		}
		if !c {
			continue
		}
		b, _ := json.Marshal(out)
		part["text"] = b
		updated, err := json.Marshal(part)
		if err != nil {
			continue
		}
		parts[i] = updated
		changed = true
	}

	if !changed {
		return raw, false, false
	}
	b, err := json.Marshal(parts)
	if err != nil {
		return raw, false, false
	}
	return b, true, false
}

// protectToolsField walks request.tools[] and the legacy functions[] array.
// Function names are deliberately skipped (renaming a tool breaks tool_choice
// references); description and parameters are scanned.
func protectToolsField(doc map[string]json.RawMessage, p protector) (bool, bool) {
	changedAll := false
	for _, key := range []string{"tools", "functions"} {
		raw, ok := doc[key]
		if !ok {
			continue
		}
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			continue
		}
		changed := false
		for i, item := range items {
			updated, c, rej := protectToolItem(item, p)
			if rej {
				return changedAll, true
			}
			if c {
				items[i] = updated
				changed = true
			}
		}
		if !changed {
			continue
		}
		b, err := json.Marshal(items)
		if err != nil {
			continue
		}
		doc[key] = b
		changedAll = true
	}
	return changedAll, false
}

func protectToolItem(raw json.RawMessage, p protector) (json.RawMessage, bool, bool) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return raw, false, false
	}
	// tools[]: {"type":"function","function":{...}} ; functions[]: {...} directly
	fnRaw, ok := m["function"]
	if !ok {
		return protectToolFunction(raw, p)
	}
	updated, changed, rej := protectToolFunction(fnRaw, p)
	if rej || !changed {
		return raw, false, rej
	}
	m["function"] = updated
	out, err := json.Marshal(m)
	if err != nil {
		return raw, false, false
	}
	return out, true, false
}

func protectToolFunction(raw json.RawMessage, p protector) (json.RawMessage, bool, bool) {
	var fn map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fn); err != nil {
		return raw, false, false
	}
	changed := false
	for _, key := range []string{"description", "parameters", "input_schema"} {
		v, ok := fn[key]
		if !ok {
			continue
		}
		updated, c, rej := protectRawValue(v, valueCtx{loc: FieldTools}, p)
		if rej {
			return raw, changed, true
		}
		if c {
			fn[key] = updated
			changed = true
		}
	}
	if !changed {
		return raw, false, false
	}
	out, err := json.Marshal(fn)
	if err != nil {
		return raw, false, false
	}
	return out, true, false
}

// topLevelFields are the request-level string locations we scan. "model" and
// other control fields are intentionally absent.
var topLevelFields = []string{"prompt", "input", "instructions", "instruction", "system", "user", "metadata"}

func protectTopLevelFields(doc map[string]json.RawMessage, p protector) (bool, bool) {
	changed := false
	for _, key := range topLevelFields {
		raw, ok := doc[key]
		if !ok {
			continue
		}
		updated, c, rej := protectRawValue(raw, valueCtx{loc: FieldTop}, p)
		if rej {
			return changed, true
		}
		if c {
			doc[key] = updated
			changed = true
		}
	}
	return changed, false
}

// protectRawValue walks an arbitrary JSON value and rewrites every string in
// it. Numbers are decoded as json.Number so they round-trip exactly.
func protectRawValue(raw json.RawMessage, ctx valueCtx, p protector) (json.RawMessage, bool, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return raw, false, false
	}

	w := &walker{p: p, ctx: ctx}
	out := w.value(v)
	if w.rejected {
		return raw, false, true
	}
	if !w.changed {
		return raw, false, false
	}
	b, err := json.Marshal(out)
	if err != nil {
		return raw, false, false
	}
	return b, true, false
}

// walker recursively applies rules to every string value.
type walker struct {
	p        protector
	ctx      valueCtx
	changed  bool
	rejected bool
}

func (w *walker) value(v any) any {
	switch x := v.(type) {
	case string:
		out, changed, rejected := protectString(x, w.ctx, w.p)
		if rejected {
			w.rejected = true
			return x
		}
		if changed {
			w.changed = true
			return out
		}
		return x

	case []any:
		for i := range x {
			x[i] = w.value(x[i])
			if w.rejected {
				return x
			}
		}
		return x

	case map[string]any:
		// Objects with a "role" (Responses API "input") scope their own strings.
		saved := w.ctx
		if !w.ctx.hasRole {
			if r, ok := x["role"].(string); ok {
				w.ctx.role = strings.ToLower(r)
				w.ctx.hasRole = true
			}
		}
		for k, val := range x {
			x[k] = w.value(val)
			if w.rejected {
				break
			}
		}
		w.ctx = saved
		return x
	}
	return v
}

// protectString applies all enabled rules to a single string value.
//
// Field selection is always honoured. Role scopes only apply to role-bearing
// locations (message content / tool_calls): a rule that names specific roles is
// therefore never applied to tool schemas or top-level fields — those need an
// unscoped rule. This keeps scoped rules from firing where the author did not
// expect them (notably reject rules).
func protectString(s string, ctx valueCtx, p protector) (out string, changed, rejected bool) {
	if s == "" {
		return s, false, false
	}
	out = s
	for _, rule := range p.rules {
		if !rule.Enabled {
			continue
		}
		if !ruleAppliesToField(rule.Fields, ctx.loc) {
			continue
		}
		if len(rule.Scopes) > 0 {
			if !ctx.hasRole || !ruleAppliesToRole(rule.Scopes, ctx.role) {
				continue
			}
		}
		rej, ch := applyRuleToString(&out, rule, p.hits)
		if rej {
			return s, false, true
		}
		if ch {
			changed = true
		}
	}
	return out, changed, false
}

// applyRuleToString applies one rule in place to *s.
func applyRuleToString(s *string, rule Rule, hits *hitSink) (rejected, changed bool) {
	// The matched text is recorded from the ORIGINAL string, before any
	// replacement, so later rules cannot hide it. Recording is a no-op when
	// hits is nil (i.e. when the caller does not need the observation).
	if rule.effectiveType() == RuleTypeDetector {
		spans := detectIn(rule, *s)
		if len(spans) == 0 {
			return false, false
		}
		if hits != nil {
			for _, sp := range spans {
				hits.add(rule, (*s)[sp.start:sp.end])
			}
		}
		if rule.Action == ActionReject {
			return true, false
		}
		out := applySpans(*s, spans, rule.Replacement)
		if out == *s {
			return false, false
		}
		*s = out
		return false, true
	}

	re, err := compilePattern(rule.Pattern)
	if err != nil {
		return false, false
	}
	ok, err := re.MatchString(*s)
	if err != nil || !ok {
		return false, false
	}
	if hits != nil {
		collectRegexHits(hits, rule, re, *s)
	}
	if rule.Action == ActionReject {
		return true, false
	}
	out, err := re.Replace(*s, rule.Replacement, -1, -1)
	if err != nil || out == *s {
		return false, false
	}
	*s = out
	return false, true
}

// collectRegexHits enumerates every match of a regex rule (same engine and same
// match semantics that Replace uses) and records it.
func collectRegexHits(hits *hitSink, rule Rule, re *regexp2.Regexp, s string) {
	m, err := re.FindStringMatch(s)
	for m != nil && err == nil {
		hits.add(rule, m.String())
		m, err = re.FindNextMatch(m)
	}
}

// needles returns the deduplicated original texts matched by request-side rules.
func (h *hitSink) needles() []string {
	if h == nil || len(h.hits) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(h.hits))
	out := make([]string, 0, len(h.hits))
	for _, hit := range h.hits {
		if seen[hit.text] {
			continue
		}
		seen[hit.text] = true
		out = append(out, hit.text)
	}
	return out
}
