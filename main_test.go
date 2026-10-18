package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testStore(t *testing.T, rules []Rule) *Store {
	t.Helper()
	s := &Store{rules: rules, path: t.TempDir() + "/rules.json", nextID: 1}
	for _, r := range rules {
		if r.ID >= s.nextID {
			s.nextID = r.ID + 1
		}
	}
	return s
}

func TestMaskSimple(t *testing.T) {
	store = testStore(t, []Rule{{
		ID: 1, Name: "mask-key", Enabled: true, Action: ActionMask,
		Pattern: "sk-[a-zA-Z0-9]{20}", Replacement: "[REDACTED]",
	}})

	in := `{"model":"gpt-4o","messages":[{"role":"user","content":"key is sk-abcdefghijklmnopqrst"}]}`
	out, rejected, err := protectBody([]byte(in))
	if err != nil || rejected {
		t.Fatalf("unexpected: rejected=%v err=%v", rejected, err)
	}
	var doc map[string]json.RawMessage
	json.Unmarshal(out, &doc)
	if !json.Valid(doc["messages"]) {
		t.Fatalf("messages not valid json: %s", doc["messages"])
	}
	var msgs []map[string]any
	json.Unmarshal(doc["messages"], &msgs)
	got := msgs[0]["content"].(string)
	if want := "key is [REDACTED]"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	// other fields must survive
	var m map[string]any
	json.Unmarshal(out, &m)
	if m["model"] != "gpt-4o" {
		t.Fatalf("model field lost: %v", m["model"])
	}
}

func TestMaskNoMatchKeepsOriginalBytes(t *testing.T) {
	store = testStore(t, []Rule{{
		ID: 1, Name: "mask-key", Enabled: true, Action: ActionMask,
		Pattern: "sk-[a-zA-Z0-9]{20}", Replacement: "[REDACTED]",
	}})
	in := `{"messages":[{"role":"user","content":"hello"}]}`
	out, rejected, err := protectBody([]byte(in))
	if err != nil || rejected {
		t.Fatalf("unexpected: rejected=%v err=%v", rejected, err)
	}
	if string(out) != in {
		t.Fatalf("body changed without match: %s", out)
	}
}

func TestReject(t *testing.T) {
	store = testStore(t, []Rule{{
		ID: 1, Name: "reject-cc", Enabled: true, Action: ActionReject,
		Pattern: `\b(?:\d{4}[-\s]?){3}\d{4}\b`,
	}})
	in := `{"messages":[{"role":"user","content":"card 4111-1111-1111-1111"}]}`
	_, rejected, err := protectBody([]byte(in))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !rejected {
		t.Fatal("expected reject")
	}
}

func TestDisabledRuleIgnored(t *testing.T) {
	store = testStore(t, []Rule{{
		ID: 1, Name: "r", Enabled: false, Action: ActionReject,
		Pattern: "sk-.*",
	}})
	in := `{"messages":[{"role":"user","content":"sk-abcdef"}]}`
	out, rejected, _ := protectBody([]byte(in))
	if rejected {
		t.Fatal("disabled rule must not reject")
	}
	if string(out) != in {
		t.Fatal("disabled rule must not modify body")
	}
}

func TestScopeFilter(t *testing.T) {
	store = testStore(t, []Rule{{
		ID: 1, Name: "user-only", Enabled: true, Action: ActionMask,
		Pattern: "secret", Replacement: "***", Scopes: []string{"user"},
	}})
	in := `{"messages":[
		{"role":"system","content":"system has secret"},
		{"role":"user","content":"user has secret"}]}`
	out, _, _ := protectBody([]byte(in))
	var doc map[string]json.RawMessage
	json.Unmarshal(out, &doc)
	var msgs []map[string]any
	json.Unmarshal(doc["messages"], &msgs)
	if msgs[0]["content"] != "system has secret" {
		t.Fatalf("system scope should not be masked: %v", msgs[0]["content"])
	}
	if msgs[1]["content"] != "user has ***" {
		t.Fatalf("user scope should be masked: %v", msgs[1]["content"])
	}
}

func TestMultipleContentParts(t *testing.T) {
	store = testStore(t, []Rule{{
		ID: 1, Name: "r", Enabled: true, Action: ActionMask,
		Pattern: "secret", Replacement: "***",
	}})
	in := `{"messages":[{"role":"user","content":[
		{"type":"text","text":"contains secret here"},
		{"type":"image_url","image_url":{"url":"http://x/y.png"}}]}]}`
	out, _, _ := protectBody([]byte(in))
	var doc map[string]json.RawMessage
	json.Unmarshal(out, &doc)
	var msgs []map[string]any
	json.Unmarshal(doc["messages"], &msgs)
	parts := msgs[0]["content"].([]any)
	textPart := parts[0].(map[string]any)
	if textPart["text"] != "contains *** here" {
		t.Fatalf("text part not masked: %v", textPart["text"])
	}
	if parts[1].(map[string]any)["type"] != "image_url" {
		t.Fatalf("image part lost: %v", parts[1])
	}
}

func TestNonJSONForwardedAsIs(t *testing.T) {
	store = testStore(t, []Rule{{ID: 1, Name: "r", Enabled: true, Action: ActionReject, Pattern: ".*"}})
	in := []byte("not-json-at-all")
	out, rejected, _ := protectBody(in)
	if rejected || string(out) != string(in) {
		t.Fatalf("non-JSON must pass through unchanged")
	}
}

func TestDeveloperToSystem(t *testing.T) {
	normalizeDeveloperToSystem = true
	defer func() { normalizeDeveloperToSystem = false }()

	store = testStore(t, nil) // no rules: normalization must still apply
	in := `{"messages":[{"role":"developer","content":"be helpful"},{"role":"user","content":"hi"}]}`
	out, rejected, err := protectBody([]byte(in))
	if err != nil || rejected {
		t.Fatalf("unexpected: rejected=%v err=%v", rejected, err)
	}
	var doc map[string]json.RawMessage
	json.Unmarshal(out, &doc)
	var msgs []map[string]any
	json.Unmarshal(doc["messages"], &msgs)
	if msgs[0]["role"] != "system" {
		t.Fatalf("developer not mapped to system: %v", msgs[0]["role"])
	}
	if msgs[1]["role"] != "user" {
		t.Fatalf("user role must not change: %v", msgs[1]["role"])
	}
	if msgs[0]["content"] != "be helpful" {
		t.Fatalf("content lost: %v", msgs[0])
	}
}

func TestDeveloperToSystemOffByDefault(t *testing.T) {
	normalizeDeveloperToSystem = false
	store = testStore(t, nil)
	in := `{"messages":[{"role":"developer","content":"x"}]}`
	out, _, _ := protectBody([]byte(in))
	if string(out) != in {
		t.Fatalf("body must stay byte-identical when normalization is off: %s", out)
	}
}

func TestDeveloperToSystemPlusMask(t *testing.T) {
	normalizeDeveloperToSystem = true
	defer func() { normalizeDeveloperToSystem = false }()

	store = testStore(t, []Rule{{
		ID: 1, Name: "mask", Enabled: true, Action: ActionMask,
		Pattern: "secret", Replacement: "***", Scopes: []string{"developer"},
	}})
	in := `{"messages":[{"role":"developer","content":"has secret"}]}`
	out, rejected, _ := protectBody([]byte(in))
	if rejected {
		t.Fatal("should not reject")
	}
	var doc map[string]json.RawMessage
	json.Unmarshal(out, &doc)
	var msgs []map[string]any
	json.Unmarshal(doc["messages"], &msgs)
	if msgs[0]["role"] != "system" {
		t.Fatalf("role not normalized: %v", msgs[0]["role"])
	}
	if msgs[0]["content"] != "has ***" {
		t.Fatalf("mask not applied: %v", msgs[0]["content"])
	}
}

func TestValidateRule(t *testing.T) {
	cases := []struct {
		rule Rule
		ok   bool
	}{
		{Rule{Name: "a", Pattern: "sk-.*", Action: ActionMask, Replacement: "x"}, true},
		{Rule{Name: "", Pattern: "x", Action: ActionMask, Replacement: "x"}, false},  // no name
		{Rule{Name: "a", Pattern: "(", Action: ActionMask, Replacement: "x"}, false}, // bad regex
		{Rule{Name: "a", Pattern: "x", Action: "blow", Replacement: "x"}, false},     // bad action
		{Rule{Name: "a", Pattern: "x", Action: ActionMask, Replacement: ""}, false},  // mask needs replacement
		{Rule{Name: "a", Pattern: "x", Action: ActionReject, Replacement: ""}, true}, // reject ok without
		{Rule{Name: "a", Pattern: "x", Action: ActionMask, Replacement: "x", Scopes: []string{"bogus"}}, false},
	}
	for i, c := range cases {
		err := validateRule(c.rule)
		if (err == nil) != c.ok {
			t.Fatalf("case %d: err=%v, want ok=%v", i, err, c.ok)
		}
	}
}

func TestLookbehindSupported(t *testing.T) {
	// regexp2 supports lookbehind, stdlib regexp does not.
	if !matchPattern(`(?<=key[:=]\s*)sk-\w+`, "key: sk-abc123") {
		t.Fatal("lookbehind pattern should match")
	}
}

// ---------------------------------------------------------------------------
// 检测器（detector）与全量扫描
// ---------------------------------------------------------------------------

func detectorRule(id int, det string, action Action, repl string) Rule {
	return Rule{ID: id, Name: det, Type: RuleTypeDetector, Detector: det, Enabled: true, Action: action, Replacement: repl}
}

func TestDetectorCNIDCard(t *testing.T) {
	if !matchDetector("cn_id_card", "身份证 11010519491231002X 测试") {
		t.Fatal("valid CN ID card should match")
	}
	if matchDetector("cn_id_card", "身份证 110105194912310021 测试") {
		t.Fatal("invalid checksum must not match")
	}
}

func TestDetectorBankCard(t *testing.T) {
	if !matchDetector("bank_card", "卡号 4111 1111 1111 1111") {
		t.Fatal("valid Luhn card should match")
	}
	if matchDetector("bank_card", "卡号 4111 1111 1111 1112") {
		t.Fatal("invalid Luhn card must not match")
	}
	if matchDetector("bank_card", "卡号 0000 0000 0000 0000") {
		t.Fatal("all-zero card must not match")
	}
}

func TestDetectorAPIKey(t *testing.T) {
	for _, s := range []string{
		"key=sk-proj-AbCdEfGhIjKlMnOpQrStUvWx",
		"key=ghp_0123456789abcdefghijklmnopqrstuvwx",
		"key=AKIAIOSFODNN7EXAMPLE",
		"key=glpat-AbCdEfGhIjKlMnOpQrSt",
	} {
		if !matchDetector("api_key", s) {
			t.Fatalf("%q should match api_key", s)
		}
	}
	if matchDetector("api_key", "just a normal sentence") {
		t.Fatal("plain text must not match api_key")
	}
}

func TestDetectorJWT(t *testing.T) {
	tok := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456ghi789"
	if !matchDetector("jwt", "Authorization: Bearer "+tok) {
		t.Fatal("valid JWT should match")
	}
	// 三段但 header 不是 JSON → 不命中
	if matchDetector("jwt", "eyJhbGciOiJIUzI1NiJ9xx.notjson.notjson") {
		t.Fatal("non-JSON header must not match")
	}
}

func TestDetectorHighEntropy(t *testing.T) {
	if !matchDetector("high_entropy", "token Xk9fQ2mZ7pL4vR8tN3wY6bC1") {
		t.Fatal("high entropy token should match")
	}
	for _, s := range []string{
		"abcdefghijklmnopqrstuvwxyz",              // 无数字/大写
		"d41d8cd98f00b204e9800998ecf8427e",        // 纯小写 hex（git sha / md5）
		"this header explains everything clearly", // 普通英文
	} {
		if matchDetector("high_entropy", s) {
			t.Fatalf("%q must not match high_entropy", s)
		}
	}
}

func TestDetectorMaskReplacesAllOccurrences(t *testing.T) {
	store = testStore(t, []Rule{detectorRule(1, "api_key", ActionMask, "[KEY]")})
	in := `{"messages":[{"role":"user","content":"a sk-proj-AbCdEfGhIjKlMnOpQrStUvWx and b ghp_0123456789abcdefghijklmnopqrstuvwx"}]}`
	out, rejected, err := protectBody([]byte(in))
	if err != nil || rejected {
		t.Fatalf("unexpected: rejected=%v err=%v", rejected, err)
	}
	if got := messageContent(t, out, 0); got != "a [KEY] and b [KEY]" {
		t.Fatalf("got %q", got)
	}
}

func TestDetectorReject(t *testing.T) {
	store = testStore(t, []Rule{detectorRule(1, "private_key", ActionReject, "")})
	in := `{"messages":[{"role":"user","content":"-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----"}]}`
	if _, rejected, _ := protectBody([]byte(in)); !rejected {
		t.Fatal("private key must be rejected")
	}
}

func TestDetectorNoMatchKeepsOriginalBytes(t *testing.T) {
	store = testStore(t, []Rule{
		detectorRule(1, "api_key", ActionMask, "[KEY]"),
		detectorRule(2, "cn_id_card", ActionMask, "[ID]"),
		detectorRule(3, "high_entropy", ActionMask, "[TOKEN]"),
	})
	in := `{"model":"gpt-4o","messages":[{"role":"user","content":"hello world"}],"tools":[{"type":"function","function":{"name":"f","description":"no secrets here"}}]}`
	out, rejected, err := protectBody([]byte(in))
	if err != nil || rejected {
		t.Fatalf("unexpected: rejected=%v err=%v", rejected, err)
	}
	if string(out) != in {
		t.Fatalf("body changed without match:\n%s", out)
	}
}

// TestCoverageOutsideMessages 锁定"以前被原样转发"的位置现在也被扫描。
func TestCoverageOutsideMessages(t *testing.T) {
	store = testStore(t, []Rule{
		{ID: 1, Name: "mask-secret", Enabled: true, Action: ActionMask, Pattern: "SECRETVALUE", Replacement: "***"},
	})

	t.Run("tool_calls.arguments", func(t *testing.T) {
		in := `{"messages":[{"role":"assistant","content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"f","arguments":"{\"key\":\"SECRETVALUE\"}"}}]}]}`
		out, _, _ := protectBody([]byte(in))
		if strings.Contains(string(out), "SECRETVALUE") {
			t.Fatalf("tool_calls arguments not masked: %s", out)
		}
		if !strings.Contains(string(out), `"name":"f"`) {
			t.Fatalf("tool_calls structure broken: %s", out)
		}
	})

	t.Run("reasoning_content", func(t *testing.T) {
		in := `{"messages":[{"role":"assistant","reasoning_content":"the key is SECRETVALUE","content":"ok"}]}`
		out, _, _ := protectBody([]byte(in))
		if strings.Contains(string(out), "SECRETVALUE") {
			t.Fatalf("reasoning_content not masked: %s", out)
		}
	})

	t.Run("tools.parameters", func(t *testing.T) {
		in := `{"messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"f","description":"call SECRETVALUE","parameters":{"type":"object","properties":{"host":{"default":"SECRETVALUE"}}}}}]}`
		out, _, _ := protectBody([]byte(in))
		if strings.Contains(string(out), "SECRETVALUE") {
			t.Fatalf("tools parameters not masked: %s", out)
		}
	})

	t.Run("top-level input", func(t *testing.T) {
		in := `{"model":"m","input":"my token is SECRETVALUE"}`
		out, _, _ := protectBody([]byte(in))
		if strings.Contains(string(out), "SECRETVALUE") {
			t.Fatalf("top-level input not masked: %s", out)
		}
	})

	t.Run("embeddings input", func(t *testing.T) {
		in := `{"model":"text-embedding-3-small","input":["hello","SECRETVALUE"]}`
		out, _, _ := protectBody([]byte(in))
		if strings.Contains(string(out), "SECRETVALUE") {
			t.Fatalf("embeddings input not masked: %s", out)
		}
	})
}

func TestFieldSelection(t *testing.T) {
	store = testStore(t, []Rule{{
		ID: 1, Name: "content-only", Enabled: true, Action: ActionMask,
		Pattern: "SECRETVALUE", Replacement: "***", Fields: []string{FieldContent},
	}})
	in := `{"messages":[{"role":"user","content":"SECRETVALUE"}],"tools":[{"type":"function","function":{"name":"f","description":"SECRETVALUE"}}]}`
	out, _, _ := protectBody([]byte(in))
	if got := messageContent(t, out, 0); got != "***" {
		t.Fatalf("content should be masked, got %q", got)
	}
	if !strings.Contains(string(out), `"description":"SECRETVALUE"`) {
		t.Fatalf("tools must be untouched with fields=[content]: %s", out)
	}
}

func TestScopedRuleDoesNotTouchTools(t *testing.T) {
	store = testStore(t, []Rule{{
		ID: 1, Name: "user-only", Enabled: true, Action: ActionReject,
		Pattern: "FORBIDDEN", Scopes: []string{"user"},
	}})
	// 工具描述里出现关键字不应触发 user 作用域的 reject 规则
	in := `{"messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"f","description":"FORBIDDEN"}}]}`
	out, rejected, _ := protectBody([]byte(in))
	if rejected {
		t.Fatal("user-scoped rule must not reject on tool descriptions")
	}
	if string(out) != in {
		t.Fatal("body must be unchanged")
	}
}

func TestNumbersRoundTripAfterMask(t *testing.T) {
	store = testStore(t, []Rule{{
		ID: 1, Name: "r", Enabled: true, Action: ActionMask,
		Pattern: "SECRETVALUE", Replacement: "***",
	}})
	in := `{"seed":123456789012345678,"temperature":0.7,"messages":[{"role":"user","content":"SECRETVALUE"}]}`
	out, _, _ := protectBody([]byte(in))
	if !strings.Contains(string(out), "123456789012345678") {
		t.Fatalf("large integer lost precision: %s", out)
	}
	if !strings.Contains(string(out), "0.7") {
		t.Fatalf("float changed: %s", out)
	}
}

func TestValidateDetectorRule(t *testing.T) {
	cases := []struct {
		rule Rule
		ok   bool
	}{
		{detectorRule(0, "api_key", ActionMask, "[K]"), true},
		{detectorRule(0, "nope", ActionMask, "[K]"), false},                                                                       // 未知检测器
		{detectorRule(0, "api_key", ActionMask, ""), false},                                                                       // mask 需要 replacement
		{Rule{Name: "a", Type: RuleTypeDetector, Detector: "api_key", Pattern: "x", Action: ActionMask, Replacement: "y"}, false}, // 检测器不能带 pattern
		{Rule{Name: "a", Type: RuleTypeRegex, Pattern: "x", Detector: "api_key", Action: ActionMask, Replacement: "y"}, false},    // regex 不能带 detector
		{Rule{Name: "a", Pattern: "x", Action: ActionMask, Replacement: "y", Fields: []string{"bogus"}}, false},                   // 非法字段
		{Rule{Name: "a", Pattern: "x", Action: ActionMask, Replacement: "y", Fields: []string{FieldTop}}, true},
		{Rule{Name: "a", Type: RuleTypeRegex, Pattern: "x", Action: ActionMask, Replacement: "y"}, true},
	}
	for i, c := range cases {
		err := validateRule(c.rule)
		if (err == nil) != c.ok {
			t.Fatalf("case %d (%+v): err=%v, want ok=%v", i, c.rule, err, c.ok)
		}
	}
}

// --- helpers --------------------------------------------------------------

func matchDetector(name, s string) bool {
	return len(detectIn(detectorRule(0, name, ActionMask, "X"), s)) > 0
}

func messageContent(t *testing.T, body []byte, i int) string {
	t.Helper()
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("bad body: %v", err)
	}
	var msgs []map[string]any
	if err := json.Unmarshal(doc["messages"], &msgs); err != nil {
		t.Fatalf("bad messages: %v", err)
	}
	s, _ := msgs[i]["content"].(string)
	return s
}

// --- static assets --------------------------------------------------------

// TestStaticAssetsNoCache 锁定 Cache-Control: no-cache。
// embed.FS 无 modtime → FileServer 不发 Last-Modified / ETag，不加这个头的话
// 换了二进制浏览器还可能用旧的 app.js。
func TestStaticAssetsNoCache(t *testing.T) {
	for _, path := range []string{"/", "/static/app.js", "/static/style.css"} {
		rec := httptest.NewRecorder()
		route(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", path, rec.Code)
		}
		if got := rec.Header().Get("Cache-Control"); got != "no-cache" {
			t.Fatalf("%s: Cache-Control = %q, want no-cache", path, got)
		}
	}
}

// TestAppJSRefillsDetectorOptions 锁定检测器下拉框在拿到 /api/detectors 之后重建。
// fillDetectorOptions 只在脚本启动时调用一次的话，那时 detectors 还是空数组，
// 下拉框就永远是空的（界面表现为"内置检测器无法选中"）。
func TestAppJSRefillsDetectorOptions(t *testing.T) {
	rec := httptest.NewRecorder()
	route(rec, httptest.NewRequest(http.MethodGet, "/static/app.js", nil))
	body := rec.Body.String()
	if n := strings.Count(body, "fillDetectorOptions();"); n < 2 {
		t.Fatalf("fillDetectorOptions() called %d time(s), want >= 2 (启动 + load 之后)", n)
	}
	if !strings.Contains(body, "fillDetectorOptions();\n  render();") {
		t.Fatal("load() 必须先 fillDetectorOptions() 再 render()")
	}
}
