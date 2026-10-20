package main

// -secret-file（已知密钥值）的测试。
//
// 锁定的是一个很窄但明确的契约：
//   - 只收 ###secret 段内的值，段外（public/未标注）一律不收；
//   - 值原样保留（含 #、引号剥除、CRLF），绝不静默变短；
//   - 显式列出的文件有问题 → 启动失败；目录展开的文件有问题 → 跳过 + 报告；
//   - 同一个键在不同项目取值不同时，两个值都要被保护；
//   - 命中后按普通 mask 规则脱敏，并且 needle 进 hitSink（响应侧 B1 因此生效）。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// signalHUP 给自己发 SIGHUP。handler 未注册时它的默认行为是终止进程，
// 所以这个测试同时也锁定了"必须 signal.Notify"这条不变量。
func signalHUP() error {
	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		return err
	}
	return p.Signal(syscall.SIGHUP)
}

func writeEnvFile(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// installSecrets 直接装快照（不启 goroutine），测试结束自动清空。
func installSecrets(t *testing.T, specs ...string) *secretSet {
	t.Helper()
	set, err := loadSecretSet(specs)
	if err != nil {
		t.Fatalf("loadSecretSet: %v", err)
	}
	secretState.mu.Lock()
	secretState.pinned = specs
	secretState.fromList = nil
	secretState.listPath = filepath.Join(t.TempDir(), "secret-files.json")
	secretState.mu.Unlock()
	secretState.current.Store(set)
	t.Cleanup(resetSecretState)
	return set
}

func resetSecretState() {
	secretState.mu.Lock()
	secretState.pinned = nil
	secretState.fromList = nil
	secretState.listPath = ""
	secretState.mu.Unlock()
	secretState.current.Store(nil)
}

const sampleEnv = `# 普通配置
API_HOST=api.openai.com
MODEL=gpt-4o-instruct

###secret
OPENAI_API_KEY=sk-abcdefghijklmnop1234567890
LARK_APP_SECRET="eScTsP12abcdefBraXlQ4g3qACe5Xojm"
OKX_SECRET=P@vS4^HabcdefQ#
DB_PASS=$SOME_REFERENCE
EMPTY_VALUE=
`

func TestSecretMarkerVariants(t *testing.T) {
	yes := []string{"###secret", "#secret", "##########secret", "#### secret", "  ### SECRET  ", "###public", "### Public"}
	for _, line := range yes {
		if got := secretMarker(line); got == "" {
			t.Fatalf("%q must be a marker", line)
		}
	}
	no := []string{"# secret 的说明", "#secrets", "###secret: 说明", "x=###secret", "#", "", "KEY=###secret", "### secrete"}
	for _, line := range no {
		if got := secretMarker(line); got != "" {
			t.Fatalf("%q must NOT be a marker (got %q)", line, got)
		}
	}
}

func TestSecretCollectsOnlySecretSection(t *testing.T) {
	path := writeEnvFile(t, filepath.Join(t.TempDir(), ".env"), sampleEnv)
	set, err := loadSecretSet([]string{path})
	if err != nil {
		t.Fatalf("loadSecretSet: %v", err)
	}

	got := map[string]string{}
	for _, e := range set.entries {
		got[e.Key] = e.Value
	}
	// public 段的值一个都不能进来（否则 API_HOST 之类会被每轮请求无谓替换）
	for _, leaked := range []string{"API_HOST", "MODEL"} {
		if _, ok := got[leaked]; ok {
			t.Fatalf("%s is outside the secret section and must not be collected", leaked)
		}
	}
	if len(got) != 3 {
		t.Fatalf("want 3 collected values, got %d: %v", len(got), got)
	}
	if got["OPENAI_API_KEY"] != "sk-abcdefghijklmnop1234567890" {
		t.Fatalf("openai key mangled: %q", got["OPENAI_API_KEY"])
	}
	// 引号剥掉但内容不动
	if got["LARK_APP_SECRET"] != "eScTsP12abcdefBraXlQ4g3qACe5Xojm" {
		t.Fatalf("lark secret mangled: %q", got["LARK_APP_SECRET"])
	}
	// 行内 # 必须原样保留：剥掉就等于让值永远匹配不上
	if got["OKX_SECRET"] != "P@vS4^HabcdefQ#" {
		t.Fatalf("inline # must be preserved, got %q", got["OKX_SECRET"])
	}
}

func TestSecretExplicitFileFailsClosed(t *testing.T) {
	dir := t.TempDir()

	cases := []struct {
		name    string
		content string
	}{
		{"no marker", "OPENAI_API_KEY=sk-abcdefghijklmnop1234567890\n"},
		{"empty secret section", "###secret\n###public\nX=1\n"},
		{"only references", "###secret\nA=$FOO\nB=\n"},
	}
	for _, tc := range cases {
		path := writeEnvFile(t, filepath.Join(dir, tc.name+".env"), tc.content)
		if _, err := loadSecretSet([]string{path}); err == nil {
			t.Fatalf("%s: an explicitly listed file must fail closed", tc.name)
		}
	}

	if _, err := loadSecretSet([]string{filepath.Join(dir, "missing.env")}); err == nil {
		t.Fatal("a missing explicitly listed file must fail closed")
	}
}

func TestSecretDirModeSkipsBadFile(t *testing.T) {
	root := t.TempDir()
	writeEnvFile(t, filepath.Join(root, "proj-a", ".env"), "###secret\nA_TOKEN=aaaaaaaaaaaaaaaa1\n")
	writeEnvFile(t, filepath.Join(root, "proj-b", ".env"), "B_TOKEN=bbbbbbbbbbbbbbbb2\n") // 漏了标记
	writeEnvFile(t, filepath.Join(root, "proj-c", ".env"), "###secret\nC_TOKEN=cccccccccccccccc3\n")

	set, err := loadSecretSet([]string{root})
	if err != nil {
		t.Fatalf("dir mode must not fail on a marker-less .env: %v", err)
	}
	if set.valueCount() != 2 {
		t.Fatalf("want 2 values from proj-a/proj-c, got %d", set.valueCount())
	}
	var skipped int
	for _, r := range set.reports {
		if r.Skipped != "" {
			skipped++
			if !strings.Contains(r.Skipped, "marker") {
				t.Fatalf("skip reason should mention the missing marker, got %q", r.Skipped)
			}
		}
	}
	if skipped != 1 {
		t.Fatalf("the marker-less file must be reported, skipped=%d", skipped)
	}
}

func TestSecretSameKeyDifferentValuesBothCollected(t *testing.T) {
	root := t.TempDir()
	writeEnvFile(t, filepath.Join(root, "proj-a", ".env"), "###secret\nOPENAI_API_KEY=sk-aaaaaaaaaaaaaaaa1\n")
	writeEnvFile(t, filepath.Join(root, "proj-b", ".env"), "###secret\nOPENAI_API_KEY=sk-bbbbbbbbbbbbbbbb2\n")

	set, err := loadSecretSet([]string{root})
	if err != nil {
		t.Fatalf("loadSecretSet: %v", err)
	}
	// 按值去重（而不是按键名）：两个项目的密钥都必须被保护。
	if set.valueCount() != 2 {
		t.Fatalf("both values must be collected, got %d", set.valueCount())
	}
}

func TestSecretMasksRequestAndFeedsNeedles(t *testing.T) {
	path := writeEnvFile(t, filepath.Join(t.TempDir(), ".env"), sampleEnv)
	installSecrets(t, path)
	store = testStore(t, nil)

	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"这个 key sk-abcdefghijklmnop1234567890 一直 401，为什么"}]}`
	out, meta, rejected, err := protectRequest([]byte(body))
	if err != nil || rejected {
		t.Fatalf("protect: rejected=%v err=%v", rejected, err)
	}
	if strings.Contains(string(out), "sk-abcdefghijklmnop1234567890") {
		t.Fatal("known secret value must be redacted before forwarding")
	}
	if !strings.Contains(string(out), SecretRedaction) {
		t.Fatalf("expected %s in the protected body: %s", SecretRedaction, out)
	}
	// 配置里的 public 段值不该被动
	if !strings.Contains(string(out), "401") {
		t.Fatalf("unrelated content must survive: %s", out)
	}
	if len(meta.needles) != 1 || meta.needles[0] != "sk-abcdefghijklmnop1234567890" {
		t.Fatalf("masked value must become a B1 needle, got %v", meta.needles)
	}
}

func TestSecretRuleRunsBeforeUserRules(t *testing.T) {
	path := writeEnvFile(t, filepath.Join(t.TempDir(), ".env"), sampleEnv)
	installSecrets(t, path)
	store = testStore(t, []Rule{{
		ID: 1, Name: "user-mask", Enabled: true, Action: ActionMask,
		Pattern: `sk-[a-z0-9]+`, Replacement: "USER-REPLACED",
	}})

	rules := activeRules()
	if len(rules) < 2 || rules[0].Name != "secret-file" {
		t.Fatalf("the secret-file rule must come first, got %+v", rules)
	}
	out, _, _, err := protectRequest([]byte(`{"messages":[{"role":"user","content":"sk-abcdefghijklmnop1234567890"}]}`))
	if err != nil {
		t.Fatalf("protect: %v", err)
	}
	// 已知值必须由 secret-file 规则处理：用户规则永远看不到原值
	if !strings.Contains(string(out), SecretRedaction) || strings.Contains(string(out), "USER-REPLACED") {
		t.Fatalf("secret-file rule must win, got %s", out)
	}
}

func TestSecretReloadKeepsOldSnapshotOnError(t *testing.T) {
	path := writeEnvFile(t, filepath.Join(t.TempDir(), ".env"), "###secret\nA_TOKEN=aaaaaaaaaaaaaaaa1\n")
	installSecrets(t, path)
	before := currentSecretSet()

	// 运行中把文件写坏（模拟编辑器写到一半）：必须保留旧快照，而不是清空保护
	if err := os.WriteFile(path, []byte("A_TOKEN=aaaaaaaaaaaaaaaa1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	reloadSecrets("test")
	if got := currentSecretSet(); got != before {
		t.Fatal("a failed reload must keep the previous snapshot (fail safe at runtime)")
	}
	if currentSecretSet().valueCount() != 1 {
		t.Fatal("previous values must remain active")
	}
}

func TestSecretReloadPicksUpNewValue(t *testing.T) {
	path := writeEnvFile(t, filepath.Join(t.TempDir(), ".env"), "###secret\nA_TOKEN=aaaaaaaaaaaaaaaa1\n")
	installSecrets(t, path)

	if err := os.WriteFile(path, []byte("###secret\nA_TOKEN=aaaaaaaaaaaaaaaa1\nB_TOKEN=bbbbbbbbbbbbbbbb2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	reloadSecrets("test")
	if got := currentSecretSet().valueCount(); got != 2 {
		t.Fatalf("reload must pick up the new value, got %d", got)
	}
}

func TestSecretSIGHUPReloads(t *testing.T) {
	path := writeEnvFile(t, filepath.Join(t.TempDir(), ".env"), "###secret\nA_TOKEN=aaaaaaaaaaaaaaaa1\n")
	if err := configureSecrets([]string{path}, filepath.Join(t.TempDir(), "secret-files.json"), 0); err != nil {
		t.Fatalf("configureSecrets: %v", err)
	}
	t.Cleanup(resetSecretState)

	if err := os.WriteFile(path, []byte("###secret\nA_TOKEN=aaaaaaaaaaaaaaaa1\nB_TOKEN=bbbbbbbbbbbbbbbb2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := signalHUP(); err != nil {
		t.Fatalf("send SIGHUP: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if currentSecretSet().valueCount() == 2 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("SIGHUP did not reload (values=%d) — is the handler registered?", currentSecretSet().valueCount())
}

func TestSecretDetectorIsRegistered(t *testing.T) {
	if detectorRegistry[detectorKnownSecret] == nil {
		t.Fatal("known_secret must be registered so rules can reference it")
	}
	var found bool
	for _, d := range detectors {
		if d.Name == detectorKnownSecret {
			found = true
		}
	}
	if !found {
		t.Fatal("known_secret must be listed by /api/detectors")
	}
}

func TestSecretsAPIIsAdminOnly(t *testing.T) {
	path := writeEnvFile(t, filepath.Join(t.TempDir(), ".env"), "###secret\nA_TOKEN=aaaaaaaaaaaaaaaa1\n")
	installSecrets(t, path)

	old := adminTokenValue
	adminTokenValue = "t0ken"
	defer func() { adminTokenValue = old }()

	req := httptest.NewRequest(http.MethodGet, "/api/secrets", nil)
	rec := httptest.NewRecorder()
	route(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("without a token: want 401, got %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/secrets", nil)
	req.Header.Set("X-Admin-Token", "t0ken")
	rec = httptest.NewRecorder()
	route(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("with a token: want 200, got %d", rec.Code)
	}
	var body secretStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !body.Enabled || body.Values != 1 {
		t.Fatalf("unexpected status: %+v", body)
	}
	// 接口只允许暴露路径与键名，绝不能回传值
	if strings.Contains(rec.Body.String(), "aaaaaaaaaaaaaaaa1") {
		t.Fatal("the secrets API must never return values")
	}
}

// TestUIExposesSecretPanel 锁定前端面板的存在性：静态资源是 embed 进二进制的，
// 没有测试的话"面板被谁删了"只能靠肉眼发现。
func TestUIExposesSecretPanel(t *testing.T) {
	rec := httptest.NewRecorder()
	route(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if !strings.Contains(rec.Body.String(), `id="secrets-table"`) {
		t.Fatal("管理界面必须包含已知密钥面板（secrets-table）")
	}

	rec = httptest.NewRecorder()
	route(rec, httptest.NewRequest(http.MethodGet, "/static/app.js", nil))
	body := rec.Body.String()
	for _, want := range []string{"loadSecrets", `"/secrets"`, `"/secrets/reload"`, `"/secrets/files"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("app.js 必须包含 %s，否则面板拿不到数据", want)
		}
	}
	if !strings.Contains(rec.Body.String(), `id="secret-path"`) && !strings.Contains(recBody(t, "/"), `id="secret-path"`) {
		t.Fatal("管理界面必须给出行路径输入框（secret-path）")
	}
}

/* ---------------- 可编辑列表（网关开机只启一次，路径必须能改） ---------------- */

func TestSecretListAddAndRemove(t *testing.T) {
	dir := t.TempDir()
	envPath := writeEnvFile(t, filepath.Join(dir, "proj-a", ".env"), "###secret\nA_TOKEN=aaaaaaaaaaaaaaaa1\n")
	listPath := filepath.Join(dir, "secret-files.json")

	if err := configureSecrets(nil, listPath, 0); err != nil {
		t.Fatalf("configureSecrets: %v", err)
	}
	t.Cleanup(resetSecretState)
	if got := currentSecretSet(); got != nil && got.valueCount() != 0 {
		t.Fatalf("empty list must start with no values, got %d", got.valueCount())
	}

	if err := addSecretPath(envPath); err != nil {
		t.Fatalf("addSecretPath: %v", err)
	}
	if got := currentSecretSet().valueCount(); got != 1 {
		t.Fatalf("adding a path must take effect immediately, got %d values", got)
	}
	listed, err := readSecretList(listPath)
	if err != nil || len(listed) != 1 || listed[0] != envPath {
		t.Fatalf("path must be persisted to %s, got %v (err=%v)", listPath, listed, err)
	}

	if err := removeSecretPath(envPath); err != nil {
		t.Fatalf("removeSecretPath: %v", err)
	}
	if got := currentSecretSet().valueCount(); got != 0 {
		t.Fatalf("removing a path must take effect immediately, got %d values", got)
	}
	if listed, _ := readSecretList(listPath); len(listed) != 0 {
		t.Fatalf("removal must be persisted, got %v", listed)
	}
}

func TestSecretListRejectsUnusablePath(t *testing.T) {
	dir := t.TempDir()
	noMarker := writeEnvFile(t, filepath.Join(dir, "bad", ".env"), "A_TOKEN=aaaaaaaaaaaaaaaa1\n")
	emptyDir := filepath.Join(dir, "empty-project")
	if err := os.MkdirAll(emptyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	listPath := filepath.Join(dir, "secret-files.json")
	if err := configureSecrets(nil, listPath, 0); err != nil {
		t.Fatalf("configureSecrets: %v", err)
	}
	t.Cleanup(resetSecretState)

	for _, path := range []string{noMarker, emptyDir, filepath.Join(dir, "nope", ".env")} {
		if err := addSecretPath(path); err == nil {
			t.Fatalf("%s must be rejected before being persisted", path)
		}
	}
	if listed, _ := readSecretList(listPath); len(listed) != 0 {
		t.Fatalf("rejected paths must not be persisted, got %v", listed)
	}
}

func TestSecretPinnedPathCannotBeRemoved(t *testing.T) {
	dir := t.TempDir()
	envPath := writeEnvFile(t, filepath.Join(dir, ".env"), "###secret\nA_TOKEN=aaaaaaaaaaaaaaaa1\n")
	listPath := filepath.Join(dir, "secret-files.json")
	if err := configureSecrets([]string{envPath}, listPath, 0); err != nil {
		t.Fatalf("configureSecrets: %v", err)
	}
	t.Cleanup(resetSecretState)

	if err := removeSecretPath(envPath); err == nil {
		t.Fatal("-secret-file entries are pinned: removing them from the UI must fail")
	}
	if currentSecretSet().valueCount() != 1 {
		t.Fatal("a pinned path must stay active")
	}
}

func TestSecretListBadEntryDoesNotBlockStartup(t *testing.T) {
	dir := t.TempDir()
	good := writeEnvFile(t, filepath.Join(dir, "proj-a", ".env"), "###secret\nA_TOKEN=aaaaaaaaaaaaaaaa1\n")
	missing := filepath.Join(dir, "renamed-project", ".env")
	listPath := filepath.Join(dir, "secret-files.json")
	if err := writeSecretList(listPath, []string{good, missing}); err != nil {
		t.Fatalf("writeSecretList: %v", err)
	}

	// 网关开机只启动一次：一条陈旧路径不能让整机起不来，只能跳过 + 告警。
	if err := configureSecrets(nil, listPath, 0); err != nil {
		t.Fatalf("a stale list entry must not refuse startup: %v", err)
	}
	t.Cleanup(resetSecretState)
	if got := currentSecretSet().valueCount(); got != 1 {
		t.Fatalf("the valid entry must still be active, got %d values", got)
	}

	var stale int
	for _, r := range currentSecretSet().reports {
		if r.Skipped != "" {
			stale++
		}
	}
	if stale != 1 {
		t.Fatalf("the stale entry must be reported, got %d skipped reports", stale)
	}
}

func TestSecretListSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	envPath := writeEnvFile(t, filepath.Join(dir, "proj-a", ".env"), "###secret\nA_TOKEN=aaaaaaaaaaaaaaaa1\n")
	listPath := filepath.Join(dir, "secret-files.json")

	if err := configureSecrets(nil, listPath, 0); err != nil {
		t.Fatalf("configureSecrets: %v", err)
	}
	if err := addSecretPath(envPath); err != nil {
		t.Fatalf("addSecretPath: %v", err)
	}
	resetSecretState()

	// 模拟重启（命令行没给 -secret-file，只靠持久化列表）
	if err := configureSecrets(nil, listPath, 0); err != nil {
		t.Fatalf("restart: %v", err)
	}
	t.Cleanup(resetSecretState)
	if got := currentSecretSet().valueCount(); got != 1 {
		t.Fatalf("the persisted list must survive a restart, got %d values", got)
	}
}

func recBody(t *testing.T, path string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	route(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Body.String()
}

// TestSecretFilesAPIManagesList 覆盖"网关开机只启动一次"的关键路径：
// 运行期通过 HTTP 增删 .env 路径，立即生效并持久化。
func TestSecretFilesAPIManagesList(t *testing.T) {
	dir := t.TempDir()
	envPath := writeEnvFile(t, filepath.Join(dir, "proj-a", ".env"), "###secret\nA_TOKEN=aaaaaaaaaaaaaaaa1\n")
	pinnedPath := writeEnvFile(t, filepath.Join(dir, "pinned", ".env"), "###secret\nB_TOKEN=bbbbbbbbbbbbbbbb2\n")
	listPath := filepath.Join(dir, "secret-files.json")

	if err := configureSecrets([]string{pinnedPath}, listPath, 0); err != nil {
		t.Fatalf("configureSecrets: %v", err)
	}
	t.Cleanup(resetSecretState)

	old := adminTokenValue
	adminTokenValue = "t0ken"
	defer func() { adminTokenValue = old }()

	post := func(body string) (*httptest.ResponseRecorder, secretStatus) {
		req := httptest.NewRequest(http.MethodPost, "/api/secrets/files", strings.NewReader(body))
		req.Header.Set("X-Admin-Token", "t0ken")
		rec := httptest.NewRecorder()
		route(rec, req)
		var st secretStatus
		_ = json.Unmarshal(rec.Body.Bytes(), &st)
		return rec, st
	}

	rec, st := post(`{"path":"` + envPath + `"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("add: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if st.Values != 2 {
		t.Fatalf("add must take effect immediately (pinned + added), got %d values", st.Values)
	}

	// 坏路径必须在写进列表之前就被拒绝
	bad := writeEnvFile(t, filepath.Join(dir, "bad", ".env"), "A_TOKEN=aaaaaaaaaaaaaaaa1\n")
	if rec, _ := post(`{"path":"` + bad + `"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("adding a marker-less .env must be rejected, got %d", rec.Code)
	}

	// 删除 pinned 路径必须失败
	req := httptest.NewRequest(http.MethodDelete, "/api/secrets/files?path="+pinnedPath, nil)
	req.Header.Set("X-Admin-Token", "t0ken")
	rec = httptest.NewRecorder()
	route(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("removing a -secret-file entry must be rejected, got %d", rec.Code)
	}

	// 删除可编辑路径 → 立即生效
	req = httptest.NewRequest(http.MethodDelete, "/api/secrets/files?path="+envPath, nil)
	req.Header.Set("X-Admin-Token", "t0ken")
	rec = httptest.NewRecorder()
	route(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("remove: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if currentSecretSet().valueCount() != 1 {
		t.Fatalf("after removal only the pinned value must remain, got %d", currentSecretSet().valueCount())
	}

	// 无 token → 401（列表决定"哪些密钥受保护"，不能对任何人开放）
	req = httptest.NewRequest(http.MethodPost, "/api/secrets/files", strings.NewReader(`{"path":"`+envPath+`"}`))
	rec = httptest.NewRecorder()
	route(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("without a token: want 401, got %d", rec.Code)
	}
}

// /api/preview 必须走 requireAdmin。
//
// 理由不是"接口不落盘所以无害"：known_secret 检测器对快照里的值做**子串匹配**，
// 所以免鉴权的试跑等于一个 membership oracle ——
//
//	POST /api/preview {"detector":"known_secret","testText":"<候选前缀>"} → hasMatch
//
// 逐个字符试就能把已知密钥值问出来（16 位随机值也只要 ~1000 次请求），
// 完全不需要读 .env，只需要能连上网关端口。WSL 连 Windows 侧网关的部署里，
// 端口必然不是 loopback-only，这条更必须 fail closed。
func TestPreviewIsAdminOnly(t *testing.T) {
	path := writeEnvFile(t, filepath.Join(t.TempDir(), ".env"),
		"###secret\nA_TOKEN=aaaaaaaaaaaaaaaa1\n")
	installSecrets(t, path)

	old := adminTokenValue
	adminTokenValue = "t0ken"
	defer func() { adminTokenValue = old }()

	// 候选前缀直接用真值：能命中就说明"脱敏逻辑正常"，但前提是必须先过鉴权。
	body := `{"type":"detector","detector":"known_secret","action":"mask",` +
		`"replacement":"[redacted]","testText":"x aaaaaaaaaaaaaaaa1 y"}`

	// 1) 没带 token：不能当 oracle 用，且响应里不能出现判定结果
	rec := previewRequest(body, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("without a token: want 401, got %d (%s)", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "hasMatch") {
		t.Fatalf("preview must not answer without a token, got %s", rec.Body.String())
	}

	// 2) 没配 token（空）= fail closed，不能因为"没配"就放开
	adminTokenValue = ""
	if rec := previewRequest(body, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("no admin token configured: want 403, got %d (%s)", rec.Code, rec.Body.String())
	}
	adminTokenValue = "t0ken"

	// 3) 带对 token：正常试跑（这条同时说明 oracle 仍然存在，只是被锁在 token 后面）
	rec = previewRequest(body, "t0ken")
	if rec.Code != http.StatusOK {
		t.Fatalf("with a token: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"hasMatch":true`) {
		t.Fatalf("expected a match, got %s", rec.Body.String())
	}
}

// previewRequest 直接打 route（管理 API 都走这里），token 为空就不带头。
func previewRequest(body, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/preview", strings.NewReader(body))
	if token != "" {
		req.Header.Set("X-Admin-Token", token)
	}
	rec := httptest.NewRecorder()
	route(rec, req)
	return rec
}
