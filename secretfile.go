package main

// 已知密钥值支持（-secret-file / -secret-list）。
//
// 设计前提是两条用户不变量（见 docs/SECRET-FILE.md）：
//
//	1. 敏感信息只写在 .env 里，且这些 .env 全部由网关的路径列表覆盖；
//	2. 所有 agent 的模型请求都经过本网关。
//
// 因此这里不做任何"形状猜测"：只把 .env 里 ###secret 段内的**真实值**收进一个
// 不可变快照，命中原值就替换为 [redacted]。命中值同时进 hitSink，响应侧 B1 于是
// 自动覆盖"模型把密钥复述回来"的情况 —— 不需要额外代码。
//
// 路径来自两处，语义刻意不同：
//
//	-secret-file（命令行，"pinned"）：由启动配置框死。显式列出的**文件**出问题 →
//	      拒绝启动（fail closed）。这是"我就要求它必须生效"的表达。
//	-secret-list（JSON 列表，默认 secret-files.json，"可编辑"）：给长期驻留的进程用
//	      —— 网关开机启一次，之后靠管理界面增删。列表项出问题只跳过 + 告警，否则
//	      一条陈旧路径（项目改名/删除）就能让机器开机起不来。
//
// 运行中重载失败永远保留上一个快照（fail safe）：你正用编辑器保存时的半截文件
// 不该把所有 agent 一起掐断。

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// detectorKnownSecret 是内置检测器名。规则通过它访问当前快照，所以"内置虚拟规则"
// 和用户手工创建的规则走的是同一条代码路径。
const detectorKnownSecret = "known_secret"

// SecretRedaction 是命中已知密钥值时的替换文本。
// 不保留原长度、不保留任何前缀 —— 长度也是信息。
const SecretRedaction = "[redacted]"

// defaultSecretListPath 是可编辑列表的默认位置。
const defaultSecretListPath = "secret-files.json"

// secretEntry 是一个已知的敏感值及其来源。
type secretEntry struct {
	Key    string // .env 里的键名（只用于日志，永不与值一起记录）
	Value  string // 真实值（只在内存里）
	Source string // 来源文件的绝对路径
}

// secretFileSource 是一份待解析的文件。
type secretFileSource struct {
	path string // 绝对路径
	// fromDir 表示这条路径是由目录参数展开得到的（宽松模式：坏文件只跳过）。
	fromDir bool
	// pinned 表示它来自 -secret-file（启动配置框死），出问题必须拒绝启动。
	pinned bool
}

// secretFileReport 是单个文件的解析结果，用于启动日志与 /api/secrets。
type secretFileReport struct {
	Path      string   `json:"path"`
	Mode      string   `json:"mode"` // "file"（显式）| "dir"（目录展开）
	Pinned    bool     `json:"pinned"`
	Collected int      `json:"collected"`
	Keys      []string `json:"keys,omitempty"`
	Skipped   string   `json:"skipped,omitempty"` // 跳过/失败原因；空 = 正常
}

// secretSet 是一份不可变快照。热路径只读它，因此不需要任何锁。
type secretSet struct {
	re       *regexp.Regexp // 所有值 QuoteMeta 后按长度降序拼成的 alternation；nil = 无值
	entries  []secretEntry  // 按值去重、按长度降序
	reports  []secretFileReport
	loadedAt time.Time
}

// valueCount 是快照里的值数量。
func (s *secretSet) valueCount() int {
	if s == nil {
		return 0
	}
	return len(s.entries)
}

var secretState struct {
	// mu 保护 pinned / fromList / listPath，并串行化重载。
	mu       sync.Mutex
	pinned   []string // -secret-file（命令行，不可在界面删除）
	fromList []string // -secret-list 里的可编辑路径
	listPath string
	// current 持有不可变快照；热路径零锁读取。
	current atomic.Pointer[secretSet]
}

// ---------------------------------------------------------------------------
// 解析
// ---------------------------------------------------------------------------

// secretMarker 判断一行是不是分节标记，返回 "secret" / "public" / ""。
//
// 标记必须是**独立一行**，且 # 与词连写（`#` 数量任意、`#` 后允许空白）：
//
//	###secret / #### secret / #secret  → 标记
//	# secret 的说明 / #secrets / x=###secret → 不是标记
func secretMarker(line string) string {
	t := strings.TrimSpace(line)
	if !strings.HasPrefix(t, "#") {
		return ""
	}
	t = strings.TrimSpace(strings.TrimLeft(t, "#"))
	switch strings.ToLower(t) {
	case "secret":
		return "secret"
	case "public":
		return "public"
	}
	return ""
}

// parseEnvAssignment 解析一行 KEY=VALUE。ok=false 表示这不是一条可用的赋值。
//
// 刻意**不剥行内 # 注释**：真实密钥里就可能带 #（例如 P@vS4^H…Q#），剥掉等于
// 让值静默变短、永远匹配不上。只处理整行注释、成对引号、export 前缀与 CRLF。
func parseEnvAssignment(line string) (key, value string, ok bool) {
	t := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
	if t == "" || strings.HasPrefix(t, "#") {
		return "", "", false
	}
	if strings.HasPrefix(t, "export ") {
		t = strings.TrimSpace(strings.TrimPrefix(t, "export"))
	}
	eq := strings.IndexByte(t, '=')
	if eq <= 0 {
		return "", "", false
	}
	key = strings.TrimSpace(t[:eq])
	value = strings.TrimSpace(t[eq+1:])
	if key == "" || value == "" {
		return "", "", false
	}
	if n := len(value); n >= 2 {
		if (value[0] == '"' && value[n-1] == '"') || (value[0] == '\'' && value[n-1] == '\'') {
			value = value[1 : n-1]
		}
	}
	if value == "" || strings.HasPrefix(value, "$") {
		// $VAR 引用无法在网关侧解析 → 明确跳过（调用方会记录原因），不猜。
		return "", "", false
	}
	return key, value, true
}

// parseSecretFile 解析一份 .env，只返回 ###secret 段内的键值。
//
// 返回 skipped 非空表示"文件读到了但收不到值"（没有标记 / 段内 0 条），
// 由调用方按 pinned 或可编辑模式决定是失败还是跳过。
func parseSecretFile(path string) (entries []secretEntry, keys []string, skipped string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, "", err
	}

	inSecret := false
	sawMarker := false
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimPrefix(line, "\ufeff") // UTF-8 BOM（Windows 编辑器常见）
		switch secretMarker(line) {
		case "secret":
			inSecret, sawMarker = true, true
			continue
		case "public":
			inSecret = false
			continue
		}
		if !inSecret {
			continue
		}
		key, value, ok := parseEnvAssignment(line)
		if !ok {
			continue
		}
		if seen[key] {
			continue // 同名键以先出现的为准（后者不覆盖，避免"后写的悄悄生效"）
		}
		seen[key] = true
		keys = append(keys, key)
		entries = append(entries, secretEntry{Key: key, Value: value, Source: path})
	}

	switch {
	case !sawMarker:
		return nil, nil, `no "###secret" marker found`, nil
	case len(entries) == 0:
		return nil, nil, `"###secret" section contains no KEY=VALUE entries`, nil
	}
	return entries, keys, "", nil
}

// expandOne 把一个路径参数展开成文件列表。
//
// 文件 → 就是它自己（pinned 决定它是否严格）。
// 目录 → <dir>/.env 与 <dir>/*/.env（只一层，跳过以 . 开头的名字），恒为宽松。
func expandOne(spec string, pinned bool) ([]secretFileSource, error) {
	abs, err := filepath.Abs(spec)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", spec, err)
	}
	st, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", abs, err)
	}
	if !st.IsDir() {
		return []secretFileSource{{path: abs, pinned: pinned}}, nil
	}

	out := []secretFileSource{{path: filepath.Join(abs, ".env")}}
	children, err := os.ReadDir(abs)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", abs, err)
	}
	names := make([]string, 0, len(children))
	for _, c := range children {
		if !c.IsDir() || strings.HasPrefix(c.Name(), ".") {
			continue
		}
		names = append(names, c.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		out = append(out, secretFileSource{path: filepath.Join(abs, name, ".env")})
	}
	for i := range out {
		out[i].fromDir = true
	}
	return out, nil
}

// expandSources 展开全部路径并去重（同一文件同时出现时，"pinned" 优先）。
func expandSources(pinned, listed []string) ([]secretFileSource, error) {
	var out []secretFileSource
	index := map[string]int{}

	merge := func(sources []secretFileSource) {
		for _, src := range sources {
			if i, ok := index[src.path]; ok {
				if src.pinned {
					out[i].pinned = true
				}
				if !src.fromDir {
					out[i].fromDir = false
				}
				continue
			}
			index[src.path] = len(out)
			out = append(out, src)
		}
	}

	for _, spec := range pinned {
		sources, err := expandOne(spec, true)
		if err != nil {
			return nil, err
		}
		merge(sources)
	}
	for _, spec := range listed {
		sources, err := expandOne(spec, false)
		if err != nil {
			// 列表项坏掉不是致命错误（否则一条陈旧路径就能让开机起不来）：
			// 保留一个显式来源，由 loadSecretSources 记录 Skipped 并告警。
			out = append(out, secretFileSource{path: strings.TrimSpace(spec)})
			continue
		}
		merge(sources)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out, nil
}

// loadSecretSet 用一组**显式文件路径**构建快照（测试与简单调用用）。
func loadSecretSet(specs []string) (*secretSet, error) {
	sources, err := expandSources(specs, nil)
	if err != nil {
		return nil, err
	}
	return loadSecretSources(sources)
}

// loadSecretSources 读取全部来源并构建快照。
//
// pinned 的来源出现任何问题都返回错误（fail closed）；其余只记录 Skipped 并继续。
func loadSecretSources(sources []secretFileSource) (*secretSet, error) {
	set := &secretSet{loadedAt: time.Now()}
	var collected []secretEntry
	byValue := map[string]bool{}

	for _, src := range sources {
		// 目录展开出的路径可能根本没有 .env（项目还没写），这不是错误，也不报告。
		if src.fromDir && !pathExists(src.path) {
			if !src.pinned {
				continue
			}
		}
		entries, keys, skipped, err := parseSecretFile(src.path)
		report := secretFileReport{Path: src.path, Mode: modeOf(src), Pinned: src.pinned}
		if skipped == "" && err != nil {
			skipped = err.Error()
		}
		if skipped != "" {
			report.Skipped = skipped
			if src.pinned && !src.fromDir {
				return nil, fmt.Errorf("%s: %s", src.path, skipped)
			}
			set.reports = append(set.reports, report)
			continue
		}
		if len(entries) == 0 {
			continue
		}
		report.Collected = len(entries)
		report.Keys = keys
		set.reports = append(set.reports, report)
		for _, e := range entries {
			// 按**值**去重：同一个键在不同项目里取值不同时，两个值都必须被保护。
			if byValue[e.Value] {
				continue
			}
			byValue[e.Value] = true
			collected = append(collected, e)
		}
	}

	// 长的在前：Go 的 alternation 是 leftmost-first，短值排在前面会把长子串吞掉。
	sort.SliceStable(collected, func(i, j int) bool {
		if len(collected[i].Value) != len(collected[j].Value) {
			return len(collected[i].Value) > len(collected[j].Value)
		}
		return collected[i].Value < collected[j].Value
	})
	set.entries = collected

	if len(collected) > 0 {
		quoted := make([]string, len(collected))
		for i, e := range collected {
			quoted[i] = regexp.QuoteMeta(e.Value)
		}
		re, err := regexp.Compile("(?:" + strings.Join(quoted, "|") + ")")
		if err != nil {
			return nil, fmt.Errorf("compile secret alternation: %w", err)
		}
		set.re = re
	}
	return set, nil
}

func modeOf(src secretFileSource) string {
	if src.fromDir {
		return "dir"
	}
	return "file"
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ---------------------------------------------------------------------------
// 可编辑路径列表（secret-files.json）
// ---------------------------------------------------------------------------

// readSecretList 读取列表文件。文件不存在视为空列表（不是错误）。
func readSecretList(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var doc struct {
		Paths []string `json:"paths"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	clean := make([]string, 0, len(doc.Paths))
	for _, p := range doc.Paths {
		if t := strings.TrimSpace(p); t != "" {
			clean = append(clean, t)
		}
	}
	return clean, nil
}

// writeSecretList 原子写入列表文件（临时文件 + rename）。
func writeSecretList(path string, paths []string) error {
	if path == "" {
		return errors.New("no secret list path configured")
	}
	if paths == nil {
		paths = []string{}
	}
	data, err := json.MarshalIndent(map[string]any{"paths": paths}, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ---------------------------------------------------------------------------
// 快照生命周期（启动加载 / 热重载 / 轮询 / SIGHUP）
// ---------------------------------------------------------------------------

// configureSecrets 是启动入口。返回错误表示主进程必须拒绝启动（fail closed，
// 只会由 pinned 的显式文件触发）。
func configureSecrets(cliSpecs []string, listPath string, reloadEvery time.Duration) error {
	pinned := make([]string, 0, len(cliSpecs))
	for _, s := range cliSpecs {
		if t := strings.TrimSpace(s); t != "" {
			pinned = append(pinned, t)
		}
	}

	secretState.mu.Lock()
	secretState.pinned = pinned
	secretState.listPath = listPath
	listed, err := readSecretList(listPath)
	if err != nil {
		secretState.mu.Unlock()
		return err
	}
	secretState.fromList = listed
	sources, err := expandSources(pinned, listed)
	if err != nil {
		secretState.mu.Unlock()
		return err
	}
	secretState.mu.Unlock()

	if len(sources) == 0 {
		log.Printf("secret-file: no paths yet (no -secret-file, empty %s) — add one from the admin UI", listPath)
		// 列表为空也要起 watcher：之后通过界面/接口加进来的路径同样要享受热重载。
		if reloadEvery > 0 && listPath != "" {
			go watchSecrets(reloadEvery)
		}
		go handleSecretSignals()
		return nil
	}

	set, err := loadSecretSources(sources)
	if err != nil {
		return err
	}
	secretState.current.Store(set)
	logSecretSummary("secret-file", set)
	if set.valueCount() == 0 {
		log.Printf("secret-file: WARNING known-value masking is INACTIVE (0 values collected)")
	}

	if reloadEvery > 0 {
		go watchSecrets(reloadEvery)
	}
	go handleSecretSignals()
	return nil
}

// currentSecretSet 返回当前快照（可能为 nil = 功能未启用）。
func currentSecretSet() *secretSet {
	return secretState.current.Load()
}

// lockedSources 展开当前路径列表。调用方必须持有 secretState.mu。
func lockedSources() ([]secretFileSource, error) {
	return expandSources(secretState.pinned, secretState.fromList)
}

// reloadSecretsLocked 重载并原子替换快照，调用方必须持有 secretState.mu。
func reloadSecretsLocked(reason string) {
	set, err := lockedSources()
	old := currentSecretSet()
	if err != nil {
		log.Printf("secret-file: reload (%s) rejected: %v — keeping the previous %d values",
			reason, err, old.valueCount())
		return
	}
	next, err := loadSecretSources(set)
	if err != nil {
		log.Printf("secret-file: reload (%s) rejected: %v — keeping the previous %d values",
			reason, err, old.valueCount())
		return
	}
	secretState.current.Store(next)
	added, removed := secretKeyDiff(old, next)
	logSecretSummary("secret-file reloaded ("+reason+")", next)
	if len(added) > 0 || len(removed) > 0 {
		log.Printf("secret-file: keys +%v -%v", added, removed)
	}
	if audit.isEnabled() {
		audit.record(auditEvent{Kind: "secrets_reload", Action: "ok"})
	}
}

// reloadSecrets 是带锁的包装（watcher / SIGHUP / API 用）。
func reloadSecrets(reason string) {
	secretState.mu.Lock()
	defer secretState.mu.Unlock()
	reloadSecretsLocked(reason)
}

// secretKeyDiff 只比较键名，绝不比较或记录值。
func secretKeyDiff(old, next *secretSet) (added, removed []string) {
	oldKeys := map[string]bool{}
	if old != nil {
		for _, e := range old.entries {
			oldKeys[e.Key] = true
		}
	}
	nextKeys := map[string]bool{}
	for _, e := range next.entries {
		nextKeys[e.Key] = true
		if !oldKeys[e.Key] {
			added = append(added, e.Key)
		}
	}
	if old != nil {
		for _, e := range old.entries {
			if !nextKeys[e.Key] {
				removed = append(removed, e.Key)
			}
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

// watchSecrets 轮询文件指纹（文件列表 + mtime + size），变化才重载。
//
// 注意 WSL 的 /mnt/c（drvfs）与 FAT 的 mtime 粒度可达 2s，所以指纹里同时带上
// size 与展开后的文件列表；目录里新增项目、列表文件被手改都会因此被发现。
func watchSecrets(every time.Duration) {
	last := secretFingerprint()
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for range ticker.C {
		cur := secretFingerprint()
		if cur == last {
			continue
		}
		last = cur
		reloadSecrets("file change")
	}
}

func secretFingerprint() string {
	secretState.mu.Lock()
	listPath := secretState.listPath
	sources, err := lockedSources()
	secretState.mu.Unlock()

	var b strings.Builder
	if listPath != "" {
		if st, err := os.Stat(listPath); err == nil {
			fmt.Fprintf(&b, "list:%s|%d|%d;", listPath, st.ModTime().UnixNano(), st.Size())
		} else {
			fmt.Fprintf(&b, "list:%s|missing;", listPath)
		}
	}
	if err != nil {
		// 目录/文件暂时不可用也是一种"变化"，修好后指纹再次变化即可触发重载。
		return b.String() + "err:" + err.Error()
	}
	for _, src := range sources {
		st, err := os.Stat(src.path)
		if err != nil {
			fmt.Fprintf(&b, "%s|missing;", src.path)
			continue
		}
		fmt.Fprintf(&b, "%s|%d|%d;", src.path, st.ModTime().UnixNano(), st.Size())
	}
	return b.String()
}

// handleSecretSignals 让 `kill -HUP <pid>` 立即重载。
//
// 必须注册 handler：SIGHUP 的默认行为是**终止进程**，没注册时敲一次等于杀掉网关。
// Windows 上 SIGHUP 不会送达，轮询与 /api/secrets/reload 仍然可用。
func handleSecretSignals() {
	ch := make(chan os.Signal, 1) // buffer=1：连敲两次不会丢，也不会堆积
	signal.Notify(ch, syscall.SIGHUP)
	for range ch {
		reloadSecrets("SIGHUP")
	}
}

// logSecretSummary 打印快照概览。只出现路径与键名，**永不出现值**。
func logSecretSummary(prefix string, set *secretSet) {
	total := set.valueCount()
	log.Printf("%s: %d values from %d files (loaded %s)",
		prefix, total, len(set.reports), set.loadedAt.Format("15:04:05"))
	for _, r := range set.reports {
		tag := r.Mode
		if r.Pinned {
			tag += "+pin"
		}
		switch {
		case r.Skipped != "":
			log.Printf("  [%s] %-40s SKIPPED  %s", tag, r.Path, r.Skipped)
		default:
			log.Printf("  [%s] %-40s %d values  %s", tag, r.Path, r.Collected,
				strings.Join(r.Keys, ", "))
		}
	}
}

// ---------------------------------------------------------------------------
// 路径列表的界面操作（add / remove）
// ---------------------------------------------------------------------------

// validateSecretPath 校验一个待添加的路径确实能产出值，避免把坏路径写进列表后
// 每次重载都刷警告。
func validateSecretPath(spec string) error {
	sources, err := expandOne(spec, false)
	if err != nil {
		return err
	}
	var found int
	var reasons []string
	for _, src := range sources {
		if !pathExists(src.path) {
			continue
		}
		entries, _, skipped, err := parseSecretFile(src.path)
		if skipped == "" && err != nil {
			skipped = err.Error()
		}
		if skipped != "" {
			reasons = append(reasons, fmt.Sprintf("%s: %s", src.path, skipped))
			continue
		}
		found += len(entries)
	}
	if found == 0 {
		if len(reasons) == 0 {
			return fmt.Errorf("%s: no .env with a ###secret section found", spec)
		}
		return fmt.Errorf("%s: %s", spec, strings.Join(reasons, "; "))
	}
	return nil
}

// addSecretPath 把一个路径加进可编辑列表并立即重载。
func addSecretPath(spec string) error {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return errors.New("path is required")
	}
	if err := validateSecretPath(spec); err != nil {
		return err
	}

	secretState.mu.Lock()
	defer secretState.mu.Unlock()
	for _, p := range secretState.fromList {
		if p == spec {
			reloadSecretsLocked("api add (already listed)")
			return nil
		}
	}
	secretState.fromList = append(secretState.fromList, spec)
	if err := writeSecretList(secretState.listPath, secretState.fromList); err != nil {
		secretState.fromList = secretState.fromList[:len(secretState.fromList)-1]
		return err
	}
	reloadSecretsLocked("api add")
	return nil
}

// removeSecretPath 从可编辑列表里删掉一个路径并立即重载。
// pinned（命令行提供）的路径不可删除 —— 删了下次开机又回来，只会让人困惑。
func removeSecretPath(spec string) error {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return errors.New("path is required")
	}

	secretState.mu.Lock()
	defer secretState.mu.Unlock()

	for _, p := range secretState.pinned {
		if p == spec || samePath(p, spec) {
			return fmt.Errorf("%s comes from -secret-file and cannot be removed here", spec)
		}
	}
	kept := make([]string, 0, len(secretState.fromList))
	removed := false
	for _, p := range secretState.fromList {
		if p == spec {
			removed = true
			continue
		}
		kept = append(kept, p)
	}
	if !removed {
		return fmt.Errorf("%s is not in %s", spec, secretState.listPath)
	}
	secretState.fromList = kept
	if err := writeSecretList(secretState.listPath, secretState.fromList); err != nil {
		return err
	}
	reloadSecretsLocked("api remove")
	return nil
}

// samePath 比较两个路径是否指向同一处（相对/绝对的差别）。
func samePath(a, b string) bool {
	aa, err1 := filepath.Abs(a)
	bb, err2 := filepath.Abs(b)
	return err1 == nil && err2 == nil && aa == bb
}

// ---------------------------------------------------------------------------
// 规则与检测器接线
// ---------------------------------------------------------------------------

// secretRule 返回内置的虚拟规则；快照为空时返回 nil（= 不参与匹配）。
//
// 用规则而不是硬编码在 protectRequest 里，是为了让 scopes/fields/action 复用同一套
// 语义：它就是一条普通的 mask 规则，只是 Pattern/Detector 由网关提供。
func secretRule() *Rule {
	set := currentSecretSet()
	if set == nil || set.re == nil {
		return nil
	}
	return &Rule{
		ID:          0,
		Name:        "secret-file",
		Description: "known secret values from .env (auto-generated)",
		Type:        RuleTypeDetector,
		Detector:    detectorKnownSecret,
		Enabled:     true,
		Action:      ActionMask,
		Replacement: SecretRedaction,
		Scopes:      []string{},
		Fields:      []string{},
	}
}

// activeRules 是热路径使用的规则列表：虚拟规则排在最前面（先脱敏已知密钥，
// 再去跑用户规则，避免用户规则把原值改写成别的东西后我们认不出来）。
func activeRules() []Rule {
	base := store.EnabledRules()
	if r := secretRule(); r != nil {
		return append([]Rule{*r}, base...)
	}
	return base
}

// detectKnownSecret 是内置检测器：命中当前快照里的任一已知值。
func detectKnownSecret(s string, _ detectorOptions) []span {
	set := currentSecretSet()
	if set == nil || set.re == nil || s == "" {
		return nil
	}
	return findAll(set.re, s)
}

// secretStatus 是 /api/secrets 的返回体：路径、键名、条数、加载时间。
// 绝不包含值。
type secretStatus struct {
	Enabled  bool               `json:"enabled"`
	LoadedAt string             `json:"loadedAt,omitempty"`
	Values   int                `json:"values"`
	ListPath string             `json:"listPath,omitempty"`
	Pinned   []string           `json:"pinned"`
	List     []string           `json:"list"`
	Files    []secretFileReport `json:"files"`
}

func currentSecretStatus() secretStatus {
	set := currentSecretSet()

	secretState.mu.Lock()
	pinned := append([]string{}, secretState.pinned...)
	listed := append([]string{}, secretState.fromList...)
	listPath := secretState.listPath
	secretState.mu.Unlock()

	st := secretStatus{
		Enabled:  set != nil,
		Values:   set.valueCount(),
		ListPath: listPath,
		Pinned:   pinned,
		List:     listed,
		Files:    []secretFileReport{},
	}
	if set != nil {
		st.LoadedAt = set.loadedAt.Format(time.RFC3339)
		st.Files = set.reports
	}
	return st
}
