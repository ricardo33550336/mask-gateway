package main

// 内置检测器（detector）库。
//
// 手写正则最大的问题是"只能防住你想到的那一种格式"。内置检测器把常见的
// 敏感数据格式固化下来，并尽量用**校验位 / 熵**做二次确认，减少误报：
//
//   - 身份证：GB 11643 加权校验
//   - 银行卡：Luhn 校验
//   - JWT：header 必须能 base64url 解码成带 alg 的 JSON
//   - 高熵兜底：未知格式的密钥也能被熵阈值抓住
//
// 这里用标准库 regexp（不是 regexp2）：检测器不需要 lookahead。所有 pattern
// 在包初始化时编译一次，热路径零编译开销。

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"regexp"
	"sort"
	"strings"
)

// span 是字符串内的一个 [start,end) 字节区间，最终被替换为 rule.Replacement。
type span struct{ start, end int }

// detectorOptions 是检测器的可调参数（目前只有高熵检测器用得上）。
type detectorOptions struct {
	threshold float64 // 熵阈值，默认 4.0
	minLength int     // 候选串最小长度，默认 20
}

const (
	defaultEntropyThreshold = 4.0
	defaultEntropyMinLength = 20
	// 超长连续串（通常是整段 base64 文件/图片）跳过：替换它只会把请求打坏。
	maxEntropyCandidateLen = 4096
)

type detectorFn func(s string, opt detectorOptions) []span

// detectorInfo 是给管理界面用的元数据（无需前端硬编码）。
type detectorInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// Tunable 表示该检测器支持 threshold / minLength 参数。
	Tunable bool `json:"tunable"`
}

// detectorRegistry 是 name → 实现 的注册表。
var detectorRegistry = map[string]detectorFn{
	"api_key":           detectAPIKey,
	"bank_card":         detectBankCard,
	"cn_id_card":        detectCNIDCard,
	"cn_phone":          detectCNPhone,
	"connection_string": detectConnectionString,
	"email":             detectEmail,
	"high_entropy":      detectHighEntropy,
	"ipv4":              detectIPv4,
	"jwt":               detectJWT,
	"private_key":       detectPrivateKey,
}

// detectors 是注册表的有序视图（按名字排序，界面稳定）。
var detectors = func() []detectorInfo {
	out := make([]detectorInfo, 0, len(detectorRegistry))
	for name := range detectorRegistry {
		out = append(out, detectorInfo{Name: name, Description: detectorDescriptions[name], Tunable: name == "high_entropy"})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}()

var detectorDescriptions = map[string]string{
	"api_key":           "常见平台 API Key（sk- / AWS / GitHub / GitLab / Slack / Google / npm / Stripe 等前缀）",
	"bank_card":         "银行卡号（13-19 位，Luhn 校验通过才命中）",
	"cn_id_card":        "中国居民身份证号（18 位，GB 11643 校验位验证）",
	"cn_phone":          "中国大陆手机号（11 位，号段校验）",
	"connection_string": "带密码的连接串（postgres://user:pass@host 等）",
	"email":             "邮箱地址",
	"high_entropy":      "高熵随机串兜底：未知格式的密钥/令牌也能命中（可调阈值与最小长度）",
	"ipv4":              "IPv4 地址（内网/公网地址会暴露拓扑）",
	"jwt":               "JWT（三段 base64url，header 含 alg）",
	"private_key":       "PEM 私钥块（-----BEGIN ... PRIVATE KEY-----）",
}

func validDetector(name string) bool {
	_, ok := detectorRegistry[name]
	return ok
}

// detectIn 用单条 detector 规则扫描 s，返回合并后的待替换区间。
func detectIn(r Rule, s string) []span {
	fn := detectorRegistry[r.Detector]
	if fn == nil || s == "" {
		return nil
	}
	opt := detectorOptions{threshold: r.Threshold, minLength: r.MinLength}
	if opt.threshold <= 0 {
		opt.threshold = defaultEntropyThreshold
	}
	if opt.minLength <= 0 {
		opt.minLength = defaultEntropyMinLength
	}
	return mergeSpans(fn(s, opt))
}

// mergeSpans 去掉重叠区间（多个 pattern 可能命中同一段）。
func mergeSpans(spans []span) []span {
	if len(spans) < 2 {
		return spans
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start == spans[j].start {
			return spans[i].end > spans[j].end
		}
		return spans[i].start < spans[j].start
	})
	out := spans[:1]
	for _, sp := range spans[1:] {
		last := &out[len(out)-1]
		if sp.start < last.end { // 重叠 → 合并
			if sp.end > last.end {
				last.end = sp.end
			}
			continue
		}
		out = append(out, sp)
	}
	return out
}

// applySpans 用 repl 替换所有区间（按字节偏移，从后往前不影响前面的偏移）。
func applySpans(s string, spans []span, repl string) string {
	if len(spans) == 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	prev := 0
	for _, sp := range spans {
		if sp.start < prev || sp.end > len(s) {
			continue
		}
		b.WriteString(s[prev:sp.start])
		b.WriteString(repl)
		prev = sp.end
	}
	b.WriteString(s[prev:])
	return b.String()
}

// ---------------------------------------------------------------------------
// 各检测器实现
// ---------------------------------------------------------------------------

func findAll(rx *regexp.Regexp, s string) []span {
	idx := rx.FindAllStringIndex(s, -1)
	out := make([]span, 0, len(idx))
	for _, m := range idx {
		out = append(out, span{m[0], m[1]})
	}
	return out
}

// --- 身份证 ---------------------------------------------------------------

var cnIDCardRe = regexp.MustCompile(`\b[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b`)

var cnIDWeights = [17]int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}

const cnIDCheckChars = "10X98765432"

func detectCNIDCard(s string, _ detectorOptions) []span {
	var out []span
	for _, m := range cnIDCardRe.FindAllStringIndex(s, -1) {
		if validCNID(s[m[0]:m[1]]) {
			out = append(out, span{m[0], m[1]})
		}
	}
	return out
}

// validCNID 校验 GB 11643-1999 的 ISO 7064 MOD 11-2 校验位。
func validCNID(id string) bool {
	if len(id) != 18 {
		return false
	}
	sum := 0
	for i := 0; i < 17; i++ {
		d := id[i] - '0'
		if d > 9 {
			return false
		}
		sum += int(d) * cnIDWeights[i]
	}
	want := cnIDCheckChars[sum%11]
	got := id[17]
	if got >= 'a' && got <= 'z' {
		got -= 'a' - 'A'
	}
	return want == got
}

// --- 银行卡 ---------------------------------------------------------------

var bankCardRe = regexp.MustCompile(`\b\d(?:[ -]?\d){12,18}\b`)

func detectBankCard(s string, _ detectorOptions) []span {
	var out []span
	for _, m := range bankCardRe.FindAllStringIndex(s, -1) {
		digits := digitsOnly(s[m[0]:m[1]])
		if len(digits) < 13 || len(digits) > 19 {
			continue
		}
		if allSameByte(digits) {
			continue
		}
		if luhnOK(digits) {
			out = append(out, span{m[0], m[1]})
		}
	}
	return out
}

func digitsOnly(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			b = append(b, s[i])
		}
	}
	return string(b)
}

func allSameByte(s string) bool {
	for i := 1; i < len(s); i++ {
		if s[i] != s[0] {
			return false
		}
	}
	return true
}

func luhnOK(digits string) bool {
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if d < 0 || d > 9 {
			return false
		}
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// --- 手机号 ---------------------------------------------------------------

var cnPhoneRe = regexp.MustCompile(`(?:^|[^\d])(1[3-9]\d{9})(?:[^\d]|$)`)

func detectCNPhone(s string, _ detectorOptions) []span {
	var out []span
	for _, m := range cnPhoneRe.FindAllStringSubmatchIndex(s, -1) {
		out = append(out, span{m[2], m[3]})
	}
	return out
}

// --- API Key --------------------------------------------------------------

// apiKeyPatterns 覆盖主流平台的密钥前缀。加新平台只需要在这里加一行。
var apiKeyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}\b`),                      // OpenAI（含 sk-proj- / sk-ant-）
	regexp.MustCompile(`\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b`),       // Stripe
	regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`),                  // AWS access key id
	regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{30,}\b`),                 // GitHub
	regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{22,}\b`),               // GitHub fine-grained PAT
	regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}\b`),                   // GitLab PAT
	regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9-]{10,}\b`),              // Slack
	regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`),                      // Google API key
	regexp.MustCompile(`\bya29\.[0-9A-Za-z_-]{20,}\b`),                   // Google OAuth token
	regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`),                        // npm
	regexp.MustCompile(`\bpypi-[A-Za-z0-9_-]{50,}\b`),                    // PyPI
	regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b`), // SendGrid
	regexp.MustCompile(`\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b`),         // Shopify
	regexp.MustCompile(`\bdo[pr]_v1_[a-f0-9]{64}\b`),                     // DigitalOcean
	regexp.MustCompile(`\bhf_[A-Za-z0-9]{34}\b`),                         // Hugging Face
	regexp.MustCompile(`\br8_[A-Za-z0-9]{36}\b`),                         // Replicate
	regexp.MustCompile(`\bpplx-[A-Za-z0-9]{40,}\b`),                      // Perplexity
	regexp.MustCompile(`\bkey-[0-9a-f]{32}\b`),                           // Mailgun
}

func detectAPIKey(s string, _ detectorOptions) []span {
	var out []span
	for _, rx := range apiKeyPatterns {
		out = append(out, findAll(rx, s)...)
	}
	return out
}

// --- JWT ------------------------------------------------------------------

var jwtRe = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)

func detectJWT(s string, _ detectorOptions) []span {
	var out []span
	for _, m := range jwtRe.FindAllStringIndex(s, -1) {
		tok := s[m[0]:m[1]]
		if validJWT(tok) {
			out = append(out, span{m[0], m[1]})
		}
	}
	return out
}

// validJWT 只认 header 能解码成 JSON 且含 alg 的三段式串，避免误伤 base64url 文本。
func validJWT(tok string) bool {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var hdr map[string]any
	if json.Unmarshal(raw, &hdr) != nil {
		return false
	}
	_, ok := hdr["alg"]
	return ok
}

// --- 私钥 -----------------------------------------------------------------

var privateKeyRe = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)

func detectPrivateKey(s string, _ detectorOptions) []span {
	return findAll(privateKeyRe, s)
}

// --- 邮箱 / IPv4 ----------------------------------------------------------

var emailRe = regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)

func detectEmail(s string, _ detectorOptions) []span { return findAll(emailRe, s) }

var ipv4Re = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b`)

func detectIPv4(s string, _ detectorOptions) []span { return findAll(ipv4Re, s) }

// --- 连接串 ---------------------------------------------------------------

var connectionStringRe = regexp.MustCompile(
	`\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqp|amqps|mssql|clickhouse|kafka)://[^\s:/@]{1,64}:[^\s@/]{1,128}@[^\s/]{1,255}`)

func detectConnectionString(s string, _ detectorOptions) []span {
	return findAll(connectionStringRe, s)
}

// --- 高熵兜底 -------------------------------------------------------------

// entropyCandidateRe 刻意用较小的下限（8），真正的长度门槛由 opt.minLength 控制，
// 这样不用为每个阈值重新编译正则。
var entropyCandidateRe = regexp.MustCompile(`[A-Za-z0-9+/=_-]{8,}`)

func detectHighEntropy(s string, opt detectorOptions) []span {
	var out []span
	for _, m := range entropyCandidateRe.FindAllStringIndex(s, -1) {
		cand := s[m[0]:m[1]]
		if len(cand) < opt.minLength || len(cand) > maxEntropyCandidateLen {
			continue
		}
		if !looksRandom(cand) {
			continue
		}
		if shannonEntropy(cand) >= opt.threshold {
			out = append(out, span{m[0], m[1]})
		}
	}
	return out
}

// looksRandom 用一组廉价前置条件过滤掉"高熵但其实不是密钥"的串：
//   - 必须同时含数字和字母
//   - 必须同时含大写和小写（纯小写十六进制 = git sha / md5，纯单词 = 英文）
//   - 不能全是同一个字符
func looksRandom(s string) bool {
	var hasDigit, hasLower, hasUpper bool
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			hasDigit = true
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		}
	}
	return hasDigit && hasLower && hasUpper && !allSameByte(s)
}

// shannonEntropy 计算字节级香农熵（bit/byte）。
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	h := 0.0
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}
