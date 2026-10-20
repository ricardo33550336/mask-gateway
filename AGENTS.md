# AGENTS.md — mask-gateway（脱敏转发网关）

> 本文件为 AI 代理 / 开发者提供项目导航与改动须知。核心设计原则：**极简、零依赖（除 regexp2）、纯转发**。

## 项目是什么

一个 OpenAI 兼容的**最小转发网关**，借鉴 [AxonHub](https://github.com/looplj/axonhub) 的提示保护（Prompt Protection）功能：

- **mask**：命中规则 → 把请求体中的敏感内容替换为 `replacement`，请求继续转发
- **reject**：命中规则 → 拦截请求，返回 400
- **两类规则**：`regex`（regexp2 手写正则）与 `detector`（内置检测器：校验位 / 熵验证）
- **已知密钥值**（`-secret-file` pinned / `-secret-list` 可编辑）：从 `.env` 的 `###secret` 段读**真实值**做精确脱敏，不靠形状猜测；路径可在管理界面增删；详见 `docs/SECRET-FILE.md`

去掉统计、会话、计费、追踪等一切复杂功能。请求（含 SSE 流式）原样透传到上游，响应方向不做检查。

## 技术栈与依赖

| 项 | 方案 |
|---|---|
| 语言 | Go（go 1.26，`go.mod` 中 `module github.com/ricardo33550336/mask-gateway`） |
| HTTP | 纯标准库 `net/http`（无 Gin/框架） |
| 存储 | 单个 JSON 文件（默认 `rules.json`），无数据库 |
| 正则 | `github.com/dlclark/regexp2/v2`（**唯一第三方依赖**，支持 lookahead/lookbehind）；检测器用标准库 `regexp` |
| 前端 | 原生 JS + CSS，零构建，`//go:embed static` 打包进二进制 |
| 仓库 | `github.com/ricardo33550336/mask-gateway`（默认分支 `main`） |
| 许可 | MIT（见 `LICENSE`） |

## 模块布局

| 文件 | 职责 |
|---|---|
| `main.go` | 入口、`route` 分发（管理页 / 管理 API / 转发）、转发逻辑 `forward`、`protectBody`、`developer→system` 归一化、静态资源 `noCache`、HTTP 辅助函数 |
| `protect.go` | 规则模型 `Rule`/`Action`、JSON 全量扫描（`protectDocument` / `walker`）、正则编译缓存、`protectString` / `applyRuleToString`、校验 `validateRule` |
| `detect.go` | 内置检测器库（`detectorRegistry`）、校验位（GB 11643 / Luhn）、熵检测、`span` 合并与替换 |
| `secretfile.go` | `-secret-file`：`.env` 解析（`###secret` 段）、不可变快照 + `atomic.Pointer`、轮询 / SIGHUP / API 热重载、内置虚拟规则与 `known_secret` 检测器、`/api/secrets` 数据结构 |
| `response.go` | 响应侧守卫：有界窥探 `peekUpstream`、B1 回显检测 `leakMatcher`、B2 告警扫描 `warnScanner`、F 模型比对、E 事件环形缓冲 `auditLog` |
| `store.go` | `Store`：规则 CRUD + JSON 文件持久化（原子写：临时文件 + rename） |
| `static/` | 管理界面（`index.html` + `app.js` + `style.css`，原生 JS，调用 `/api/...`）；改动后必须**重新 `go build`** 才生效（`embed` 编进二进制） |
| `main_test.go` / `response_test.go` / `hardening_test.go` / `secretfile_test.go` | 全部测试（无外部依赖，`go test` 直接跑） |
| `rules.json` | 规则存储文件（被 `.gitignore` 忽略，启动时自动创建） |

## 核心数据模型（`protect.go`）

```go
type Rule struct {
    ID          int      `json:"id"`
    Name        string   `json:"name"`            // 必填
    Description string   `json:"description,omitempty"`
    Type        string   `json:"type,omitempty"`  // "" / "regex" | "detector"
    Pattern     string   `json:"pattern,omitempty"`   // regex 规则必填
    Detector    string   `json:"detector,omitempty"`  // detector 规则必填
    Threshold   float64  `json:"threshold,omitempty"` // high_entropy 熵阈值，默认 4.0
    MinLength   int      `json:"minLength,omitempty"` // high_entropy 最小长度，默认 20
    Enabled     bool     `json:"enabled"`
    Action      Action   `json:"action"`          // "mask" | "reject"
    Replacement string   `json:"replacement,omitempty"` // mask 时必填
    Scopes      []string `json:"scopes"`          // 留空 = 应用到所有角色
    Fields      []string `json:"fields"`          // 留空 = 扫描所有位置
}
```

- `Scopes` 合法值：`system` / `developer` / `user` / `assistant` / `tool`（`validScopes`）
- `Fields` 合法值：`content` / `tool_calls` / `tools` / `top`（`validFields`）
- 两个切片都不加 `omitempty`：空数组也序列化为 `[]`，避免前端拿到 `undefined`
- 老规则没有 `type` 字段 → 视为 `regex`；有 `detector` 无 `type` 也视为 detector（`effectiveType()`）

## 请求处理链路（热路径）

```
forward (main.go)
  ├─ 读请求体（上限 128MB）
  ├─ protectRequest(body) → protected, meta{model, stream, needles}
  │    ├─ 非 JSON → 原样返回（不修改）
  │    ├─ 规则按 ID 升序处理（activeRules() 每次请求实时取快照：
  │    │   `-secret-file` 的虚拟规则排在最前面，然后是 store.EnabledRules()）
  │    ├─ protectDocument 依次扫描 messages / tools+functions / 顶层字段
  │    ├─ mask 规则依次叠加；第一个 reject 命中立即拦截
  │    ├─ hitSink 旁路记录"被替换掉的原文" → meta.needles（仅供响应守卫用）
  │    ├─ 规则匹配按客户端【原始】角色（归一化之后才转发）
  │    └─ developer→system 归一化（仅当 normalizeDeveloperToSystem 开启）
  ├─ 被拒 → 返回 400 OpenAI 风格错误
  ├─ 上游请求
  │    ├─ guard 关闭 → streamPassthrough（= 旧实现：不窥探/不缓冲/不检测）
  │    └─ guard 开启 → upstreamStream 独占 body（单 goroutine + channel 交接）
  │         └─ peekUpstream：SSE 只取 1 个 chunk，其余最多 peekBytes，
  │            总等待时间受 peekBudget（200ms）限制
  ├─ guardPeek：F 模型比对 / B2 检测器告警 / B1 回显检测（命中 → 502，此时未写 header）
  └─ copyHeaders + WriteHeader → 32KB 粒度写 + Flush（未命中时与旧实现逐字节一致）
       └─ 后续 chunk：B1 命中 → panic(ErrAbortHandler) 断流；B2 命中 → 仅告警
```

**响应侧守卫的三条检查**（`response.go`）：

| 代号 | 检测什么 | 处置 |
|---|---|---|
| B1 | 本次请求被 mask 的**原文**在响应里出现（精确匹配）；发送端扣留 `maxLen-1` 字节，前缀也不外泄 | 未写出→502；已写出→断流（`http.ErrAbortHandler`） |
| B2 | 响应字节里的检测器命中（只跑 detector 规则，有字节预算） | 仅告警（stderr + `-audit` 事件） |
| F | 响应 `model` 与请求 `model` 不一致（只剥 `-YYYY-MM-DD`/`-YYYYMMDD`/`-YYYY` 快照后缀后**精确比较**，不做前缀匹配） | 仅告警 |

**扫描位置**（`Fields` 留空 = 全部）：

| loc | 覆盖 |
|---|---|
| `content` | `messages[].content`：纯字符串，或数组里 `type=="text"` 的 part |
| `tool_calls` | `messages[].tool_calls`、`reasoning_content`、`reasoning`（整棵子树递归） |
| `tools` | `tools[].function` / `functions[]` 的 `description`、`parameters`、`input_schema`（**不碰 `name`**） |
| `top` | 顶层 `prompt` / `input` / `instructions` / `instruction` / `system` / `user` / `metadata` |

刻意不动：`model` 等控制字段、`image_url` / `input_image` / `file` 等非 text part（替换 base64 会打坏请求）。

**角色作用域规则**：`Scopes` 非空的规则只会作用于**带 role 的位置**（消息正文 / tool_calls）；
`tools` 与顶层字段没有 role，只受 `Fields` 控制。这样 user 作用域的 reject 规则不会因为工具描述里的词误拦。

**关键保证**：
- 脱敏失败/非 JSON 永不破坏转发 → 回退为原始 body
- 无命中时**字节级不变**（用 `changed` 标志跟踪，没改就返回原 body，见 `TestMaskNoMatchKeepsOriginalBytes`）
- 数值走 `json.Number`，大整数（`seed`）不丢精度（`TestNumbersRoundTripAfterMask`）
- 消息体兼容两种 `content` 格式：纯字符串 / `[{type:"text",...}]` 数组（只改 `text` part，`image_url` 等其它字段不动）

## 全局状态与并发

`main.go` 顶层 package 变量（**测试会直接覆写**，改动时注意）：

```go
store        *Store   // 规则存储
upstreamBase string   // 上游 base URL（-upstream 或 UPSTREAM 环境变量）
client       *http.Client
normalizeDeveloperToSystem bool  // developer→system 开关
```

- `Store` 内部 `sync.RWMutex` 保护，`EnabledRules()` 返回快照，热路径无锁竞争
- 正则编译缓存 `regexCache`（`sync.RWMutex` 保护，含编译失败缓存，失败也缓存）
- 检测器的正则全部在包初始化时编译一次，`detectorRegistry` 只读，热路径零分配查找

## 管理 API

```
GET    /api/rules                # 列表
POST   /api/rules                # 创建
PUT    /api/rules/{id}           # 更新（body 中 id 被路径 id 覆盖）
DELETE /api/rules/{id}           # 删除
POST   /api/rules/{id}/status    # 启停 {"enabled": true|false}
GET    /api/detectors            # 内置检测器清单（含 tunable 标记）
GET    /api/events?limit=50      # 响应侧守卫事件（未开 -audit 时返回 enabled=false）
DELETE /api/events               # 清空事件
GET    /api/secrets              # 已加载的 .env（路径/键名/条数/加载时间，绝不含值；需 admin token）
POST   /api/secrets/reload       # 立即重载（需 admin token；Windows 无 SIGHUP 时用它）
POST   /api/secrets/files        # 加入可编辑路径列表（先验证再落盘；需 admin token）
DELETE /api/secrets/files?path=  # 从列表移除（pinned 条目 400；需 admin token）
POST   /api/preview              # 试跑规则（正则或检测器，不落盘）
```

错误格式统一 `{"error": "..."}`（管理 API）或 OpenAI 风格 `{"error":{"message","type"}}`（转发路径）。

## 常用命令

```bash
go build -o mask-gateway .           # 构建（单二进制，含前端）
go test ./...                        # 跑全部测试（测试直接操作全局 store，无并行问题）
go vet ./...
UPSTREAM=https://api.openai.com ./mask-gateway -addr :8080   # 启动
AUDIT=1 ./mask-gateway -upstream ... -audit                  # 开启诊断事件环形缓冲
```

提交与发布（默认分支 `main`，仓库 `github.com/ricardo33550336/mask-gateway`）：

```bash
git add -A && git commit -m "feat: ..." && git push   # 只推代码；二进制与 rules.json 已被忽略
gh release create v0.x.0 --generate-notes             # 打 tag 并生成 release notes
```

提交前跑一遍 `gofmt -l . && go vet ./... && go test ./...`（目前没有 CI，靠本地把关）。

启动参数（除原有 `-addr` / `-rules` / `-upstream` / `-developer-as-system`）：

| 参数 | 默认 | 说明 |
|---|---|---|
| `-response-guard` / `RESPONSE_GUARD=0` | 开 | 关闭后走 `streamPassthrough`（真正的旧路径：不窥探、不缓冲、不检测） |
| `-peek-bytes` | 1MB | 非流式响应预先缓冲上限；SSE 恒为 1 次 read |
| `-leak-min-len` | 8 | B1 needle 最短长度 |
| `-warn-scan-bytes` | 256KB | B2 每条响应的扫描预算（0 = 关闭） |
| `-audit` / `AUDIT=1` | 关 | 事件环形缓冲（不存内容） |
| `-admin-token` / `ADMIN_TOKEN` | 空 | 诊断接口 Bearer token；空 = `/api/events` `/api/secrets` 403（fail closed） |
| `-secret-file` / `SECRET_FILE` | 空 | **pinned** `.env` 路径（可重复）。显式文件坏 → 拒绝启动；目录展开为 `<dir>/.env` 与 `<dir>/*/.env`（只一层，问题只跳过） |
| `-secret-list` / `SECRET_LIST` | `secret-files.json` | **可编辑**路径列表（界面上增删；条目坏掉只 WARN，不阻止启动） |
| `-secret-reload` | `5s` | `-secret-file` 轮询间隔；`0` 关闭（SIGHUP / API 仍可用） |
| `-audit-size` / `-audit-hint-chars` | 200 / 0 | 缓冲条数 / 事件里保留的命中前缀字节 |

## 改动须知（容易踩的坑）

1. **转发必须字节安全**：`forward` 依赖 `DisableCompression: true`（避免 Go 自动解压破坏 SSE 透传）和 hop-by-hop 头过滤（`isHopByHop`）。改转发路径时保持这两点。
2. **响应未命中必须与旧实现一致**：状态码 / header / 字节 / 32KB 写-冲刷粒度。
   `TestForwardNoHitPassthrough*` / `TestForwardLargeBodyStreamsIdentically` 锁定。
   改 `forward` 时注意：窥探前缀在 `guardPeek` 扫过一遍，所以 `writeSlice(prefixSlice, false)` 不重复扫。
3. **不要为检测而缓冲整个响应**：SSE 只允许 1 个 chunk；非流式上限 `peekBytes`，且整体等待受
   `peekBudget`（默认 200ms，`main.go` 包变量，刻意不做成命令行开关）限制——`peekBytes` 是上限，
   不是"要凑满"的目标。
4. **窥探为什么用 goroutine + channel**：同步 `Read` 无法被定时器打断；对连接 `SetReadDeadline`
   又会因 `persistConn.readLoop → pc.closeLocked` 废弃整条连接（后续字节取不回来）。所以由
   `upstreamStream` 单 goroutine 独占 body，`nextChunk(wait)` 到期只"停止等待"，不丢已读字节。
   改这里时注意两个坑：(a) `Read` 允许 `(n>0, io.EOF)` 同时返回，**必须先处理 err 再判断
   "够了"**，否则会丢掉 EOF 让 drain 永久阻塞；(b) `run()` 退出时 `close(out)` 是安全网。
5. **已知边界**：上游首字节晚于 `peekBudget` 时响应头已提交，B1 只能断流，无法再返回 502
   （`TestLeakAfterPeekBudgetAbortsInsteadOfBlocking` 锁定）。
4. **B1 只做精确匹配**：needle 是"请求里被替换掉的原文"（`hitSink`），不要改成模式匹配，否则误报会直接阻断用户请求。
5. **覆盖缺口必须暴露**：`hitSink` 丢弃命中值（>512B 或超过 256 条）时计数，
   `requestMeta.coverageGap` → `X-Mask-Guard: coverage-incomplete` + `coverage_gap` 事件。
   丢弃是**静默变不完整**的原始来源，不要去掉计数。
6. **B2 预算与重叠**：`warnScanner` 的窗口是 `tail(4096B) + chunk`，窗口长度计入 `budget`；
   耗尽后 `exhaustedScan()` 为真 → `scan_incomplete` 事件 + `X-Mask-Guard: scan-partial`（仅提交前可知）。
7. **日志限流**：`recordEvent` 中只有 `kind=="leak"` 不限流；其余按 key 每分钟 1 条并输出
   `suppressed=N`。审计环形缓冲不受限流影响（这是"事件不丢"的保证）。
8. **诊断接口鉴权**：`requireAdmin` 唯一入口，空 token = 403（fail closed），比较用
   `subtle.ConstantTimeCompare`。新增诊断类接口必须走它。
9. **holdback 不变量**：`leakGuardWriter` 每次都在 `pending + chunk` 窗口上检查后才 `release(window[:len-keep])`。
   任何 needle 的前缀都必须留在 `pending` 里，直到包含它的窗口被检查。`finish()`（EOF **和**读错误都要调用）
   会再检测一次再释放；漏调 `finish()` 会丢尾部字节，跳过检测则等于绕过 B1。
   无 needle 时 `push` 走零拷贝快路径（直接写 chunk），这条路必须保持。
5. **B2/F 永远只告警**：任何"让 B2 阻断"的改动都要先想清楚误报代价。
6. **`hitSink` 是纯观测**：`protector.hits` 只在请求入口按 `guardEnabled` 创建（nil = 不采集），
   绝不能影响匹配/替换结果，否则"无命中字节不变"会破。
7. **正则缓存含失败缓存**：`compilePattern` 对非法正则也缓存 error，避免热路径重复编译。
8. **无命中字节级不变**是明确的测试约束（`TestMaskNoMatchKeepsOriginalBytes` / `TestDetectorNoMatchKeepsOriginalBytes`），
   靠 `changed` 标志实现：任何环节都没改动就返回原始 body。改动扫描逻辑时保持这点。
9. **新增检测器**：在 `detect.go` 的 `detectorRegistry` 加一个 `detectorFn`，并在 `detectorDescriptions` 加说明。
   能用校验位（checksum）就别只写正则；能用标准库 `regexp` 就别用 regexp2。
10. **归一化顺序**：mask/reject 用原始角色匹配（`developer` 作用域仍命中），归一化只在转发前。测试 `TestDeveloperToSystemPlusMask` 锁定此行为。
11. **规则实时生效**：每次请求从 store 取启用规则快照，改规则不用重启。
12. **没有鉴权**：管理界面与转发接口均无认证，生产需前置网关（README 已注明）。
13. **`ruleItem` 的 id 解析**：先剥 `/status` 后缀判断启停接口，再按普通 id 处理，加新子路由时注意顺序。
14. **新增测试**：用 `testStore(t, rules)` 辅助函数构造 store 并赋值给全局 `store`；涉及 `normalizeDeveloperToSystem` 的测试用 `defer` 恢复。
    响应侧测试用 `setupGuard()` + `startGateway()`（起两个 httptest server，自动恢复全局 `guardEnabled` / `peekBytes` / `upstreamBase` / `client` / audit）。
    测试辅助：`detectorRule()` 造检测器规则、`matchDetector()` 只跑检测、`messageContent()` 取消息正文。
    直接调用 `route` + `httptest.NewRecorder()` 即可测静态资源（见 `TestStaticAssetsNoCache`）。
15. **静态资源必须 `Cache-Control: no-cache`**：`embed.FS` 里的文件 modtime 为零，`http.FileServer`
    不会发 `Last-Modified` / `ETag`，浏览器只能启发式缓存 —— 换了二进制却继续跑旧 `app.js`。
    `/`（`serveUI`）和 `/static/` 两条分支都要经过 `noCache(w)`，`TestStaticAssetsNoCache` 锁定。
16. **`static/` 改动必须重新编译**：`//go:embed static` 在构建期快照，改 JS/CSS 不重启进程 = 页面没变。
    排查"前端改了却没生效"时，先 `curl -s localhost:PORT/static/app.js | head` 确认服务端字节数。
17. **前端异步数据不要抢跑**：`detectors` 来自 `GET /api/detectors`，`fillDetectorOptions()` 必须在
    `load()` 拿到数据之后调用（启动时 `detectors` 还是 `[]`，只调一次下拉框就永远是空的）。
    新增依赖接口数据的表单控件照此办理；`TestAppJSRefillsDetectorOptions` 锁定调用次数与顺序。
18. **`-secret-file` 的标记只认独立整行**：`secretMarker` 用"剥掉行首全部 `#` 再比较"，
    `###secret` / `#### secret` / `#SECRET` 都算，但 `# secret 的说明` / `###secret: x` 不算。
    改这个函数等于改用户的 `.env` 契约，必须同步改 `docs/SECRET-FILE.md` 与 `TestSecretMarkerVariants`。
19. **绝不剥行内 `#` 注释**：真实密钥里就有 `#`（如 `P@vS4^H…Q#`），剥掉 = 值静默变短 =
    永远匹配不上（比报错更坏）。只处理整行注释、成对引号、`export` 前缀、CRLF/BOM。
20. **三条失败语义别混**：① `-secret-file` 的**显式文件**坏 → `configureSecrets` 返回错误，
    主进程 `log.Fatalf`（fail closed）；② `-secret-list` 的条目坏 → 只 `SKIPPED` + 告警照常启动
    （网关开机只启一次，一条陈旧路径不能让整机起不来）；③ 运行中 `reloadSecretsLocked` 失败 →
    **保留旧快照**（编辑器保存时的半截文件不能掐断所有 agent）。三条都有测试锁定。
21. **SIGHUP 必须注册 handler**：未注册时默认行为是**终止进程**，敲一次 `kill -HUP` 等于杀掉
    网关（`handleSecretSignals` + `TestSecretSIGHUPReloads`）。Windows 上 SIGHUP 不存在，
    只能靠轮询与 `POST /api/secrets/reload`。
22. **已知值按"值"去重、日志只到键名**：同一键在不同项目取值不同时两个值都要保护；
    启动日志、`/api/secrets`、audit 事件一律只出现路径与键名（`secretKeyDiff` 也只比较键名）。
    任何把值写进日志/响应的改动都是不可接受的回归。
23. **虚拟规则由 `activeRules()` 注入并排在最前**：`protectRequest` 不再直接调 `store.EnabledRules()`。
    已知值必须先被脱敏，否则用户的 mask 规则会先把原值改写成别的东西，导致 `known_secret` 认不出来。

## 测试与代码索引
- 本仓库有 codegraph 索引（`.codegraph/`）。改动代码后先 `codegraph sync` 再查询：
  - `codegraph node <symbol>` — 查看符号源码与调用链
  - `codegraph impact <symbol>` — 改动影响面
  - `codegraph affected main.go protect.go -q` — 改动后需要跑的测试
- 代码量小（7 个 Go 文件约 2900 行），绝大多数场景直接 `rg`/`read` 即可。

## 性能基线

完整数据、复现命令与容量规划公式见 [`docs/PERF-BASELINE.md`](docs/PERF-BASELINE.md)（不是本节）。
改热路径（`response.go` / `forward`）后按那份文档的「回归对比清单」跑一遍。

## 参考

- 日常运维手册（启动/加规则/看事件/故障速查）：`USAGE.md`。
- 已知密钥值（`.env` 已知值脱敏）的契约与运维：`docs/SECRET-FILE.md`。
- 未知边界（**改代码前先读**，其中几条是有意为之且有测试锁定）：`docs/KNOWN-LIMITS.md`。
- 未实现项与"为什么没做"：`docs/BACKLOG.md`。
- 性能基线与容量规划：`docs/PERF-BASELINE.md`。
- 设计动机、FAQ 详见根目录 `README.md`（中文）。
- 许可与提交规范：`LICENSE`（MIT）；仓库 https://github.com/ricardo33550336/mask-gateway （`main`）。
- 脱敏逻辑移植自 AxonHub：`protect.go` 注释中标注了对应原函数名（`ApplyPromptProtectionRules`、`ValidateSettings`、`promptProtectionRuleAppliesToRole` 等）。
