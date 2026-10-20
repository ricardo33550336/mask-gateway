# mask-gateway（脱敏转发网关）

一个**极简**的 OpenAI 兼容转发网关，借鉴了 [AxonHub](https://github.com/looplj/axonhub) 的
**提示保护（Prompt Protection / 脱敏）** 功能：

- **mask**：转发前用替换文本把命中的敏感内容替换掉（脱敏），请求继续转发
- **reject**：命中即拦截，直接返回 400
- **两种规则**：自己写的正则，或内置检测器（带校验位 / 熵验证，见下文）
- **全量扫描**：`messages` 正文、`tool_calls`、`reasoning_content`、`tools` 函数定义、顶层 `input`/`metadata` 都扫
- **已知密钥值**：`-secret-file .env` 直接按 `.env` 里 `###secret` 段的**真实值**做精确脱敏 ——
  不需要描述密钥长什么样（见 [docs/SECRET-FILE.md](docs/SECRET-FILE.md)）

去掉了一切复杂功能：**无统计、无会话保存、无用量计费、无追踪**。接口只做转发，
响应（含 SSE 流式）原样透传。

## 设计目标

| 维度 | 方案 |
|------|------|
| 后端框架 | 纯 Go 标准库 `net/http`，无 Gin/Ent/gqlgen/FX |
| 存储 | 单个 JSON 文件（`rules.json`），无数据库 |
| 前端 | 单个静态页面，原生 JS + CSS，**零构建、零 npm、零依赖**，`embed` 打包进二进制 |
| 正则 | `github.com/dlclark/regexp2/v2`（唯一第三方依赖，纯 Go），支持 lookahead/lookbehind；检测器用标准库 `regexp` |
| 转发 | 请求体脱敏后流式转发，响应带 `Flush` 透传（SSE 安全）；响应侧守卫只窥探有界前缀 |

> 日常怎么起、怎么加规则、怎么排查？看 **[USAGE.md](USAGE.md)**（含可复制的 curl 命令和故障速查表）。
> 安全边界、未做项与性能数据在 **[docs/](docs/)**。

## 快速开始

```bash
# 0. 取源码（也可以直接 `go install github.com/ricardo33550336/mask-gateway@latest`）
git clone https://github.com/ricardo33550336/mask-gateway.git
cd mask-gateway

# 1. 编译（产物是单个二进制，含前端页面）
go build -o mask-gateway .

# 2. 启动（指向你的上游，比如 OpenAI 或任何 OpenAI 兼容服务）
UPSTREAM=https://api.openai.com ./mask-gateway -addr :8080
# 或: ./mask-gateway -upstream https://api.openai.com

# 3. 打开管理界面
open http://localhost:8080
```

想让它直接认识你的密钥（推荐），启动时加一份 `.env`：

```bash
# .env 里用 ###secret 标出敏感段，其余（API_HOST/MODEL 等）不会被脱敏
./mask-gateway -upstream https://api.openai.com -secret-file ~/.secrets/.env
```

```dotenv
API_HOST=api.openai.com
MODEL=gpt-4o

##########secret
OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxx
```

客户端用法不变：把 base URL 指到网关即可。

```bash
curl http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer sk-xxx" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"我的 key 是 sk-abcdef..."}]}'
```

## 参数

| 参数 | 默认 | 说明 |
|------|------|------|
| `-addr` | `:8080` | 监听地址 |
| `-rules` | `rules.json` | 规则存储文件（自动创建） |
| `-secret-file` / 环境变量 `SECRET_FILE` | 空 | **pinned** `.env` 路径（可重复）。只读 `###secret` 段内的真实值，命中即脱敏；**显式文件有问题时拒绝启动**（fail closed） |
| `-secret-list` / 环境变量 `SECRET_LIST` | `secret-files.json` | **可编辑**路径列表：管理界面「已知密钥」里增删，立即生效并持久化。列表条目坏掉只跳过 + 告警（不阻止启动） |
| `-secret-reload` | `5s` | `-secret-file` 的轮询间隔（`0` = 关闭，仍可用 `kill -HUP` 或 `POST /api/secrets/reload`） |
| `-upstream` / 环境变量 `UPSTREAM` | 空 | 上游 base URL，如 `https://api.openai.com` |
| `-developer-as-system` / 环境变量 `DEVELOPER_AS_SYSTEM=1` | 关 | 转发前把 `developer` 角色映射为 `system`（用于不支持 developer 角色的上游） |
| `-response-guard` / 环境变量 `RESPONSE_GUARD=0` | **开** | 响应侧守卫：阻断真值回显（B1）、敏感内容与模型不一致告警（B2/F）。`RESPONSE_GUARD=0` 关闭 |
| `-peek-bytes` | `1048576` | 非流式响应最多预先缓冲多少字节；SSE 只窥探一次 read（TTFB 不变） |
| `-leak-min-len` | `8` | 回显检测的最短 needle；更短的值（单词/数字）不参与匹配，避免误报 |
| `-warn-scan-bytes` | `262144` | 每条响应用于检测器告警扫描的字节预算（`0` = 关闭 B2） |
| `-audit` / 环境变量 `AUDIT=1` | 关 | 保留诊断事件环形缓冲（**不保存请求/响应内容**） |
| `-admin-token` / 环境变量 `ADMIN_TOKEN` | 空 | 诊断接口（`GET/DELETE /api/events`、`GET /api/secrets`、`POST /api/secrets/reload`）的 Bearer token。**为空时这些接口直接 403（fail closed）** |
| `-audit-size` | `200` | 环形缓冲条数 |
| `-audit-hint-chars` | `0` | 事件里保留命中值的前 N 字节（默认 0 = 不保留内容；硬上限 16，且**永不记录完整值**） |

## 响应侧守卫（防中转站回吐）

请求侧只能保证"发出去的是什么"。中转站还可能：把你的密钥**回显**回来、注入敏感内容、偷偷换模型。
这一层在 `response.go`，**默认开启**。

| 检查 | 做什么 | 处置 |
|------|--------|------|
| **B1 回显泄漏** | 本次请求里被规则 mask 过的真值，在响应里又出现（**发送前扣留 `maxLen-1` 字节**，连前缀都不会漏出） | 未写出响应头 → `502` 阻断；已开始流式输出 → 断流（客户端看到网络错误） |
| **B2 敏感内容** | 响应里出现检测器认得的密钥/身份证/卡号等 | **仅告警**，字节不动 |
| **F 模型不一致** | 响应 `model` 与请求 `model` 不一致。只剥离**明确的快照后缀**（`-YYYY-MM-DD` / `-YYYYMMDD` / `-YYYY`）后做**精确比较**；`gpt-4o → gpt-4o-mini`、`gpt-4 → gpt-4o` 都会告警 | **仅告警**，字节不动 |

B1 的 needle 来自"请求侧规则实际命中的原文"（含你自己的自定义正则），所以公司内部密钥格式也能被抓到；
占位符本身（我们真正发出去的内容）不会被当成泄漏。

**不缓冲整个响应**：

```
upstream ──▶ forward ──┬──▶ 首 chunk / 前 N 字节 ──▶ 守卫 ──┬──▶ 正常透传
                       │                                    └──▶ 阻断 / 断流 / 仅告警
                       └──▶ 环形缓冲（-audit 开启时，旁路）
```

- SSE：只取**一个 chunk**，TTFB 与旧实现一致
- 非流式：最多缓冲 `-peek-bytes`；超过上限则只检查前缀、其余正常流式透传
- **窥探有 200ms 时间预算**：到期即放行已读前缀并继续透传（`-peek-bytes` 是上限，不是要凑满的目标）
- `-response-guard=false` 时**完全不窥探**，直接走旧的流式透传路径
- 未命中时：状态码 / header / 字节流 / 32KB 写-冲刷粒度与旧实现完全一致（有测试锁定）

**已知边界**：如果上游首字节比 200ms 预算更晚，响应头已经提交，B1 只能断流而无法再返回 502。

### 覆盖信号（`X-Mask-Guard`）

`-audit` 打开时事件里有信号，但调用方也需要能感知"这次响应有没有被完整检查"。当且仅当存在缺口时，
响应头会带上：

| 值 | 含义 | 对调用方的意义 |
|---|---|---|
| `coverage-incomplete` | 请求里有命中值**太长**（>512B）或命中条数超过 256，没能生成 B1 needle | 本次回显检测不完整，**不代表已阻断** |
| `scan-partial` | B2 检测器扫描预算（默认 256KB/响应）已耗尽 | 响应只被部分扫描 |

两者都是"保护覆盖不完整"的诚实信号，**不是**"已拦截"。B1 无法阻断它没有采集到的值——这一点必须明确，
不能虚报安全。

**注意**：B1 中途断流会让客户端看到网络错误（这是故意的，不能把泄漏内容写完再说）。
如果你不希望任何响应被拦截，用 `-response-guard=false` 关闭整层。

## 路由

| 路径 | 说明 |
|------|------|
| `/` | 管理界面（脱敏规则管理） |
| `/api/rules` 等 | 管理 API（见下） |
| `/healthz` | 健康检查 |
| 其余所有路径 | 原样转发到上游（含查询参数、请求头） |

## 管理 API

```
GET    /api/rules                # 规则列表
POST   /api/rules                # 创建规则
PUT    /api/rules/{id}           # 更新规则
DELETE /api/rules/{id}           # 删除规则
POST   /api/rules/{id}/status    # 启停 {"enabled": true}
GET    /api/detectors            # 内置检测器清单
GET    /api/events?limit=50      # 响应侧守卫事件（需 -audit）
DELETE /api/events               # 清空事件
POST   /api/preview              # 试跑规则（正则或检测器，不落盘）
```

规则结构：

```json
{
  "id": 1,
  "name": "mask-api-keys",
  "description": "脱敏 OpenAI key",
  "type": "detector",
  "detector": "api_key",
  "enabled": true,
  "action": "mask",
  "replacement": "[REDACTED]",
  "scopes": [],
  "fields": []
}
```

- `action`：`mask`（脱敏）或 `reject`（拒绝）
- `type`：`regex`（默认，手写正则）或 `detector`（内置检测器）
- `detector`：检测器名字（`type=detector` 时必填），见下表
- `threshold` / `minLength`：仅 `high_entropy` 使用，默认 4.0 / 20
- `scopes`：`system` / `developer` / `user` / `assistant` / `tool`，**留空 = 应用到所有角色**；
  仅对消息位置生效，`tools` 和顶层字段不受 `scopes` 限制（由 `fields` 控制）
- `fields`：`content` / `tool_calls` / `tools` / `top`，**留空 = 扫描全部位置**
- 规则按 ID 升序处理；多个 `mask` 规则依次叠加；第一个 `reject` 命中立即拦截

## 内置检测器

| 名字 | 说明 |
|------|------|
| `api_key` | 常见平台密钥前缀：`sk-` / `sk-proj-` / `sk-ant-` / AWS `AKIA\|ASIA` / GitHub `ghp_` `github_pat_` / GitLab `glpat-` / Slack `xox?-` / Google `AIza` `ya29.` / npm / PyPI / Stripe / SendGrid / Shopify / DigitalOcean / HuggingFace / Replicate / Perplexity / Mailgun |
| `cn_id_card` | 中国身份证 18 位，**GB 11643 校验位验证**（不是纯正则，伪造号不会命中） |
| `bank_card` | 银行卡 13-19 位，**Luhn 校验**通过才命中 |
| `cn_phone` | 中国大陆手机号（号段校验） |
| `jwt` | 三段 base64url，且 header 能解码成含 `alg` 的 JSON |
| `private_key` | `-----BEGIN ... PRIVATE KEY-----` PEM 块 |
| `connection_string` | `postgres://user:pass@host` 等带密码连接串 |
| `email` / `ipv4` | 邮箱 / IPv4 地址 |
| `high_entropy` | **兜底**：高熵随机串（≥20 字符、含大小写+数字、香农熵 ≥4.0），能抓住你没写规则的未知密钥 |

`GET /api/detectors` 返回检测器清单（管理界面用它渲染下拉框）。

## 扫描范围

请求体里**所有可能泄漏的位置**都会被扫描（不只是 `messages[].content`）：

| `fields` | 覆盖内容 |
|----------|----------|
| `content` | `messages[].content`（纯字符串，或数组里的 `text` part） |
| `tool_calls` | `messages[].tool_calls[].function.arguments`、`reasoning_content`、`reasoning` |
| `tools` | `tools[]` / `functions[]` 的 `description` 与 `parameters`（**函数名不动**，否则会破坏 `tool_choice`） |
| `top` | 顶层 `prompt` / `input` / `instructions` / `system` / `user` / `metadata` |

刻意不动的位置：`model` 等控制字段、`image_url` / `input_image` / `file` 等二进制 part
（替换 base64 图片只会把请求打坏）。

## 脱敏逻辑（从 AxonHub 移植，已扩展）

核心代码在 `protect.go`（规则模型 + 扫描）+ `detect.go`（检测器）：

- 解析 OpenAI 请求体，按需只重写命中的子字段，其余字段保持原始字节
- 兼容两种消息格式：`content: "字符串"` 与 `content: [{"type":"text",...}]`
- 非 JSON 请求（如 multipart）原样转发，不做任何改动
- 数值走 `json.Number`，大整数（如 `seed`）不会丢精度
- 正则编译结果带缓存（含编译失败缓存），热路径零重复编译
- **无命中时字节级不变**（`TestMaskNoMatchKeepsOriginalBytes` / `TestDetectorNoMatchKeepsOriginalBytes`）
- 拦截时返回 OpenAI 风格错误：
  `{"error":{"message":"request blocked by prompt protection policy","type":"invalid_request_error"}}`

## 常见问题

**Q: 调用报 400 `messages[0].role: unknown variant 'developer'`？**
客户端（如 Claude Code、新版 OpenAI SDK）会发 `developer` 角色的消息，但部分
OpenAI 兼容上游只接受 `system/user/assistant/tool`。启动网关时加参数即可把
`developer` 映射为 `system`：

```bash
./mask-gateway -upstream https://上游 -developer-as-system
# 或环境变量 DEVELOPER_AS_SYSTEM=1
```

注意：规则作用域按客户端**原始**角色匹配（`developer` 作用域仍会命中），
归一化只在转发前执行。

**Q: 为什么不直接用 Go 标准库 regexp？**
标准库不支持 lookahead/lookbehind（如 `(?=---|$)`），匹配 API key、卡号等真实敏感数据不够用。
`regexp2` 是纯 Go 单模块依赖。若想零依赖，把 `protect.go` 中的 `compilePattern` 换成
`regexp.Compile` 即可。

**Q: 为什么优先用检测器而不是手写正则？**
手写正则只能防住你想到的那一种格式，换个服务（`sk-proj-`、`ghp_`、JWT）就漏了。检测器把
常见格式固化下来，并用校验位/熵做二次确认；`high_entropy` 则能抓住你根本没写规则的未知密钥。

**Q: 检测器会不会误伤正常内容？**
`cn_id_card` / `bank_card` 需要校验位通过（随机串约 1/11、1/10 会过），`jwt` 要求 header 是
含 `alg` 的 JSON，`high_entropy` 要求大小写+数字混合且熵 ≥4.0（纯小写 hex、普通英文不会命中）。
担心误伤时先用管理界面的「测试」跑几段真实内容，或把 `fields` 收窄到 `content`。

**Q: 规则改了要重启吗？**
不用。规则实时生效（每次请求读取启用规则快照）。

**Q: 响应侧守卫会不会让正常请求变慢？**
SSE 只多一次 `Read`（本来就要读），非流式多一次有界缓冲（默认上限 1MB）。未命中时写出粒度、字节、header、状态码与旧实现逐字节一致，有测试锁定（`TestForwardNoHitPassthrough*`）。

**Q: B1 的 needle 从哪来？会不会误伤？**
只来自"本次请求中你的规则实际命中并替换掉的原文"，且长度 ≥ `-leak-min-len`（默认 8）。这是**精确匹配**，不是模式匹配，所以模型正常输出不会误伤；占位符（替换后的内容）也不算泄漏。

**Q: B2 会拦请求吗？**
不会。B2 和 F（模型不一致）永远只告警（stderr + `-audit` 事件），不改一个字节。只有 B1 才会阻断。

**Q: 并发大响应时内存怎么估算？**
峰值主要来自窥探缓冲，结构上界约为 `peekBytes × 同时在途的大非流式响应数`，实测 1MB 配置下
约 2.6MB/请求（含 buffer 翻倍开销）。高并发部署建议把 `-peek-bytes` 降到 256KB（实测约
0.9MB/请求），代价是 >256KB 的响应只能断流、不能返回 502。基准数据见 `AGENTS.md`。

**Q: 安全注意？**
管理界面与转发接口没有内置鉴权，生产环境请绑定内网地址或前置网关做认证。
`-audit` 默认不保存任何请求/响应内容（只有规则名、长度、模型名）；需要片段时用 `-audit-hint-chars` 显式开启。

## 许可

[MIT](LICENSE) © 2026 ricardo33550336

## 安装（可选）

```bash
go install github.com/ricardo33550336/mask-gateway@latest
```
