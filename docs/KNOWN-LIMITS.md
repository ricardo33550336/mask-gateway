# 已知边界（Known Limits）

这份文件记录**我们明确不保证的事情**。用途有两个：

1. 运维/安全评审时不要高估保护范围；
2. 改代码时不要把这些边界当 bug"顺手修掉"——其中几条是有意为之，且有测试锁定。

格式：**结论 → 依据（代码位置/测试）→ 影响 → 建议**。

---

## 1. B1 只保护"已知 needle"

**结论**：响应侧回显检测只针对**本次请求里被你的规则脱敏掉的值**做精确匹配。

- 依据：`protect.go` 的 `hitSink`（观测旁路）+ `response.go` 的 `leakMatcher`
- 测试：`TestForwardAllowsEchoOfReplacement`、`TestForwardBlockedEcho*`

**不保证**：
- 上游自己注入的、请求里没出现过的第三方秘密（B2 只会告警，不会阻断）
- 模型正常输出里本来就有的密钥（那是"内容"，不是"回显"）

**建议**：不要把 B1 当内容安全过滤器。它的定位是"防止中转站把你发出去的东西吐回来"。

---

## 2. 超过 512B 的命中值不被追踪（只给信号）

**结论**：单条命中值 > 512B，或单请求命中条数 > 256 时，超出部分**不生成 needle**。

- 依据：`protect.go` 的 `maxHitTextLen = 512`、`maxCollectedHits = 256`（内存上界 128KB/请求）
- 信号：`X-Mask-Guard: coverage-incomplete` + `coverage_gap` 事件
- 测试：`TestCoverageGapForOverlongMatch`、`TestCoverageGapOnCollectionCapReached`

**影响**：一次 600B 的密钥如果被上游回显，**不会被阻断**。

**建议**：出现 `coverage_gap` 说明某条正则匹配范围太宽（例如把整段文档当成命中），
收窄该正则，而不是调大上限。

---

## 3. needle 最短 8 字节

**结论**：被脱敏的值短于 `-leak-min-len`（默认 8）时，不参与回显检测。

- 依据：`response.go` 的 `newLeakMatcher(needles, minLen)`
- 测试：`TestLeakMatcherIgnoresShortNeedles`

**原因**：8 字节以下的串（单词、数字、短 ID）在正常模型输出里出现频率太高，
纳入检测会造成随机断流。这是**刻意的精度换覆盖率**。

**建议**：不要把 `-leak-min-len` 调到 8 以下。需要保护短凭证时，改用更长的匹配上下文
（例如正则包含 `password=` 前缀）。

---

## 4. B1 是字节级精确匹配：编码/加密/跨字段后不可检测

**结论**：只匹配原文与它的 JSON 转义形式。

- 依据：`response.go` 的 `needleVariants`（原文 + `json.Marshal` 转义形式）
- 测试：`TestLeakMatcher*`、`TestForwardHoldbackNoPrefixLeakE2E`

**不保证**：
- 上游把密钥 base64 / URL 编码 / hex 编码后回显
- 上游把密钥拆成多个 JSON 字段（`"sk-abc"` + `"def..."`）
- 上游用 `\uXXXX` 形式转义非 ASCII 值

**建议**：这是"精确匹配"的必然代价。改成模式匹配会引入误报，进而随机阻断正常请求——不要这么做。

---

## 5. 上游截断会被静默"修补"

**结论**：上游在响应中途断开时，网关会把已收到的字节**正常收尾**发给客户端，
客户端**看不到错误**（只会看到内容变短）。

- 依据：`main.go` 的 `guardAndStream` → `if peek.err != nil || peek.full { guardOut.finish(); return }`
- 测试：`TestForwardHoldbackReadErrorKeepsReceivedBytes`（按此契约断言，并在注释中记录）
- 状态：**旧实现即如此**，本轮未改（不扩大范围）

**影响**：客户端无法区分"模型就这么短"与"上游断了"。

**建议**：已在 `BACKLOG.md` 列为待评估项（会导致客户端重试语义变化，需单独设计）。

---

## 6. 中途断流会送出"已确认安全"的字节

**结论**：B1 命中发生在响应头已提交之后时，只能断流（`http.ErrAbortHandler`）。

- 依据：`main.go` 的 `abortWith` → `response.go` 的 `abortHandler`
- 测试：`TestForwardAbortsMidStreamLeak`、`TestLeakAfterPeekBudgetAbortsInsteadOfBlocking`

**保证**：完整 needle 及**它的任何前缀**都不会落到达客户端（holdback，见 `leakGuardWriter`）。
**不保证**：在这之前的正常内容已经发出去了；客户端会看到网络错误而不是完整回答。

**建议**：不能容忍断流的流量，用 `-response-guard=false`（但那等于关掉整层防护）。

---

## 7. 首字节慢于窥探预算时，B1 只能断流、不能返回 502

**结论**：`peekBudget`（200ms，`main.go` 包变量）到期后响应头即提交，
此后命中只能断流。

- 依据：`response.go` 的 `peekUpstream`（预算只限制**等待**，不限制字节）
- 测试：`TestLeakAfterPeekBudgetAbortsInsteadOfBlocking`（明确锁定该行为）
- 补偿：holdback 仍然保证前缀不外泄

---

## 8. B2 的可见性有先后限制

**结论**：B2（检测器告警）是**有界扫描**，且"扫描不完整"这件事在流式开始后无法写进响应头。

- 依据：`response.go` 的 `warnScanner`（`warnOverlapBytes = 4096`、`budget`、`exhausted`）
- 测试：`TestWarnScannerBudgetIsPerResponseAndObservable`、`TestScanBudgetExhaustionIsObservableE2E`

**保证**：预算严格按"每请求总字节数"计（含重叠窗口）；耗尽时 `scan_incomplete` 事件 + 日志。
**不保证**：超出预算的部分被扫描；流式中途耗尽时响应头 `X-Mask-Guard` 里看不到（已提交）。

---

## 9. `/api/*` 路径被管理接口占用，无法转发

**结论**：`route()` 先匹配 `/api/` 再转发，所以**上游的 `/api/...` 路径到不了上游**。

- 依据：`main.go` 的 `route`（`strings.HasPrefix(p, "/api/")` 分支在 `default` 之前）

**影响**：Ollama 原生 API（`/api/chat`、`/api/generate`、`/api/tags`）无法经此网关转发；
OpenAI 兼容路径（`/v1/...`）不受影响。

**建议**：需要在前面套一层路径重写，或改用上游的 `/v1` 兼容端点。

---

## 10. `/api/rules` 与 UI 没有鉴权

**结论**：**诊断类**接口（`/api/events`、`/api/secrets*`、`/api/preview`）已加 fail-closed token；
**规则接口与管理界面仍然是开放的**。

- 依据：`main.go` 的 `requireAdmin`（空 token = 403，比较用常量时间）
- 状态：规则 CRUD 的开放是项目原有定位（"生产需前置网关"），本轮未扩大范围

**影响**：能访问网关端口的人可以：
- 读取规则（**正则会暴露你在保护什么格式**）
- 新增一条 `reject` 规则（对使用者造成 DoS）
- 关掉现有规则（让你在无保护状态下继续用）
- 通过 `/api/rules/*/status` 静默禁用 `-secret-file` 之外的脱敏规则

**为什么 `/api/preview` 一定要 token**（曾经是开放的）：
`known_secret` 检测器对快照里的值做**子串匹配**，所以免鉴权的试跑就是一个
membership oracle：

```bash
POST /api/preview {"detector":"known_secret","testText":"<候选前缀>"} → hasMatch
```

逐个字符试即可把已知密钥值问出来（16 位随机值约 ~1000 次请求），**完全不需要读 `.env`**。
WSL 连 Windows 侧网关这类部署里端口必然不是 loopback-only，因此这条必须 fail closed。
测试：`TestPreviewIsAdminOnly`。

**建议**：绑定内网地址 + 前置网关做认证。别把 `:8282` 直接暴露到公网。
只给 WSL/局域网用时，至少保证 `-admin-token` 非空（空 token 会让诊断接口直接 403）。

---

## 11. 请求头全量转发（指纹泄漏）

**结论**：除 hop-by-hop 头与 `Content-Length` 外，客户端请求头原样发给上游。

- 依据：`main.go` 的 `copyHeaders` / `isHopByHop`
- 影响：`x-stainless-*`、`User-Agent`、`OpenAI-Organization` 等指纹会暴露给你用的中转站

**建议**：见 `BACKLOG.md`（请求头清洗未实现）。临时办法：在客户端侧改 UA / 去掉这些头。

---

## 12. 没有并发/速率/大小保护（除请求体 128MB）

**结论**：网关不做并发限制、不做速率限制、不设响应超时（只有 `ResponseHeaderTimeout: 120s`）。

- 依据：`main.go` 的 `client` 配置；`forward` 无信号量

**影响**：慢上游会堆积 goroutine 与内存（峰值 ≈ `peekBytes × 并发大响应数`，见
`PERF-BASELINE.md`）；单个客户端可以打满。

**建议**：前置网关做限流；高并发下调小 `-peek-bytes`。

---

## 13. 诊断 hint 即使开启也只记录前缀，但仍要谨慎

**结论**：`-audit-hint-chars` 默认 0（不记录内容）；开启后最多保留 16 字节，
且**永不记录完整值**；事件里仍会带 `matchedLen`（精确长度）。

- 依据：`response.go` 的 `hintValue`（`maxAuditHintChars = 16`、`len(s) <= n` → 返回空）
- 测试：`TestAuditHintNeverStoresCompleteValue`

**影响**：前缀 + 长度对某些格式（如固定前缀 + 长度可推断的 key）仍有一定信息量。

**建议**：保持默认 0。排查时临时开，查完关掉并 `DELETE /api/events`。

---

## 14. holdback 的延迟代价（极端情况）

**结论**：holdback 扣留 `maxLen-1` 字节，所以**如果单帧比这个窗口还小**，
该帧会整体被扣留到下一帧（或收尾）才发出。

- 依据：`response.go` 的 `leakGuardWriter.release`
- 测试：`TestForwardHoldbackCleanStreamIsIdenticalAndIncremental`（用 >4096B 的帧验证）

**影响**：SSE 首帧如果只有几十字节、而配置的 needle 长达数百字节，首帧会慢一拍。
正常场景（短密钥、几十字节帧）只有 ≤25 字节的额外延迟。

---

## 15. 模型一致性只核对 `model` 字段

**结论**：不校验 `usage` 合理性、`system_fingerprint`、`id` 前缀等。

- 依据：`response.go` 的 `extractUpstreamModel`（正则抓 `"model":"..."`）
- 测试：`TestModelsCompatibleExactAndSuffix`、`TestForwardModelDowngradeIsWarned`

**不保证**：上游用同一模型名但降低采样质量、偷偷裁剪上下文、改写 `usage`。

---

## 16. `-secret-file` 只保护「已知值」

**结论**：从 `.env` 的 `###secret` 段读到什么值，就只保护这些值（见 `docs/SECRET-FILE.md`）。

| 子边界 | 后果 | 依据 / 测试 |
|---|---|---|
| **没进路径列表的 `.env`** | 完全不被保护（网关不知道它存在） | 路径由用户在 `-secret-file` / 界面里显式提供，不做自动发现 |
| **列表里的陈旧路径** | 只跳过 + 告警，不会报错（为了让开机不失败） | `-secret-list` 条目坏掉不影响启动；看 `/api/secrets` 的 `skipped` |
| **值被编码/拼接后** | 不匹配（`base64("sk-…")`、拆成两行、只贴前半段） | 与第 4 条同源：字节级精确匹配 |
| **旧值从 `.env` 删除后** | 历史对话里的旧值不再被保护 | 快照即真相；建议轮换时先保留旧值一段时间 |
| **热加载窗口** | 改完到生效最长 5s（`-secret-reload`），窗口内贴进 prompt 仍会漏 | SIGHUP / `POST /api/secrets/reload` 可立即生效 |
| **过短的值** | 不按长度过滤，因此可能过度脱敏（正文里偶然出现的 `1234` 也被替换） | 刻意取舍：宁可多脱敏，也不静默漏 |
| **进程内存** | 值常驻内存，swap / core dump 里可见 | 单用户本地场景可接受 |

**不保证**：能发现「你以为加进去、其实没加」的路径 —— 启动日志与 `/api/secrets` 是唯一的核对手段。

---

## 附：这些边界由哪些测试锁定

| 边界 | 锁定测试 |
|---|---|
| 无命中字节不变 / 不缓存整包 | `TestForwardNoHitPassthrough*`、`TestForwardLargeBodyStreamsIdentically`、`TestForwardSSEDeliversFirstFrameBeforeStreamEnds` |
| guard=false 真正回退 | `TestGuardOffDoesNotPeek`、`TestHoldbackNotAppliedWhenGuardDisabled` |
| 覆盖缺口信号 | `TestCoverageGap*`、`TestNoCoverageSignalForNormalValues` |
| B2 预算与重叠 | `TestWarnScanner*`、`TestScanBudgetExhaustionIsObservableE2E` |
| 诊断鉴权 | `TestEventsAPI*`、`TestPreviewIsAdminOnly` |
| 已知值只保护 `###secret` 段 / 显式文件 fail closed | `TestSecretCollectsOnlySecretSection`、`TestSecretExplicitFileFailsClosed`、`TestSecretDirModeSkipsBadFile` |
| 值不被截断、命中即脱敏且产生 needle | `TestSecretMarkerVariants`、`TestSecretMasksRequestAndFeedsNeedles` |
| 热重载（保留旧快照 / SIGHUP） | `TestSecretReloadKeepsOldSnapshotOnError`、`TestSecretReloadPicksUpNewValue`、`TestSecretSIGHUPReloads` |
| 已知值接口不回传值 | `TestSecretsAPIIsAdminOnly`、`TestPreviewIsAdminOnly` |
| 断流与 holdback | `TestForwardAbortsMidStreamLeak`、`TestHoldback*`、`TestLeakAfterPeekBudgetAbortsInsteadOfBlocking` |
