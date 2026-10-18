# USAGE.md — 日常使用手册

面向"每天都在用"的场景：怎么起、怎么加规则、怎么验证、出问题怎么查。
所有命令都已在本机实测（`curl` + `jq` 可选，没有 jq 也能用）。

---

## 0. 一次性准备

```bash
cd mask-gateway
go build -o mask-gateway .          # 单二进制，含前端
```

> 二进制、`rules.json`、`rules.json.tmp` 都在 `.gitignore` 里，不会误提交。

---

## 1. 启动

### 1.1 日常（接中转站）

```bash
UPSTREAM=https://你的中转站 ./mask-gateway -addr :8282
```

打开 <http://localhost:8282> 就是管理界面。

### 1.2 带诊断（推荐灰度期一直开着）

```bash
UPSTREAM=https://你的中转站 \
AUDIT=1 ADMIN_TOKEN='换成一个随机串' \
./mask-gateway -addr :8282
```

- `AUDIT=1` 打开诊断事件环形缓冲（**不保存请求/响应内容**）
- `ADMIN_TOKEN` 是读诊断接口的令牌；**不设的话 `/api/events` 直接 403**（有意的 fail-closed）
- 管理界面「诊断事件」面板里粘贴同一个 token 才能看事件

### 1.3 上游不认 `developer` 角色时

```bash
UPSTREAM=... ./mask-gateway -addr :8282 -developer-as-system
```

### 1.4 高并发 / 大响应

```bash
UPSTREAM=... ./mask-gateway -addr :8282 -peek-bytes 262144   # 内存约降到 1/3
```

### 1.5 出问题时临时关掉响应守卫

```bash
UPSTREAM=... ./mask-gateway -addr :8282 -response-guard=false
```

> 这是**真正的**旧透传路径：不窥探、不缓冲、不检测。但代价是完全没有回显泄漏防护，
> 只用于排查，别长期这么跑。

### 1.6 后台跑（本机）

```bash
nohup env UPSTREAM=... AUDIT=1 ADMIN_TOKEN=xxx ./mask-gateway -addr :8282 >> gateway.log 2>&1 &
```

---

## 2. 客户端怎么配

把 base URL 指到网关即可，其余不变：

```bash
export OPENAI_BASE_URL=http://localhost:8282/v1
export OPENAI_API_KEY=sk-xxx          # 你自己的上游 key，网关原样转发
```

```bash
curl http://localhost:8282/v1/chat/completions \
  -H "Authorization: Bearer sk-xxx" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}'
```

---

## 3. 加规则：两条命令就够

### 3.1 首选：用内置检测器（不用写正则）

```bash
curl -s -XPOST localhost:8282/api/rules \
  -H 'Content-Type: application/json' -d '{
  "name": "mask-api-keys",
  "type": "detector",
  "detector": "api_key",
  "action": "mask",
  "replacement": "[API_KEY]",
  "enabled": true,
  "scopes": [],
  "fields": []
}'
```

> ⚠️ **`"enabled": true` 必须显式传**。创建接口不会自动启用；漏了就会得到一条
> `"enabled": false` 的规则（不生效）。管理界面新建的规则同样是**默认停用**的，
> 需要在列表里把开关打开。

### 3.2 公司内部格式：写正则

```bash
curl -s -XPOST localhost:8282/api/rules \
  -H 'Content-Type: application/json' -d '{
  "name": "internal-token",
  "pattern": "INT-[A-Z0-9]{8}",
  "action": "reject",
  "enabled": true,
  "scopes": [],
  "fields": []
}'
```

- `mask` 必须给 `replacement`
- `reject` 不需要 `replacement`
- `scopes` 留空 = 所有角色；填了则**只作用于消息位置**（`tools`/顶层字段需留空）
- `fields` 留空 = 扫描所有位置；可选 `content` / `tool_calls` / `tools` / `top`

### 3.3 高熵兜底（抓"没写过规则的密钥"）

```bash
curl -s -XPOST localhost:8282/api/rules \
  -H 'Content-Type: application/json' -d '{
  "name": "entropy-fallback",
  "type": "detector",
  "detector": "high_entropy",
  "threshold": 4.0,
  "minLength": 20,
  "action": "mask",
  "replacement": "[TOKEN]",
  "enabled": true,
  "scopes": [],
  "fields": ["content", "tool_calls"]
}'
```

### 3.4 保存前先试跑（不落盘）

```bash
# 检测器
curl -s -XPOST localhost:8282/api/preview -H 'Content-Type: application/json' -d '{
  "type":"detector","detector":"cn_id_card",
  "testText":"身份证 11010519491231002X","action":"mask","replacement":"[ID]"
}'
# → {"hasMatch":true,"result":"身份证 [ID]"}

# 正则
curl -s -XPOST localhost:8282/api/preview -H 'Content-Type: application/json' -d '{
  "type":"regex","pattern":"INT-[A-Z0-9]{8}",
  "testText":"leak INT-ABCD1234 here","action":"reject"
}'
# → {"hasMatch":true,"result":"reject"}
```

---

## 4. 日常管理（增删改查 / 启停）

```bash
# 列表（jq 可选）
curl -s localhost:8282/api/rules | jq '.[] | {id,name,action,enabled}'
curl -s localhost:8282/api/rules                      # 没有 jq

# 启停（改完立即生效，不用重启）
curl -s -XPOST localhost:8282/api/rules/2/status \
  -H 'Content-Type: application/json' -d '{"enabled": false}'

# 整体替换某条
curl -s -XPUT localhost:8282/api/rules/2 \
  -H 'Content-Type: application/json' -d '{
  "name":"internal-token","pattern":"INT-[A-Z0-9]{10}","action":"reject",
  "enabled":true,"scopes":[],"fields":[]
}'

# 删除
curl -s -XDELETE localhost:8282/api/rules/3

# 可用检测器清单
curl -s localhost:8282/api/detectors | jq -r '.[] | "\(.name)\t\(.description)"'
```

### 备份 / 迁移

规则就是**一个 JSON 文件**：

```bash
cp rules.json rules.$(date +%F).bak        # 备份
scp rules.json other-host:mask-gateway/    # 迁移（改完需要重启对端）
```

> 注意：规则是**启动时读入内存**的，之后靠 API 改。所以**手工编辑 `rules.json` 后要重启**才生效；
> 用 API 改则立即生效（会原子写回文件）。

---

## 5. 看诊断事件（灰度期每天看一次）

```bash
T='你的 ADMIN_TOKEN'
curl -s -H "Authorization: Bearer $T" 'localhost:8282/api/events?limit=50' | jq .
curl -s -XDELETE -H "Authorization: Bearer $T" localhost:8282/api/events   # 清空
```

事件类型与含义：

| kind | action | 含义 | 要做什么 |
|---|---|---|---|
| `leak` | `blocked` | 响应在**写出前**发现回显真值 → 返回 502 | 上游可疑，查是哪个中转站/日志回显 |
| `leak` | `aborted` | 已经在流式输出，命中后**断流** | 同上；客户端会看到网络错误 |
| `sensitive` | `warned` | 响应里有检测器认得的敏感内容（**只告警**） | 确认是不是模型正常输出 |
| `model_mismatch` | `warned` | 上游换了模型（如 `gpt-4o` → `gpt-4o-mini`） | 换中转站或找服务商 |
| `coverage_gap` | `warned` | 有命中值太长（>512B）没被追踪 → 回显检测不完整 | 那条规则的正则太宽了，收窄它 |
| `scan_incomplete` | `warned` | 响应太长，B2 只扫了前 256KB | 需要更全覆盖就调大 `-warn-scan-bytes` |

同时看日志：

```bash
tail -f gateway.log | grep 'response guard'
```

> 日志做了限流：B1 泄漏事件**永不限流**；其余同类事件每分钟 1 条，并带 `suppressed=N`。
> 事件本身不会丢——只要开了 `-audit`，环形缓冲里一条不少。

### 响应头里的覆盖信号

```bash
curl -si ... | grep -i x-mask-guard
```

- `coverage-incomplete`：本次没采集全 needle，**不代表已阻断**
- `scan-partial`：B2 只扫了一部分

---

## 6. 验证"它真的在工作"

### 6.1 mask 生效

```bash
curl -s -XPOST localhost:8282/v1/chat/completions -H 'Content-Type: application/json' -d '{
  "model":"gpt-4o",
  "messages":[{"role":"user","content":"key sk-proj-AbCdEfGhIjKlMnOpQrStUvWx"}]
}'
```

上游若回显你发出去的内容，应看到 `[API_KEY]` 而不是原始 key。

### 6.2 reject 生效

```bash
curl -s -w '\nHTTP %{http_code}\n' -XPOST localhost:8282/v1/chat/completions \
  -H 'Content-Type: application/json' -d '{"messages":[{"role":"user","content":"INT-ABCD1234"}]}'
# HTTP 400
# {"error":{"message":"request blocked by prompt protection policy","type":"invalid_request_error"}}
```

### 6.3 健康检查

```bash
curl -s localhost:8282/healthz     # → ok
```

---

## 7. 常见问题速查

| 现象 | 原因 / 处理 |
|---|---|
| 规则加了但不生效 | 99% 是没传 `"enabled": true`。查：`curl -s localhost:8282/api/rules \| jq '.[] \| {id,enabled}'` |
| 400 `unknown variant 'developer'` | 启动加 `-developer-as-system` |
| `/api/events` 返回 403 | 没配 `-admin-token`/`ADMIN_TOKEN`，这是有意的 fail-closed |
| `/api/events` 返回 401 | token 不对；`Authorization: Bearer <token>` 或 `X-Admin-Token: <token>` |
| 事件面板空的 | 没开 `-audit`（面板会显示"未开启"） |
| 客户端报流式连接中断 | 可能是 B1 命中后**主动断流**；查 `kind=leak action=aborted` |
| 偶发 502 `leak guard` | B1 在写出前命中；同上查事件 |
| 大响应首字节变慢 | 窥探在等 1MB/200ms；`-peek-bytes 262144` 可显著改善 |
| 内存涨 | 峰值 ≈ `peek-bytes × 并发大响应数`；高并发下调小 `-peek-bytes` |
| 日志刷屏 | 已限流；确认不是 `leak`（leak 不限流，出现就该关注） |
| 改了 `rules.json` 没反应 | 手工改文件需重启；用 API 改才热生效 |

---

## 8. 灰度期日常检查清单（建议每天 1 分钟）

```bash
T='你的 ADMIN_TOKEN'
# 1) 有没有回显泄漏
curl -s -H "Authorization: Bearer $T" 'localhost:8282/api/events?limit=200' \
  | jq '[.events[] | select(.kind=="leak")] | length'
# 2) 有没有模型被换
curl -s -H "Authorization: Bearer $T" 'localhost:8282/api/events?limit=200' \
  | jq -r '.events[] | select(.kind=="model_mismatch") | "\(.model) -> \(.upstreamModel)"' | sort | uniq -c
# 3) 有没有覆盖缺口（正则写太宽 / 响应太长）
curl -s -H "Authorization: Bearer $T" 'localhost:8282/api/events?limit=200' \
  | jq -r '.events[] | select(.kind|startswith("coverage") or startswith("scan")) | .kind' | sort | uniq -c
# 4) 关键日志
grep -c 'kind=leak' gateway.log
```

**判读**：`leak` 应该长期为 0；`model_mismatch` 偶尔有（换模型/别名）可接受但要看频率；
`coverage_gap` 出现说明某条正则匹配范围太宽，收窄它；`scan_incomplete` 多说明响应体大，
可接受（B2 只是告警）。

---

## 9. 维护 / 升级

```bash
# 升级：重新构建 → 重启（规则在 rules.json 里，不受影响）
go build -o mask-gateway.new . && mv mask-gateway.new mask-gateway && pkill -f mask-gateway && \
  nohup env UPSTREAM=... ./mask-gateway -addr :8282 >> gateway.log 2>&1 &

# 自检（开发机）
go test ./... && go vet ./...
go test -race -count=1 ./...
go test -run '^$' -bench BenchmarkForward -benchtime 1s ./...   # 吞吐基线
```

---

## 10. 想知道"它到底不保证什么"

看 [`docs/KNOWN-LIMITS.md`](docs/KNOWN-LIMITS.md)：15 条明确边界（哪些值不会被追踪、哪些路径
转发不了、截断为什么会被静默修补、诊断 hint 的风险…），每条都标了代码位置和对应的测试。

## 附：全部启动参数

```bash
./mask-gateway -h
```

| 参数 | 默认 | 说明 |
|---|---|---|
| `-addr` | `:8282` | 监听地址 |
| `-upstream` / `UPSTREAM` | 空 | 上游 base URL（必填） |
| `-rules` | `rules.json` | 规则文件 |
| `-developer-as-system` | 关 | `developer` → `system` |
| `-response-guard` / `RESPONSE_GUARD=0` | 开 | 响应侧守卫总开关 |
| `-peek-bytes` | `1048576` | 非流式窥探上限（也是内存主因） |
| `-leak-min-len` | `8` | 回显检测最短 needle |
| `-warn-scan-bytes` | `262144` | B2 每响应扫描预算 |
| `-audit` / `AUDIT=1` | 关 | 诊断事件环形缓冲 |
| `-audit-size` | `200` | 环形条数 |
| `-audit-hint-chars` | `0` | 事件里保留的命中前缀字节（上限 16，永不记录完整值） |
| `-admin-token` / `ADMIN_TOKEN` | 空 | 诊断接口令牌；空 = 403 |
