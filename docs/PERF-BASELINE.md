# 性能基线（Performance Baseline）

用途：灰度决策与改动回归对比。**所有数字都是本机实测**，不是估算。

## 测量环境

| 项 | 值 |
|---|---|
| 机器 | Intel Xeon E5-2680 v3 @ 2.50GHz，macOS（Darwin x86_64） |
| Go | 1.26.0 darwin/amd64 |
| 网络 | 全部 loopback（httptest），**不含真实公网 RTT** |
| 上游 | `httptest.NewServer`，writes + `Flush` |
| 客户端 | 默认 `http.Client`（keep-alive） |

> loopback 的特点：绝对延迟很低、无抖动。所以**相对差异**可参考，**绝对值**不能直接当线上数字。

---

## 1. 三态对比（3MB JSON，64KB/5ms 滴灌，32 并发）

| 状态 | TTFB p50 | p95 | p99 | 峰值堆增量 | GC 次数 | 吞吐（4KB 响应） |
|---|---|---|---|---|---|---|
| `guard=off` | 12.7 ms | 14.8 ms | 14.9 ms | 0.2 MB/请求 | 5 | 12.4 MB/s |
| `guard=on`（无 needle） | 92.3 ms | 93.2 ms | 93.2 ms | 1.85 MB/请求 | 10 | 12.6 MB/s |
| `guard=on`（holdback 生效） | 101.1 ms | 104.8 ms | 105.2 ms | 2.6 MB/请求 | 11 | 10.9 MB/s |

**怎么读这张表**：

- **大非流式响应**的 TTFB 差异 100% 来自窥探：要读满 `peek-bytes`（1MB）或撞 200ms 预算才提交响应。
  这里 3MB / 64KB / 5ms → 1MB 需要约 80ms，实测 92ms 吻合。
- **SSE 基本无差异**：只取 1 个 chunk 就放行，实测 1–2ms 级别。
- holdback 的吞吐差（12.6 → 10.9 MB/s）是 4KB 小响应下的拷贝开销；
  4KB 体量下 per-request 开销占比最高，所以这个数字是**上界**。

### 吞吐基准复现

```bash
go test -run '^$' -bench BenchmarkForward -benchtime 1s -count 2 ./...
```

本机结果（n=2 取范围）：

```
BenchmarkForwardGuardOff-24          322–332 µs/op   12.3–12.7 MB/s
BenchmarkForwardGuardOnNoNeedles-24  322–327 µs/op   12.5–12.7 MB/s
BenchmarkForwardGuardOnHoldback-24   369–383 µs/op   10.7–11.1 MB/s
```

### TTFB 分位数复现

```bash
go test -run TestConcurrentLargeResponses -v ./...
```

---

## 2. 峰值内存来源（F10 隔离实验）

固定 32 并发、3MB 响应，**只改 `-peek-bytes`**：

| peek-bytes | 峰值堆增量 | 每请求 |
|---|---|---|
| 64 KB | 18.3 MB | 0.57 MB |
| 256 KB | 28.7 MB | 0.90 MB |
| 1 MB | 93.2 MB | 2.91 MB |

**结论**：峰值 ≈ `peek-bytes × 同时在途的大非流式响应数`，**线性、有界**。
超出 1MB 的部分来自 `bytes.Buffer` 翻倍增长（瞬时旧缓冲未回收）。

已做的两项最小优化：
1. 按 `Content-Length` **有界**预分配（夹到 `peekBytes`，不信任上游声明的长度）；
2. 前缀写出后立即解除引用，长流期间不再持有这 1MB。

**没有**引入 `sync.Pool` 之类的缓冲池：它不降低并发峰值（每个在途请求仍需自己的缓冲），
只会减少分配次数，收益不足以抵上"池化内存常驻"的代价。

### 容量规划公式

```
峰值内存 ≈ 并发在途大响应数 × (peek-bytes × ~2.9)
```

| 并发 | 1MB（默认） | 256KB | 64KB |
|---|---|---|---|
| 10 | ~29 MB | ~9 MB | ~6 MB |
| 50 | ~145 MB | ~45 MB | ~29 MB |
| 200 | ~580 MB | ~180 MB | ~114 MB |

> 上式只算窥探缓冲。请求体上限 128MB，**请求侧**内存另算（`io.ReadAll` + JSON 解析）。

### 内存压测复现

```bash
go test -run TestConcurrentLargeResponses -v ./...
```

---

## 3. 日志量（F8）

50 次检测器命中（同一检测器）：

| 指标 | 值 |
|---|---|
| 请求数 | 50 |
| stderr 日志行 | **1**（其余折叠为 `suppressed=49`） |
| 审计事件 | **50**（环形缓冲不限流，一条不少） |
| B1 `leak` 事件 | 永不限流（每次都会写） |

复现：`go test -run TestLogRateLimit -v ./...`

---

## 4. 回归对比清单（改代码后跑一遍）

```bash
# 1) 功能
go test ./... && go test -count=3 ./... && go test -race -count=1 ./...

# 2) 吞吐
go test -run '^$' -bench BenchmarkForward -benchtime 1s ./...

# 3) 首字节 / 内存
go test -run 'TestConcurrentLargeResponses|TestPeekBudgetCapsFirstByteWait|TestGuardOffDoesNotPeek' -v ./...

# 4) 日志量
go test -run 'TestLogRateLimit' -v ./...
```

**判定标准**（建议）：

| 项 | 可接受变化 |
|---|---|
| `BenchmarkForwardGuardOff` | ±10% |
| `BenchmarkForwardGuardOnNoNeedles` | ±10% |
| `BenchmarkForwardGuardOnHoldback` | ±15% |
| 每请求峰值内存（同 `peek-bytes`） | +20% 以内 |
| TTFB p95（同场景） | +20% 以内 |

超过就查是不是又引入了额外缓冲/拷贝（尤其看 `response.go` 的 `leakGuardWriter` 与 `upstreamStream`）。

---

## 5. 线上需要另行采集的指标（本机测不出来）

- 真实上游 RTT 下的 TTFB（loopback 掩盖了网络抖动）
- 具体中转站的 SSE 分帧习惯（有的服务把多个 event 塞进一个 TCP 包，影响首帧延迟）
- 断流率（`leak/aborted` ÷ 总请求）与客户端重试率
- 误报率（`sensitive` 告警里人为判定为误报的比例）

灰度时建议把 `-audit` 开起来，按 `USAGE.md` §8 的清单每天看一次。
