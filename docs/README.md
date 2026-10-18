# 文档索引

| 文件 | 读者 | 内容 |
|---|---|---|
| [`../README.md`](../README.md) | 所有人 | 项目是什么、设计取舍、FAQ |
| [`../USAGE.md`](../USAGE.md) | 日常使用者 | 启动、加规则、看事件、故障速查 |
| [`KNOWN-LIMITS.md`](KNOWN-LIMITS.md) | 运维 / 安全评审 | **已知边界与不保证的内容**（含代码位置与对应测试） |
| [`BACKLOG.md`](BACKLOG.md) | 开发者 | 未实现项、为什么没做、风险与前置条件 |
| [`PERF-BASELINE.md`](PERF-BASELINE.md) | 灰度决策者 | 三态性能数据、测量方法、容量规划 |
| [`../AGENTS.md`](../AGENTS.md) | 改代码的人 | 模块地图、热路径、踩坑清单 |

## 一句话现状

功能已冻结，等灰度数据决定是否发布稳定版。
已交付：请求侧脱敏/拦截（正则 + 10 个内置检测器 + 全量扫描）、响应侧守卫（B1 回显阻断含 holdback、B2 告警、F 模型核对）、有界窥探 + 时间预算、诊断事件（默认关、fail-closed token）。

**剩余边界见 [`KNOWN-LIMITS.md`](KNOWN-LIMITS.md)，未做的工作见 [`BACKLOG.md`](BACKLOG.md)。**
