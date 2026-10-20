# SECRET-FILE —— 用 `.env` 里的真实值做脱敏

> 一句话：**你不需要描述密钥长什么样；网关已经知道它是什么。**
>
> 从 `.env` 的 `###secret` 段读出真实值，请求正文里出现这些值就替换成 `[redacted]`，
> 命中值同时成为响应侧 B1 的 needle（模型复述回来会被拦）。

## 0. 为什么是这个方案（设计前提）

本功能只在下面两条**不变量**成立时才是正确的，这是刻意的收敛：

1. **敏感信息只写在 `.env` 里**，且这些 `.env` 全部由 `-secret-file` 显式列出（文件或目录）；
2. **所有 agent 的模型请求都经过本网关**。

由此得到的好处是"不需要猜"：

| 判据 | 误杀风险 | 密钥轮换后 |
|---|---|---|
| 形状（固定位数 / 熵） | 高（`[A-Za-z0-9]{32}` 在本仓库 5698 行代码里误中 52 次） | 长度一变就静默失效 |
| `.env` 行结构 | 低，但只能覆盖"以 .env 形式粘贴"的内容 | 免疫 |
| **已知值（本功能）** | **0**（只替换真值） | **重启/热重载即生效** |

代价：网关进程常驻持有这些值（内存 / swap / core dump）。这是本地方案可以接受的取舍。

## 1. `.env` 的写法

```dotenv
# 普通配置放外面，随便写
API_HOST=api.openai.com
MODEL=gpt-4o-instruct

##########secret
OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxx
LARK_APP_SECRET=eScTsP12xxxxxxxxxxxxxxxxx
OKX_SECRET=P@vS4^HxxxxxxQ#

##########public
LOG_LEVEL=debug
```

标记规则（**只有一条**，避免"额外判断"）：

```
去掉行首所有空白与 # → 剩余部分（转小写）等于 secret 或 public → 是标记
```

- 必须是**独立一行**：`###secret`、`#### secret`、`#SECRET` 都行，`#` 数量任意
- `# secret 的说明`、`###secret: 说明`、`###secrets` **都不是**标记
- 行内出现也不算（`KEY=###secret` 就是一条普通赋值）

值的解析规则：

| 情况 | 处理 |
|---|---|
| `export KEY=value` | 支持，`export` 前缀被剥掉 |
| `KEY="value"` / `KEY='value'` | 成对引号剥掉 |
| **值里含 `#`** | **原样保留**（剥行内注释会让值静默变短、永远匹配不上） |
| `KEY=$OTHER` | 跳过（网关不解析变量引用） |
| `KEY=`（空值） | 跳过 |
| CRLF / UTF-8 BOM | 自动处理 |
| 同名键重复 | 以**先出现的为准** |

## 2. 启动

```bash
# 单文件
./mask-gateway -upstream https://api.openai.com -secret-file ~/.secrets/.env

# 多个项目各一份（可重复）
./mask-gateway -secret-file ~/work/proj-a/.env -secret-file ~/work/proj-b/.env

# 目录：展开为 <dir>/.env 与 <dir>/*/.env（只一层，跳过 . 开头的名字）
./mask-gateway -secret-file ~/work

# 环境变量等价写法（OS 路径分隔符分隔多个）
SECRET_FILE=~/.secrets/.env
```

启动日志会逐份打印实际读取的**绝对路径**与**键名**（永不打印值）：

```
secret-file: 3 values from 2 files (loaded 14:32:07)
  [file] /Users/mac12/work/proj-a/.env      3 values  OPENAI_API_KEY, LARK_APP_SECRET, OKX_SECRET
  [dir]  /Users/mac12/work/proj-b/.env      1 values  ANTHROPIC_API_KEY
  [dir]  /Users/mac12/work/proj-c/.env      SKIPPED   no "###secret" marker found
```

## 3. 失败语义（启动 fail closed / 运行中 fail safe）

| 时机 | 出问题 | 行为 |
|---|---|---|
| **启动**，`-secret-file` 的显式文件不可读 / 没有 `###secret` 标记 / 段内 0 条 | 启动配置被框死 | **拒绝启动**（进程退出，对 agent 表现为连接被拒） |
| **启动**，`-secret-file` 给的目录里某个 `.env` 有问题 | 一个项目坏不该拖垮全部 | 跳过 + `SKIPPED` 报告 |
| **启动**，`-secret-list` 里的条目有问题（路径删了/改名了） | 开机只启一次，起不来代价太大 | 跳过 + `SKIPPED` 报告，**照常启动** |
| **运行中**重载失败（含编辑器写到一半） | 不能把所有 agent 一起掐断 | 保留上一个快照 + 告警 `keeping the previous N values` |

## 4. 改完怎么生效

| 方式 | 延迟 | 说明 |
|---|---|---|
| 轮询（`-secret-reload` 默认 5s） | ≤5s | 指纹 = 展开后的文件列表 + 每个文件的 `(mtime, size)`；新增项目也会被发现 |
| `kill -HUP <pid>` | 立即 | 必须已注册 handler（本程序注册了）；未注册时 SIGHUP 的默认行为是**杀掉进程** |
| `POST /api/secrets/reload` | 立即 | 需 `-admin-token`；Windows 上 SIGHUP 不存在时用这个 |

操作纪律：**先加密钥 → 确认生效（日志 reload 行 / `/api/secrets` 的 `loadedAt`）→ 再把密钥贴进 prompt。**

## 5. 自查接口

```bash
curl -s -H "X-Admin-Token: $ADMIN_TOKEN" localhost:8282/api/secrets | jq
```

返回路径、模式（`file`/`dir`）、是否 pinned、收进条数、键名、加载时间、列表内容 —— **不含值**。
token 未配置时一律 403（fail closed）。

| 接口 | 作用 |
|---|---|
| `GET /api/secrets` | 当前快照 + 路径列表 |
| `POST /api/secrets/reload` | 立即重载（Windows 无 SIGHUP 时用它） |
| `POST /api/secrets/files` `{"path":"…"}` | 加入可编辑列表（先验证，解析不出值就 400） |
| `DELETE /api/secrets/files?path=…` | 从列表移除（pinned 条目返回 400） |

管理界面的「已知密钥」面板就是这四个接口的界面：列表（路径/模式/收进条数/键名/跳过原因）+
输入框添加 + 删除 + 立即重载。面板与接口都只显示路径与键名。

## 6. 明确不做的事

- ❌ 形状规则（固定位数 / 熵）保持不变的必要性：已知值不需要猜
- ❌ `.env` 行结构检测器：按值已覆盖
- ❌ 自动发现（扫盘 / glob）：路径列表由用户显式提供，网关不猜
- ❌ 规则文件加密 / 0600：单用户本地场景下不是风险点
- ❌ 命中即 400 阻断：会打断 agent 工作流；脱敏 + B1 回显拦截已足够

边界见 [`docs/KNOWN-LIMITS.md`](KNOWN-LIMITS.md) 第 16 节。
