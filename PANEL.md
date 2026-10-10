# 管理面板使用说明（PANEL.md）

> 这是 v2 的 **bot token 管理面板 + 远程审批**：给每个 bot 发 token、
> 配「每个工具三档策略」、在手机上批准/拒绝 bot 发来的危险操作、看过期与调用记录。
> 面板与 MCP 本体**同一个进程、独立端口**，所以沿用已有的计划任务 + 看门狗，
> 没有新增守护。

---

## 1. 地址与登录

| 项目 | 值 |
| --- | --- |
| 本机地址 | `http://127.0.0.1:8771/` |
| 公网地址 | `https://admin.example.com/` |
| 首次口令 | 在 `D:\window-mcp-v2\PANEL-LOGIN.txt`（**登录一次后请删掉它**） |
| 改口令 | `python panel_passwd.py`（改完**不用重启**：面板下次请求就用新哈希） |
| 随机重设 | `python panel_passwd.py --generate`（明文重新写到 `PANEL-LOGIN.txt`） |

`PANEL-LOGIN.txt` 故意放在 `D:\window-mcp-v2\` 下：MCP 工具的 `read_roots` 只有
`D:\window-mcp\workspace`，所以**任何 MCP 客户端（包括 Hark）都读不到它**。

面板只监听 `127.0.0.1`（配置里强制，写成 `0.0.0.0` 会拒绝启动），对外只经命名隧道。

**手机上装成一个 App**：面板是 PWA（`/manifest.webmanifest` + 图标 + service worker）。
用 Chrome/Edge 打开 `https://admin.example.com/` → 菜单 →「添加到主屏幕」，
之后从桌面图标打开就是全屏、没有地址栏的独立窗口。service worker **不缓存任何响应**，
所以永远看到的是服务器上的最新版本。

---

## 2. 面板的两道门

`config.toml` 里的 `[server.panel] auth_mode` 有四种取值：

| 取值 | 含义 |
| --- | --- |
| `passphrase` | 只要本地管理口令 |
| `access` | 只信任 Cloudflare Access 的 `Cf-Access-Jwt-Assertion`（验 RS256 签名 + `aud` + `iss` + `exp` + 邮箱） |
| `either` | 两者任一即可 |
| `both`（当前） | 口令**始终**必需；**经 Cloudflare 进来的请求**还必须带有效 Access JWT |

`both` 的关键细节：**没配置的那一项自动跳过**。所以在填上 `access_aud` 之前，
它实际等于「只要口令」；而本机直连 `http://127.0.0.1:8771/`（没有 `cf-ray` 头）
永远只要口令 —— 万一 Access 配错了，你永远还有一条能进面板的路。

另有一层登录失败节流：同一来源 IP 5 分钟内失败 10 次即返回 429，全局 5 分钟 60 次。
来源 IP 取 Cloudflare 写的 `CF-Connecting-IP`。

---

## 3. 还差一步：Cloudflare Access（需要人在浏览器里点）

现在面板**只校验口令**。补上 Access 之后就变成「Google 登录 + 口令」两道门。

1. 打开 <https://one.dash.cloudflare.com/>，用 `admin@example.com` 登录。
2. 左侧 **Access → Applications** → **Add an application** → **Self-hosted**。
3. **Application domain**：Subdomain 填 `admin`，Domain 选 `example.com`，**Path 留空**。
4. **Policies → Add a policy**：Action = **Allow**，Include = **Emails** =
   `admin@example.com`。
5. 回 **Overview** 复制 **Application Audience (AUD) Tag**，填进 `config.toml`：

```toml
access_team = "<team>.cloudflareaccess.com"
access_aud  = "<粘贴 AUD Tag>"
```

改完重启服务生效：`D:\window-mcp-v2\supervise_server.cmd stop`，然后
`schtasks /run /tn WindowMCP-v2-Server`。启动 banner 里会打印
`Cloudflare Access：已启用`。

> 真被锁在外面时：把 `auth_mode` 改成 `"passphrase"` 重启，本机口令就能进；
> 或者直接访问 `http://127.0.0.1:8771/`。

---

## 4. 远程审批（本次新增的核心）

### 4.1 三档策略：放行 / 审批 / 禁止

每个 bot × 每个工具一档，在面板「Bots → 工具策略」里用三段式切换：

| 档位 | 行为 |
| --- | --- |
| **放行 allow** | 直接执行；`tools/list` 里可见 |
| **审批 ask** | 工具照常出现在 `tools/list` 里，但**调用会阻塞**，等你在手机上点批准 |
| **禁止 deny** | 等于原来的「不在白名单」：`tools/list` 里不出现，直接调用 **403** |

**默认档**（没显式配置的工具）：**只读 / 截图 / 状态查询类默认放行，其余一律「审批」**
—— 点击、输入、快捷键、执行命令、写文件这些本来就是要人点头的操作。
名单见 `mcp_server/policy.py` 的 `READONLY_TOOLS` / `DEFAULT_POLICY`。

> ⚠️ **升级影响**：已有的三个 bot（`hark` / `cue` / `muse`）都是全量权限，
> 升级后它们的 `click` / `type_text` / `hotkey` / `run_command` / `write_file` 等
> 会从「直接执行」变成「要审批」。只读类（`system_info` / `screenshot` / `read_file`…）
> 仍然直接放行。
> 想让某个 bot 的某个工具回到「直接执行」，在面板里把它切成**放行**即可，改完立即生效。

**静态 token**（`config.toml` 里的 `tokens` / `named_tokens` / `token_files`）
不受三档策略约束，行为与加面板之前完全一致 —— 它们没有「bot」这个身份，
也就没有可以逐工具配置的策略。当前配置里没有静态 token，所以这条只是后备路径。

### 4.2 审批队列（阻塞式）

bot 调用「审批」档工具时：

1. 服务端生成一条待审批记录：**bot 名、工具名、一句话参数摘要、调用前截图缩略图、时间**；
2. 该次调用被**挂起**，最多等 `approval_wait_s` 秒（默认 **120**）；
3. 你在面板上点「批准」→ 这次调用继续执行并返回真实结果；
4. 点「拒绝」或**超时** → 自动拒绝，bot 收到一个明确的 JSON-RPC 错误：

```json
{"jsonrpc":"2.0","id":1,
 "error":{"code":-32001,
          "message":"审批超时（120 秒内没有人批准，已自动拒绝）：hark 调用 run_command 未执行。",
          "data":{"reason":"timeout","tool":"run_command","approval_id":"…"}}}
```

用 `error` 而不是「成功的工具结果」，是为了让 bot 一眼看出**这条操作没有执行**，
不会以为点击成功了继续往下走。

> ⚠️ **客户端超时要够长**：这次调用是**阻塞**的，所以 MCP 客户端自己的 HTTP 超时
> 必须 ≥ `approval_wait_s`，否则 bot 会先超时断开（你后来批准了，操作仍然会执行，
> 但 bot 不知道结果）。Hark 单次调用默认 60 秒，如果它发起的操作要审批，
> 建议把 `approval_wait_s` 调到 45 秒左右，或者把 Hark 的超时调大。
> 面板「设置」页可以随时改这个值，**改完立即生效，不用重启**。

### 4.3 面板「审批」页

* 顶部标签栏上有一个**角标**显示待审数；
* 每条一张卡片：bot 名彩色标签、工具名、一句话参数摘要、**调用前截图缩略图**
  （点一下放大）、**倒计时进度条**（最后 15 秒变红）；
* 底部两个大按钮 **拒绝 / 批准**；「**本 bot 10 分钟内同类放行**」放在「更多」里；
* 下方折叠显示**最近已处理**；
* 空状态显示「没有待审批」以及**当前持锁的 bot**；
* 页面每 **3 秒**自动刷新（切到后台时暂停，切回来立刻刷一次）；
* 新审批到达时**页面标题闪烁**并**震动**（浏览器支持时）。

「同类放行」= 接下来 N 分钟（默认 10，`panel.auto_allow_minutes`）内，
这个 bot 调用这个工具不再需要批准。它**只活在内存里**，服务重启即失效。

页面底部还有「**全部拒绝（N）**」，会把当前所有待审批一次拒掉（有二次确认）。

**旧通道的单子也在这一页**：危险命令走的还是老的「轮询式」审批
（工具立刻返回 `pending_approval`，由调用方自己回来问结果）。这些卡片上标着
「轮询式」，它们**不阻塞任何请求**。

### 4.4 手机推送（ntfy）

新审批到达时推一条到 **ntfy 私有 topic**。topic 写在配置里：

```toml
[server.panel]
ntfy_server = "https://ntfy.sh"
ntfy_topic  = "wmcp-replace-with-your-own-topic"   # 随机串；留空 = 不推送
ntfy_token  = ""                        # 自建 ntfy 才需要
public_url  = "https://admin.example.com" # 通知里「打开审批面板」指向的地址
```

* 手机装 ntfy App，订阅同一个 topic 即可收到；
* 通知里只有 **bot 名、工具名、时间、面板链接**，**没有 token，也没有参数明文**
  —— 参数摘要只显示在有登录态保护的面板里；
* 通知上的按钮点开就是面板（会走 Access + 口令两道门）；
* 面板「设置」页能改 topic / 服务器，还有「**发测试通知**」按钮；
* ntfy.sh 是公开服务器，**topic 名就是唯一的密码**，所以用的是随机串。
  想更强就自建 ntfy 并填 `ntfy_token`。

### 4.5 鼠标键盘全局锁

`type_text` / `click` / `hotkey` / `uia_click` / `uia_type` 都作用在**当时的焦点窗口**上。
两个 bot 同时动鼠标，点到的可能是对方刚切过去的窗口。所以这五个工具共用一把
**全局锁**：

* 同一时间只允许一个 bot 持有；
* 其他 bot 按先来后到**排队**，最多等 `lock_wait_s` 秒（默认 120），超时返回
  `reason: "busy"` 的错误；
* 面板「审批」页顶部显示**谁在用、队列里有谁**。

### 4.6 记录

所有审批决定都写进现有的审计日志（`logs/audit-YYYY-MM-DD.jsonl`，`kind = "approval"`），
带上 **谁批的（`actor`）、何时（`ts`）、结果（`result`）**。面板「记录」页按
bot / 工具 / 结果筛选，时间线上能看到 `awaiting_approval` → `approval_approved` /
`approval_rejected` / `approval_timeout` 的完整轨迹。

### 4.7 安全

* 审批接口（`/api/approvals*`、`/api/settings`）**只认面板登录态**（口令会话或
  Cloudflare Access JWT），**bot token 一律 401**；
* 面板跑在独立端口上，MCP 的 token 根本到不了它；反过来 `/mcp` 也不认面板 cookie；
* 老的 `/admin/approve` 只认 `config.toml` 的 `admin_token`，**bot token 调不动**；
* 改状态的请求都要求 `X-Panel-Request: 1` 头（跨站表单发不出自定义头，配合
  `SameSite=Lax` cookie 挡 CSRF）；
* 参数值**不落盘**：审批记录只写参数名（`arg_keys`）。

---

## 5. 面板能做什么

* **审批**：见上一节。
* **Bots**：每个 bot 一张卡片（名称、在线/持锁状态、过期时间、**今日调用数**、
  累计调用数、三档统计）。点「工具策略」进详情：
  * 按工具分组的三段式切换（放行/审批/禁止），有「只读放行 / 全部审批 / 全部禁止」
    三个快捷键；
  * 独占工具（动鼠标键盘的）标「独占」，高危工具标「高危」；
  * 改过期时间与备注。
* **新建 bot**：名称（只允许 ASCII 字母/数字/`_.-`，最长 32）、备注、可选过期时间、
  逐工具策略。token 明文**只在创建那一刻显示一次**，可一键复制；
  之后列表里只显示 **6 位指纹**（它其实是哈希的前几位，不含 token 本身的字符）。
* **轮换 token**：旧 token **当场失效**，新值只显示一次。
* **停用 / 启用**：停用后该 token 一律 403（`token_disabled`）。
* **吊销（删除）**：二次确认要**原样输入 bot 名字**。
* **记录**：按 bot / 工具 / 结果筛选的时间线，含被 403 拒绝的越权尝试与审批轨迹。
* **设置**：审批超时秒数、ntfy topic + 测试按钮、主题切换、退出登录。

所有改动**立即生效，不需要重启**——名册存在 `state/bots.json`，MCP 侧每次请求现查。

---

## 6. 三档策略是怎么强制的

* 存的是**不带工具前缀的内部名**（如 `read_file`），面板显示时才拼上 `wb_`。
  好处：改 `tool_prefix` 不会让已有 bot 的策略失效。
* `tools/call` 命中 `deny` → 直接 **403**（`{"error":"tool_not_allowed"}`），
  请求**根本到不了工具函数**。
* `tools/call` 命中 `ask` → **在 MCP 入口就挂起**，批准后才转发给工具函数；
  批准时会把这次请求里所有 `ask` 档工具一次性标记为「已获批」，
  所以**一次调用只会要人点一次**（不会出现「外层批了、内层又要批」）。
* `tools/list` 只返回档位不是 `deny` 的工具（响应被缓冲后过滤，JSON 与 SSE 都处理）。
* 批量请求（JSON-RPC batch）里任何一条 `deny` 都整体拒；只要有 `ask`，
  也只产生**一条**待审批。
* **三档策略不替代危险命令清单**：把 `run_command` 设成「放行」之后，
  危险命令（删除/改注册表/下载执行…）仍然照旧走内层审批，
  只是那条走的是老的「轮询式」通道。

**默认放行集合**（`policy.READONLY_TOOLS`）：

```
system_info  system_stats  list_processes  list_windows  list_dir  read_file
screenshot  job_status  approval_status  list_pending_approvals
agent_status  uia_snapshot  uia_wait_for
```

刻意**不含** `clipboard_get`：剪贴板里可能是刚复制的密码或验证码，比只读文件更敏感。

---

## 7. 审计与日志

| 文件 | 内容 |
| --- | --- |
| `logs/audit-YYYY-MM-DD.jsonl` | 工具调用（含 `token` 名字、`client` 来源 IP、`decision`）、审批记录（含 `actor` / `result`）与面板操作（`panel_bot_*`、`panel_login`、`panel_settings_update`） |
| `logs/access.log` | MCP 侧每一条 HTTP 请求（含 403 与 `denied` 原因） |
| `logs/panel-access.log` | 面板请求（method / path / status / 耗时 / client / who） |
| `logs/server.log` | 启动 banner、uvicorn 日志、看门狗重启记录 |
| `state/panel-settings.json` | 面板「设置」页改的运行时旋钮（审批超时、ntfy topic） |

**永不落盘的东西**：token 值、口令、参数值。被拒绝的调用只记**参数名**（`arg_keys`）。

---

## 8. 出问题怎么办

* **面板打不开**：先看 `logs\panel-access.log` 有没有请求进来。
  启动 banner 会打印 `管理面板 : ...` 与 `Cloudflare Access：已启用/未启用`。
* **忘了口令**：`python panel_passwd.py --generate`，读 `PANEL-LOGIN.txt`。
* **改了 `panel.*` 不生效**：`approval_wait_s` / `ntfy_topic` 在面板「设置」页改是
  立即生效的；其余 `panel.*` 是启动时读的，需要重启服务。
  **面板里改 bot 永远即时生效。**
* **bot 一直卡着不动**：它多半在等审批。看面板「审批」页有没有待审批，
  或者看 `logs/audit-*.jsonl` 里有没有 `awaiting_approval`。
  没有待审批但 bot 又卡住 → 检查它是不是在排队等鼠标键盘的全局锁。
* **手机收不到推送**：面板「设置」页点「发测试通知」。
  失败原因会直接显示（topic 没填 / 服务器连不上 / token 不对）。
* **Hark 突然 401**：面板里看 bot `hark` 的状态是不是被停用/过期了，
  或者 token 被轮换过（旧值当场失效）。
* **Hark 突然被 403**：它的白名单里没有那个工具。面板里勾上即可。
* **名册文件坏了**：`state/bots.json` 写坏时启动会先从 `bots.json.bak` 恢复；
  两个都坏才会拒绝启动。
* **端口被占**：面板启动失败会重试 5 次后放弃，**不影响 MCP 本体**。

---

## 9. 相关命令速查

```bash
# 看服务与看门狗状态
D:\window-mcp-v2\supervise_server.cmd status

# 重启服务（会先停看门狗再让计划任务接管）
D:\window-mcp-v2\supervise_server.cmd stop
schtasks /run /tn WindowMCP-v2-Server

# 隧道
D:\window-mcp-v2\supervise_tunnel.cmd status
schtasks /run /tn WindowMCP-v2-Tunnel

# 设 / 重设面板口令
E:\Python\python.exe D:\window-mcp-v2\panel_passwd.py
E:\Python\python.exe D:\window-mcp-v2\panel_passwd.py --path   # 只看文件位置

# 跑测试（含远程审批的端到端）
cd /d D:\window-mcp-v2 && E:\Python\python.exe -m pytest -q
```

---

## 10. 验收测试步骤（两个测试 bot）

目标：验证「手机上能分别批准/拒绝，且两者不会同时操作鼠标键盘」。

### 准备

1. 重启服务让新配置生效：
   `D:\window-mcp-v2\supervise_server.cmd stop` → `schtasks /run /tn WindowMCP-v2-Server`。
2. 手机装 ntfy App 并订阅 `config.toml` 里的 `panel.ntfy_topic`。
3. 手机浏览器打开 `https://admin.example.com/`，登录，**添加到主屏幕**。

### 造两个测试 bot

在面板「Bots → 新建 bot」建两个（名字随便，例如 `test-a`、`test-b`），
工具策略里把 **`run_command` 设成「审批」**、其余全设「禁止」，
创建时把 token 复制出来（各一份）。

### 用例 1：分别批准 / 拒绝

在电脑上开两个终端，各发一条 `ask` 档调用（`<TOKEN-A>` / `<TOKEN-B>` 换成刚复制的）：

```bash
curl -s -X POST http://127.0.0.1:8770/mcp \
  -H "Authorization: Bearer <TOKEN-A>" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"wb_run_command","arguments":{"command":"whoami"}}}'
```

第二条把 token 换成 `<TOKEN-B>`，命令换成 `hostname`。

预期：
* 两条 curl 都**卡住不返回**；
* 手机上先后收到两条 ntfy 通知（只有 bot 名、工具名、面板链接）；
* 面板「审批」页出现**两条卡片**，角标显示 2，各带一张调用前截图；
* 在手机上点 **批准** 第一条 → 第一条 curl 立刻返回 `whoami` 的输出；
* 点 **拒绝** 第二条 → 第二条 curl 返回 `{"error":{"code":-32001,"message":"审批被拒绝：…未执行。"}}`；
* 面板「记录」页能看到 `awaiting_approval` → `approval_approved` / `approval_rejected`，
  且 `actor` 是你登录的身份。

### 用例 2：超时自动拒绝

把面板「设置 → 审批超时」临时改成 **10 秒**，再发一条 `ask` 档调用，**什么都不点**。
预期：10 秒后 curl 返回 `reason: "timeout"` 的错误，面板上这条变成「已超时」。
测完把超时改回 120。

### 用例 3：两者不会同时操作鼠标键盘

1. 面板里把两个测试 bot 的 **`click` 设成「审批」**。
2. 两个终端**同时**发 `wb_click`（坐标随便，例如 `{"x":10,"y":10}`）。
3. 预期：
   * 面板上出现**两条**待审批；
   * 批准第一条后，它去抢全局锁；此时面板顶部显示
     「现在 test-a 正在操作鼠标键盘（click）」；
   * 第二条批准后**不会**立刻执行 —— 它进入队列（面板上能看到「排队中」）；
   * 第一条跑完释放锁，第二条才拿到锁执行。
4. 想验证排队超时：面板「设置」把 `lock_wait_s` 调小（或在 `config.toml` 里改），
   让一个 bot 长时间持锁，另一个会返回 `reason: "busy"` 的错误。

### 用例 4：同类放行

在任一条待审批卡片上展开「更多」→「**本 bot 10 分钟内同类放行**」并确认。
预期：立刻批准这一条，并且 10 分钟内这个 bot 再调用同一个工具**不再弹审批**；
面板「审批」页顶部能看到这条放行的剩余时间。

### 用例 5：安全

```bash
# bot token 调审批接口 → 必须 401
curl -s -o /dev/null -w "%{http_code}\n" https://admin.example.com/api/approvals \
  -H "Authorization: Bearer <TOKEN-A>"
```

预期 `401`。用面板登录后的浏览器访问同一地址则应返回 200（在 DevTools 里看）。

---

## 11. UI 自查（390×844 与桌面）

用真实浏览器渲染面板、在手机与桌面两种尺寸下截图并做程序化检查
（不横向滚动 / 文字不溢出 / 按钮不重叠 / 点击区域 ≥ 44px / 页面里不出现完整 token）。

截图与检查报告在 `docs/panel-ui/`：

| 文件 | 说明 |
| --- | --- |
| `mobile-390x844-approvals.png` | 手机尺寸 · 审批页 |
| `mobile-390x844-light.png` | 手机尺寸 · 浅色主题 |
| `mobile-390x844-login.png` | 手机尺寸 · 登录页 |
| `mobile-390x844-bot-detail.png` | 手机尺寸 · bot 工具策略（三段式） |
| `desktop-1280x900-approvals.png` | 桌面尺寸 · 审批页（左侧栏布局） |
| `layout-report.txt` | 各页面各尺寸的检查结果（全为 0 / 空即通过） |

重新生成：

```bash
cd /d D:\window-mcp-v2
E:\Python\python.exe tools\ui_selftest.py docs\panel-ui
```

脚本自己起一个临时面板（临时 state 目录 + 演示 bot + 演示审批单 + 演示全局锁），
用系统已装的 Edge 渲染并截图，**不碰生产环境**。检查项：

* `hscroll` —— 是否出现横向滚动条（必须为 0）；
* `overflow` —— 有没有元素越出视口（必须为空）；
* `smallTap` —— 小于 44px 的点击区域（必须为空）；
* `overlap` —— 同一行里互相重叠的按钮（必须为空）；
* `longToken` —— 页面里是否出现 40 字符以上的疑似 token（必须为空）。

最新一次结果：9 个页面 × 2 种尺寸全部通过。

