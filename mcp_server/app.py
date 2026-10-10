"""ASGI 外壳：Bearer 鉴权、工具白名单强制、审批端点、健康检查。

文档 §2：Hark 只支持「单头静态密钥」，所以鉴权就在这里做。
文档 §6.5：审批推送消息里带批准/拒绝按钮，落地端点就是 /admin/approve 与 /admin/reject。
这些端点经隧道对外可达，用独立于 MCP token 的 admin_token 保护；
为了能在手机上直接点通知里的链接，只有 /admin/* 接受 ?token= 查询参数。

这里还负责五件事：

1. 访问日志（logs/access.log，JSONL 一行一条）。排「连上了但一用就断」这类问题时，
   这是唯一能看到客户端真实请求的地方：method / path / status / 耗时 / JSON-RPC method /
   UA / 协议版本 / 原始 Accept / 会话号 / 来源 IP。

2. 补齐 Accept 头。MCP SDK 的 Streamable HTTP 实现只认 Accept 里含 application/json，
   连 `*/*` 和「不发 Accept」都会直接返回 406 Not Acceptable。
   而 curl、多数 HTTP 客户端库默认发的就是 `*/*`，不发 Accept 的也不少——
   对它们来说服务器就是「连不上」。这里统一补成 SDK 认的值。

3. Host / Origin 白名单。SDK 只做精确匹配（外加 `host:*`），不认子域通配，
   而 Cloudflare 快速隧道的域名每次重启都会变。所以这里自己按通配规则校验，
   通过后再把 Host / Origin 规范化成 SDK 白名单里的字面值。

4. **工具白名单**（面板里给每个 bot 配的）。这是安全边界，必须在服务端强制：
   * ``tools/call`` 越权 → 直接 **403**，请求根本不会到达工具函数；
   * ``tools/list`` 只返回该 bot 允许的工具（缓冲响应后过滤，JSON 与 SSE 两种格式都处理）。
   判定用的是**不带前缀的内部工具名**，所以改 ``tool_prefix`` 不会让已有白名单失效。

5. 审计归属：鉴权通过后把「哪个 token（名字）」与「来源 IP」写进 ContextVar，
   后续工具调用链里的审计日志自动带上，token 值本身永不落盘。

注意：白名单**不替代**审批/危险策略。越权是拒绝，危险命令仍然照旧走审批——
两套机制各管一段，互不干扰。
"""

from __future__ import annotations

import asyncio
import html
import json
import time
import urllib.parse
from pathlib import Path

from .bots import ALL, BotStore
from .policy import (EXCLUSIVE_TOOLS, LEVEL_ASK, LEVEL_DENY, clear_grants,
                     grant_tools)
from .remote_approval import (APPROVED, DENIED, PENDING, TIMEOUT,
                              capture_thumbnail, notify_new_approval)
from .security import (current_token_name, match_token_name, redact,
                       set_client_ip, set_token_name, token_matches)
from .server import Server
from .tokens import Identity, TokenRegistry

JSON_HEADERS = [(b"content-type", b"application/json; charset=utf-8")]
HTML_HEADERS = [(b"content-type", b"text/html; charset=utf-8")]

# MCP SDK 接受的最小集合；顺序按规范来
ACCEPT_OK = "application/json, text/event-stream"


def host_matches(value: str, patterns: list[str]) -> bool:
    """按白名单匹配 Host / Origin。支持三种写法：

    * 精确：      myhost.example-tailnet.ts.net
    * 任意端口：  myhost.example-tailnet.ts.net:*   （也匹配不带端口的裸域名）
    * 子域通配：  *.trycloudflare.com            （也匹配裸域名本身）
    """
    value = (value or "").strip().lower()
    if not value:
        return False
    for pattern in patterns:
        pattern = (pattern or "").strip().lower()
        if not pattern:
            continue
        if pattern == value:
            return True
        if pattern.endswith(":*"):
            base = pattern[:-2]
            if value == base or value.startswith(base + ":"):
                return True
        if pattern.startswith("*."):
            bare = pattern[2:]
            if value == bare or value.endswith("." + bare):
                return True
    return False


async def _send(send, status: int, body: bytes, headers: list[tuple[bytes, bytes]]) -> None:
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": headers + [(b"content-length", str(len(body)).encode())],
    })
    await send({"type": "http.response.body", "body": body})


async def _send_json(send, status: int, payload: dict,
                     extra: list[tuple[bytes, bytes]] | None = None) -> None:
    body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    await _send(send, status, body, JSON_HEADERS + (extra or []))


async def _send_html(send, status: int, title: str, detail: str) -> None:
    body = (
        "<!doctype html><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{html.escape(title)}</title>"
        "<body style='font-family:system-ui;padding:24px;line-height:1.6'>"
        f"<h2>{html.escape(title)}</h2><pre style='white-space:pre-wrap'>{html.escape(detail)}</pre>"
        "</body>"
    ).encode("utf-8")
    await _send(send, status, body, HTML_HEADERS)


def _summarize(tool: str, args: dict, limit: int = 180) -> str:
    """一句话参数摘要（面板审批卡片上显示的那行）。

    只服务面板展示：值会被 ``redact`` 遮蔽并截断。**推送通知里不带它**
    ——手机锁屏上不该出现参数内容。
    """
    if not args:
        return f"{tool}（无参数）"
    bits = [f"{key}={_short_value(value)}" for key, value in list(args.items())[:8]]
    text = " ".join(bits)
    if len(text) > limit:
        text = text[:limit] + "…"
    return f"{tool}: {text}"


def _short_value(value, limit: int = 60) -> str:
    if isinstance(value, str):
        text = redact(value)
        if len(text) > limit:
            return f"{text[:limit]}…（共 {len(value)} 字符）"
        return text
    if isinstance(value, (dict, list)):
        text = json.dumps(value, ensure_ascii=False)
        return text if len(text) <= limit else text[:limit] + "…"
    return repr(value)


class App:
    """把 MCP 应用包一层：先鉴权 + 白名单，再交给 FastMCP 的 Streamable HTTP 应用。"""

    def __init__(self, server: Server) -> None:
        self.server = server
        self.cfg = server.cfg
        self.mcp_app = server.mcp.streamable_http_app()
        self.access_log = Path(self.cfg.log_path) / "access.log"
        # bot 名册是**动态**的：面板改完立即生效，不需要重启。
        # 静态 token（config.toml）仍然有效且不受白名单限制。
        settings = self.cfg.panel_settings
        self.bots = BotStore(settings.bots_file, settings.pepper_file)
        self.bots.load()
        self.registry = TokenRegistry(self.cfg.token_entries(), self.bots)
        if not self.registry.usable():
            raise SystemExit(
                "没有可用的凭据，拒绝启动。\n"
                f"  * config.toml 的 tokens / named_tokens / token_files 全空；\n"
                f"  * 面板管理的 bot 名册里也没有启用的 bot（{settings.bots_file}）。\n"
                "至少恢复一处凭据再启动；否则任何人都进不来，等于服务不可用。"
            )

    # ------------------------------------------------------------ 响应包装

    @staticmethod
    def _plain_send(send, captured: dict):
        """只顺手记下状态码，原样转发。"""
        async def _send_msg(message):
            if message["type"] == "http.response.start":
                captured["status"] = message["status"]
            await send(message)
        return _send_msg

    def _filtering_send(self, send, captured: dict, allow):
        """缓冲响应、把 tools/list 里越权的工具摘掉，再整体发出。

        只在「这个 bot 有白名单」时才用；Hark 这类全量 token 走 _plain_send，零开销。
        缓冲是必要的：MCP SDK 的响应是一次性生成好的（json_response=True 时就是一段 JSON），
        没有「边生成边过滤」的钩子。
        """
        buffer = bytearray()
        headers: list[tuple[bytes, bytes]] = []

        async def _send_msg(message):
            if message["type"] == "http.response.start":
                captured["status"] = message["status"]
                headers.clear()
                headers.extend(message.get("headers") or [])
                return
            if message["type"] == "http.response.body":
                buffer.extend(message.get("body", b""))
                if message.get("more_body"):
                    return
                new_body = self._filter_tools_list(bytes(buffer), headers, allow)
                out_headers = [(k, v) for k, v in headers
                               if k.lower() != b"content-length"]
                out_headers.append((b"content-length", str(len(new_body)).encode()))
                await send({"type": "http.response.start",
                            "status": captured["status"], "headers": out_headers})
                await send({"type": "http.response.body", "body": new_body,
                            "more_body": False})
                return
            await send(message)

        return _send_msg

    # ------------------------------------------------------------ ASGI 入口

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            # lifespan 必须原样透传，否则 FastMCP 的会话管理器不会启动
            await self.mcp_app(scope, receive, send)
            return

        path = scope.get("path", "")
        start = time.perf_counter()
        captured: dict = {"status": 0}
        rpc: str | None = None
        payload = None
        body = b""

        # 先记下客户端原始 Accept（排查用），再把它补成 SDK 认的样子
        original_accept = self._header(scope, "accept") or ""
        scope = self._normalize_accept(scope)

        # Host / Origin 自己判（SDK 不认子域通配），通过后规范化成 SDK 认的值
        scope, host_ok = self._check_and_normalize_host(scope)

        # POST 的请求体要缓冲下来：既要记 JSON-RPC method，也要看 tools/call 请求的是哪个工具；
        # 缓冲后必须回放给下游，否则下游读到空 body。GET（SSE 长连接）不能缓冲。
        if scope.get("method") == "POST":
            body = await self._read_body(receive)
            payload, rpc = self._parse_rpc(body)
            replayed = False

            async def downstream_receive():
                nonlocal replayed
                if not replayed:
                    replayed = True
                    return {"type": "http.request", "body": body, "more_body": False}
                return await receive()
        else:
            downstream_receive = receive

        try:
            if not host_ok:
                await _send_json(self._plain_send(send, captured), 421,
                                 {"error": "invalid_host",
                                  "message": "Host 不在 allowed_hosts 白名单里"})
            elif path.startswith("/admin/"):
                await self._admin(scope, downstream_receive,
                                  self._plain_send(send, captured))
            else:
                await self._handle_mcp(scope, path, payload, rpc,
                                       downstream_receive, send, captured)
        finally:
            self._log_access(scope, captured["status"], rpc, start, original_accept,
                             captured.get("token", ""), captured.get("denied", ""))

    async def _handle_mcp(self, scope, path: str, payload, rpc: str | None,
                          downstream_receive, send, captured: dict) -> None:
        identity, _reason = self._identify(scope)
        client_ip = (scope.get("client") or ("", 0))[0]

        if identity is None:
            captured["token"] = "-"
            await _send_json(self._plain_send(send, captured), 401,
                             {"error": "unauthorized"}, extra=[(b"www-authenticate", b"Bearer")])
            return

        captured["token"] = identity.name
        # 审计归属：本请求后续的工具调用（与这里同一个任务上下文）都会记下这个名字，
        # 而 token 值本身永不进日志。
        set_token_name(identity.name)
        set_client_ip(client_ip)

        if identity.status != "ok":
            # 被禁用 / 已过期的 bot：401 会让人以为是「密钥不对」，
            # 403 才能说清「密钥对，但这个身份已经不能用了」。
            captured["denied"] = identity.status
            self.server.audit.denied("(any)", f"token 状态不允许调用：{identity.status}")
            text = ("该 token 已被禁用" if identity.status == "disabled"
                    else "该 token 已过期")
            await _send_json(self._plain_send(send, captured), 403,
                             {"error": f"token_{identity.status}",
                              "message": f"{text}，请联系管理员在面板里重新启用或轮换。"})
            return

        if identity.bot_id and self.bots is not None:
            self.bots.touch(identity.bot_id)

        if path == "/healthz":
            await _send_json(self._plain_send(send, captured), 200, {"status": "ok"})
            return

        verdict = self._policy_verdict(identity, payload)
        if verdict is not None and verdict[0] == "deny":
            _kind, tool, reason, keys = verdict
            captured["denied"] = reason
            self.server.audit.denied(tool, reason, keys=keys)
            await _send_json(self._plain_send(send, captured), 403,
                             {"error": "tool_not_allowed",
                              "tool": f"{self.cfg.tool_prefix or ''}{tool}",
                              "message": f"该 token 的白名单里没有 {tool}。"
                                         "请在管理面板里勾选后再试。"})
            return

        grants: tuple[str, ...] = ()
        if verdict is not None:
            # ask 档：把这次调用挂起，等手机端点头（超时自动拒绝）。
            calls = verdict[1]
            approved, detail = await self._await_approval(identity, calls)
            if not approved:
                captured["denied"] = f"approval_{detail.get('status', 'denied')}"
                await self._rpc_error(send, captured, payload, detail)
                return
            grants = tuple(call["tool"] for call in calls)

        # 会动鼠标键盘的工具共用一把全局锁：同一时间只允许一个 bot 持有，
        # 其余排队（面板上能看到谁在用、队列里有谁）。
        exclusive = next((name for name in self._called_tools(payload)
                          if name in EXCLUSIVE_TOOLS), "")
        ticket = ""
        if exclusive:
            ticket = self.server.tool_lock.request(identity.name, exclusive)
            if not await self._await_lock(ticket):
                self.server.audit.tool_gate(
                    exclusive, "lock_timeout",
                    f"{identity.name} 排队等 {exclusive} 的全局锁超时", level="W")
                await self._rpc_error(send, captured, payload, {
                    "status": "busy", "tool": exclusive,
                    "message": f"另一个 bot 正在操作鼠标键盘（{exclusive}），"
                               "排队超时，请稍后重试。"})
                return
        grant_tools(grants)
        try:
            if identity.unrestricted:
                await self.mcp_app(scope, downstream_receive,
                                   self._plain_send(send, captured))
            else:
                # 有白名单的 bot：tools/list 要缓冲过滤；其它请求原样转发
                if rpc == "tools/list":
                    await self.mcp_app(scope, downstream_receive,
                                       self._filtering_send(send, captured, identity.allow))
                else:
                    await self.mcp_app(scope, downstream_receive,
                                       self._plain_send(send, captured))
        finally:
            # 授权只在这一次请求里有效，绝不能漏到下一个请求
            clear_grants()
            if ticket:
                self.server.tool_lock.release(ticket)

    # ------------------------------------------------------------ 三档闸门

    def _internal_tool_name(self, name: str) -> str:
        """去掉对外前缀，得到内部/审计里用的工具名。"""
        prefix = self.cfg.tool_prefix or ""
        text = str(name or "")
        if prefix and text.startswith(prefix):
            return text[len(prefix):]
        return text

    def _tool_allowed(self, exposed_name, allow) -> bool:
        if allow is None or ALL in allow:
            return True
        return self._internal_tool_name(exposed_name) in allow

    def _called_tools(self, payload) -> list[str]:
        """这次请求里调用的内部工具名（批量请求会有多个）。"""
        if not isinstance(payload, (dict, list)):
            return []
        out: list[str] = []
        for item in (payload if isinstance(payload, list) else [payload]):
            if not isinstance(item, dict) or item.get("method") != "tools/call":
                continue
            params = item.get("params")
            params = params if isinstance(params, dict) else {}
            name = params.get("name")
            if isinstance(name, str) and name:
                out.append(self._internal_tool_name(name))
        return out

    def _policy_verdict(self, identity: Identity, payload):
        """三档判定。只检查 ``tools/call``（其它方法不涉及工具权限）。

        * ``None`` —— 全部放行；
        * ``("deny", 工具名, 原因, 参数名列表)`` —— 直接 403；
        * ``("ask", [{"tool", "args", "exposed"}, …])`` —— 需要人批准。

        批量请求里只要有一条是 deny 就整体拒；只要有一条是 ask 就先挂起等批准，
        批准后这一次请求里所有 ask 档工具一起放行（否则一次批量要人点很多下）。
        """
        # 只有**静态 token**（allow is None）完全跳过这一层。bot 的 "*" 白名单
        # 只是「工具全都看得见」，三档策略照样管着它们——否则给 bot 加个 "*"
        # 就等于把远程审批整个关掉了。
        if identity.allow is None or not isinstance(payload, (dict, list)):
            return None
        ask: list[dict] = []
        for item in (payload if isinstance(payload, list) else [payload]):
            if not isinstance(item, dict) or item.get("method") != "tools/call":
                continue
            params = item.get("params")
            params = params if isinstance(params, dict) else {}
            raw_name = params.get("name")
            if not isinstance(raw_name, str) or not raw_name:
                continue
            internal = self._internal_tool_name(raw_name)
            args = params.get("arguments")
            args = args if isinstance(args, dict) else {}
            level = identity.level_for(internal)
            if level == LEVEL_DENY:
                return ("deny", internal,
                        f"{identity.name} 的白名单里没有 {internal}（越权调用被拒）",
                        sorted(args))
            # 只对**注册过**的工具走审批：名字拼错的交给 SDK 回它自己的错误，
            # 而不是挂起 120 秒让人去批一个根本不存在的工具。
            if (level == LEVEL_ASK
                    and internal in getattr(self.server, "tool_names", ())
                    and not self.server.remote.auto_remaining(identity.name, internal)):
                ask.append({"tool": internal, "args": args, "exposed": raw_name})
        return ("ask", ask) if ask else None

    # ------------------------------------------------------------ 远程审批

    @property
    def panel_url(self) -> str:
        """面板地址：优先用配置里的公网地址，没配就退回本机地址。"""
        settings = self.cfg.panel_settings
        base = (settings.public_url or "").rstrip("/")
        return base or f"http://{settings.host}:{settings.port}"

    async def _await_approval(self, identity: Identity,
                              calls: list[dict]) -> tuple[bool, dict]:
        """把这次调用挂起等手机端批准。返回 (是否放行, 详情)。"""
        # 去重：批量请求里同一个工具调用两次，也只该在面板上出现一次
        tools = list(dict.fromkeys(call["tool"] for call in calls))
        keys = sorted({key for call in calls for key in call["args"]})
        summary = "；".join(_summarize(call["tool"], call["args"]) for call in calls)
        wait_s = int(self.server.runtime.get().get("approval_wait_s") or 120)

        # 调用前截图缩略图：审批卡片上「这是在什么画面上发生的」比参数更有说服力。
        # 截不到（锁屏 / 无桌面）就留空，审批单照样成立。
        thumb = ""
        try:
            thumb = await asyncio.to_thread(capture_thumbnail)
        except Exception:
            thumb = ""

        item = self.server.remote.create(
            bot=identity.name, bot_id=identity.bot_id or "", tools=tools,
            summary=summary, arg_keys=keys, thumb=thumb, wait_s=wait_s)
        self.server.audit.tool_gate(
            item.tool, "awaiting_approval",
            f"{identity.name} 调用 {item.tool}，等待手机端批准",
            keys=keys, approval_id=item.approval_id)
        # 推送在后台线程里发，绝不能卡住正在等待的这个请求
        notify_new_approval(self.server.runtime, item, self.panel_url)

        while time.time() < item.expires_at:
            current = self.server.remote.get(item.approval_id)
            if current is None or current.status != PENDING:
                break
            await asyncio.sleep(0.25)
        self.server.remote.sweep()
        current = self.server.remote.get(item.approval_id)
        status = current.status if current is not None else TIMEOUT

        if status == APPROVED:
            self.server.audit.tool_gate(
                item.tool, "approval_approved",
                f"{identity.name} 的 {item.tool} 已批准"
                f"（{current.decided_by or 'panel'}）",
                keys=keys, approval_id=item.approval_id)
            return True, {"status": "approved", "approval_id": item.approval_id,
                          "tool": item.tool, "decided_by": current.decided_by}

        if status == DENIED:
            reason = "审批被拒绝"
        else:
            reason = f"审批超时（{wait_s} 秒内没有人批准，已自动拒绝）"
        # 决定名要和面板「记录」页的筛选项一致：approval_rejected / approval_timeout
        decision = {"denied": "approval_rejected",
                    "timeout": "approval_timeout"}.get(status, f"approval_{status}")
        self.server.audit.tool_gate(
            item.tool, decision,
            f"{identity.name} 的 {item.tool}：{reason}",
            keys=keys, approval_id=item.approval_id)
        return False, {
            "status": status,
            "approval_id": item.approval_id,
            "tool": item.tool,
            "decided_by": (current.decided_by if current is not None else "timeout"),
            "message": f"{reason}：{identity.name} 调用 {item.tool} 未执行。",
        }

    async def _await_lock(self, ticket: str) -> bool:
        """排队等鼠标键盘的全局锁。超时返回 False（票会被撤销）。"""
        lock = self.server.tool_lock
        deadline = time.time() + max(10, int(self.cfg.panel_settings.lock_wait_s))
        while time.time() < deadline:
            if lock.try_acquire(ticket):
                return True
            await asyncio.sleep(0.1)
        lock.cancel(ticket)
        return False

    async def _rpc_error(self, send, captured, payload, detail: dict) -> None:
        """把「没批准 / 拿不到锁」变成一个标准的 JSON-RPC 错误回给 bot。

        用 ``error`` 而不是「成功的工具结果」：bot 必须能一眼看出这条调用**没有执行**，
        否则它会以为点击成功了继续往下走。
        """
        error = {
            "code": -32001,
            "message": str(detail.get("message") or "操作未获批准"),
            "data": {
                "reason": str(detail.get("status") or "denied"),
                "tool": str(detail.get("tool") or ""),
                "approval_id": str(detail.get("approval_id") or ""),
                "decided_by": str(detail.get("decided_by") or ""),
            },
        }
        if isinstance(payload, list):
            # 批量请求：JSON-RPC 要求逐条回应，id 也要对得上
            body = [{"jsonrpc": "2.0", "id": item.get("id"), "error": error}
                    for item in payload
                    if isinstance(item, dict) and item.get("method") == "tools/call"]
            if not body:
                body = [{"jsonrpc": "2.0", "id": None, "error": error}]
        else:
            body = {"jsonrpc": "2.0", "id": payload.get("id") if isinstance(payload, dict)
                    else None, "error": error}
        await _send_json(self._plain_send(send, captured), 200, body)

    def _filter_tools_list(self, body: bytes, headers, allow) -> bytes:
        """把响应里越权的工具摘掉。JSON 与 SSE 两种载体都处理。"""
        ctype = ""
        for key, value in headers:
            if key.lower() == b"content-type":
                ctype = value.decode("latin-1").lower()
                break
        if "text/event-stream" in ctype:
            return self._filter_sse(body, allow)
        try:
            data = json.loads(body.decode("utf-8"))
        except Exception:
            return body
        if not self._filter_payload(data, allow):
            return body
        return json.dumps(data, ensure_ascii=False).encode("utf-8")

    def _filter_payload(self, data, allow) -> bool:
        items = data if isinstance(data, list) else [data]
        changed = False
        for item in items:
            if not isinstance(item, dict):
                continue
            result = item.get("result")
            if not isinstance(result, dict):
                continue
            tools = result.get("tools")
            if not isinstance(tools, list):
                continue
            kept = [tool for tool in tools
                    if isinstance(tool, dict) and self._tool_allowed(tool.get("name"), allow)]
            if len(kept) != len(tools):
                result["tools"] = kept
                changed = True
        return changed

    def _filter_sse(self, body: bytes, allow) -> bytes:
        try:
            text = body.decode("utf-8")
        except Exception:
            return body
        out: list[str] = []
        changed = False
        for line in text.split("\n"):
            stripped = line.strip()
            if stripped.startswith("data:"):
                try:
                    data = json.loads(stripped[5:].strip())
                except Exception:
                    out.append(line)
                    continue
                if self._filter_payload(data, allow):
                    changed = True
                    line = "data: " + json.dumps(data, ensure_ascii=False)
            out.append(line)
        if not changed:
            return body
        return "\n".join(out).encode("utf-8")

    # ------------------------------------------------------------ 请求体

    @staticmethod
    async def _read_body(receive) -> bytes:
        chunks: list[bytes] = []
        more = True
        try:
            while more:
                message = await receive()
                chunks.append(message.get("body", b""))
                more = message.get("more_body", False)
        except Exception:
            pass
        return b"".join(chunks)

    @staticmethod
    def _parse_rpc(body: bytes):
        """返回 (解析后的 JSON, JSON-RPC method)。解析不了就 (None, None)。"""
        if not body:
            return None, None
        try:
            payload = json.loads(body.decode("utf-8"))
        except Exception:
            return None, None
        if isinstance(payload, dict):
            return payload, payload.get("method")
        if isinstance(payload, list):
            for item in payload:
                if isinstance(item, dict) and item.get("method"):
                    return payload, item.get("method")
        return payload, None

    # ------------------------------------------------------------ 头部规范化

    @staticmethod
    def _normalize_accept(scope) -> dict:
        """确保 Accept 里含 application/json，否则 SDK 一律 406。

        只补不删：客户端已经带了 application/json 就原样放行。
        """
        headers = list(scope.get("headers", []))
        accept = ""
        for key, value in headers:
            if key.lower() == b"accept":
                accept = value.decode("latin-1")
                break
        if "application/json" in accept.lower():
            return scope
        scope = dict(scope)
        scope["headers"] = (
            [(k, v) for k, v in headers if k.lower() != b"accept"]
            + [(b"accept", ACCEPT_OK.encode("latin-1"))]
        )
        return scope

    def _check_and_normalize_host(self, scope) -> tuple[dict, bool]:
        """校验 Host / Origin，并把它们换成 SDK 白名单里的字面值。

        返回 (scope, ok)；ok=False 时调用方回 421。
        """
        host = self._header(scope, "host") or ""
        if not host_matches(host, self.cfg.allowed_hosts):
            return scope, False

        origin = self._header(scope, "origin")
        if origin and not host_matches(origin, self.cfg.allowed_origins):
            return scope, False

        canonical_host = self.cfg.allowed_hosts[0] if self.cfg.allowed_hosts else host
        canonical_origin = self.cfg.allowed_origins[0] if self.cfg.allowed_origins else None

        headers = [(k, v) for k, v in scope.get("headers", []) if k.lower() != b"host"]
        headers.append((b"host", canonical_host.encode("latin-1")))
        if canonical_origin is not None and origin:
            headers = [(k, v) for k, v in headers if k.lower() != b"origin"]
            headers.append((b"origin", canonical_origin.encode("latin-1")))

        scope = dict(scope)
        scope["headers"] = headers
        return scope, True

    # ------------------------------------------------------------ 访问日志

    def _log_access(self, scope, status: int, rpc: str | None, start: float,
                    accept: str = "", captured_token: str = "",
                    denied: str = "") -> None:
        """写 logs/access.log。日志失败绝不能影响响应，所以整段吞异常。"""
        try:
            headers = {k.decode("latin-1").lower(): v.decode("latin-1")
                       for k, v in scope.get("headers", [])}
            entry = {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()),
                "method": scope.get("method"),
                "path": scope.get("path"),
                "status": status,
                "ms": int((time.perf_counter() - start) * 1000),
                "rpc": rpc,
                "ua": headers.get("user-agent", ""),
                "session": headers.get("mcp-session-id", ""),
                "proto": headers.get("mcp-protocol-version", ""),
                "accept": accept or headers.get("accept", ""),
                "auth": "yes" if headers.get("authorization") else "no",
                # 命中的是哪个 token（名字）——域名/UA 都可能是共用的，
                # 排查「这条请求是谁发的」只能靠它；值永不写日志。
                "token": captured_token or current_token_name() or "-",
                "client": (scope.get("client") or ("", 0))[0],
            }
            if denied:
                entry["denied"] = denied
            self.access_log.parent.mkdir(parents=True, exist_ok=True)
            with open(self.access_log, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception:
            pass

    # ------------------------------------------------------------ 鉴权

    @staticmethod
    def _header(scope, name: str) -> str | None:
        for key, value in scope.get("headers", []):
            if key.decode("latin-1").lower() == name.lower():
                return value.decode("latin-1")
        return None

    def _presented_token(self, scope, *, admin: bool) -> str:
        raw = self._header(scope, self.cfg.auth_header) or self._header(scope, "authorization") or ""
        scheme = (self.cfg.auth_scheme or "").strip()
        token = raw
        if scheme and raw:
            prefix = scheme + " "
            if raw.lower().startswith(prefix.lower()):
                token = raw[len(prefix):].strip()
            else:
                token = ""
        if not token and admin:
            # 只有 /admin/* 才接受 ?token=：手机点通知里的批准/拒绝链接需要它。
            # /mcp 必须走请求头——URL 里的 token 会进浏览器历史、隧道日志和 Referer。
            query = urllib.parse.parse_qs(scope.get("query_string", b"").decode("latin-1"))
            token = (query.get("token") or [""])[0]
        return token

    def _identify(self, scope) -> tuple[Identity | None, str]:
        """辨认调用方。返回 (身份, 失败原因)；身份为 None 时原因用于日志。"""
        presented = self._presented_token(scope, admin=False)
        if not presented:
            return None, "no_token"
        identity = self.registry.resolve(presented)
        if identity is None:
            return None, "unknown_token"
        return identity, ""

    def _auth_token_name(self, scope) -> str | None:
        """命中且**状态可用**才返回名字（其余当未授权）。"""
        identity, _ = self._identify(scope)
        if identity is None or identity.status != "ok":
            return None
        return identity.name

    def _authorized(self, scope) -> bool:
        return self._auth_token_name(scope) is not None

    def _admin_authorized(self, scope) -> bool:
        # 只认 admin_token（config 里留空时会自动回退成 tokens[0]，见 Config.__post_init__）。
        # 不再接受任意 MCP token：否则 MCP token 一旦泄露，
        # 等于连带拿到「批准危险命令」的权力。
        candidates = [self.cfg.admin_token] if self.cfg.admin_token else self.cfg.tokens
        return token_matches(self._presented_token(scope, admin=True), candidates)

    # ------------------------------------------------------------ 审批端点

    async def _admin(self, scope, receive, send) -> None:
        if not self._admin_authorized(scope):
            await _send_json(send, 401, {"error": "unauthorized", "message": "admin token 不正确"},
                             extra=[(b"www-authenticate", b"Bearer")])
            return
        # 审批端点走的是 admin_token，审计里就记这个名字（不是某个 MCP token 的名字）。
        set_token_name("admin_token")
        set_client_ip((scope.get("client") or ("", 0))[0])

        path = scope.get("path", "")
        query = urllib.parse.parse_qs(scope.get("query_string", b"").decode("latin-1"))
        store = self.server.approvals

        if path == "/admin/pending":
            items = store.list_pending()
            await _send_json(send, 200, {
                "count": len(items),
                "pending": [a.as_dict() for a in items],
            })
            return

        if path in ("/admin/approve", "/admin/reject"):
            approval_id = (query.get("id") or [""])[0]
            if not approval_id:
                await _send_html(send, 400, "参数错误", "缺少 id 参数")
                return
            approve = path.endswith("approve")
            approval = store.decide(approval_id, approve, actor="admin-endpoint")
            if approval is None:
                await _send_html(send, 404, "审批单不存在", approval_id)
                return
            self.server.audit.approval("approved" if approve else "rejected",
                                       approval.approval_id, approval.tool, approval.args)
            status_text = {
                "approved": "已批准。请让 Hark 调用 approval_status 取执行结果。",
                "rejected": "已拒绝，这条操作不会执行。",
                "expired": "审批单已过期，未执行。",
                "executed": "该审批单此前已经执行过。",
                "error": "该审批单此前执行失败。",
            }.get(approval.status, approval.status)
            await _send_html(send, 200, f"审批结果：{approval.status}",
                             f"{status_text}\n\n工具：{approval.tool}\n内容：{approval.summary}\n"
                             f"审批号：{approval.approval_id}")
            return

        await _send_json(send, 404, {"error": "not_found", "path": path})
