"""bot token 管理面板（独立 ASGI 应用 + 独立端口 + 自己的鉴权）。

它做什么
--------
一个手机友好的单页：新建 bot / 轮换 token / 改白名单与过期 / 启用停用 / 删除，
以及查看每个 bot 的最近调用（时间、工具、结果、来源 IP）。改动**立即生效**，
不需要重启服务——因为名册就存在 ``state/bots.json`` 里，MCP 那边每次请求现查。

两道门（都要才最稳，见 ``config.PanelSettings.auth_mode``）
---------------------------------------------------------
1. **本地管理口令**：文件里只放 scrypt 哈希（``secrets/panel.passphrase``），
   明文只在你自己的浏览器里出现一次。登录后换一个 HMAC 签名的会话 cookie。
2. **Cloudflare Access JWT**：校验 ``Cf-Access-Jwt-Assertion`` 的 RS256 签名
   + ``aud`` / ``iss`` / ``exp`` / 邮箱白名单（见 ``access.py``）。

``both`` 模式的语义（避免把自己锁在外面）：口令始终必需；**只有经 Cloudflare
进来的请求**（带 ``cf-ray`` / ``cf-connecting-ip`` 头）才额外要求有效 Access JWT。
所以本机直连 ``http://127.0.0.1:8771`` 永远能进——出问题时总有一条修复路径。

安全上的取舍
------------
* 面板只监听 ``127.0.0.1``，对外只经已有命名隧道（``admin.example.com``）。
* 页面外壳（HTML/CSS/JS）不需要鉴权——它不含任何数据；**所有 /api 都要鉴权**。
* 改状态的请求都要求 ``X-Panel-Request: 1`` 头（跨站表单发不出自定义头，
  配合 SameSite=Lax cookie 挡住 CSRF）。
* 明文 token 只在创建 / 轮换的响应里出现一次，之后服务端只有哈希。
* 面板自己的操作也写审计（``token`` 记为 ``panel``），但**永不记 token 值**。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import io
import json
import os
import secrets
import subprocess
import threading
import time
from pathlib import Path
from urllib.parse import parse_qs

from .access import AccessError, AccessVerifier, extract_token
from .bots import ALL, DEFAULT_ALLOW, BotStore, BotStoreError, parse_when
from .policy import (DEFAULT_POLICY, EXCLUSIVE_TOOLS, HIGH_RISK_TOOLS, LEVEL_ALLOW,
                     LEVEL_ASK, LEVEL_DENY, LEVELS, READONLY_TOOLS)
from .remote_approval import (APPROVED, DENIED, PENDING, TIMEOUT,
                              send_test_notification)
from .security import set_client_ip, set_token_name

COOKIE_NAME = "panel_session"
CSRF_HEADER = "x-panel-request"
MAX_BODY = 256 * 1024
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 14, 8, 1
SESSION_LABEL = b"panel-session-v1"

# 工具分组：面板按这个顺序显示，并标注风险。不在表里的工具落到「其他」。
TOOL_GROUPS: list[tuple[str, str, list[str]]] = [
    ("只读监控", "不改动任何东西，风险最低", [
        "system_info", "system_stats", "list_processes", "list_windows",
        "list_dir", "read_file", "screenshot", "job_status",
        "approval_status", "list_pending_approvals", "agent_status",
    ]),
    ("无障碍树（只读）", "读取界面元素，信息量等价于截屏", [
        "uia_snapshot", "uia_wait_for",
    ]),
    ("剪贴板", "剪贴板里可能是刚复制的密码或验证码", [
        "clipboard_get", "clipboard_set",
    ]),
    ("GUI 操作", "真的会动鼠标键盘，作用在当时的焦点窗口上", [
        "type_text", "click", "hotkey", "wake_screen", "uia_click", "uia_type",
    ]),
    ("文件写入", "会改磁盘上的文件（仍受工作目录限制）", [
        "write_file", "edit_file",
    ]),
    ("命令与任务", "能执行任意 PowerShell，权限最大", [
        "run_command", "start_job", "stop_job",
    ]),
]


class PanelDisabled(RuntimeError):
    """面板不该启动（比如一个鉴权方式都没配）。"""


# ---------------------------------------------------------------------------
# 本地管理口令
# ---------------------------------------------------------------------------

def hash_passphrase(passphrase: str) -> str:
    """生成 ``scrypt$n$r$p$salt$hash`` 记录。明文永不落盘。"""
    text = str(passphrase or "")
    if len(text) < 8:
        raise ValueError("管理口令至少 8 个字符")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(text.encode("utf-8"), salt=salt, n=SCRYPT_N,
                            r=SCRYPT_R, p=SCRYPT_P, dklen=32)
    return (f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}"
            f"${salt.hex()}${digest.hex()}")


def _tighten_acl(path: Path) -> None:
    """把文件 ACL 收到「只有当前用户」（尽力而为）。"""
    try:
        user = os.environ.get("USERNAME") or ""
        domain = os.environ.get("USERDOMAIN") or ""
        who = f"{domain}\\{user}" if domain and user else user
        if not who:
            return
        subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r", f"{who}:(F)"],
                       capture_output=True, timeout=20,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except Exception:
        pass


class PassphraseStore:
    """读 / 写 ``secrets/panel.passphrase``（内容是 scrypt 哈希）。"""

    def __init__(self, path: str | os.PathLike | None) -> None:
        self.path = Path(path) if path else None
        self._record = ""
        self._load()

    def _load(self) -> None:
        if self.path is None:
            return
        try:
            self._record = self.path.read_text(encoding="utf-8").strip()
        except OSError:
            self._record = ""

    def configured(self) -> bool:
        return bool(self._record) and self._record.startswith("scrypt$")

    def set(self, passphrase: str) -> None:
        if self.path is None:
            raise PanelDisabled("没有配置 panel.passphrase_file，无法保存口令")
        record = hash_passphrase(passphrase)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(record + "\n", encoding="utf-8")
        os.replace(tmp, self.path)
        _tighten_acl(self.path)
        self._load()          # 顺带刷新 _record 与 _mtime，避免下次误判「文件变了」

    def verify(self, passphrase: str) -> bool:
        if not self.configured():
            return False
        try:
            _, n, r, p, salt_hex, hash_hex = self._record.split("$")
            salt = bytes.fromhex(salt_hex)
            expected = bytes.fromhex(hash_hex)
            digest = hashlib.scrypt(str(passphrase or "").encode("utf-8"), salt=salt,
                                    n=int(n), r=int(r), p=int(p), dklen=len(expected))
        except (ValueError, TypeError):
            return False
        return hmac.compare_digest(digest, expected)


# ---------------------------------------------------------------------------
# 面板
# ---------------------------------------------------------------------------


class LoginThrottle:
    """口令登录失败节流。

    面板经隧道暴露在公网，登录接口必然会被扫。scrypt 已经很慢，再加一层计数
    几乎不花成本：同一来源 IP 在窗口内失败次数超限就返回 429；
    另外设一个全局上限，防「换 IP 慢慢猜」。

    注意来源 IP 取 ``CF-Connecting-IP``（Cloudflare 会写，客户端伪造不了），
    否则经隧道过来时所有人看到的都是 127.0.0.1，按 IP 计数等于没计。
    """

    def __init__(self, per_ip: int = 10, window_s: int = 300, global_max: int = 60) -> None:
        self.per_ip = max(1, int(per_ip))
        self.window_s = max(30, int(window_s))
        self.global_max = max(self.per_ip, int(global_max))
        self._lock = threading.Lock()
        self._hits: dict[str, list[float]] = {}
        self._all: list[float] = []

    def _prune(self, now: float) -> None:
        cutoff = now - self.window_s
        for key in list(self._hits):
            kept = [t for t in self._hits[key] if t >= cutoff]
            if kept:
                self._hits[key] = kept
            else:
                del self._hits[key]
        self._all = [t for t in self._all if t >= cutoff]

    def retry_after(self, key: str) -> int:
        """还要等几秒才能再试；0 表示可以试。"""
        now = time.time()
        with self._lock:
            self._prune(now)
            hits = self._hits.get(key, [])
            if len(hits) >= self.per_ip:
                return max(1, int(hits[0] + self.window_s - now))
            if len(self._all) >= self.global_max:
                return max(1, int(self._all[0] + self.window_s - now))
        return 0

    def record_failure(self, key: str) -> None:
        now = time.time()
        with self._lock:
            self._prune(now)
            self._hits.setdefault(key, []).append(now)
            self._all.append(now)

    def clear(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)


class PanelApp:
    """独立 ASGI 应用：挂在自己的 uvicorn 上（127.0.0.1 的另一个端口）。"""

    def __init__(self, cfg, server, tools: list[tuple[str, str]],
                 bots: BotStore, verifier: AccessVerifier | None = None) -> None:
        self.cfg = cfg
        self.settings = cfg.panel_settings
        self.server = server
        self.tools = list(tools or [])
        self.bots = bots
        self.verifier = verifier
        self.passphrase = PassphraseStore(self.settings.passphrase_file)
        self.session_key = hmac.new(bots.pepper, SESSION_LABEL, hashlib.sha256).digest()
        self.log_dir = Path(cfg.log_path)
        self.access_log = self.log_dir / "panel-access.log"
        # 远程审批：待审批队列 / 全局锁 / 面板可改的运行时旋钮都挂在 Server 上，
        # MCP 侧与面板侧共用同一份（同一个进程，不需要跨进程同步）。
        self.remote = server.remote
        self.runtime = server.runtime
        self.tool_lock = server.tool_lock
        self.allowed_hosts = list(cfg.allowed_hosts) + [
            f"{self.settings.host}:{self.settings.port}",
            f"localhost:{self.settings.port}",
            # 面板只监听回环（config 里已强制），所以任何回环端口都放行——
            # 改了端口却忘了同步配置时不该直接 421。公网主机名仍然必须显式列出。
            "127.0.0.1:*", "localhost:*",
        ]
        self.warnings: list[str] = list(cfg.load_warnings) + list(bots.warnings)
        self._check_auth_available()
        self.throttle = LoginThrottle()

    # ------------------------------------------------------------ 启动前检查

    def _check_auth_available(self) -> None:
        has_pass = self.passphrase.configured()
        has_access = self.verifier is not None and self.verifier.configured()
        if not has_pass and not has_access:
            raise PanelDisabled(
                "面板一个鉴权方式都没有，拒绝启动（否则等于把管理界面敞开）：\n"
                f"  * 本地口令文件不存在或为空：{self.settings.passphrase_file}\n"
                "    （生成方法：python panel_passwd.py）\n"
                f"  * Cloudflare Access 未配置：access_team={self.settings.access_team!r} "
                f"access_aud={'已填' if self.settings.access_aud else '空'}\n"
                "配好任意一个再启动。")

    def auth_summary(self) -> dict:
        return {
            "mode": self.settings.auth_mode,
            "passphrase_configured": self.passphrase.configured(),
            "access_configured": bool(self.verifier and self.verifier.configured()),
            "access": self.verifier.status() if self.verifier else None,
            "warnings": self.warnings,
        }

    # ------------------------------------------------------------ 鉴权

    def _authenticate(self, scope) -> tuple[bool, str, str]:
        """返回 (通过?, 身份, 说明)。说明只用于日志，不含任何凭据。"""
        headers = self._headers(scope)
        cookies = self._cookies(scope)
        settings = self.settings

        need_access = (settings.needs_access() and self.verifier is not None
                       and self.verifier.configured())
        need_pass = settings.needs_passphrase() and self.passphrase.configured()

        access_ok, access_who, access_note = False, "", ""
        if need_access:
            token = extract_token(headers, cookies)
            if token:
                try:
                    identity = self.verifier.verify(token)
                    access_ok, access_who = True, identity.email
                    access_note = "access:" + (identity.email or "ok")
                except AccessError as exc:
                    access_note = f"access 校验失败：{exc}"
            else:
                access_note = "缺少 Access JWT"

        pass_ok = False
        if need_pass:
            cookie = cookies.get(COOKIE_NAME, "")
            pass_ok = bool(cookie) and self._session_valid(cookie)

        via_cf = bool(headers.get("cf-ray") or headers.get("cf-connecting-ip"))
        mode = settings.auth_mode
        if mode == "both":
            # 口令始终要；Access 只在「经 Cloudflare 进来」时才强制——
            # 这样本机直连永远进得去，出问题还有修复路径。
            ok = (not need_pass or pass_ok) and (not need_access or not via_cf or access_ok)
        elif mode == "access":
            ok = need_access and access_ok
        elif mode == "passphrase":
            ok = need_pass and pass_ok
        else:  # either
            ok = (need_access and access_ok) or (need_pass and pass_ok)

        who = access_who if access_ok else ("local" if pass_ok else "")
        note = access_note or ("passphrase-session" if pass_ok else "未通过")
        if not ok and need_pass and not pass_ok:
            note += " / 无有效口令会话"
        return ok, who, note

    # ------------------------------------------------------------ cookie

    def _session_cookie(self, who: str) -> str:
        payload = json.dumps({"who": who, "exp": int(time.time()) + self.settings.session_ttl_s},
                             separators=(",", ":"))
        blob = base64.urlsafe_b64encode(payload.encode("utf-8")).rstrip(b"=").decode("ascii")
        sig = hmac.new(self.session_key, blob.encode("ascii"), hashlib.sha256).hexdigest()
        return f"{blob}.{sig}"

    def _session_valid(self, value: str) -> bool:
        try:
            blob, sig = value.rsplit(".", 1)
        except ValueError:
            return False
        expected = hmac.new(self.session_key, blob.encode("ascii"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return False
        try:
            data = json.loads(base64.urlsafe_b64decode(blob + "=" * (-len(blob) % 4)))
        except Exception:
            return False
        return isinstance(data, dict) and float(data.get("exp") or 0) > time.time()

    def _cookie_header(self, value: str, max_age: int, scope) -> tuple[bytes, bytes]:
        secure = self._headers(scope).get("x-forwarded-proto", "").lower() == "https"
        parts = [f"{COOKIE_NAME}={value}", "Path=/", "HttpOnly", "SameSite=Lax",
                 f"Max-Age={max_age}"]
        if secure:
            parts.append("Secure")
        return (b"set-cookie", "; ".join(parts).encode("latin-1"))

    # ------------------------------------------------------------ ASGI

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] == "lifespan":
            await self._lifespan(receive, send)
            return
        if scope["type"] != "http":
            return

        start = time.perf_counter()
        path = (scope.get("path") or "/").rstrip("/") or "/"
        method = (scope.get("method") or "GET").upper()
        captured: dict = {"status": 500}
        who = ""

        try:
            host = self._headers(scope).get("host", "")
            if not _host_ok(host, self.allowed_hosts):
                await self._json(send, captured, 421, {"error": "invalid_host"})
                return

            if path == "/healthz":
                # 纯存活探测，不含任何数据；面板真正的数据都在 /api/* 后面。
                await self._json(send, captured, 200, {"status": "ok"})
                return

            if path in ("/", "/index.html") and method == "GET":
                body = PAGE.encode("utf-8")
                await self._bytes(send, captured, 200, body,
                                  [(b"content-type", b"text/html; charset=utf-8")])
                return

            # PWA 外壳：manifest / 图标 / service worker 都不含数据，和页面一样免鉴权
            # （否则「添加到主屏幕」时拿不到图标，也装不成独立窗口）。
            if path == "/favicon.ico":
                await self._bytes(send, captured, 200, _icon_png(64),
                                  [(b"content-type", b"image/png"),
                                   (b"cache-control", b"public, max-age=86400")])
                return
            if path == "/manifest.webmanifest" and method == "GET":
                await self._bytes(send, captured, 200,
                                  json.dumps(_manifest(), ensure_ascii=False).encode("utf-8"),
                                  [(b"content-type", b"application/manifest+json; charset=utf-8")])
                return
            if path == "/sw.js" and method == "GET":
                await self._bytes(send, captured, 200, SERVICE_WORKER.encode("utf-8"),
                                  [(b"content-type", b"application/javascript; charset=utf-8")])
                return
            if path in ("/icon-192.png", "/icon-512.png", "/apple-touch-icon.png"):
                size = {"icon-192.png": 192, "icon-512.png": 512,
                        "apple-touch-icon.png": 180}[path.lstrip("/")]
                await self._bytes(send, captured, 200, _icon_png(size),
                                  [(b"content-type", b"image/png"),
                                   (b"cache-control", b"public, max-age=86400")])
                return

            if path == "/api/login" and method == "POST":
                await self._login(scope, receive, send, captured)
                return

            ok, who, note = self._authenticate(scope)
            client_ip = self._client_ip(scope)
            if not ok:
                await self._json(send, captured, 401,
                                 {"error": "unauthorized", "message": "需要管理口令或 Cloudflare Access"},
                                 extra=[(b"www-authenticate", b"Bearer")])
                return
            set_token_name("panel")
            set_client_ip(client_ip)

            if path == "/api/session" and method == "GET":
                await self._json(send, captured, 200, {
                    "who": who or "local",
                    "auth": self.auth_summary(),
                    "token_prefix": self.settings.tool_prefix or "",
                    "bots_file": str(self.settings.bots_file),
                })
                return
            if path == "/api/logout" and method == "POST":
                await self._json(send, captured, 200, {"ok": True},
                                 extra=[self._cookie_header("", 0, scope)])
                return
            if path == "/api/tools" and method == "GET":
                await self._json(send, captured, 200, self._tools_payload())
                return
            if path == "/api/audit" and method == "GET":
                query = parse_qs((scope.get("query_string") or b"").decode("latin-1"))
                limit = _int(query.get("limit"), 120, 1, 500)
                await self._json(send, captured, 200, {"events": self._recent_audit(
                    (query.get("bot") or [""])[0] or None, limit,
                    tool=(query.get("tool") or [""])[0] or None,
                    result=(query.get("result") or [""])[0] or None)})
                return
            if path == "/api/approvals" and method == "GET":
                await self._json(send, captured, 200, self._approvals_payload())
                return
            if path == "/api/approvals/decide" and method == "POST":
                if not self._csrf_ok(scope):
                    await self._json(send, captured, 403, {"error": "csrf"})
                    return
                await self._decide_approval(receive, send, captured, who)
                return
            if path == "/api/approvals/deny-all" and method == "POST":
                if not self._csrf_ok(scope):
                    await self._json(send, captured, 403, {"error": "csrf"})
                    return
                count = self.remote.deny_all(actor=who or "panel")
                self.server.audit.note("panel_approval_deny_all", actor=who or "panel",
                                       count=count)
                await self._json(send, captured, 200, {"denied": count})
                return
            if path == "/api/settings":
                if method == "GET":
                    await self._json(send, captured, 200, self._settings_payload())
                    return
                if method == "PATCH":
                    if not self._csrf_ok(scope):
                        await self._json(send, captured, 403, {"error": "csrf"})
                        return
                    await self._update_settings(receive, send, captured, who)
                    return
            if path == "/api/notify/test" and method == "POST":
                if not self._csrf_ok(scope):
                    await self._json(send, captured, 403, {"error": "csrf"})
                    return
                result = send_test_notification(self.runtime, self.public_url)
                self.server.audit.note("panel_notify_test", actor=who or "panel",
                                       ok=bool(result.get("ok")))
                await self._json(send, captured, 200 if result.get("ok") else 400,
                                 result)
                return

            if path == "/api/bots":
                if method == "GET":
                    await self._json(send, captured, 200, self._bots_payload())
                    return
                if method == "POST":
                    if not self._csrf_ok(scope):
                        await self._json(send, captured, 403, {"error": "csrf"})
                        return
                    await self._create_bot(receive, send, captured)
                    return

            bot_id, tail = _split_bot_path(path)
            if bot_id:
                if method == "GET" and tail == "":
                    bot = self.bots.get(bot_id)
                    if bot is None:
                        await self._json(send, captured, 404, {"error": "not_found"})
                        return
                    await self._json(send, captured, 200, {"bot": bot.public()})
                    return
                if method == "GET" and tail == "audit":
                    bot = self.bots.get(bot_id)
                    if bot is None:
                        await self._json(send, captured, 404, {"error": "not_found"})
                        return
                    await self._json(send, captured, 200,
                                     {"bot": bot.public(),
                                      "events": self._recent_audit(bot.name, 80)})
                    return
                if not self._csrf_ok(scope):
                    await self._json(send, captured, 403, {"error": "csrf"})
                    return
                if method == "PATCH" and tail == "":
                    await self._update_bot(bot_id, receive, send, captured)
                    return
                if method == "POST" and tail == "rotate":
                    await self._rotate_bot(bot_id, send, captured)
                    return
                if method == "DELETE" and tail == "":
                    await self._delete_bot(bot_id, receive, send, captured)
                    return

            await self._json(send, captured, 404, {"error": "not_found", "path": path})
        except Exception as exc:  # 面板崩了也不能把 uvicorn 的 worker 带下去
            try:
                await self._json(send, captured, 500,
                                 {"error": "internal", "message": f"{type(exc).__name__}"})
            except Exception:
                pass
        finally:
            self._log(method, path, captured.get("status", 0), start,
                      self._client_ip(scope), who)

    async def _lifespan(self, receive, send) -> None:
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return

    # ------------------------------------------------------------ 处理函数

    async def _login(self, scope, receive, send, captured) -> None:
        if not self._csrf_ok(scope):
            await self._json(send, captured, 403, {"error": "csrf"})
            return
        if not self.passphrase.configured():
            await self._json(send, captured, 400,
                             {"error": "passphrase_not_configured",
                              "message": "本机没有配置管理口令；请改用 Cloudflare Access 登录。"})
            return

        client = self._client_ip(scope)
        wait = self.throttle.retry_after(client)
        if wait:
            set_token_name("panel")
            set_client_ip(client)
            self.server.audit.note("panel_login", result="throttled",
                                   retry_after_s=wait)
            await self._json(send, captured, 429,
                             {"error": "too_many_attempts",
                              "message": f"失败次数过多，请 {wait} 秒后再试。"},
                             extra=[(b"retry-after", str(wait).encode())])
            return

        data = await self._read_json(receive)
        if not self.passphrase.verify(str(data.get("passphrase") or "")):
            self.throttle.record_failure(client)
            set_token_name("panel")
            set_client_ip(client)
            self.server.audit.note("panel_login", result="failed")
            await self._json(send, captured, 401,
                             {"error": "bad_passphrase", "message": "口令不正确"})
            return
        self.throttle.clear(client)
        set_token_name("panel")
        set_client_ip(client)
        self.server.audit.note("panel_login", result="ok")
        await self._json(send, captured, 200, {"ok": True},
                         extra=[self._cookie_header(
                             self._session_cookie("local"),
                             self.settings.session_ttl_s, scope)])

    async def _create_bot(self, receive, send, captured) -> None:
        data = await self._read_json(receive)
        try:
            expires = parse_when(data.get("expires_at")) if data.get("expires_at") else None
            public, token = self.bots.create(
                str(data.get("name") or ""),
                allow=data.get("allow"),
                expires_at=expires,
                note=str(data.get("note") or ""),
                protected=bool(data.get("protected")),
            )
        except (BotStoreError, ValueError) as exc:
            await self._json(send, captured, 400, {"error": "bad_request", "message": str(exc)})
            return
        self.server.audit.note("panel_bot_create", bot=public["name"],
                               allow=public["allow"], expires_at=public["expires_at"])
        # 明文 token 只在这里出现一次
        await self._json(send, captured, 201, {"bot": public, "token": token})

    async def _rotate_bot(self, bot_id: str, send, captured) -> None:
        try:
            public, token = self.bots.rotate(bot_id)
        except BotStoreError as exc:
            await self._json(send, captured, 404, {"error": "not_found", "message": str(exc)})
            return
        self.server.audit.note("panel_bot_rotate", bot=public["name"])
        await self._json(send, captured, 200, {"bot": public, "token": token})

    async def _update_bot(self, bot_id: str, receive, send, captured) -> None:
        data = await self._read_json(receive)
        changes = {key: data[key] for key in ("allow", "expires_at", "enabled", "note")
                   if key in data}
        try:
            public = self.bots.update(bot_id, changes)
        except (BotStoreError, ValueError) as exc:
            await self._json(send, captured, 400, {"error": "bad_request", "message": str(exc)})
            return
        self.server.audit.note("panel_bot_update", bot=public["name"],
                               changed=sorted(changes), allow=public["allow"],
                               enabled=public["enabled"], expires_at=public["expires_at"])
        await self._json(send, captured, 200, {"bot": public})

    async def _delete_bot(self, bot_id: str, receive, send, captured) -> None:
        data = await self._read_json(receive)
        try:
            snapshot = self.bots.delete(bot_id, str(data.get("confirm") or ""))
        except BotStoreError as exc:
            message = str(exc)
            code = 404 if "不存在" in message else 400
            await self._json(send, captured, code, {"error": "delete_refused",
                                                    "message": message})
            return
        self.server.audit.note("panel_bot_delete", bot=snapshot["name"])
        await self._json(send, captured, 200, {"deleted": snapshot["name"]})

    # ------------------------------------------------------------ 远程审批

    @property
    def public_url(self) -> str:
        base = (self.settings.public_url or "").rstrip("/")
        return base or f"http://{self.settings.host}:{self.settings.port}"

    def _approvals_payload(self) -> dict:
        """待审批 + 最近已处理 + 全局锁 + 同类放行 + 旧的轮询式审批单。

        「旧的轮询式」指的是 ``state/approvals.json`` 里那些：危险命令走的还是那条
        路（工具立刻返回 ``pending_approval``，由调用方自己回来问结果）。放在同一个
        页面上是为了「所有要人点头的事都在一处」，但它们**不阻塞任何请求**。
        """
        runtime = self.runtime.get()
        legacy = []
        try:
            legacy = [a.as_dict() for a in self.server.approvals.list_pending()]
        except Exception:
            legacy = []
        return {
            "pending": [item.as_dict() for item in self.remote.list_pending()],
            "recent": [item.as_dict() for item in self.remote.list_recent(30)],
            "legacy": legacy,
            "auto": self.remote.list_auto(),
            "lock": self.tool_lock.snapshot(),
            "wait_s": int(runtime.get("approval_wait_s") or 120),
            "auto_minutes": int(self.settings.auto_allow_minutes),
            "ntfy_topic_set": bool(str(runtime.get("ntfy_topic") or "")),
            "panel_url": self.public_url,
        }

    async def _decide_approval(self, receive, send, captured, who: str) -> None:
        data = await self._read_json(receive)
        approval_id = str(data.get("id") or "")
        approve = str(data.get("decision") or "").lower() in ("approve", "allow", "ok")
        remember = 0
        if approve and data.get("remember_minutes"):
            try:
                remember = max(0, min(24 * 60, int(data["remember_minutes"])))
            except (TypeError, ValueError):
                remember = 0
        actor = who or "local"
        item = self.remote.decide(approval_id, approve, actor=actor, via="panel",
                                  remember_minutes=remember)
        if item is None:
            # 也可能是旧通道（state/approvals.json）里的单子
            legacy = self.server.approvals.decide(approval_id, approve, actor=actor)
            if legacy is None:
                await self._json(send, captured, 404, {"error": "not_found",
                                                       "message": "审批单不存在或已过期"})
                return
            self.server.audit.approval("approved" if approve else "rejected",
                                       legacy.approval_id, legacy.tool,
                                       actor=actor, result=legacy.status)
            await self._json(send, captured, 200, {"ok": True, "status": legacy.status,
                                                   "approval_id": legacy.approval_id})
            return
        await self._json(send, captured, 200, {
            "ok": True, "status": item.status, "approval_id": item.approval_id,
            "decided_by": item.decided_by, "remember_minutes": item.remember_minutes,
        })

    def _settings_payload(self) -> dict:
        payload = self.runtime.public()
        payload.update({
            "auto_allow_minutes": int(self.settings.auto_allow_minutes),
            "lock_wait_s": int(self.settings.lock_wait_s),
            "panel_url": self.public_url,
            "tool_prefix": self.settings.tool_prefix or "",
            "auth_mode": self.settings.auth_mode,
            "bots_file": str(self.settings.bots_file),
            "settings_file": str(self.settings.settings_file),
        })
        return payload

    async def _update_settings(self, receive, send, captured, who: str) -> None:
        data = await self._read_json(receive)
        try:
            updated = self.runtime.update(data)
        except ValueError as exc:
            await self._json(send, captured, 400, {"error": "bad_request",
                                                   "message": str(exc)})
            return
        self.server.audit.note("panel_settings_update", actor=who or "local",
                               changed=sorted(k for k in data if k != "ntfy_token"),
                               ntfy_token_changed="ntfy_token" in data)
        payload = self.runtime.public()
        payload["ok"] = True
        payload["approval_wait_s"] = int(updated.get("approval_wait_s") or 120)
        await self._json(send, captured, 200, payload)

    # ------------------------------------------------------------ 数据组装

    def _tools_payload(self) -> dict:
        prefix = self.settings.tool_prefix or ""
        registered = {name: desc for name, desc in self.tools}
        seen: set[str] = set()
        groups: list[dict] = []
        for label, note, names in TOOL_GROUPS:
            items = []
            for name in names:
                if name not in registered:
                    continue
                seen.add(name)
                items.append(self._tool_item(name, registered[name], prefix))
            if items:
                groups.append({"label": label, "note": note, "tools": items})
        others = [self._tool_item(name, desc, prefix)
                  for name, desc in self.tools if name not in seen]
        if others:
            groups.append({"label": "其他", "note": "未分组的新工具，默认要审批",
                           "tools": others})
        return {"prefix": prefix, "groups": groups,
                "default_allow": list(DEFAULT_ALLOW),
                "default_policy": dict(DEFAULT_POLICY),
                "readonly": list(READONLY_TOOLS),
                "exclusive": sorted(EXCLUSIVE_TOOLS),
                "high_risk": sorted(HIGH_RISK_TOOLS),
                "levels": list(LEVELS),
                "total": len(self.tools)}

    @staticmethod
    def _tool_item(name: str, description: str, prefix: str) -> dict:
        return {
            "internal": name,
            "exposed": prefix + name,
            "description": description,
            "default": name in DEFAULT_ALLOW,
            "default_level": DEFAULT_POLICY.get(name, LEVEL_ASK),
            "exclusive": name in EXCLUSIVE_TOOLS,
            "high_risk": name in HIGH_RISK_TOOLS,
        }

    def _bots_payload(self) -> dict:
        """bot 列表 + 每个 bot 对**每个已注册工具**的实际档位。

        档位在服务端算好再下发，前端就不用重复实现一遍「白名单 + 默认档」的推导
        （两边实现不一致的话，面板显示的和实际生效的就会不一样）。
        """
        names = [name for name, _ in self.tools]
        lock = self.tool_lock.snapshot()
        holder = (lock.get("holder") or {}).get("bot")
        waiting = {entry["bot"] for entry in lock.get("queue") or []}
        today = self._today_calls()
        bots = []
        for item in self.bots.list_public():
            bot = self.bots.get(item["id"])
            levels = {}
            if bot is not None:
                levels = {name: bot.level_for(name) for name in names}
            entry = dict(item)
            entry["levels"] = levels
            entry["holding_lock"] = bool(holder and holder == item["name"])
            entry["in_queue"] = item["name"] in waiting
            entry["today_calls"] = int(today.get(item["name"], 0))
            bots.append(entry)
        return {
            "bots": bots,
            "default_allow": list(DEFAULT_ALLOW),
            "protected_names": sorted(b["name"] for b in bots if b["protected"]),
            "lock": lock,
        }

    def _today_calls(self) -> dict[str, int]:
        """今天的调用次数（按 bot 名）。只扫今天这一个审计文件。"""
        counts: dict[str, int] = {}
        path = self.log_dir / f"audit-{time.strftime('%Y-%m-%d')}.jsonl"
        try:
            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        item = json.loads(line)
                    except ValueError:
                        continue
                    if item.get("kind") != "tool_call":
                        continue
                    name = str(item.get("token") or "-")
                    counts[name] = counts.get(name, 0) + 1
        except OSError:
            return counts
        return counts

    def _recent_audit(self, name: str | None, limit: int,
                      tool: str | None = None, result: str | None = None) -> list[dict]:
        """读审计日志里最近的调用 / 审批记录。

        只回传面板需要的字段：**不带 args**（审计里 args 已经被遮蔽，但面板根本
        不需要它们，不传更干净）。token 值本来就不在日志里。
        """
        files = sorted(self.log_dir.glob("audit-*.jsonl"))[-2:]
        rows: list[dict] = []
        for path in files:
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            item = json.loads(line)
                        except ValueError:
                            continue
                        if item.get("kind") not in ("tool_call", "approval"):
                            continue
                        if name and item.get("token") != name:
                            continue
                        if tool and item.get("tool") != tool:
                            continue
                        decision = item.get("decision") or item.get("action", "")
                        if result and decision != result:
                            continue
                        rows.append({
                            "ts": item.get("ts", ""),
                            "bot": item.get("token", "-"),
                            "tool": item.get("tool", ""),
                            "kind": item.get("kind", ""),
                            "decision": decision,
                            "level": item.get("level", ""),
                            "summary": item.get("summary", ""),
                            "client": item.get("client", ""),
                            "ms": item.get("duration_ms"),
                            # 审批决定的「谁批的」——需求要求可追溯
                            "actor": item.get("actor", ""),
                            "approval_id": item.get("approval_id", ""),
                        })
            except OSError:
                continue
        return rows[-limit:]

    # ------------------------------------------------------------ 小工具

    @staticmethod
    def _client_ip(scope) -> str:
        """真实来源 IP。

        经隧道进来时对端永远是 127.0.0.1，所以优先用 Cloudflare 写的
        ``CF-Connecting-IP``（客户端伪造不了），其次 ``X-Forwarded-For`` 的第一段，
        最后才退回对端地址。只用于日志与登录节流，**不作授权依据**。
        """
        headers = PanelApp._headers(scope)
        for key in ("cf-connecting-ip", "x-real-ip"):
            value = (headers.get(key) or "").strip()
            if value:
                return value
        forwarded = (headers.get("x-forwarded-for") or "").split(",")[0].strip()
        if forwarded:
            return forwarded
        return (scope.get("client") or ("", 0))[0]

    @staticmethod
    def _headers(scope) -> dict[str, str]:
        return {k.decode("latin-1").lower(): v.decode("latin-1")
                for k, v in scope.get("headers", [])}

    @staticmethod
    def _cookies(scope) -> dict[str, str]:
        out: dict[str, str] = {}
        for key, value in scope.get("headers", []):
            if key.lower() != b"cookie":
                continue
            for chunk in value.decode("latin-1").split(";"):
                if "=" in chunk:
                    name, _, val = chunk.strip().partition("=")
                    out[name] = val
        return out

    @staticmethod
    def _csrf_ok(scope) -> bool:
        return PanelApp._headers(scope).get(CSRF_HEADER) == "1"

    @staticmethod
    async def _read_body(receive) -> bytes:
        chunks: list[bytes] = []
        more = True
        total = 0
        while more:
            message = await receive()
            chunk = message.get("body", b"")
            total += len(chunk)
            if total > MAX_BODY:
                raise ValueError("请求体过大")
            chunks.append(chunk)
            more = message.get("more_body", False)
        return b"".join(chunks)

    async def _read_json(self, receive) -> dict:
        try:
            body = await self._read_body(receive)
        except ValueError:
            return {}
        if not body:
            return {}
        try:
            data = json.loads(body.decode("utf-8"))
        except Exception:
            return {}
        return data if isinstance(data, dict) else {}

    @staticmethod
    async def _bytes(send, captured, status: int, body: bytes, headers) -> None:
        captured["status"] = status
        out = list(headers) + [(b"content-length", str(len(body)).encode())]
        await send({"type": "http.response.start", "status": status, "headers": out})
        await send({"type": "http.response.body", "body": body})

    async def _json(self, send, captured, status: int, payload: dict, extra=None) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers = [(b"content-type", b"application/json; charset=utf-8")] + list(extra or [])
        await self._bytes(send, captured, status, body, headers)

    def _log(self, method: str, path: str, status: int, start: float,
             client: str, who: str) -> None:
        """面板访问日志。**绝不记口令、cookie、token 值。**"""
        try:
            self.log_dir.mkdir(parents=True, exist_ok=True)
            entry = {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()),
                "method": method,
                "path": path,
                "status": status,
                "ms": int((time.perf_counter() - start) * 1000),
                "client": client,
                "who": who,
            }
            with open(self.access_log, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception:
            pass


def _host_ok(host: str, patterns: list[str]) -> bool:
    from .app import host_matches
    return host_matches(host, patterns)


def _split_bot_path(path: str) -> tuple[str, str]:
    """/api/bots/<id>[/<tail>] -> (id, tail)。不匹配返回 ("", "")。"""
    parts = [p for p in path.split("/") if p]
    if len(parts) < 3 or parts[0] != "api" or parts[1] != "bots":
        return "", ""
    bot_id = parts[2]
    tail = parts[3] if len(parts) > 3 else ""
    if len(parts) > 4:
        return "", ""
    return bot_id, tail


def _int(value, default: int, low: int, high: int) -> int:
    try:
        number = int(value[0] if isinstance(value, list) else value)
    except (TypeError, ValueError, IndexError):
        return default
    return max(low, min(high, number))


# ---------------------------------------------------------------------------
# PWA 外壳：图标 / manifest / service worker
# ---------------------------------------------------------------------------

_ICON_CACHE: dict[int, bytes] = {}


def _icon_png(size: int) -> bytes:
    """画一枚应用图标（深底 + 蓝色圆角方块 + 白色对勾）。

    用 Pillow 现画而不是塞一个二进制文件进仓库：图标只有几十行，改颜色改形状都
    在一个地方，也不用把 base64 贴进源码。
    """
    cached = _ICON_CACHE.get(size)
    if cached is not None:
        return cached
    try:
        from PIL import Image, ImageDraw

        image = Image.new("RGBA", (size, size), (15, 17, 21, 255))
        draw = ImageDraw.Draw(image)
        pad = int(size * 0.15)
        draw.rounded_rectangle([pad, pad, size - pad, size - pad],
                               radius=int(size * 0.24), fill=(79, 140, 255, 255))
        width = max(2, int(size * 0.08))
        draw.line([(size * 0.31, size * 0.52), (size * 0.44, size * 0.67)],
                  fill=(255, 255, 255, 255), width=width, joint="curve")
        draw.line([(size * 0.44, size * 0.67), (size * 0.70, size * 0.35)],
                  fill=(255, 255, 255, 255), width=width, joint="curve")
        buffer = io.BytesIO()
        image.save(buffer, format="PNG", optimize=True)
        data = buffer.getvalue()
    except Exception:
        # 画不出来也不能让页面挂掉：给一个 1x1 的透明 PNG
        data = base64.b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")
    _ICON_CACHE[size] = data
    return data


def _manifest() -> dict:
    return {
        "name": "Window MCP 远程审批",
        "short_name": "MCP 审批",
        "description": "批准或拒绝远程 bot 对这台电脑发起的工具调用。",
        "lang": "zh-CN",
        "start_url": "/",
        "scope": "/",
        "display": "standalone",
        "orientation": "portrait",
        "background_color": "#0f1115",
        "theme_color": "#0f1115",
        "icons": [
            {"src": "/icon-192.png", "sizes": "192x192", "type": "image/png",
             "purpose": "any"},
            {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png",
             "purpose": "any"},
            {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png",
             "purpose": "maskable"},
        ],
    }


# 只为了让浏览器认为「可安装」。**故意不缓存任何响应**：审批页面必须永远是最新的，
# 缓存住一个旧外壳，等于手机上看到的和服务器上的不是一回事。
SERVICE_WORKER = """\
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', () => {});
"""


# ---------------------------------------------------------------------------
# 页面（单文件、无外部依赖，手机优先）
# ---------------------------------------------------------------------------

PAGE = r"""<!doctype html>
<html lang="zh-CN" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="color-scheme" content="dark light">
<meta name="theme-color" content="#0f1115">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="MCP 审批">
<link rel="manifest" href="/manifest.webmanifest">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="icon" href="/favicon.ico">
<title>远程审批 · Window MCP</title>
<style>
*{box-sizing:border-box}
:root{
  --radius:16px; --tap:44px;
  --accent:#4f8cff; --ok:#22c55e; --danger:#ef4444; --warn:#f59e0b;
  --bg:#0f1115; --card:#181b22; --line:#262b34; --fg:#e8eaee; --muted:#8b95a5;
  --accent-soft:rgba(79,140,255,.16); --ok-soft:rgba(34,197,94,.18);
  --warn-soft:rgba(245,158,11,.18); --danger-soft:rgba(239,68,68,.18);
}
html[data-theme="light"]{
  --bg:#f4f5f7; --card:#ffffff; --line:#e4e7ec; --fg:#171a1f; --muted:#667085;
}
@media (prefers-color-scheme:light){
  html[data-theme="auto"]{
    --bg:#f4f5f7; --card:#ffffff; --line:#e4e7ec; --fg:#171a1f; --muted:#667085;
  }
}
html,body{margin:0;padding:0}
body{
  background:var(--bg); color:var(--fg); font-size:15px; line-height:1.5;
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",
    "PingFang SC","Hiragino Sans GB","Microsoft YaHei",sans-serif;
  -webkit-text-size-adjust:100%; -webkit-tap-highlight-color:transparent;
  padding:0; overscroll-behavior-y:none;
}
code,.mono,pre,.num,input[type=number]{
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
}
.hidden{display:none !important}
.muted{color:var(--muted);font-size:13px}
.grow{flex:1;min-width:0}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}

/* ---------- 外壳：手机底部标签栏 / 桌面左侧栏 ---------- */
.content{padding:0 0 calc(78px + env(safe-area-inset-bottom))}
main{max-width:720px;margin:0 auto;padding:14px}
header{
  position:sticky;top:0;z-index:6;background:var(--bg);
  border-bottom:1px solid var(--line);display:flex;align-items:center;gap:10px;
  padding:calc(10px + env(safe-area-inset-top)) 14px 10px;
}
header h1{font-size:17px;margin:0;font-weight:600;white-space:nowrap;overflow:hidden;
  text-overflow:ellipsis}
header .sub{font-size:12px;color:var(--muted);white-space:nowrap;overflow:hidden;
  text-overflow:ellipsis}
.iconbtn{min-width:var(--tap);min-height:var(--tap);border-radius:12px;border:1px solid var(--line);
  background:var(--card);color:var(--fg);font-size:17px;line-height:1}

.rail{position:fixed;left:0;right:0;bottom:0;z-index:7;display:flex;background:var(--card);
  border-top:1px solid var(--line);padding-bottom:env(safe-area-inset-bottom)}
.rail .brand{display:none}
.rail button.tab{flex:1;min-height:58px;border:0;background:none;color:var(--muted);
  display:flex;flex-direction:column;align-items:center;justify-content:center;gap:2px;
  font:inherit;font-size:11px;padding:6px 0;position:relative}
.rail button.tab .ic{font-size:19px;line-height:1}
.rail button.tab.on{color:var(--accent)}
.rail button.tab .pill{position:absolute;top:4px;left:calc(50% + 6px);min-width:18px;
  height:18px;border-radius:9px;background:var(--warn);color:#1b1f24;font-size:11px;
  font-weight:700;display:none;align-items:center;justify-content:center;padding:0 5px}
.rail button.tab .pill.show{display:flex}

@media (min-width:900px){
  .rail{top:0;bottom:0;right:auto;width:216px;flex-direction:column;align-items:stretch;
    border-top:0;border-right:1px solid var(--line);padding:16px 12px;gap:4px}
  .rail .brand{display:block;padding:6px 10px 14px}
  .rail .brand b{display:block;font-size:15px}
  .rail .brand span{font-size:12px;color:var(--muted)}
  .rail button.tab{flex:0 0 auto;flex-direction:row;justify-content:flex-start;gap:10px;
    font-size:14px;min-height:var(--tap);padding:0 12px;border-radius:12px}
  .rail button.tab .ic{font-size:17px}
  .rail button.tab.on{background:var(--accent-soft)}
  .rail button.tab .pill{position:static;margin-left:auto}
  .content{margin-left:216px;padding-bottom:24px}
}

/* ---------- 通用组件 ---------- */
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);
  padding:14px;margin:0 0 12px}
.card h2{font-size:15px;margin:0 0 10px;font-weight:600;display:flex;align-items:center;gap:8px}
button{font:inherit;color:var(--fg)}
.btn{min-height:var(--tap);padding:11px 16px;border-radius:12px;border:1px solid var(--line);
  background:var(--card)}
.btn.primary{background:var(--accent);border-color:var(--accent);color:#fff}
.btn.ok{background:var(--ok);border-color:var(--ok);color:#04220f}
.btn.danger{background:transparent;border-color:var(--danger);color:var(--danger)}
.btn.ghost{background:transparent}
.btn.small{min-height:var(--tap);padding:9px 12px;font-size:13px;border-radius:12px}
.btn.big{flex:1;min-height:52px;font-size:16px;font-weight:600}
.btn:disabled{opacity:.45}
input,select,textarea{width:100%;min-height:var(--tap);padding:10px 12px;font:inherit;
  color:var(--fg);background:var(--bg);border:1px solid var(--line);border-radius:12px}
label{display:block;font-size:13px;color:var(--muted);margin:12px 0 4px}
.badge{display:inline-block;font-size:12px;padding:2px 9px;border-radius:999px;
  border:1px solid var(--line);color:var(--muted)}
.badge.ok{color:var(--ok);border-color:var(--ok);background:var(--ok-soft)}
.badge.off{color:var(--danger);border-color:var(--danger);background:var(--danger-soft)}
.badge.exp{color:var(--warn);border-color:var(--warn);background:var(--warn-soft)}
.warn{background:var(--warn-soft);border:1px solid var(--warn);border-radius:12px;
  padding:10px 12px;font-size:13px;margin-bottom:12px}
.empty{text-align:center;color:var(--muted);padding:26px 10px;font-size:14px}
.empty .big{font-size:34px;display:block;margin-bottom:8px;opacity:.7}

/* ---------- 审批卡片 ---------- */
.appr{border-left:3px solid var(--warn)}
.appr .top{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.chip{font-size:12px;font-weight:600;padding:3px 10px;border-radius:999px;
  background:var(--accent-soft);color:var(--accent);max-width:46%;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tool{font-size:13px;background:var(--bg);border:1px solid var(--line);
  padding:2px 8px;border-radius:8px}
.appr .sum{margin:10px 0;font-size:14px;word-break:break-word}
.thumb{border-radius:12px;overflow:hidden;border:1px solid var(--line);background:#000;
  margin:8px 0;max-height:200px}
.thumb img{display:block;width:100%;height:auto}
.bar{height:6px;border-radius:999px;background:var(--line);overflow:hidden;margin:10px 0 4px}
.bar i{display:block;height:100%;width:0;background:var(--warn)}
.acts{display:flex;gap:10px;margin-top:10px}
details.more{margin-top:10px;border-top:1px solid var(--line);padding-top:10px}
details.more>summary,details.fold>summary{cursor:pointer;font-size:13px;color:var(--muted);
  list-style:none}
details.more>summary::-webkit-details-marker,details.fold>summary::-webkit-details-marker{
  display:none}
details.more>summary::before,details.fold>summary::before{content:"\25B8  "}
details.more[open]>summary::before,details.fold[open]>summary::before{content:"\25BE  "}
details.fold>summary{font-size:14px;color:var(--fg);font-weight:600;margin-bottom:8px}

/* ---------- 三段式切换 ---------- */
.seg{display:flex;gap:4px;background:var(--bg);border:1px solid var(--line);
  border-radius:12px;padding:3px;flex:0 0 auto}
.seg button{flex:1;min-height:var(--tap);min-width:var(--tap);border:0;background:none;
  color:var(--muted);border-radius:9px;font-size:12px;padding:0 6px}
.seg button.on[data-lv="allow"]{background:var(--ok-soft);color:var(--ok);font-weight:600}
.seg button.on[data-lv="ask"]{background:var(--warn-soft);color:var(--warn);font-weight:600}
.seg button.on[data-lv="deny"]{background:var(--danger-soft);color:var(--danger);font-weight:600}
.toolrow{display:flex;align-items:center;gap:10px;padding:8px 0;border-top:1px solid var(--line)}
.toolrow:first-of-type{border-top:0}
.toolrow .nm{min-width:0;flex:1}
.toolrow .nm .n{font-size:13px;word-break:break-all}
.toolrow .nm .d{font-size:11px;color:var(--muted);overflow:hidden;text-overflow:ellipsis;
  white-space:nowrap}

/* ---------- 记录时间线 ---------- */
.tl{list-style:none;margin:0;padding:0}
.tl li{display:flex;gap:10px;padding:10px 0;border-bottom:1px solid var(--line)}
.tl li:last-child{border-bottom:0}
.tl .t{font-size:12px;color:var(--muted);flex:0 0 58px}
.tl .body{min-width:0;flex:1}
.tl .body .l1{font-size:13px;display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.tl .body .l2{font-size:12px;color:var(--muted);word-break:break-word;margin-top:2px}
.d-allow{color:var(--ok)}
.d-ask{color:var(--warn)}
.d-deny{color:var(--danger)}

/* ---------- 弹层 ---------- */
.mask{position:fixed;inset:0;background:rgba(0,0,0,.6);display:none;z-index:30;
  align-items:flex-end;justify-content:center}
.mask.show{display:flex}
.modal{background:var(--card);border:1px solid var(--line);border-radius:16px 16px 0 0;
  width:100%;max-width:720px;max-height:92vh;overflow:auto;padding:16px;
  padding-bottom:calc(16px + env(safe-area-inset-bottom))}
@media (min-width:900px){
  .mask{align-items:center}
  .modal{border-radius:16px;max-height:86vh}
}
.toast{position:fixed;left:50%;bottom:calc(84px + env(safe-area-inset-bottom));
  transform:translateX(-50%);background:#111418;color:#fff;border:1px solid var(--line);
  padding:10px 18px;border-radius:999px;font-size:14px;opacity:0;pointer-events:none;
  transition:opacity .2s;z-index:40;max-width:88vw;text-align:center}
.toast.show{opacity:.97}
.zoom{position:fixed;inset:0;background:rgba(0,0,0,.92);z-index:50;display:none;
  align-items:center;justify-content:center;padding:12px}
.zoom.show{display:flex}
.zoom img{max-width:100%;max-height:100%;border-radius:12px}
pre.token{background:var(--bg);border:1px dashed var(--accent);border-radius:12px;
  padding:12px;font-size:13px;word-break:break-all;white-space:pre-wrap;margin:10px 0}
</style>
</head>
<body>

<div class="rail" id="rail">
  <div class="brand"><b>Window MCP</b><span>远程审批</span></div>
  <button class="tab on" data-view="approvals"><span class="ic">&#9203;</span><span>审批</span>
    <span class="pill" id="tabPill"></span></button>
  <button class="tab" data-view="bots"><span class="ic">&#129302;</span><span>Bots</span></button>
  <button class="tab" data-view="audit"><span class="ic">&#128220;</span><span>记录</span></button>
  <button class="tab" data-view="settings"><span class="ic">&#9881;&#65039;</span><span>设置</span></button>
</div>

<div class="content">
  <header>
    <div class="grow">
      <h1 id="viewTitle">审批</h1>
      <div class="sub" id="viewSub"></div>
    </div>
    <button class="iconbtn" id="themeBtn" title="切换主题">&#127769;</button>
    <button class="iconbtn hidden" id="logoutBtn" title="退出登录">&#9099;</button>
  </header>

  <main>
    <div id="warnings"></div>

    <section id="loginCard" class="card hidden">
      <h2>需要登录</h2>
      <p class="muted">输入本机管理口令。若你是经 Cloudflare Access 进来的，Access 那道门
        已经过了一次，这里再输一次口令即可。</p>
      <label for="pp">管理口令</label>
      <input id="pp" type="password" autocomplete="current-password" placeholder="口令">
      <div class="row" style="margin-top:12px">
        <button class="btn primary grow" id="doLogin">登录</button>
      </div>
      <p class="muted" id="loginErr" style="margin-bottom:0"></p>
    </section>

    <section id="view-approvals" class="view">
      <div id="lockCard"></div>
      <div id="apprList"></div>
      <details class="card fold" id="handledWrap">
        <summary>最近已处理 <span class="muted" id="handledCount"></span></summary>
        <div id="handledList"></div>
      </details>
      <div class="row" id="denyAllRow" style="margin-bottom:12px"></div>
    </section>

    <section id="view-bots" class="view hidden">
      <div class="card">
        <h2>Bots <span class="grow muted" id="botCount"></span>
          <button class="btn small" id="reloadBots">刷新</button></h2>
        <div id="bots"></div>
      </div>
      <button class="btn primary" id="newBot" style="width:100%">新建 bot</button>
    </section>

    <section id="view-audit" class="view hidden">
      <div class="card">
        <h2>筛选</h2>
        <label for="fBot">bot</label>
        <select id="fBot"><option value="">全部</option></select>
        <label for="fTool">工具</label>
        <select id="fTool"><option value="">全部</option></select>
        <label for="fResult">结果</label>
        <select id="fResult">
          <option value="">全部</option>
          <option value="allowed">allowed 放行</option>
          <option value="denied">denied 拒绝</option>
          <option value="awaiting_approval">awaiting_approval 等待批准</option>
          <option value="approval_approved">approval_approved 已批准</option>
          <option value="approval_rejected">approval_rejected 已拒绝</option>
          <option value="approval_timeout">approval_timeout 超时</option>
          <option value="lock_timeout">lock_timeout 排队超时</option>
          <option value="approved">approved 批准</option>
          <option value="rejected">rejected 拒绝</option>
          <option value="timeout">timeout 超时</option>
          <option value="executed">executed 已执行</option>
          <option value="pending_approval">pending_approval 轮询待批</option>
          <option value="error">error 出错</option>
        </select>
        <div class="row" style="margin-top:12px">
          <button class="btn small grow" id="applyFilter">查询</button>
          <button class="btn small" id="clearFilter">重置</button>
        </div>
      </div>
      <div class="card">
        <h2>时间线 <span class="grow muted" id="auditCount"></span>
          <button class="btn small" id="reloadAudit">刷新</button></h2>
        <ul class="tl" id="auditList"></ul>
      </div>
    </section>

    <section id="view-settings" class="view hidden">
      <div class="card">
        <h2>审批</h2>
        <label for="setWait">审批超时（秒）</label>
        <input id="setWait" type="number" min="10" max="600" step="10" inputmode="numeric">
        <p class="muted">bot 调用「审批」档工具时最多阻塞这么久，超时自动拒绝并回一个
          明确的错误。10 ~ 600 秒。</p>
        <label for="setAuto">「同类放行」时长（分钟）</label>
        <input id="setAuto" type="number" min="1" max="1440" inputmode="numeric" disabled>
        <p class="muted">面板上「本 bot N 分钟内同类放行」按钮用的时长，改这个值要重启服务
          （在 <code>config.toml</code> 的 <code>panel.auto_allow_minutes</code>）。</p>
        <div class="row" style="margin-top:12px">
          <button class="btn primary grow" id="saveSettings">保存</button>
        </div>
      </div>

      <div class="card">
        <h2>手机推送（ntfy）</h2>
        <label for="setTopic">私有 topic</label>
        <input id="setTopic" placeholder="例如 wmcp-7f3a9c2b" autocapitalize="off"
          autocomplete="off" spellcheck="false">
        <label for="setServer">ntfy 服务器</label>
        <input id="setServer" placeholder="https://ntfy.sh" autocapitalize="off"
          autocomplete="off" spellcheck="false">
        <p class="muted" id="topicState"></p>
        <div class="row" style="margin-top:12px">
          <button class="btn small grow" id="saveNotify">保存</button>
          <button class="btn small" id="testNotify">发测试通知</button>
        </div>
        <p class="muted">通知里只有 bot 名、工具名和面板链接，<b>不含 token，也不含参数明文</b>。</p>
      </div>

      <div class="card">
        <h2>外观</h2>
        <div class="seg" id="themeSeg">
          <button data-th="dark" data-lv="deny">深色</button>
          <button data-th="light" data-lv="allow">浅色</button>
          <button data-th="auto" data-lv="ask">跟随系统</button>
        </div>
      </div>

      <div class="card">
        <h2>会话</h2>
        <p class="muted" id="whoLine"></p>
        <div class="row" style="margin-top:8px">
          <button class="btn danger grow" id="logoutBtn2">退出登录</button>
        </div>
      </div>
    </section>
  </main>
</div>

<div class="mask" id="mask"><div class="modal" id="modal"></div></div>
<div class="zoom" id="zoom"><img id="zoomImg" alt=""></div>
<div class="toast" id="toast"></div>

<script>
const BASE_TITLE = '远程审批 · Window MCP';
const S = {
  session: null, tools: [], toolIndex: {}, groups: [], bots: [],
  approvals: {pending: [], recent: [], legacy: [], lock: {}, auto: [], wait_s: 120},
  view: 'approvals', deadlines: {}, seen: new Set(), primed: false,
  theme: localStorage.getItem('wmcp-theme') || 'dark', poll: null, tick: null,
  flash: null, audit: {bot: '', tool: '', result: ''}
};
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) =>
  ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const LEVEL_LABEL = {allow: '放行', ask: '审批', deny: '禁止'};
const LEVEL_CLASS = {allow: 'ok', ask: 'exp', deny: 'off'};

/* ---------------------------------------------------------------- 基础 */
let toastTimer;
function toast(msg){
  const el = $('toast');
  el.textContent = msg;
  el.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('show'), 2600);
}
async function api(path, opts){
  const o = Object.assign({credentials: 'same-origin'}, opts || {});
  o.headers = Object.assign({'X-Panel-Request': '1'}, o.headers || {});
  if (o.body && typeof o.body !== 'string'){
    o.body = JSON.stringify(o.body);
    o.headers['Content-Type'] = 'application/json';
  }
  const res = await fetch(path, o);
  let data = null;
  try { data = await res.json(); } catch (e) {}
  return {status: res.status, ok: res.ok, data: data || {}};
}
function openModal(html){ $('modal').innerHTML = html; $('mask').classList.add('show'); }
function closeModal(){ $('mask').classList.remove('show'); }
function askConfirm(title, text, okLabel, danger){
  return new Promise((resolve) => {
    openModal('<h2>' + esc(title) + '</h2><p class="muted">' + esc(text) + '</p>'
      + '<div class="row" style="margin-top:14px"><button class="btn grow" id="cNo">取消</button>'
      + '<button class="btn ' + (danger ? 'danger' : 'primary')
      + ' grow" id="cYes">' + esc(okLabel) + '</button></div>');
    $('cNo').onclick = () => { closeModal(); resolve(false); };
    $('cYes').onclick = () => { closeModal(); resolve(true); };
  });
}
function hhmmss(iso){
  if (!iso) return '';
  const t = String(iso).replace('T', ' ');
  return t.length >= 19 ? t.slice(11, 19) : t;
}
function countdown(seconds){
  const s = Math.max(0, Math.round(seconds));
  return s >= 60 ? (Math.floor(s / 60) + ' 分 ' + (s % 60) + ' 秒') : (s + ' 秒');
}

/* ---------------------------------------------------------------- 主题 */
function applyTheme(theme){
  S.theme = theme;
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('wmcp-theme', theme);
  document.querySelectorAll('#themeSeg button').forEach((b) =>
    b.classList.toggle('on', b.dataset.th === theme));
  const meta = document.querySelector('meta[name=theme-color]');
  if (meta){
    const light = theme === 'light'
      || (theme === 'auto' && matchMedia('(prefers-color-scheme:light)').matches);
    meta.setAttribute('content', light ? '#f4f5f7' : '#0f1115');
  }
}
$('themeBtn').onclick = () => {
  const order = ['dark', 'light', 'auto'];
  applyTheme(order[(order.indexOf(S.theme) + 1) % order.length]);
  toast('主题：' + {dark: '深色', light: '浅色', auto: '跟随系统'}[S.theme]);
};

/* ---------------------------------------------------------------- 视图 */
const TITLES = {approvals: '审批', bots: 'Bots', audit: '记录', settings: '设置'};
function switchView(name){
  S.view = name;
  document.querySelectorAll('.view').forEach((el) =>
    el.classList.toggle('hidden', el.id !== 'view-' + name));
  document.querySelectorAll('.rail button.tab').forEach((b) =>
    b.classList.toggle('on', b.dataset.view === name));
  $('viewTitle').textContent = TITLES[name] || name;
  $('viewSub').textContent = ({
    approvals: '批准或拒绝 bot 发来的操作',
    bots: '每个 bot × 每个工具的三档策略',
    audit: '谁在什么时候调用了什么、结果如何',
    settings: '超时、推送、外观'
  })[name] || '';
  location.hash = name;
  if (name === 'bots') loadBots();
  if (name === 'audit') loadAudit();
  if (name === 'settings') loadSettings();
}
document.querySelectorAll('.rail button.tab').forEach((b) =>
  b.addEventListener('click', () => switchView(b.dataset.view)));

/* ---------------------------------------------------------------- 登录 */
function showLogin(msg){
  $('loginCard').classList.remove('hidden');
  document.querySelectorAll('.view').forEach((el) => el.classList.add('hidden'));
  $('rail').classList.add('hidden');
  $('logoutBtn').classList.add('hidden');
  $('warnings').innerHTML = '';
  $('loginErr').textContent = msg || '';
}
function showApp(){
  $('loginCard').classList.add('hidden');
  $('rail').classList.remove('hidden');
  $('logoutBtn').classList.remove('hidden');
  switchView(location.hash.replace('#', '') || 'approvals');
}
$('doLogin').onclick = async () => {
  const btn = $('doLogin');
  btn.disabled = true;
  $('loginErr').textContent = '校验中…';
  const r = await api('/api/login', {method: 'POST', body: {passphrase: $('pp').value}});
  btn.disabled = false;
  $('pp').value = '';
  if (r.ok){ await boot(); toast('已登录'); }
  else $('loginErr').textContent = r.data.message || '登录失败';
};
$('pp').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('doLogin').click(); });
async function doLogout(){
  await api('/api/logout', {method: 'POST'});
  location.reload();
}
$('logoutBtn').onclick = doLogout;
$('logoutBtn2').onclick = doLogout;

/* ---------------------------------------------------------------- 审批 */
function renderWarnings(list){
  $('warnings').innerHTML = (list || []).map((w) => '<div class="warn">' + esc(w) + '</div>').join('');
}
function lockLine(lock){
  const holder = lock && lock.holder;
  const queue = (lock && lock.queue) || [];
  if (!holder && !queue.length) return '';
  let text = holder
    ? '现在 ' + holder.bot + ' 正在操作鼠标键盘（' + holder.tool + '）'
    : '鼠标键盘空闲';
  if (queue.length) text += '；排队：' + queue.map((q) => q.bot + '(' + q.tool + ')').join('、');
  return text;
}
function apprCard(a){
  const remaining = a.expires_in_s;
  const total = a.total_s || 1;
  const done = Math.min(100, Math.round(((total - remaining) / total) * 100));
  return '<article class="card appr" data-id="' + esc(a.approval_id) + '">'
    + '<div class="top"><span class="chip">' + esc(a.bot) + '</span>'
    + '<code class="tool">' + esc(a.tool) + '</code>'
    + '<span class="muted grow num">' + esc(hhmmss(a.created_at_iso)) + '</span></div>'
    + '<p class="sum">' + esc(a.summary || '（无参数）') + '</p>'
    + (a.thumb ? '<div class="thumb"><img src="' + a.thumb + '" alt="调用前截图"></div>' : '')
    + '<div class="bar"><i data-bar="' + esc(a.approval_id) + '" style="width:' + done + '%"></i></div>'
    + '<div class="muted" data-left="' + esc(a.approval_id) + '">剩余 <span class="num">'
    + esc(countdown(remaining)) + '</span></div>'
    + '<div class="acts"><button class="btn big danger" data-act="deny">拒绝</button>'
    + '<button class="btn big ok" data-act="approve">批准</button></div>'
    + '<details class="more"><summary>更多</summary>'
    + '<div class="row" style="margin-top:8px">'
    + '<button class="btn small" data-act="remember">本 bot ' + S.approvals.auto_minutes
    + ' 分钟内同类放行</button></div>'
    + '<div class="muted" style="margin-top:8px">参数名：'
    + esc((a.arg_keys || []).join('、') || '无') + '</div>'
    + '<div class="muted">审批号：<code>' + esc(a.approval_id) + '</code></div>'
    + '</details></article>';
}
function handledRow(a){
  const cls = a.status === 'approved' ? 'd-allow' : 'd-deny';
  const label = {approved: '已批准', denied: '已拒绝', timeout: '已超时'}[a.status] || a.status;
  return '<div class="row" style="padding:6px 0;border-top:1px solid var(--line)">'
    + '<span class="chip">' + esc(a.bot) + '</span>'
    + '<code class="tool">' + esc(a.tool) + '</code>'
    + '<span class="grow ' + cls + '" style="font-size:13px">' + esc(label) + '</span>'
    + '<span class="muted">' + esc(a.decided_by || '-') + ' · '
    + esc(hhmmss(a.decided_at_iso)) + '</span></div>';
}
function legacyCard(a){
  return '<article class="card appr" style="border-left-color:var(--accent)" data-legacy="'
    + esc(a.approval_id) + '">'
    + '<div class="top"><span class="badge">轮询式</span>'
    + '<code class="tool">' + esc(a.tool) + '</code>'
    + '<span class="muted grow">' + esc(a.created_at_iso || '') + '</span></div>'
    + '<p class="sum">' + esc(a.summary || '') + '</p>'
    + '<div class="muted">这条不阻塞任何请求：调用方自己回来问结果。</div>'
    + '<div class="acts"><button class="btn big danger" data-lact="deny">拒绝</button>'
    + '<button class="btn big ok" data-lact="approve">批准</button></div></article>';
}
function renderApprovals(){
  const data = S.approvals;
  const pending = data.pending || [];
  $('lockCard').innerHTML = lockLine(data.lock)
    ? '<div class="card"><div class="row"><span class="badge exp">全局锁</span>'
      + '<span class="grow">' + esc(lockLine(data.lock)) + '</span></div></div>' : '';
  if (!pending.length && !(data.legacy || []).length){
    $('apprList').innerHTML = '<div class="card empty"><span class="big">&#9989;</span>'
      + '没有待审批<br><span class="muted">'
      + esc(lockLine(data.lock) || '鼠标键盘空闲') + '</span></div>';
  } else {
    $('apprList').innerHTML = pending.map(apprCard).join('')
      + (data.legacy || []).map(legacyCard).join('');
  }
  S.deadlines = {};
  pending.forEach((a) => { S.deadlines[a.approval_id] = Date.now() + a.expires_in_s * 1000; });
  const recent = data.recent || [];
  $('handledCount').textContent = recent.length ? recent.length + ' 条' : '';
  $('handledList').innerHTML = recent.length ? recent.map(handledRow).join('')
    : '<p class="muted">还没有处理过任何审批。</p>';
  const pill = $('tabPill');
  pill.textContent = pending.length;
  pill.classList.toggle('show', pending.length > 0);
  $('denyAllRow').innerHTML = pending.length > 1
    ? '<button class="btn small danger" id="denyAll">全部拒绝（' + pending.length + '）</button>' : '';
  if ($('denyAll')) $('denyAll').onclick = async () => {
    if (!await askConfirm('全部拒绝', '会拒绝当前 ' + pending.length
      + ' 条待审批，且不可撤销。', '全部拒绝', true)) return;
    const r = await api('/api/approvals/deny-all', {method: 'POST'});
    toast(r.ok ? ('已拒绝 ' + r.data.denied + ' 条') : '操作失败');
    await loadApprovals();
  };
  // 新审批到达：标题闪烁 + 震动
  const ids = new Set(pending.map((a) => a.approval_id));
  if (S.primed){
    const fresh = [...ids].filter((id) => !S.seen.has(id));
    if (fresh.length) alertNew(fresh.length);
  }
  S.seen = ids;
  S.primed = true;
}
function alertNew(count){
  if (navigator.vibrate){ try { navigator.vibrate([120, 60, 120]); } catch (e) {} }
  let on = false;
  clearInterval(S.flash);
  S.flash = setInterval(() => {
    on = !on;
    document.title = on ? '（' + count + '）有新审批' : BASE_TITLE;
  }, 900);
  setTimeout(() => { clearInterval(S.flash); document.title = BASE_TITLE; }, 12000);
}
async function loadApprovals(){
  const r = await api('/api/approvals');
  if (r.status === 401){ showLogin(); return false; }
  if (!r.ok) return false;
  S.approvals = r.data;
  renderApprovals();
  return true;
}
async function decide(id, decision, remember){
  const r = await api('/api/approvals/decide', {method: 'POST', body: {
    id: id, decision: decision, remember_minutes: remember || 0}});
  if (!r.ok){ toast(r.data.message || '操作失败'); return; }
  toast(decision === 'approve'
    ? (remember ? '已批准，并放行同类 ' + remember + ' 分钟' : '已批准，bot 会继续执行')
    : '已拒绝，这条操作不会执行');
  await loadApprovals();
}
document.addEventListener('click', async (ev) => {
  const zoom = ev.target.closest('.thumb img');
  if (zoom){
    $('zoomImg').src = zoom.src;
    $('zoom').classList.add('show');
    return;
  }
  if (ev.target.id === 'zoom'){ $('zoom').classList.remove('show'); return; }

  const btn = ev.target.closest('button[data-act],button[data-lact]');
  if (!btn) return;
  const card = btn.closest('.appr');
  if (!card) return;
  const legacy = card.dataset.legacy;
  const act = btn.dataset.act || btn.dataset.lact;
  const id = legacy || card.dataset.id;
  if (act === 'approve') await decide(id, 'approve', 0);
  else if (act === 'deny') await decide(id, 'deny', 0);
  else if (act === 'remember'){
    const minutes = S.approvals.auto_minutes || 10;
    if (!await askConfirm('同类放行',
        '接下来 ' + minutes + ' 分钟内，这个 bot 调用「' + (card.querySelector('.tool').textContent)
        + '」不再需要批准。要现在批准这一条并放行同类吗？', '批准并放行', false)) return;
    await decide(id, 'approve', minutes);
  }
});

/* 倒计时：只更新进度条与剩余时间，不重排整个列表 */
function tickCountdown(){
  Object.keys(S.deadlines).forEach((id) => {
    const bar = document.querySelector('[data-bar="' + id + '"]');
    const left = document.querySelector('[data-left="' + id + '"]');
    if (!bar && !left) return;
    const remain = (S.deadlines[id] - Date.now()) / 1000;
    const card = (S.approvals.pending || []).find((a) => a.approval_id === id);
    const total = card ? (card.total_s || 1) : 1;
    const done = Math.min(100, Math.max(0, ((total - remain) / total) * 100));
    if (bar){
      bar.style.width = done + '%';
      bar.style.background = remain <= 15 ? 'var(--danger)' : 'var(--warn)';
    }
    if (left) left.innerHTML = '剩余 <span class="num">' + countdown(remain) + '</span>';
  });
}

/* ---------------------------------------------------------------- Bots */
function botCard(b){
  const cls = b.status === 'ok' ? 'ok' : (b.status === 'expired' ? 'exp' : 'off');
  const label = {ok: '在线', disabled: '已停用', expired: '已过期'}[b.status] || b.status;
  const lock = b.holding_lock ? '<span class="badge exp">持锁中</span>'
    : (b.in_queue ? '<span class="badge">排队中</span>' : '');
  const counts = Object.values(b.levels || {}).reduce((acc, lv) => {
    acc[lv] = (acc[lv] || 0) + 1; return acc; }, {});
  return '<div class="card" style="margin:10px 0">'
    + '<div class="row"><strong class="grow">' + esc(b.name) + '</strong>'
    + '<span class="badge ' + cls + '">' + esc(label) + '</span>' + lock
    + (b.protected ? ' <span class="badge">受保护</span>' : '') + '</div>'
    + '<div class="muted" style="margin-top:6px">指纹 <code>'
    + esc(String(b.token_hint || '').slice(0, 6)) + '</code>'
    + ' · 今日调用 <span class="num">' + esc(b.today_calls) + '</span> 次 · 累计 <span class="num">'
    + esc(b.call_count) + '</span> 次</div>'
    + '<div class="muted">'
    + (b.expires_at ? '到期 ' + esc(b.expires_at) : '永不过期')
    + ' · 放行 <span class="num">' + (counts.allow || 0) + '</span> / 审批 <span class="num">'
    + (counts.ask || 0) + '</span> / 禁止 <span class="num">' + (counts.deny || 0) + '</span></div>'
    + (b.note ? '<div class="muted">备注：' + esc(b.note) + '</div>' : '')
    + '<div class="row" style="margin-top:10px">'
    + '<button class="btn small" data-bot="' + esc(b.id) + '" data-bact="detail">工具策略</button>'
    + '<button class="btn small" data-bot="' + esc(b.id) + '" data-bact="rotate">轮换 token</button>'
    + '<button class="btn small" data-bot="' + esc(b.id) + '" data-bact="toggle">'
    + (b.enabled ? '停用' : '启用') + '</button>'
    + '<button class="btn small danger" data-bot="' + esc(b.id) + '" data-bact="delete">吊销</button>'
    + '</div></div>';
}
function renderBots(){
  $('botCount').textContent = S.bots.length + ' 个';
  $('bots').innerHTML = S.bots.length ? S.bots.map(botCard).join('')
    : '<p class="muted">还没有 bot。</p>';
}
function botById(id){ return S.bots.find((b) => b.id === id); }
function levelOf(bot, tool){
  const explicit = bot.levels && bot.levels[tool];
  if (explicit) return explicit;
  const allow = bot.allow || [];
  if (allow.indexOf('*') >= 0 || allow.indexOf(tool) >= 0)
    return (S.defaultPolicy && S.defaultPolicy[tool]) || 'ask';
  return 'deny';
}
function policyEditor(bot, editable){
  return S.groups.map((g) => {
    const rows = g.tools.map((t) => {
      const lv = editable ? (bot.policy[t.internal] || levelOf(bot, t.internal)) : levelOf(bot, t.internal);
      const seg = ['allow', 'ask', 'deny'].map((k) =>
        '<button data-tool="' + esc(t.internal) + '" data-lv="' + k + '"'
        + (lv === k ? ' class="on"' : '') + '>' + LEVEL_LABEL[k] + '</button>').join('');
      return '<div class="toolrow"><div class="nm"><div class="n">' + esc(t.exposed)
        + (t.exclusive ? ' <span class="badge exp">独占</span>' : '')
        + (t.high_risk ? ' <span class="badge off">高危</span>' : '') + '</div>'
        + '<div class="d">' + esc(t.description) + '</div></div>'
        + '<div class="seg" data-seg="' + esc(t.internal) + '">' + seg + '</div></div>';
    }).join('');
    return '<details class="fold" open><summary>' + esc(g.label)
      + ' <span class="muted">' + esc(g.note) + '</span></summary>' + rows + '</details>';
  }).join('');
}
function setAllLevels(kind){
  document.querySelectorAll('#modal .seg').forEach((seg) => {
    const tool = seg.dataset.seg;
    const lv = kind === 'all' ? 'ask'
      : kind === 'none' ? 'deny'
      : ((S.defaultPolicy && S.defaultPolicy[tool]) || 'ask');
    seg.querySelectorAll('button').forEach((b) => b.classList.toggle('on', b.dataset.lv === lv));
  });
}
function collectPolicy(){
  const out = {};
  document.querySelectorAll('#modal .seg').forEach((seg) => {
    const on = seg.querySelector('button.on');
    if (on) out[seg.dataset.seg] = on.dataset.lv;
  });
  return out;
}
function openBotDetail(bot){
  openModal('<h2>' + esc(bot.name) + ' 的工具策略</h2>'
    + '<p class="muted">每个工具三档：<b>放行</b>直接执行；<b>审批</b>阻塞等你在手机上点；'
    + '<b>禁止</b>工具不出现、直接调用 403。独占工具（会动鼠标键盘）共用一把全局锁。</p>'
    + '<div class="row" style="margin:10px 0">'
    + '<button class="btn small" id="pRo">只读放行</button>'
    + '<button class="btn small" id="pAsk">全部审批</button>'
    + '<button class="btn small" id="pNone">全部禁止</button></div>'
    + '<div id="policyBox">' + policyEditor(bot, true) + '</div>'
    + '<label for="eExp">过期时间（留空 = 永不过期）</label>'
    + '<input id="eExp" type="datetime-local" value="'
    + esc((bot.expires_at || '').slice(0, 16)) + '">'
    + '<label for="eNote">备注</label><input id="eNote" value="' + esc(bot.note || '') + '">'
    + '<div class="row" style="margin-top:14px">'
    + '<button class="btn primary grow" id="pSave">保存</button>'
    + '<button class="btn grow" id="pCancel">取消</button></div>');
  $('pRo').onclick = () => setAllLevels('ro');
  $('pAsk').onclick = () => setAllLevels('all');
  $('pNone').onclick = () => setAllLevels('none');
  $('pCancel').onclick = closeModal;
  $('policyBox').addEventListener('click', (ev) => {
    const b = ev.target.closest('.seg button');
    if (!b) return;
    b.parentElement.querySelectorAll('button').forEach((x) => x.classList.remove('on'));
    b.classList.add('on');
  });
  $('pSave').onclick = async () => {
    const policy = collectPolicy();
    const allow = Object.keys(policy).filter((k) => policy[k] !== 'deny');
    const r = await api('/api/bots/' + bot.id, {method: 'PATCH', body: {
      policy: policy, allow: allow,
      expires_at: $('eExp').value || null, note: $('eNote').value.trim()}});
    if (!r.ok){ toast(r.data.message || '保存失败'); return; }
    closeModal();
    await loadBots();
    toast('已保存，立刻生效');
  };
}
async function loadBots(){
  const r = await api('/api/bots');
  if (!r.ok) return;
  S.bots = r.data.bots || [];
  renderBots();
  fillBotFilter();
}
function fillBotFilter(){
  const sel = $('fBot');
  const keep = sel.value;
  sel.innerHTML = '<option value="">全部</option>'
    + S.bots.map((b) => '<option value="' + esc(b.name) + '">' + esc(b.name)
      + '</option>').join('');
  sel.value = keep;
}
document.addEventListener('click', async (ev) => {
  const btn = ev.target.closest('button[data-bact]');
  if (!btn) return;
  const bot = botById(btn.dataset.bot);
  if (!bot) return;
  const act = btn.dataset.bact;
  if (act === 'detail'){ openBotDetail(bot); return; }
  if (act === 'rotate'){
    if (!await askConfirm('轮换 token', '旧 token 立刻失效，所有还在用它的客户端会 401。',
        '轮换', true)) return;
    const r = await api('/api/bots/' + bot.id + '/rotate', {method: 'POST'});
    if (!r.ok){ toast('轮换失败'); return; }
    await loadBots();
    revealToken(r.data.bot, r.data.token);
    return;
  }
  if (act === 'toggle'){
    const r = await api('/api/bots/' + bot.id, {method: 'PATCH', body: {enabled: !bot.enabled}});
    if (!r.ok){ toast('操作失败'); return; }
    await loadBots();
    toast(bot.enabled ? '已停用' : '已启用');
    return;
  }
  if (act === 'delete'){
    if (!await askConfirm('吊销 bot', '删除 ' + bot.name + ' 后它的 token 立即失效，不可撤销。'
        + (bot.protected ? '（这是受保护的 bot，请先确认已有替代 token。）' : ''),
        '继续', true)) return;
    const typed = prompt('二次确认：请原样输入 bot 名字\n\n' + bot.name);
    if (typed === null) return;
    const r = await api('/api/bots/' + bot.id, {method: 'DELETE', body: {confirm: typed}});
    if (!r.ok){ toast(r.data.message || '删除失败'); return; }
    await loadBots();
    toast('已吊销');
  }
});
function revealToken(bot, token){
  openModal('<h2>' + esc(bot.name) + ' 的新 token</h2>'
    + '<p class="muted">只显示这一次。复制走之后再关；服务端只保存哈希，'
    + '丢了就只能再轮换。</p>'
    + '<pre class="token" id="tok">' + esc(token) + '</pre>'
    + '<div class="row"><button class="btn primary grow" id="copy">复制</button>'
    + '<button class="btn grow" id="closeTok">我已保存</button></div>');
  $('copy').onclick = async () => {
    try { await navigator.clipboard.writeText(token); toast('已复制'); }
    catch (e){
      const r = document.createRange();
      r.selectNodeContents($('tok'));
      const s = getSelection();
      s.removeAllRanges();
      s.addRange(r);
      toast('请手动复制（已选中）');
    }
  };
  $('closeTok').onclick = closeModal;
}
$('reloadBots').onclick = () => loadBots();
$('newBot').onclick = () => {
  const draft = {id: '', name: '', note: '', allow: S.defaultAllow || [], policy: {},
                 levels: {}};
  openModal('<h2>新建 bot</h2>'
    + '<label for="nName">名称（字母/数字/下划线/点/连字符）</label>'
    + '<input id="nName" placeholder="例如 phone-claude" autocapitalize="off">'
    + '<label for="nNote">备注（可选）</label>'
    + '<input id="nNote" placeholder="例如 手机上用的助手">'
    + '<label for="nExp">过期时间（留空 = 永不过期）</label>'
    + '<input id="nExp" type="datetime-local">'
    + '<p class="muted">默认只读类放行、其余要审批。下面可以逐个改。</p>'
    + '<div class="row" style="margin:10px 0">'
    + '<button class="btn small" id="pRo">只读放行</button>'
    + '<button class="btn small" id="pAsk">全部审批</button>'
    + '<button class="btn small" id="pNone">全部禁止</button></div>'
    + '<div id="policyBox">' + policyEditor(draft, true) + '</div>'
    + '<div class="row" style="margin-top:14px">'
    + '<button class="btn primary grow" id="nCreate">创建并生成 token</button>'
    + '<button class="btn grow" id="pCancel">取消</button></div>');
  $('pRo').onclick = () => setAllLevels('ro');
  $('pAsk').onclick = () => setAllLevels('all');
  $('pNone').onclick = () => setAllLevels('none');
  $('pCancel').onclick = closeModal;
  $('policyBox').addEventListener('click', (ev) => {
    const b = ev.target.closest('.seg button');
    if (!b) return;
    b.parentElement.querySelectorAll('button').forEach((x) => x.classList.remove('on'));
    b.classList.add('on');
  });
  $('nCreate').onclick = async () => {
    const name = $('nName').value.trim();
    if (!name){ toast('请填名称'); return; }
    const policy = collectPolicy();
    const allow = Object.keys(policy).filter((k) => policy[k] !== 'deny');
    const r = await api('/api/bots', {method: 'POST', body: {
      name: name, note: $('nNote').value.trim(), expires_at: $('nExp').value || null,
      policy: policy, allow: allow}});
    if (!r.ok){ toast(r.data.message || '创建失败'); return; }
    closeModal();
    await loadBots();
    revealToken(r.data.bot, r.data.token);
  };
};

/* ---------------------------------------------------------------- 记录 */
function auditRow(e){
  const d = e.decision || '';
  const cls = /deny|reject|timeout|error|locked/.test(d) ? 'd-deny'
    : (/await|pending/.test(d) ? 'd-ask' : 'd-allow');
  return '<li><span class="t num">' + esc(hhmmss(e.ts)) + '</span><div class="body">'
    + '<div class="l1"><span class="chip">' + esc(e.bot) + '</span>'
    + '<code class="tool">' + esc(e.tool) + '</code>'
    + '<span class="' + cls + '" style="font-size:12px">' + esc(d) + '</span>'
    + (e.actor ? '<span class="muted">by ' + esc(e.actor) + '</span>' : '')
    + (e.level ? '<span class="muted">[' + esc(e.level) + ']</span>' : '') + '</div>'
    + (e.summary ? '<div class="l2">' + esc(e.summary) + '</div>' : '')
    + (e.approval_id ? '<div class="l2"><code>' + esc(e.approval_id) + '</code></div>' : '')
    + '</div></li>';
}
async function loadAudit(){
  const q = new URLSearchParams({limit: '150'});
  if (S.audit.bot) q.set('bot', S.audit.bot);
  if (S.audit.tool) q.set('tool', S.audit.tool);
  if (S.audit.result) q.set('result', S.audit.result);
  const r = await api('/api/audit?' + q.toString());
  if (!r.ok) return;
  const events = r.data.events || [];
  $('auditCount').textContent = events.length + ' 条';
  $('auditList').innerHTML = events.length
    ? events.slice().reverse().map(auditRow).join('')
    : '<li><span class="muted">没有符合条件的记录。</span></li>';
  const sel = $('fTool');
  if (!sel.options.length || sel.options.length <= 1){
    sel.innerHTML = '<option value="">全部</option>'
      + S.tools.map((t) => '<option value="' + esc(t.internal) + '">' + esc(t.exposed)
        + '</option>').join('');
  }
}
$('applyFilter').onclick = () => {
  S.audit = {bot: $('fBot').value, tool: $('fTool').value, result: $('fResult').value};
  loadAudit();
};
$('clearFilter').onclick = () => {
  $('fBot').value = ''; $('fTool').value = ''; $('fResult').value = '';
  S.audit = {bot: '', tool: '', result: ''};
  loadAudit();
};
$('reloadAudit').onclick = () => loadAudit();

/* ---------------------------------------------------------------- 设置 */
async function loadSettings(){
  const r = await api('/api/settings');
  if (!r.ok) return;
  const d = r.data;
  $('setWait').value = d.approval_wait_s;
  $('setAuto').value = d.auto_allow_minutes;
  $('setTopic').value = d.ntfy_topic || '';
  $('setServer').value = d.ntfy_server || '';
  $('topicState').textContent = d.ntfy_topic
    ? ('当前 topic：' + d.ntfy_topic + '（' + (d.ntfy_token_set ? '带 token' : '无 token')
       + '）')
    : '还没配 topic：新审批不会推手机，只能在面板里看。';
  $('whoLine').textContent = '登录身份：' + ((S.session && S.session.who) || 'local')
    + ' · 鉴权模式：' + (d.auth_mode || '')
    + ' · 面板地址：' + (d.panel_url || '');
}
$('saveSettings').onclick = async () => {
  const r = await api('/api/settings', {method: 'PATCH',
    body: {approval_wait_s: Number($('setWait').value)}});
  if (!r.ok){ toast(r.data.message || '保存失败'); return; }
  toast('已保存，立刻生效');
};
$('saveNotify').onclick = async () => {
  const r = await api('/api/settings', {method: 'PATCH', body: {
    ntfy_topic: $('setTopic').value.trim(), ntfy_server: $('setServer').value.trim()}});
  if (!r.ok){ toast(r.data.message || '保存失败'); return; }
  await loadSettings();
  toast('已保存');
};
$('testNotify').onclick = async () => {
  const btn = $('testNotify');
  btn.disabled = true;
  const r = await api('/api/notify/test', {method: 'POST'});
  btn.disabled = false;
  toast(r.ok ? '测试通知已发出，看看手机' : ('发送失败：' + (r.data.error || '未知原因')));
};
document.querySelectorAll('#themeSeg button').forEach((b) =>
  b.addEventListener('click', () => applyTheme(b.dataset.th)));

/* ---------------------------------------------------------------- 启动 */
async function loadSession(){
  const r = await api('/api/session');
  if (r.status === 401){ showLogin(); return false; }
  S.session = r.data;
  renderWarnings(r.data.auth && r.data.auth.warnings);
  return true;
}
async function loadTools(){
  const r = await api('/api/tools');
  if (!r.ok) return;
  S.groups = r.data.groups || [];
  S.tools = S.groups.reduce((acc, g) => acc.concat(g.tools), []);
  S.toolIndex = {};
  S.tools.forEach((t) => { S.toolIndex[t.internal] = t; });
  S.defaultPolicy = r.data.default_policy || {};
  S.defaultAllow = r.data.default_allow || [];
}
async function boot(){
  if (!await loadSession()) return;
  await Promise.all([loadTools(), loadBots(), loadApprovals()]);
  showApp();
  if (!S.poll) S.poll = setInterval(poll, 3000);
  if (!S.tick) S.tick = setInterval(tickCountdown, 1000);
}
async function poll(){
  if (document.hidden || !S.session) return;
  await loadApprovals();
  if (S.view === 'audit') await loadAudit();
}
document.addEventListener('visibilitychange', () => { if (!document.hidden) poll(); });
$('mask').addEventListener('click', (ev) => { if (ev.target === $('mask')) closeModal(); });

applyTheme(S.theme);
if ('serviceWorker' in navigator){
  navigator.serviceWorker.register('/sw.js').catch(() => {});
}
boot();
</script>
</body>
</html>
"""
