"""远程审批：阻塞式待审批队列 + 运行时设置 + ntfy 推送。

和 ``approvals.py`` 的区别
--------------------------
``approvals.py`` 是**轮询式**的老通道：工具立刻返回 ``pending_approval``，
由调用方稍后自己来问结果（危险命令走的就是它）。远程审批是**阻塞式**的：
bot 调用 ``ask`` 档工具时，服务器把请求挂起，手机端点「批准」才继续执行，
超时（默认 120 秒）自动拒绝并回一个明确的错误。

三件事都在这里
--------------
1. :class:`RemoteApprovalQueue` —— 待审批记录本身（谁、什么工具、参数摘要、
   调用前截图缩略图、何时过期）以及决定。
2. :class:`RuntimeSettings` —— 面板「设置」页能改的东西（审批超时秒数、ntfy
   topic），落在 ``state/panel-settings.json``，改完立刻生效、不用重启。
3. ntfy 推送 —— 新审批到达时推手机。**推送里只有 bot 名、工具名、时间和面板
   链接**，没有 token，也没有参数明文。

队列只活在内存里：它代表的是「此刻正挂起等待的 HTTP 请求」。进程一重启，
这些请求本来也就断了，落盘反而会留下永远不会有人认领的僵尸记录。
**决定**会进审计日志（``logs/audit-YYYY-MM-DD.jsonl``，``kind = "approval"``），
所以「谁批的、何时、结果」是可追溯的。
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

import httpx

PENDING = "pending"
APPROVED = "approved"
DENIED = "denied"
TIMEOUT = "timeout"

NTFY_TIMEOUT = 10.0

# 面板里能改的运行时设置。默认值同时也是取值范围校验的兜底。
DEFAULT_RUNTIME: dict = {
    "approval_wait_s": 120,      # 单次 ask 调用最多阻塞多久（秒）
    "ntfy_server": "https://ntfy.sh",
    "ntfy_topic": "",            # 空 = 不推送
    "ntfy_token": "",            # 私有 ntfy 服务器才需要
}


# ---------------------------------------------------------------------------
# 一条待审批
# ---------------------------------------------------------------------------


@dataclass
class RemoteApproval:
    approval_id: str
    bot: str
    bot_id: str
    tool: str                     # 主工具（卡片标题用它）
    tools: list[str]              # 本次请求里所有需要审批的工具
    summary: str                  # 一句话参数摘要（已遮蔽敏感内容）
    arg_keys: list[str]           # 只留参数名，不留参数值
    thumb: str                    # 调用前截图缩略图（data URL；失败为空串）
    created_at: float
    expires_at: float
    status: str = PENDING
    decided_at: float | None = None
    decided_by: str = ""
    decided_via: str = ""         # panel / api / timeout
    remember_minutes: int = 0     # >0 表示同时放行了「同类」

    def as_dict(self) -> dict:
        data = asdict(self)
        now = time.time()
        data["created_at_iso"] = _iso(self.created_at)
        data["decided_at_iso"] = _iso(self.decided_at) if self.decided_at else None
        data["expires_in_s"] = max(0, int(self.expires_at - now))
        data["total_s"] = max(1, int(self.expires_at - self.created_at))
        data["elapsed_s"] = max(0, int(now - self.created_at))
        data["progress"] = min(1.0, max(0.0, (now - self.created_at)
                                        / max(1.0, self.expires_at - self.created_at)))
        return data


def _iso(ts: float | None) -> str | None:
    if not ts:
        return None
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ts))


# ---------------------------------------------------------------------------
# 队列
# ---------------------------------------------------------------------------


class RemoteApprovalQueue:
    """内存里的待审批队列。线程安全（MCP 线程与面板线程都会碰它）。"""

    def __init__(self, audit=None, wait_s: int = 120, auto_minutes: int = 10,
                 keep_recent: int = 50) -> None:
        self.audit = audit
        self.wait_s = max(10, int(wait_s))
        self.auto_minutes = max(1, int(auto_minutes))
        self.keep_recent = max(5, int(keep_recent))
        self._lock = threading.Lock()
        self._items: dict[str, RemoteApproval] = {}
        self._order: list[str] = []
        self._auto: dict[tuple[str, str], float] = {}

    # ------------------------------------------------------------ 创建

    def create(self, *, bot: str, bot_id: str, tools, summary: str,
               arg_keys=None, thumb: str = "", wait_s: int | None = None,
               ) -> RemoteApproval:
        names = [str(t) for t in (tools or []) if str(t)]
        now = time.time()
        ttl = max(10, int(wait_s or self.wait_s))
        item = RemoteApproval(
            approval_id=uuid.uuid4().hex[:16],
            bot=str(bot or "-"),
            bot_id=str(bot_id or ""),
            tool=names[0] if names else "",
            tools=names,
            summary=_clip(summary, 400),
            arg_keys=[str(k) for k in (arg_keys or [])][:40],
            thumb=thumb,
            created_at=now,
            expires_at=now + ttl,
        )
        with self._lock:
            self._items[item.approval_id] = item
            self._order.append(item.approval_id)
            self._trim_locked()
        return item

    def _trim_locked(self) -> None:
        """只保留最近的若干条已决定记录，别让内存无限涨。"""
        decided = [i for i in self._order
                   if self._items.get(i) and self._items[i].status != PENDING]
        for approval_id in decided[:-self.keep_recent]:
            self._items.pop(approval_id, None)
            try:
                self._order.remove(approval_id)
            except ValueError:
                pass

    # ------------------------------------------------------------ 查询

    def get(self, approval_id: str) -> RemoteApproval | None:
        with self._lock:
            return self._items.get(str(approval_id or ""))

    def sweep(self) -> int:
        """把过期仍挂起的判成超时（并记审计）。返回本次超时的条数。"""
        now = time.time()
        expired: list[RemoteApproval] = []
        with self._lock:
            for item in self._items.values():
                if item.status == PENDING and item.expires_at <= now:
                    item.status = TIMEOUT
                    item.decided_at = now
                    item.decided_by = "timeout"
                    item.decided_via = "timeout"
                    expired.append(item)
        for item in expired:
            self._audit(item, "timeout", actor="timeout", result="timeout")
        return len(expired)

    def list_pending(self) -> list[RemoteApproval]:
        self.sweep()
        with self._lock:
            items = [i for i in self._items.values() if i.status == PENDING]
        return sorted(items, key=lambda i: i.created_at)

    def list_recent(self, limit: int = 30) -> list[RemoteApproval]:
        self.sweep()
        with self._lock:
            items = [i for i in self._items.values() if i.status != PENDING]
        items.sort(key=lambda i: (i.decided_at or i.created_at), reverse=True)
        return items[:max(1, int(limit))]

    def pending_count(self) -> int:
        self.sweep()
        with self._lock:
            return sum(1 for i in self._items.values() if i.status == PENDING)

    # ------------------------------------------------------------ 决定

    def decide(self, approval_id: str, approve: bool, actor: str = "panel",
               via: str = "panel", remember_minutes: int = 0,
               ) -> RemoteApproval | None:
        """落定一条审批。已经决定过的不再改（返回原记录）。"""
        self.sweep()
        now = time.time()
        with self._lock:
            item = self._items.get(str(approval_id or ""))
            if item is None:
                return None
            if item.status != PENDING:
                return item
            item.status = APPROVED if approve else DENIED
            item.decided_at = now
            item.decided_by = str(actor or "")
            item.decided_via = str(via or "")
            item.remember_minutes = max(0, int(remember_minutes or 0))
        self._audit(item, "approved" if approve else "rejected",
                    actor=item.decided_by, result=item.status)
        if approve and item.remember_minutes:
            for name in item.tools:
                self.grant_auto(item.bot, name, item.remember_minutes, actor=actor)
        return item

    def deny_all(self, actor: str = "panel") -> int:
        count = 0
        for item in self.list_pending():
            if self.decide(item.approval_id, False, actor=actor, via="panel") is not None:
                count += 1
        return count

    def _audit(self, item: RemoteApproval, action: str, *, actor: str = "",
               result: str = "") -> None:
        if self.audit is None:
            return
        try:
            self.audit.approval(action, item.approval_id, item.tool,
                                keys=item.arg_keys, actor=actor, bot=item.bot,
                                result=result)
        except Exception:
            pass

    # ------------------------------------------------------------ 同类放行

    def grant_auto(self, bot: str, tool: str, minutes: int, actor: str = "panel") -> float:
        """「本 bot N 分钟内同类放行」。只活在内存里，重启即失效。"""
        minutes = max(0, int(minutes or 0))
        key = (str(bot or ""), str(tool or ""))
        if minutes <= 0:
            with self._lock:
                self._auto.pop(key, None)
            return 0.0
        expires = time.time() + minutes * 60
        with self._lock:
            self._auto[key] = expires
        if self.audit is not None:
            try:
                self.audit.note("approval_auto_allow", bot=key[0], tool=key[1],
                                minutes=minutes, actor=str(actor or ""))
            except Exception:
                pass
        return expires

    def auto_remaining(self, bot: str, tool: str) -> int:
        """还剩几秒的同类放行；0 表示没有。"""
        key = (str(bot or ""), str(tool or ""))
        with self._lock:
            expires = self._auto.get(key, 0.0)
            if expires and expires <= time.time():
                self._auto.pop(key, None)
                return 0
        return max(0, int(expires - time.time())) if expires else 0

    def list_auto(self) -> list[dict]:
        now = time.time()
        with self._lock:
            dead = [k for k, v in self._auto.items() if v <= now]
            for key in dead:
                self._auto.pop(key, None)
            rows = [{"bot": k[0], "tool": k[1], "remaining_s": max(0, int(v - now))}
                    for k, v in self._auto.items()]
        return sorted(rows, key=lambda r: -r["remaining_s"])

    # ------------------------------------------------------------ 等待

    def wait_seconds(self, item: RemoteApproval) -> float:
        return max(0.0, item.expires_at - time.time())


def _clip(text: str, limit: int) -> str:
    value = str(text or "")
    return value if len(value) <= limit else value[: limit - 1] + "…"


# ---------------------------------------------------------------------------
# 运行时设置（面板「设置」页改的就是它）
# ---------------------------------------------------------------------------


class RuntimeSettings:
    """``state/panel-settings.json``：改完立刻生效，不需要重启。

    只放**非敏感**的运行时旋钮。ntfy token 虽然是密钥，但它本来就该存在
    本机文件里（和 ``secrets/`` 同级待遇：ACL 收紧、MCP 工具读不到）。
    """

    def __init__(self, path: str | os.PathLike, defaults: dict | None = None) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._data = dict(DEFAULT_RUNTIME)
        if defaults:
            self._data.update({k: v for k, v in defaults.items() if v is not None})
        self._load()

    def _load(self) -> None:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if isinstance(raw, dict):
            with self._lock:
                for key in DEFAULT_RUNTIME:
                    if key in raw:
                        self._data[key] = raw[key]

    def _save_locked(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(self._data, ensure_ascii=False, indent=2),
                       encoding="utf-8")
        os.replace(tmp, self.path)

    def get(self) -> dict:
        with self._lock:
            return dict(self._data)

    def update(self, changes: dict) -> dict:
        """校验并落盘。取值非法时抛 ``ValueError``（调用方回 400）。"""
        clean: dict = {}
        with self._lock:
            data = dict(self._data)
        for key, value in (changes or {}).items():
            if key not in DEFAULT_RUNTIME:
                raise ValueError(f"不认识的设置项：{key}")
            if key == "approval_wait_s":
                try:
                    number = int(value)
                except (TypeError, ValueError):
                    raise ValueError("审批超时必须是整数秒") from None
                if not 10 <= number <= 600:
                    raise ValueError("审批超时只能是 10 ~ 600 秒")
                clean[key] = number
            elif key == "ntfy_server":
                text = str(value or "").strip().rstrip("/")
                if text and not text.startswith(("http://", "https://")):
                    raise ValueError("ntfy 服务器地址必须以 http:// 或 https:// 开头")
                clean[key] = text or DEFAULT_RUNTIME["ntfy_server"]
            elif key == "ntfy_topic":
                text = str(value or "").strip()
                if len(text) > 64:
                    raise ValueError("ntfy topic 最长 64 个字符")
                if text and not all(c.isalnum() or c in "-_" for c in text):
                    raise ValueError("ntfy topic 只允许字母/数字/连字符/下划线")
                clean[key] = text
            elif key == "ntfy_token":
                clean[key] = str(value or "").strip()
        with self._lock:
            self._data.update(clean)
            self._save_locked()
            return dict(self._data)

    def public(self) -> dict:
        """给面板看的：token 只回一个「有没有配」的布尔，不回值。"""
        data = self.get()
        return {
            "approval_wait_s": int(data.get("approval_wait_s") or 120),
            "ntfy_server": str(data.get("ntfy_server") or ""),
            "ntfy_topic": str(data.get("ntfy_topic") or ""),
            "ntfy_token_set": bool(str(data.get("ntfy_token") or "")),
        }


# ---------------------------------------------------------------------------
# ntfy 推送
# ---------------------------------------------------------------------------


def send_ntfy(*, server: str, topic: str, token: str = "", title: str,
              message: str, click: str = "", tags: str = "warning",
              priority: str = "4", actions=None) -> dict:
    """发一条 ntfy 消息。返回 ``{"ok": bool, ...}``，**绝不抛异常**。"""
    server = (str(server or "") or DEFAULT_RUNTIME["ntfy_server"]).rstrip("/")
    topic = str(topic or "").strip()
    if not topic:
        return {"ok": False, "error": "未配置 ntfy topic"}
    headers = {"Title": title, "Priority": str(priority), "Tags": tags}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body: dict = {"topic": topic, "message": message}
    if click:
        body["click"] = click
    if actions:
        body["actions"] = actions
    try:
        response = httpx.post(f"{server}/", json=body, headers=headers,
                              timeout=NTFY_TIMEOUT)
        response.raise_for_status()
        return {"ok": True, "status": response.status_code}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def approval_message(item: RemoteApproval, panel_url: str) -> tuple[str, str]:
    """拼通知标题与正文。

    只放 bot 名、工具名、时间与面板链接——**没有 token，也没有参数明文**。
    参数摘要本身可能含敏感内容（比如输入框里敲的是什么），所以一律不进通知；
    要看详情就点开面板，那里有登录态保护。
    """
    title = f"待审批：{item.bot} 要调用 {item.tool}"
    lines = [
        f"{item.bot} 请求调用 {item.tool}",
        f"时间：{time.strftime('%H:%M:%S', time.localtime(item.created_at))}",
        f"{max(1, int((item.expires_at - item.created_at) / 60))} 分钟内不处理将自动拒绝",
        f"打开面板处理：{panel_url}",
    ]
    return title, "\n".join(lines)


def notify_new_approval(settings: RuntimeSettings, item: RemoteApproval,
                        panel_url: str) -> None:
    """后台线程推送——绝不能卡住正在等待审批的那个请求。"""
    data = settings.get()
    topic = str(data.get("ntfy_topic") or "")
    if not topic:
        return
    title, message = approval_message(item, panel_url)
    server = str(data.get("ntfy_server") or DEFAULT_RUNTIME["ntfy_server"])
    token = str(data.get("ntfy_token") or "")

    def _run() -> None:
        send_ntfy(server=server, topic=topic, token=token, title=title,
                  message=message, click=panel_url, tags="warning", priority="5",
                  actions=[{"action": "view", "label": "打开审批面板",
                            "url": panel_url, "clear": True}])

    threading.Thread(target=_run, name="ntfy-push", daemon=True).start()


def send_test_notification(settings: RuntimeSettings, panel_url: str) -> dict:
    data = settings.get()
    topic = str(data.get("ntfy_topic") or "")
    if not topic:
        return {"ok": False, "error": "还没填 ntfy topic"}
    return send_ntfy(
        server=str(data.get("ntfy_server") or DEFAULT_RUNTIME["ntfy_server"]),
        topic=topic, token=str(data.get("ntfy_token") or ""),
        title="Window MCP 测试通知",
        message="如果你看到这条消息，审批推送就是通的。\n" f"面板：{panel_url}",
        click=panel_url, tags="white_check_mark", priority="3")


# ---------------------------------------------------------------------------
# 调用前截图缩略图
# ---------------------------------------------------------------------------


def capture_thumbnail(max_width: int = 420, quality: int = 55) -> str:
    """调用前截一张缩略图，返回 ``data:image/jpeg;base64,...``。

    审批卡片上「这个操作是在什么画面上发生的」比参数摘要更有说服力。
    截不到（锁屏、没有桌面、mss 不可用）就返回空串——审批单照样成立，
    只是少一张图。
    """
    try:
        import base64
        import io

        import mss
        from PIL import Image

        with mss.mss() as sct:
            monitors = sct.monitors
            region = monitors[1] if len(monitors) > 1 else monitors[0]
            shot = sct.grab(region)
        image = Image.frombytes("RGB", shot.size, shot.rgb)
        if image.width > max_width:
            scale = max_width / image.width
            image = image.resize((max_width, max(1, int(image.height * scale))),
                                 Image.LANCZOS)
        buffer = io.BytesIO()
        image.save(buffer, format="JPEG", quality=quality, optimize=True)
        encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
        return f"data:image/jpeg;base64,{encoded}"
    except Exception:
        return ""
