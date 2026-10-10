"""bot token 管理：多具名 token + 工具白名单 + 过期 / 禁用（管理面板的存储层）。

设计要点
--------
* **token 只存哈希**：HMAC-SHA256 + pepper（``secrets/bots.key``）。token 是 64 字符的
  高熵随机串，不需要 scrypt/bcrypt 那种慢哈希；keyed hash 已经足够，而且能承受
  「每个请求都校验一遍」的开销（慢哈希做不到）。
* ``token_hint`` 只存**哈希**的前 8 位十六进制，用来在面板上区分不同 token。
  它不包含 token 本身的任何字符，看到它也还原不出 token。
* 记录里**永不保存明文 token**。明文只在创建 / 轮换的那一刻返回一次。
* 文件用「临时文件 + os.replace」原子替换，并保留一份 ``.bak``；
  文件损坏时先尝试从 ``.bak`` 恢复，而不是让服务器起不来（起不来就连面板都进不去，
  那样反而更难修）。

白名单
------
``allow`` 里存的是**不带工具前缀的内部名**（如 ``read_file``），面板显示时才拼上
``config.toml`` 的 ``tool_prefix``。这样改前缀不会让已有 bot 的白名单失效。
``allow`` 含 ``"*"`` 表示全量权限（Hark 现在就是全量）。

``allow`` 只回答「这个工具可见吗」；**每个工具还要有三档**（``policy``）：
``allow`` 直接执行 / ``ask`` 阻塞等手机批准 / ``deny`` 拒绝。没显式配置的工具
按 ``policy.DEFAULT_POLICY`` 取默认档（只读类放行，其余 ask）。详见 ``policy.py``。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .policy import READONLY_TOOLS, level_for as _level_for, normalize_policy

# token_urlsafe(48) -> 64 个字符（与既有 token 同规格）
TOKEN_BYTES = 48
HINT_LEN = 8
PEPPER_BYTES = 32
ALL = "*"

# 新建 bot 的默认白名单：只读类。
# 刻意**不含** clipboard_get —— 剪贴板里可能是刚复制的密码/验证码，比只读文件更敏感，
# 需要的人自己勾。也刻意不含任何写文件 / 跑命令 / GUI 操作的工具。
#
# 名单本身在 ``policy.READONLY_TOOLS`` 里（那里同时定义了三档策略的默认档），
# 这里只是换个名字给旧调用方用。
DEFAULT_ALLOW: tuple[str, ...] = tuple(READONLY_TOOLS)

# 名字规则与 config.py 保持一致（会进审计日志）
NAME_MAX_LEN = 32


class BotStoreError(RuntimeError):
    """存储层错误（文件损坏且无法从 .bak 恢复、名字不合法等）。"""


def _now() -> float:
    return time.time()


def _iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(ts))


def parse_when(text) -> float | None:
    """把面板/API 传来的时间解析成 epoch 秒。

    接受 ``2026-10-20``、``2026-10-20 12:30:00``、``2026-10-20T12:30:00``、
    带时区偏移的 ISO，以及数字（epoch 秒）。空值 = 不过期。
    不带时区时按本机时区解释（面板上填的就是本机时间）。
    """
    if text is None:
        return None
    if isinstance(text, (int, float)):
        return float(text)
    s = str(text).strip()
    if not s:
        return None
    dt: datetime | None = None
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(s, fmt)
                break
            except ValueError:
                continue
    if dt is None:
        raise ValueError(f"时间格式无法识别：{text!r}"
                         "（用 2026-10-20 或 2026-10-20 12:30:00）")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.now().astimezone().tzinfo)
    return dt.timestamp()


def _tighten_acl(path: Path) -> None:
    """把文件 ACL 收到「只有当前用户」——尽力而为，失败不影响功能。

    与 secrets/ 目录现有的 ACL 风格一致（``EXAMPLE\\user:(OI)(CI)(F)``）。
    """
    try:
        user = os.environ.get("USERNAME") or ""
        domain = os.environ.get("USERDOMAIN") or ""
        who = f"{domain}\\{user}" if domain and user else user
        if not who:
            return
        subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"{who}:(F)"],
            capture_output=True, timeout=20,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception:
        pass


def valid_name(name: str) -> bool:
    """名字规则与 config.py 的 TOKEN_NAME_RE 一致：**只允许 ASCII** 字母/数字/_.-。

    注意不能用 ``str.isalnum()`` 判断：它对中日韩字符也返回 True，
    于是「中文」会被当成合法名字，而 config 那边是拒绝的——两边规则必须一致。
    名字会进审计日志（JSONL）和面板，限制成 ASCII 最省心。
    """
    text = str(name or "").strip()
    if not text or len(text) > NAME_MAX_LEN:
        return False
    return all((c.isascii() and c.isalnum()) or c in "_.-" for c in text)


@dataclass
class Bot:
    id: str
    name: str
    token_hash: str
    token_hint: str
    created_at: float
    rotated_at: float | None = None
    expires_at: float | None = None
    enabled: bool = True
    allow: tuple[str, ...] = DEFAULT_ALLOW
    # 逐工具的三档策略（内部名 -> allow/ask/deny）。空 = 全部按默认档。
    policy: dict[str, str] = field(default_factory=dict)
    note: str = ""
    protected: bool = False
    last_used_at: float | None = None
    call_count: int = 0

    # -- 状态 --
    def expired(self, now: float | None = None) -> bool:
        return self.expires_at is not None and (now or _now()) >= self.expires_at

    def status(self, now: float | None = None) -> str:
        if not self.enabled:
            return "disabled"
        if self.expired(now):
            return "expired"
        return "ok"

    def allows(self, tool: str) -> bool:
        """内部名是否在白名单里。allow 含 "*" = 全量。"""
        return ALL in self.allow or tool in self.allow

    def level_for(self, tool: str) -> str:
        """这个工具对这个 bot 的实际档位：allow / ask / deny。"""
        return _level_for(self.allow, self.policy, tool)

    def public(self) -> dict:
        """给面板 / API 的表示。**不含 token_hash**。"""
        return {
            "id": self.id,
            "name": self.name,
            "token_hint": self.token_hint,
            "created_at": _iso(self.created_at),
            "rotated_at": _iso(self.rotated_at),
            "expires_at": _iso(self.expires_at),
            "enabled": self.enabled,
            "allow": list(self.allow),
            "allow_all": ALL in self.allow,
            "policy": dict(self.policy),
            "note": self.note,
            "protected": self.protected,
            "last_used_at": _iso(self.last_used_at),
            "call_count": self.call_count,
            "status": self.status(),
        }

    def to_json(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "token_hash": self.token_hash,
            "token_hint": self.token_hint,
            "created_at": self.created_at,
            "rotated_at": self.rotated_at,
            "expires_at": self.expires_at,
            "enabled": self.enabled,
            "allow": list(self.allow),
            "policy": dict(self.policy),
            "protected": self.protected,
            "last_used_at": self.last_used_at,
            "call_count": self.call_count,
        }

    @classmethod
    def from_json(cls, raw: dict) -> "Bot":
        allow = raw.get("allow")
        if not isinstance(allow, (list, tuple)):
            allow = DEFAULT_ALLOW
        return cls(
            id=str(raw.get("id") or ""),
            name=str(raw.get("name") or ""),
            token_hash=str(raw.get("token_hash") or ""),
            token_hint=str(raw.get("token_hint") or ""),
            created_at=float(raw.get("created_at") or 0),
            rotated_at=raw.get("rotated_at"),
            expires_at=raw.get("expires_at"),
            enabled=bool(raw.get("enabled", True)),
            allow=tuple(str(x) for x in allow),
            policy=normalize_policy(raw.get("policy")),
            protected=bool(raw.get("protected", False)),
            last_used_at=raw.get("last_used_at"),
            call_count=int(raw.get("call_count") or 0),
        )


class BotStore:
    """``state/bots.json`` 的读写 + 校验。全程线程安全。"""

    def __init__(self, path: str | os.PathLike, pepper_path: str | os.PathLike) -> None:
        self.path = Path(path)
        self.pepper_path = Path(pepper_path)
        self._lock = threading.RLock()
        self._bots: dict[str, Bot] = {}
        self._pepper: bytes = b""
        self._touch_pending: dict[str, float] = {}
        self.warnings: list[str] = []

    # ------------------------------------------------------------ 载入

    def load(self) -> None:
        """读 pep-per 与 bots.json。文件不存在 = 空库（正常，不是错误）。"""
        self._pepper = self._load_pepper()
        with self._lock:
            self._bots = {}
            if not self.path.is_file():
                return
            raw, source = self._read_json(self.path)
            if raw is None:
                raw, source = self._read_json(self.path.with_suffix(self.path.suffix + ".bak"))
            if raw is None:
                raise BotStoreError(
                    f"bot 名册文件损坏且无法从备份恢复：{self.path}\n"
                    f"（备份：{self.path}.bak）\n"
                    "修复办法：删掉损坏的文件后重启服务（会得到空名册），"
                    "或在面板里重建 bot。"
                )
            if source != self.path:
                self.warnings.append(f"bot 名册主文件损坏，已从备份恢复：{source}")
            for item in (raw.get("bots") or []):
                if not isinstance(item, dict):
                    continue
                bot = Bot.from_json(item)
                if not bot.id or not bot.token_hash:
                    continue
                self._bots[bot.id] = bot

    def _read_json(self, path: Path) -> tuple[dict | None, Path]:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except FileNotFoundError:
            return None, path
        except (OSError, ValueError):
            return None, path
        return (data if isinstance(data, dict) else None), path

    def _load_pepper(self) -> bytes:
        """pepper 只存文件（ACL 收紧）。没有就生成一个。"""
        try:
            text = self.pepper_path.read_text(encoding="utf-8").strip()
        except OSError:
            text = ""
        if text:
            try:
                raw = bytes.fromhex(text)
            except ValueError:
                raise BotStoreError(f"pepper 文件内容不是十六进制：{self.pepper_path}")
            if len(raw) < 16:
                raise BotStoreError(f"pepper 文件太短（{len(raw)} 字节）：{self.pepper_path}")
            return raw
        raw = secrets.token_bytes(PEPPER_BYTES)
        self.pepper_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.pepper_path.with_suffix(self.pepper_path.suffix + ".tmp")
        tmp.write_text(raw.hex() + "\n", encoding="utf-8")
        os.replace(tmp, self.pepper_path)
        _tighten_acl(self.pepper_path)
        return raw

    # ------------------------------------------------------------ 保存

    def _save_locked(self) -> None:
        payload = {
            "version": 1,
            "saved_at": _iso(_now()),
            "bots": [b.to_json() for b in self._bots.values()],
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        if self.path.is_file():
            try:
                os.replace(self.path, self.path.with_suffix(self.path.suffix + ".bak"))
            except OSError:
                pass
        os.replace(tmp, self.path)

    # ------------------------------------------------------------ 哈希

    def hash_token(self, token: str) -> str:
        return hmac.new(self._pepper, str(token).encode("utf-8"),
                        hashlib.sha256).hexdigest()

    @staticmethod
    def _new_token() -> str:
        return secrets.token_urlsafe(TOKEN_BYTES)

    def _hint(self, digest: str) -> str:
        return digest[:HINT_LEN]


    @property
    def pepper(self) -> bytes:
        """HMAC pepper。面板用它派生自己的会话签名密钥——**不要外传、不要落盘**。"""
        return self._pepper
    # ------------------------------------------------------------ 校验

    def verify(self, presented: str) -> tuple[Bot | None, str]:
        """返回 (命中的 bot, 状态)。状态取 ``ok`` / ``disabled`` / ``expired``。

        **遍历全部记录、不提前返回**：命中位置本身也会影响耗时，
        而这里的结果还会进审计日志。
        """
        if not presented:
            return None, "empty"
        digest = self.hash_token(presented)
        hit: Bot | None = None
        with self._lock:
            bots = list(self._bots.values())
        for bot in bots:
            if hmac.compare_digest(digest, bot.token_hash):
                hit = bot
        if hit is None:
            return None, "unknown"
        return hit, hit.status()

    def find_by_name(self, name: str) -> Bot | None:
        text = str(name or "").strip().lower()
        with self._lock:
            for bot in self._bots.values():
                if bot.name.lower() == text:
                    return bot
        return None

    def get(self, bot_id: str) -> Bot | None:
        with self._lock:
            return self._bots.get(str(bot_id or ""))

    def list_public(self) -> list[dict]:
        with self._lock:
            items = sorted(self._bots.values(), key=lambda b: (b.created_at, b.name))
        return [b.public() for b in items]

    def enabled_count(self) -> int:
        with self._lock:
            return sum(1 for b in self._bots.values() if b.status() == "ok")

    def total(self) -> int:
        with self._lock:
            return len(self._bots)

    # ------------------------------------------------------------ 写操作

    def create(self, name: str, allow=None, expires_at=None, note: str = "",
               protected: bool = False, policy=None) -> tuple[dict, str]:
        """新建 bot。返回 (公开表示, 明文 token)——明文只在此刻出现一次。

        ``policy`` 是逐工具的三档策略。给了 ``policy`` 又没给 ``allow`` 时，
        白名单按「档位不是 deny 的工具」推导，两边不会打架。
        """
        text = str(name or "").strip()
        if not valid_name(text):
            raise BotStoreError(
                f"名字不合法：{name!r}（只允许字母/数字/下划线/点/连字符，最长 {NAME_MAX_LEN}）")
        if self.find_by_name(text) is not None:
            raise BotStoreError(f"名字已存在：{text}")
        clean_policy = normalize_policy(policy)
        if allow is None and clean_policy:
            allow = _clean_allow([tool for tool, level in clean_policy.items()
                                  if level != "deny"], fallback=False)
        token = self._new_token()
        digest = self.hash_token(token)
        bot = Bot(
            id="b_" + secrets.token_hex(4),
            name=text,
            token_hash=digest,
            token_hint=self._hint(digest),
            created_at=_now(),
            expires_at=expires_at,
            enabled=True,
            allow=_clean_allow(allow),
            policy=clean_policy,
            note=str(note or ""),
            protected=bool(protected),
        )
        with self._lock:
            self._bots[bot.id] = bot
            self._save_locked()
        return bot.public(), token

    def rotate(self, bot_id: str) -> tuple[dict, str]:
        """换一把新 token（旧 token 立刻失效）。返回 (公开表示, 新明文)。"""
        with self._lock:
            bot = self._bots.get(str(bot_id or ""))
            if bot is None:
                raise BotStoreError("bot 不存在")
            token = self._new_token()
            digest = self.hash_token(token)
            bot.token_hash = digest
            bot.token_hint = self._hint(digest)
            bot.rotated_at = _now()
            self._save_locked()
            return bot.public(), token

    def update(self, bot_id: str, changes: dict) -> dict:
        """局部更新。``changes`` 里出现哪个键就改哪个（没出现 = 不动）。

        可改：``allow``（列表 / 逗号串）、``policy``（三档策略表）、
        ``expires_at``（ISO 串 / epoch / None=不过期）、``enabled``（bool）、
        ``note``（str）。改完立刻落盘，无需重启。

        同时给了 ``policy`` 和 ``allow`` 时以 ``allow`` 为准（它决定可见性），
        只给 ``policy`` 时白名单按「档位不是 deny」自动推导。
        """
        changes = dict(changes or {})
        unknown = set(changes) - {"allow", "policy", "expires_at", "enabled", "note"}
        if unknown:
            raise BotStoreError(f"不认识的字段：{', '.join(sorted(unknown))}")
        with self._lock:
            bot = self._bots.get(str(bot_id or ""))
            if bot is None:
                raise BotStoreError("bot 不存在")
            if "policy" in changes:
                policy = normalize_policy(changes["policy"])
                bot.policy = policy
                if "allow" not in changes:
                    bot.allow = _clean_allow(
                        [tool for tool, level in policy.items() if level != "deny"],
                        fallback=False)
            if "allow" in changes:
                bot.allow = _clean_allow(changes["allow"])
            if "expires_at" in changes:
                bot.expires_at = parse_when(changes["expires_at"])
            if "enabled" in changes:
                bot.enabled = bool(changes["enabled"])
            if "note" in changes:
                bot.note = str(changes["note"] or "")
            self._save_locked()
            return bot.public()

    def delete(self, bot_id: str, confirm_name: str) -> dict:
        """删除 bot。必须把 bot 名字原样传进 ``confirm_name``（二次确认），
        名字对不上就拒绝——防止面板上误点。
        """
        with self._lock:
            bot = self._bots.get(str(bot_id or ""))
            if bot is None:
                raise BotStoreError("bot 不存在")
            if str(confirm_name or "").strip() != bot.name:
                raise BotStoreError(
                    f"二次确认失败：需要原样输入 bot 名字 {bot.name!r} 才能删除")
            snapshot = bot.public()
            del self._bots[bot.id]
            self._touch_pending.pop(bot.id, None)
            self._save_locked()
            return snapshot

    # ------------------------------------------------------------ 使用计数

    def touch(self, bot_id: str) -> None:
        """记一次使用（``last_used_at`` / ``call_count``）。

        内存里立刻更新，落盘**节流**（同一 bot 最多 30 秒写一次）：
        每个请求都写文件既没必要，也会把磁盘打满。
        """
        now = _now()
        with self._lock:
            bot = self._bots.get(str(bot_id or ""))
            if bot is None:
                return
            bot.last_used_at = now
            bot.call_count += 1
            last = self._touch_pending.get(bot.id, 0.0)
            if now - last >= 30:
                self._touch_pending[bot.id] = now
                try:
                    self._save_locked()
                except OSError:
                    pass

    def flush_touch(self) -> None:
        """把节流中的使用计数落盘（进程退出前调用一次）。"""
        with self._lock:
            if not self._touch_pending:
                return
            self._touch_pending.clear()
            try:
                self._save_locked()
            except OSError:
                pass

    # ------------------------------------------------------------ 迁移

    def bootstrap(self, entries: list[tuple[str, str]], *, protected=("hark",),
                  allow_all: bool = True) -> list[str]:
        """把「已有 token 值」导入成 bot（保号不破：token 值不变，只是改成存哈希）。

        ``entries`` 是 (名字, token 明文) 列表，来自 config.toml 的旧名册。
        名字已存在则跳过（幂等，重复跑不会造出第二份）。
        返回实际导入的名字列表。
        """
        imported: list[str] = []
        for name, token in entries:
            text = str(name or "").strip()
            value = str(token or "").strip()
            if not value or not valid_name(text):
                continue
            if self.find_by_name(text) is not None:
                continue
            digest = self.hash_token(value)
            bot = Bot(
                id="b_" + secrets.token_hex(4),
                name=text,
                token_hash=digest,
                token_hint=self._hint(digest),
                created_at=_now(),
                enabled=True,
                allow=(ALL,) if allow_all else DEFAULT_ALLOW,
                note="从 config.toml 迁移（token 值未变）",
                protected=text in set(protected or ()),
            )
            with self._lock:
                self._bots[bot.id] = bot
                self._save_locked()
            imported.append(text)
        return imported


def _clean_allow(allow, *, fallback: bool = True) -> tuple[str, ...]:
    """规整白名单：去重、去空白。

    ``fallback=True``（默认）：空 / None 用默认只读集——这是「新建 bot 时没勾任何
    工具」的语义。``fallback=False``：空就是空（「全禁止」是一个合法配置，
    不能悄悄变回只读集）。
    """
    if allow is None:
        return DEFAULT_ALLOW if fallback else ()
    if isinstance(allow, str):
        allow = [x for x in allow.replace(",", " ").split()]
    out: list[str] = []
    for item in allow:
        text = str(item or "").strip()
        if text and text not in out:
            out.append(text)
    if not out:
        return DEFAULT_ALLOW if fallback else ()
    return tuple(out)
