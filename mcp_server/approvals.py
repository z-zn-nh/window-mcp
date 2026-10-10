"""审批队列。

文档 §6.5：
* 工具调用立即返回 pending_approval（**成功结果**，不是 isError），不阻塞；
* Hark 之后调 approval_status 轮询，批准后由服务器执行原样的那条命令；
* 审批绑定命令哈希——批准的是这一条，不能拿去执行别的；
* 超时自动拒绝（默认 10 分钟）。

状态落在 state/approvals.json，服务器按 mtime 重新加载，
所以既支持 /admin/approve 端点，也支持离线用 CLI 改状态。
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

PENDING = "pending"
APPROVED = "approved"
REJECTED = "rejected"
EXPIRED = "expired"
EXECUTED = "executed"
ERROR = "error"


def command_hash(tool: str, args: dict) -> str:
    """绑定审批对象的哈希：工具名 + 规范化参数。"""
    payload = json.dumps({"tool": tool, "args": args}, ensure_ascii=False,
                         sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class Approval:
    approval_id: str
    tool: str
    args: dict
    summary: str
    level: str
    hash: str
    created_at: float
    expires_at: float
    status: str = PENDING
    decided_at: float | None = None
    decided_by: str = ""
    executed_at: float | None = None
    result: dict | None = None
    attempts: int = 0

    def as_dict(self) -> dict:
        data = asdict(self)
        data["created_at_iso"] = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(self.created_at))
        data["expires_at_iso"] = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(self.expires_at))
        data["expires_in_s"] = max(0, int(self.expires_at - time.time()))
        return data

    def public(self) -> dict:
        """返回给 Hark 的 pending 结构（文档 §11 第 5 条）。"""
        return {
            "status": "pending_approval",
            "approval_id": self.approval_id,
            "tool": self.tool,
            "summary": self.summary,
            "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.expires_at)),
            "expires_in_s": max(0, int(self.expires_at - time.time())),
            "next": "call approval_status",
        }


class ApprovalStore:
    def __init__(self, path: Path, ttl_s: int = 600) -> None:
        self.path = Path(path)
        self.ttl_s = ttl_s
        self._lock = threading.Lock()
        self._items: dict[str, Approval] = {}
        self._mtime: float = 0.0
        self._load(force=True)

    # ------------------------------------------------------------- 持久化

    def _load(self, force: bool = False) -> None:
        try:
            mtime = self.path.stat().st_mtime
        except OSError:
            return
        if not force and mtime == self._mtime:
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        items: dict[str, Approval] = {}
        for key, raw in (data.get("approvals") or {}).items():
            try:
                items[key] = Approval(**raw)
            except TypeError:
                continue
        with self._lock:
            self._items = items
            self._mtime = mtime

    def _save(self) -> None:
        with self._lock:
            payload = {"approvals": {k: asdict(v) for k, v in self._items.items()}}
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            tmp.replace(self.path)
            self._mtime = self.path.stat().st_mtime

    def _reload_if_changed(self) -> None:
        self._load(force=False)

    # ------------------------------------------------------------- 操作

    def create(self, tool: str, args: dict, summary: str, level: str = "H") -> Approval:
        self._reload_if_changed()
        now = time.time()
        approval = Approval(
            approval_id=uuid.uuid4().hex[:16],
            tool=tool,
            args=args,
            summary=summary,
            level=level,
            hash=command_hash(tool, args),
            created_at=now,
            expires_at=now + self.ttl_s,
        )
        with self._lock:
            self._items[approval.approval_id] = approval
        self._save()
        return approval

    def find_pending_by_request_id(self, request_id: str) -> Approval | None:
        if not request_id:
            return None
        self._reload_if_changed()
        with self._lock:
            for item in self._items.values():
                if item.status == PENDING and item.args.get("request_id") == request_id:
                    return item
        return None

    def get(self, approval_id: str) -> Approval | None:
        self._reload_if_changed()
        self.sweep_expired()
        with self._lock:
            return self._items.get(approval_id)

    def list_pending(self) -> list[Approval]:
        self._reload_if_changed()
        self.sweep_expired()
        now = time.time()
        with self._lock:
            return sorted(
                (a for a in self._items.values() if a.status == PENDING and a.expires_at > now),
                key=lambda a: a.created_at,
            )

    def decide(self, approval_id: str, approve: bool, actor: str = "admin") -> Approval | None:
        self._reload_if_changed()
        self.sweep_expired()
        with self._lock:
            item = self._items.get(approval_id)
            if item is None:
                return None
            if item.status != PENDING:
                return item
            item.status = APPROVED if approve else REJECTED
            item.decided_at = time.time()
            item.decided_by = actor
        self._save()
        return item

    def mark_executed(self, approval_id: str, result: dict, ok: bool = True) -> None:
        with self._lock:
            item = self._items.get(approval_id)
            if item is None:
                return
            item.status = EXECUTED if ok else ERROR
            item.result = result
            item.executed_at = time.time()
            item.attempts += 1
        self._save()

    def sweep_expired(self) -> int:
        now = time.time()
        changed = 0
        with self._lock:
            for item in self._items.values():
                if item.status == PENDING and item.expires_at <= now:
                    item.status = EXPIRED
                    item.decided_at = now
                    item.decided_by = "timeout"
                    changed += 1
        if changed:
            self._save()
        return changed
