"""审计日志：按天滚动的 JSONL，写入前对敏感字段做遮蔽。"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from .security import current_client_ip, current_token_name, redact


class AuditLog:
    def __init__(self, log_dir: Path) -> None:
        self.dir = Path(log_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _file(self) -> Path:
        return self.dir / f"audit-{time.strftime('%Y-%m-%d')}.jsonl"

    def write(self, event: dict) -> None:
        # 每条记录都带上「哪个 token 干的」（名字，不是值）：
        #   * 值来自 security 的 ContextVar，由 ASGI 外壳在鉴权通过后写入，
        #     所以工具调用方不用改一行；后台线程拿不到时记 "-"。
        #   * event 里自带 "token" 会覆盖它（留个显式指定的口子）。
        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "token": current_token_name() or "-",
            # 来源 IP：面板要显示「最近调用来自哪个 IP」。经 Cloudflare 隧道进来时
            # 它是边缘节点地址，只当排查线索，**不作授权依据**。
            "client": current_client_ip(),
            **event,
        }
        line = json.dumps(record, ensure_ascii=False, default=str)
        with self._lock:
            with open(self._file(), "a", encoding="utf-8") as fh:
                fh.write(line + "\n")

    # 常用事件的便捷方法 -------------------------------------------------

    def call(self, tool: str, args: dict, level: str, decision: str,
             duration_ms: int, summary: str) -> None:
        self.write({
            "kind": "tool_call",
            "tool": tool,
            "level": level,
            "decision": decision,
            "args": _redact_args(args),
            "duration_ms": duration_ms,
            "summary": redact(str(summary))[:500],
        })

    def approval(self, action: str, approval_id: str, tool: str, args: dict | None = None,
                 *, keys=None, actor: str = "", bot: str = "", result: str = "") -> None:
        """审批相关记录。

        ``keys`` 给了就**只记参数名**（远程审批走这条：参数值不落盘）；
        否则退回旧行为，记 ``_redact_args(args)``（危险命令那条路在用）。
        ``actor`` 是「谁批的」，``result`` 是结果——需求要求审批决定可追溯到人。
        """
        record = {
            "kind": "approval",
            "action": action,  # requested / approved / rejected / timeout / executed
            "approval_id": approval_id,
            "tool": tool,
        }
        if keys is not None:
            record["arg_keys"] = sorted(str(k) for k in keys)
        else:
            record["args"] = _redact_args(args or {})
        if actor:
            record["actor"] = str(actor)
        if bot:
            record["bot"] = str(bot)
        if result:
            record["result"] = str(result)
        self.write(record)

    def tool_gate(self, tool: str, decision: str, summary: str, keys=None,
                  approval_id: str = "", level: str = "H") -> None:
        """三档闸门的调用记录。

        与 :meth:`denied` 一样**只记参数名，不记参数值**：``ask`` 档的工具往往是
        点击 / 输入 / 执行命令，参数里完全可能是刚复制的密码或验证码。
        """
        record = {
            "kind": "tool_call",
            "tool": tool,
            "level": level,
            "decision": decision,
            "arg_keys": sorted(str(k) for k in (keys or ())),
            "duration_ms": 0,
            "summary": redact(str(summary))[:300],
        }
        if approval_id:
            record["approval_id"] = approval_id
        self.write(record)

    def note(self, kind: str, **fields) -> None:
        self.write({"kind": kind, **fields})

    def denied(self, tool: str, reason: str, keys=None) -> None:
        """记录一次被拒的调用（白名单越权 / token 被禁用 / 已过期）。

        **只记参数名，不记参数值**：被拒的调用往往是越权尝试，参数里可能就有敏感内容，
        既没必要也不该落盘。
        """
        self.write({
            "kind": "tool_call",
            "tool": tool,
            "level": "W",
            "decision": "denied",
            "arg_keys": sorted(str(k) for k in (keys or ())),
            "duration_ms": 0,
            "summary": redact(str(reason))[:300],
        })


def _redact_args(args: dict) -> dict:
    out = {}
    for key, value in (args or {}).items():
        if isinstance(value, str):
            # 文件内容不落盘，只记长度
            if key in {"content", "new", "old", "text"}:
                out[key] = f"<{len(value)} chars>"
            else:
                out[key] = redact(value)
        else:
            out[key] = value
    return out
