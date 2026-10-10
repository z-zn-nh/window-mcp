"""agent_status —— 只读地看两个 agent 的会话概况。

数据来源
--------
* PI-Desktop：``C:/Users/<user>/.pi-desktop/pi.sqlite``（SQLite，WAL）。
  表 sessions / messages / turns。
* DeepSeek Harness：``C:/Users/<user>/.dsh/sessions/<工作区 slug>/<会话目录>/session*.jsonl.zstd``
  （zstd 压缩的 JSONL，事件形如 ``{type, seq, time, data}``）。

安全约定
--------
* **全程只读**：SQLite 用 ``mode=ro``，DSH 只解压到内存，不写任何文件。
* **只取末尾、只返回片段**：每条消息截断到 max_chars，换行压平。
* **脱敏**：命中 token / 密钥 / 长随机串的片段替换成 <redacted>，
  避免把会话里出现过的凭据再带出去一次。
"""
from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import time
from pathlib import Path
from typing import Any

log = logging.getLogger("mcp_server.agent_status")

HOME = Path(os.path.expanduser("~"))
PI_DB = HOME / ".pi-desktop" / "pi.sqlite"
DSH_SESSIONS = HOME / ".dsh" / "sessions"

# 顺序有讲究：先长后短，避免长 token 被短规则切碎
_REDACTIONS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-]{12,}"), "Bearer <redacted>"),
    (re.compile(r"\bsk-[A-Za-z0-9_\-]{12,}"), "<redacted>"),
    (re.compile(r"\bphc_[A-Za-z0-9]{12,}"), "<redacted>"),
    (re.compile(r"\beyJ[A-Za-z0-9._\-]{20,}"), "<redacted>"),          # JWT
    (re.compile(r"\b[A-Fa-f0-9]{32,}\b"), "<redacted>"),                 # hex 长串
    (re.compile(r"\b[A-Za-z0-9_\-]{40,}\b"), "<redacted>"),              # 不透明长串
]


def _redact(text: str) -> str:
    for pat, repl in _REDACTIONS:
        text = pat.sub(repl, text)
    return text


def _clip(text: str, max_chars: int) -> str:
    text = (text or "").replace("\r", " ").replace("\n", " ")
    text = re.sub(r"\s+", " ", text).strip()
    text = _redact(text)
    if len(text) > max_chars:
        text = text[:max_chars] + "…"
    return text


def _fmt_ts(ms: Any) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(ms) / 1000.0))
    except Exception:
        return ""


# --------------------------------------------------------------------------- PI-Desktop

def _pi_sessions(limit: int, max_chars: int) -> dict[str, Any]:
    out: dict[str, Any] = {"source": str(PI_DB), "ok": False, "sessions": []}
    if not PI_DB.exists():
        out["error"] = "pi.sqlite 不存在"
        return out
    try:
        con = sqlite3.connect(f"file:{PI_DB.as_posix()}?mode=ro", uri=True, timeout=5.0)
    except Exception as exc:
        out["error"] = f"打不开数据库：{exc}"
        return out
    try:
        con.row_factory = sqlite3.Row
        rows = con.execute(
            "select id, title, updated_at from sessions "
            "where deleted_at is null order by updated_at desc limit ?",
            (int(limit),),
        ).fetchall()
        for row in rows:
            sid = row["id"]

            def last(role: str) -> str:
                r = con.execute(
                    "select text from messages where session_id=? and role=? "
                    "and text is not null and length(text) > 0 "
                    "order by seq desc limit 1",
                    (sid, role),
                ).fetchone()
                return _clip(r["text"] if r else "", max_chars)

            running = con.execute(
                "select count(*) from turns where session_id=? and status='running'",
                (sid,),
            ).fetchone()[0]

            last_turn = con.execute(
                "select status, started_at, ended_at from turns where session_id=? "
                "order by started_at desc limit 1",
                (sid,),
            ).fetchone()

            out["sessions"].append({
                "id": sid,
                "title": _clip(row["title"] or "", 80),
                "updated_at": _fmt_ts(row["updated_at"]),
                "running": bool(running),
                "last_turn_status": (last_turn["status"] if last_turn else ""),
                "last_user_message": last("user"),
                "last_reply": last("assistant"),
            })
        out["ok"] = True
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        con.close()
    return out


# --------------------------------------------------------------------------- DSH

def _dsh_text(ev: dict[str, Any]) -> str:
    """从 user/message 或 assistant/message 里取纯文本（丢掉 reasoning）。"""
    data = ev.get("data") or {}
    blocks = data.get("content")
    if not isinstance(blocks, list):
        blocks = (data.get("message") or {}).get("content")
    if not isinstance(blocks, list):
        return ""
    parts = [b.get("text", "") for b in blocks
             if isinstance(b, dict) and b.get("type") == "text"]
    return " ".join(p for p in parts if p)


def _dsh_read(path: Path) -> list[dict[str, Any]]:
    try:
        import zstandard
    except ImportError:
        zstandard = None  # type: ignore[assignment]
    try:
        if path.suffix == ".zstd":
            if zstandard is None:
                return []
            with open(path, "rb") as fh:
                raw = zstandard.ZstdDecompressor().stream_reader(fh).read()
        else:
            raw = path.read_bytes()
    except Exception as exc:
        log.debug("读 DSH 会话失败 %s: %s", path, exc)
        return []
    out = []
    for line in raw.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out


def _dsh_sessions(limit: int, max_chars: int) -> dict[str, Any]:
    out: dict[str, Any] = {"source": str(DSH_SESSIONS), "ok": False, "sessions": []}
    if not DSH_SESSIONS.exists():
        out["error"] = ".dsh/sessions 不存在"
        return out
    try:
        files = list(DSH_SESSIONS.glob("*/*/session*.jsonl.zstd"))
        files += list(DSH_SESSIONS.glob("*/*/session*.jsonl"))
        files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    except Exception as exc:
        out["error"] = f"枚举失败：{exc}"
        return out

    for path in files[: int(limit)]:
        try:
            mtime = path.stat().st_mtime
        except OSError:
            continue
        evs = _dsh_read(path)

        last_user = last_reply = ""
        running = False
        turn_seen = False
        last_event = ""
        goal_phase = ""
        for ev in reversed(evs):
            t = ev.get("type") or ""
            if not last_event:
                last_event = t
            # 注意：这里不能 break。最后一条 assistant/message 经常是空占位
            # （流式还没提交），而 turn 边界往往在它之后；早退会一条消息都拿不到。
            # 条件写成 `not last_reply` 而不是 `last_reply is None`，空占位会被
            # 更早的那条非空消息自动补上。
            if not last_reply and t == "assistant/message":
                last_reply = _dsh_text(ev)
            if not last_user and t == "user/message":
                last_user = _dsh_text(ev)
            if t == "goal/change" and not goal_phase:
                goal_phase = str(((ev.get("data") or {}).get("goal") or {}).get("phase") or "")
            if t in ("turn/end", "turn/start") and not turn_seen:
                running = (t == "turn/start")
                turn_seen = True
        # 兜底：文件刚刚还在写 → 认为在跑
        if not running and (time.time() - mtime) < 90:
            running = True

        out["sessions"].append({
            "id": path.parent.name,
            "workspace": path.parent.parent.name,
            "updated_at": _fmt_ts(mtime * 1000),
            "running": running,
            "last_event": last_event,
            "goal_phase": goal_phase,
            "last_user_message": _clip(last_user, max_chars),
            "last_reply": _clip(last_reply, max_chars),
            "events": len(evs),
        })
    out["ok"] = True
    return out


# --------------------------------------------------------------------------- 入口

def collect(pi_limit: int = 3, dsh_limit: int = 3, max_chars: int = 240) -> dict[str, Any]:
    pi_limit = max(1, min(int(pi_limit or 3), 10))
    dsh_limit = max(1, min(int(dsh_limit or 3), 10))
    max_chars = max(60, min(int(max_chars or 240), 800))
    pi = _pi_sessions(pi_limit, max_chars)
    dsh = _dsh_sessions(dsh_limit, max_chars)
    any_running = any(s.get("running") for s in pi.get("sessions", [])) or \
                  any(s.get("running") for s in dsh.get("sessions", []))
    return {
        "ok": bool(pi.get("ok") or dsh.get("ok")),
        "any_running": any_running,
        "note": "只读；消息已截断并脱敏，不含工具输出与凭据",
        "pi_desktop": pi,
        "deepseek_harness": dsh,
    }
