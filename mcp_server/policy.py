"""工具访问策略：三档 allow / ask / deny，以及「会动鼠标键盘的工具」的全局互斥锁。

为什么要有这一层
----------------
原来的 bot 白名单只有两态：在列表里 = 放行，不在 = 403。远程审批要求多一档
——「可以用，但每次都得人在手机上点一下」。于是白名单升级成三态：

======== ==================================================================
``allow`` 直接执行；``tools/list`` 里可见。
``ask``   阻塞等待手机端批准（最长 ``approval_wait_s`` 秒，超时自动拒绝）；
          ``tools/list`` 里可见。
``deny``  等同原来的「不在白名单」：``tools/list`` 里不出现，直接调用 403。
======== ==================================================================

未显式配置的工具取 :data:`DEFAULT_POLICY` 的默认档：**只读 / 截图类默认 ``allow``，
其余一律 ``ask``**——点击、输入、快捷键、执行命令这些本来就是要人点头的操作。

静态 token（``config.toml`` 里的）不受这一层约束，行为与加面板之前完全一致：
它们没有「bot」这个身份，也就没有可以逐工具配置的策略。

互斥锁
------
``type_text`` / ``click`` / ``hotkey`` / ``uia_click`` / ``uia_type`` 都作用在**当时的
焦点窗口**上。两个 bot 同时动鼠标，点到的可能是对方刚切过去的窗口，谁都不知道发生了
什么。所以这几个工具共用一把全局锁：同一时间只允许一个 bot 持有，其余按先来后到排队，
面板上能看到「谁在用、队列里有谁」。
"""

from __future__ import annotations

import threading
import time
from contextvars import ContextVar

# ---------------------------------------------------------------------------
# 三档
# ---------------------------------------------------------------------------

LEVEL_ALLOW = "allow"
LEVEL_ASK = "ask"
LEVEL_DENY = "deny"
LEVELS: tuple[str, ...] = (LEVEL_ALLOW, LEVEL_ASK, LEVEL_DENY)

# 没有任何配置时的兜底档位。**默认 ask**：没配过的工具一律要人点头。
LEVEL_FALLBACK = LEVEL_ASK

# 只读 / 截图 / 状态查询类：这些不改动系统状态，默认放行（面板里可改成 ask / deny）。
READONLY_TOOLS: tuple[str, ...] = (
    "system_info",
    "system_stats",
    "list_processes",
    "list_windows",
    "list_dir",
    "read_file",
    "screenshot",
    "job_status",
    "approval_status",
    "list_pending_approvals",
    "agent_status",
    "uia_snapshot",
    "uia_wait_for",
)

# 工具 -> 默认档位。没出现在表里的工具取 LEVEL_FALLBACK（ask）。
DEFAULT_POLICY: dict[str, str] = {name: LEVEL_ALLOW for name in READONLY_TOOLS}

# 会动鼠标键盘的工具：共用一把全局锁。
EXCLUSIVE_TOOLS: frozenset[str] = frozenset({
    "type_text", "click", "hotkey", "uia_click", "uia_type",
})

# 危险操作（面板上要二次确认的）——只用于界面提示，不参与判定。
HIGH_RISK_TOOLS: frozenset[str] = frozenset({
    "run_command", "start_job", "stop_job", "write_file", "edit_file",
    "clipboard_set",
})


def normalize_level(value, default: str = LEVEL_FALLBACK) -> str:
    text = str(value or "").strip().lower()
    return text if text in LEVELS else default


def normalize_policy(raw) -> dict[str, str]:
    """把面板 / JSON 传来的策略表规整成 ``{工具内部名: 档位}``。

    认不出的档位直接丢掉（而不是退回默认值）：写错的键静默变成 ask 会让人
    以为自己配好了。丢掉之后它就是「没配置」，同样取默认档。
    """
    if raw is None:
        return {}
    if isinstance(raw, str):
        raw = {}
    if not isinstance(raw, dict):
        return {}
    out: dict[str, str] = {}
    for key, value in raw.items():
        name = str(key or "").strip()
        if not name:
            continue
        level = str(value or "").strip().lower()
        if level not in LEVELS:
            continue
        out[name] = level
    return out


def level_for(allow, policy, tool: str) -> str:
    """算出某个工具对某个身份的实际档位。

    ``allow`` 是白名单（可见性），``policy`` 是逐工具的显式档位。规则：

    1. 不在白名单里（且白名单不是 ``"*"``）→ ``deny``（白名单说了算）；
    2. 在 ``policy`` 里有显式档位 → 用它；
    3. 否则取 ``DEFAULT_POLICY``，再不行就是 ``ask``。
    """
    name = str(tool or "")
    if allow is None:
        # 静态 token：全量权限，三档策略不适用
        return LEVEL_ALLOW
    if "*" not in allow and name not in allow:
        return LEVEL_DENY
    level = normalize_policy(policy).get(name)
    if level is not None:
        return level
    return DEFAULT_POLICY.get(name, LEVEL_FALLBACK)


# ---------------------------------------------------------------------------
# 全局互斥锁（鼠标 / 键盘）
# ---------------------------------------------------------------------------


class ToolLock:
    """先来后到的全局锁：同一时间只有一个持有者。

    实现故意用普通线程锁 + 显式队列，而不是 ``asyncio.Lock``：等待方（MCP 请求）
    在 MCP 的事件循环里，而读状态的一方（面板）在**另一个线程的另一个事件循环**里。
    跨事件循环共享 asyncio 原语是不安全的，共享一个受 ``threading.Lock`` 保护的
    普通字典则完全没问题。等待方用 ``await asyncio.sleep()`` 轮询 :meth:`try_acquire`，
    既不阻塞事件循环，也能被面板实时看见。
    """

    def __init__(self) -> None:
        self._guard = threading.Lock()
        self._holder: dict | None = None
        self._queue: list[dict] = []
        self._seq = 0

    def request(self, bot: str, tool: str) -> str:
        """排队并拿到一张票。票号单调递增，用来保证先来后到。"""
        with self._guard:
            self._seq += 1
            ticket = f"t{self._seq}"
            self._queue.append({"ticket": ticket, "bot": str(bot or "-"),
                                "tool": str(tool or ""), "since": time.time()})
            return ticket

    def try_acquire(self, ticket: str) -> bool:
        """队首且无人持有时拿到锁；否则 False（调用方继续等）。"""
        with self._guard:
            if self._holder is not None:
                return False
            for index, item in enumerate(self._queue):
                if item["ticket"] != ticket:
                    continue
                if index != 0:
                    return False
                self._queue.pop(index)
                self._holder = {"ticket": ticket, "bot": item["bot"],
                                "tool": item["tool"], "since": time.time()}
                return True
            return False

    def release(self, ticket: str) -> None:
        with self._guard:
            if self._holder and self._holder["ticket"] == ticket:
                self._holder = None

    def cancel(self, ticket: str) -> None:
        """放弃排队 / 释放（超时或出错时调用）。"""
        with self._guard:
            self._queue = [x for x in self._queue if x["ticket"] != ticket]
            if self._holder and self._holder["ticket"] == ticket:
                self._holder = None

    def snapshot(self) -> dict:
        with self._guard:
            return {
                "holder": dict(self._holder) if self._holder else None,
                "queue": [dict(x) for x in self._queue],
                "waiting": len(self._queue),
            }


# ---------------------------------------------------------------------------
# 请求级授权上下文
# ---------------------------------------------------------------------------

# 本次请求已经被人批准过的工具（内部名）。ASGI 闸门在放行前写入，
# 工具层读它来决定「要不要再走一次内层审批」。
#
# 为什么用 ContextVar 而不是请求头：MCP SDK 是**在事件循环上直接调用同步工具函数**的
# （见 ``fastmcp/utilities/func_metadata.py``），所以工具函数与 ASGI 处理函数在同一个
# 任务上下文里——``security.set_token_name`` 一直靠的就是这一点。
_granted: ContextVar[frozenset] = ContextVar("mcp_tool_grant", default=frozenset())


def grant_tools(names) -> None:
    _granted.set(frozenset(str(n) for n in (names or ()) if str(n)))


def clear_grants() -> None:
    _granted.set(frozenset())


def granted_tools() -> frozenset:
    return _granted.get()


def tool_granted(name: str) -> bool:
    return str(name or "") in _granted.get()
