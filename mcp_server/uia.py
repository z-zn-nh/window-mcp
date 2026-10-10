"""UIA 无障碍树桥接：Snapshot / WaitFor / 按标签 Click,Type / Clipboard。

底层用的是 vendor/ 里从 CursorTouch/Windows-MCP 移植的 uia/ + tree/（MIT）。

设计要点
--------
* **所有 UIA 调用固定在同一个 STA 线程上。** UI Automation 是 COM，要求
  单线程套间（STA）；上游自己就为此写了 thread_affinity.py，注释里也写明
  「多线程各自 CoInitialize 会造成跨套间封送死锁」。这里用一个
  max_workers=1 的线程池 + initializer 里 CoInitializeEx 达到同样效果。
* **标签 = interactive_nodes 的下标**（溢出后接 scrollable_nodes），和上游
  get_coordinates_from_label 的语义一致。快照时把 label→坐标 存下来，
  uia_click / uia_type 直接用；标签失效就提示重新 Snapshot。
* 适配器对象必须**持强引用**：Tree 内部用 weakref.proxy(desktop)。
"""
from __future__ import annotations

import ctypes
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from typing import Any

import psutil

from mcp_server.vendor import uia
from mcp_server.vendor.tree.service import Tree
from mcp_server.vendor.tree.views import BoundingBox, TreeState

log = logging.getLogger("mcp_server.uia")

# 浏览器进程名（用于 is_window_browser，决定要不要走 DOM 提取）
BROWSER_EXES = {
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe",
    "vivaldi.exe", "chromium.exe", "iexplore.exe", "arc.exe", "zen.exe",
}

COINIT_APARTMENTTHREADED = 0x2

_ACTION_MAP = {
    "edit": "fill", "check box": "toggle", "checkbox": "toggle",
    "combo box": "select", "combobox": "select", "slider": "slide",
    "radio button": "select", "document": "scroll",
}


def _action_for(control_type: str) -> str:
    return _ACTION_MAP.get((control_type or "").lower(), "click")


def _coinit() -> None:
    """线程池 initializer：把工作线程初始化成 STA。"""
    try:
        ctypes.windll.ole32.CoInitializeEx(None, COINIT_APARTMENTTHREADED)
    except Exception:  # pragma: no cover - 只在极端环境失败
        log.warning("CoInitializeEx 失败，UIA 可能不稳定", exc_info=True)


class _Size:
    __slots__ = ("width", "height")

    def __init__(self, width: int, height: int) -> None:
        self.width = width
        self.height = height


class _DesktopAdapter:
    """Tree 只用到这三个方法（见 vendor/tree/service.py 的 Tree.__init__）。

    注意 get_screen_box() 必须返回 tree.views.BoundingBox：
      * 它要 .get_center()（Tree 构造根节点时用）
      * 它还要能被 uia.Rect.intersect() 当参数读 .left/.top/.right/.bottom
    BoundingBox 两个都满足。
    """

    def __init__(self) -> None:
        left, top, width, height = uia.GetVirtualScreenRect()
        self._box = BoundingBox(left=left, top=top, right=left + width,
                                bottom=top + height, width=width, height=height)
        w, h = uia.GetVirtualScreenSize()
        self._size = _Size(w, h)

    def get_screen_size(self) -> _Size:
        return self._size

    def get_screen_box(self) -> BoundingBox:
        return self._box

    def is_window_browser(self, node: Any) -> bool:
        try:
            return psutil.Process(node.ProcessId).name().lower() in BROWSER_EXES
        except Exception:
            return False


def _top_level_windows() -> list[int]:
    """可见、有标题的顶层窗口，按 z 序（最前在前）。"""
    import win32gui

    out: list[int] = []

    def cb(hwnd: int, _param: Any) -> bool:
        try:
            if not win32gui.IsWindowVisible(hwnd):
                return True
            if not win32gui.GetWindowText(hwnd):
                return True
        except Exception:
            return True
        out.append(hwnd)
        return True

    win32gui.EnumWindows(cb, None)
    return out


def _window_title(hwnd: int) -> str:
    try:
        import win32gui
        return win32gui.GetWindowText(hwnd) or ""
    except Exception:
        return ""


def _window_process(hwnd: int) -> str:
    try:
        import win32process
        _, pid = win32process.GetWindowThreadProcessId(hwnd)
        return psutil.Process(pid).name()
    except Exception:
        return ""


class UiaBridge:
    """把 vendored 的 UIA/Tree 包成一个可用的服务对象。"""

    def __init__(self, max_windows: int = 6, call_timeout_s: float = 40.0) -> None:
        self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="uia",
                                        initializer=_coinit)
        self._adapter: _DesktopAdapter | None = None   # 必须持强引用！
        self._tree: Tree | None = None
        self._lock = threading.Lock()
        self._labels: dict[int, dict[str, Any]] = {}
        self._snapshot_ts: float = 0.0
        self._snapshot_meta: dict[str, Any] = {}
        self.max_windows = max_windows
        self.call_timeout_s = call_timeout_s

    # ---------------------------------------------------------------- 线程调度

    def _call(self, fn, *args, **kwargs):
        """把 UIA 调用丢到唯一的 STA 线程上执行。"""
        try:
            return self._pool.submit(fn, *args, **kwargs).result(self.call_timeout_s)
        except FutureTimeout:
            raise TimeoutError(
                f"UIA 调用超过 {self.call_timeout_s:.0f} 秒未返回；"
                "多半是某个窗口的无障碍提供程序卡住了"
                "（可用 uia_snapshot 的 exclude 参数跳过它）"
            )

    # ---------------------------------------------------------------- 快照

    def _ensure_tree(self) -> Tree:
        if self._tree is None:
            self._adapter = _DesktopAdapter()   # 强引用，防止 weakref.proxy 失效
            self._tree = Tree(self._adapter)
        return self._tree

    def _snapshot_sync(self, use_dom: bool, max_elements: int,
                       exclude: set[str]) -> dict[str, Any]:
        import win32gui

        tree = self._ensure_tree()
        active = win32gui.GetForegroundWindow()
        all_hwnds = _top_level_windows()

        picked: list[int] = []
        for h in all_hwnds:
            if h == active:
                continue
            proc = _window_process(h).lower()
            if proc and proc in exclude:
                continue
            picked.append(h)
            if len(picked) >= max(0, self.max_windows - 1):
                break

        if active:
            proc = _window_process(active).lower()
            if proc and proc in exclude:
                active = 0

        started = time.perf_counter()
        state: TreeState = tree.get_state(active or None, picked, use_dom=use_dom)
        elapsed = time.perf_counter() - started

        labels: dict[int, dict[str, Any]] = {}
        lines: list[str] = []

        def add(node: Any, idx: int, kind: str) -> None:
            center = getattr(node, "center", None)
            name = getattr(node, "name", "") or ""
            ctrl = getattr(node, "control_type", "") or ""
            win = getattr(node, "window_name", "") or ""
            meta = getattr(node, "metadata", {}) or {}
            if center is None:
                return
            labels[idx] = {
                "label": idx, "x": int(center.x), "y": int(center.y),
                "name": name, "control_type": ctrl, "window": win,
                "kind": kind, "metadata": meta,
            }
            extra = []
            if meta.get("is_password"):
                extra.append("password")
            value = meta.get("value")
            if value is not None and value not in ("", "(empty)"):
                extra.append(f'value:"{value}"')
            if meta.get("has_focused"):
                extra.append("focused")
            toggle = meta.get("toggle_state")
            if toggle:
                extra.append(f"toggle:{toggle}")
            if kind == "scroll":
                if meta.get("vertical_scrollable"):
                    extra.append(f'v:{meta.get("vertical_scroll_percent", 0)}%')
                if meta.get("horizontal_scrollable"):
                    extra.append(f'h:{meta.get("horizontal_scroll_percent", 0)}%')
            suffix = ("  [" + "  ".join(extra) + "]") if extra else ""
            lines.append(
                f'[{idx}] {ctrl.lower() or "element"} "{name}"  '
                f'center=({int(center.x)},{int(center.y)})  '
                f'action={_action_for(ctrl)}  window="{win}"{suffix}'
            )

        interactive = list(getattr(state, "interactive_nodes", []) or [])
        scrollable = list(getattr(state, "scrollable_nodes", []) or [])
        idx = 0
        for node in interactive[:max_elements]:
            add(node, idx, "interactive")
            idx += 1
        remaining = max(0, max_elements - idx)
        for node in scrollable[:remaining]:
            add(node, idx, "scroll")
            idx += 1

        # 语义树（父子层级）——同样带标签的补充视图
        semantic = ""
        try:
            semantic = state.semantic_tree_to_string() or ""
        except Exception:
            log.debug("semantic_tree_to_string 失败", exc_info=True)

        self._labels = labels
        self._snapshot_ts = time.time()
        meta = {
            "active_hwnd": active,
            "active_title": _window_title(active) if active else "",
            "active_process": _window_process(active) if active else "",
            "windows_traversed": len(picked) + (1 if active else 0),
            "capture_sec": round(elapsed, 3),
            "interactive_count": len(interactive),
            "scrollable_count": len(scrollable),
            "labelled": len(labels),
            "truncated": bool(getattr(state, "truncated", False)),
            "element_limit": int(getattr(state, "element_limit", 0) or 0),
            "status": bool(getattr(state, "status", True)),
            "use_dom": use_dom,
        }
        return {"meta": meta, "lines": lines, "semantic": semantic,
                "state": state}

    def snapshot(self, *, use_dom: bool = False, max_elements: int = 150,
                 include_tree: bool = True,
                 exclude: list[str] | None = None) -> dict[str, Any]:
        excl = {e.strip().lower() for e in (exclude or []) if e and e.strip()}
        res = self._call(self._snapshot_sync, use_dom, max_elements, excl)
        meta = res["meta"]
        lines = res["lines"]

        head = [
            f'Focused window: "{meta["active_title"]}" ({meta["active_process"]})',
            f'Screen: {self._screen_desc()}',
            f'Capture: {meta["capture_sec"]}s   '
            f'interactive={meta["interactive_count"]}  '
            f'scrollable={meta["scrollable_count"]}  '
            f'labelled={meta["labelled"]}',
        ]
        if not meta["status"]:
            head.append("警告：UIA 返回 status=False，树可能不完整")
        if meta["truncated"]:
            head.append(
                f"注意：元素达到上限 {meta['element_limit']}，部分元素未遍历"
                "（可缩小窗口范围或提高上限）")
        body = "\n".join(lines) if lines else "（没有取到可交互元素）"

        text = (
            "\n".join(head)
            + "\n\n可交互元素（用 uia_click / uia_type 时传 label）：\n"
            + body
            + "\n\n提示：label 只在最近一次 uia_snapshot 之后有效；"
              "界面变了要重新 uia_snapshot。"
        )
        if include_tree and res["semantic"]:
            tree_text = res["semantic"]
            if len(tree_text) > 12000:
                tree_text = tree_text[:12000] + "\n... [层级视图已截断]"
            text += "\n\n层级视图：\n" + tree_text

        return {
            "ok": True,
            "meta": meta,
            "elements": list(self._labels.values()),
            "text": text,
        }

    def _screen_desc(self) -> str:
        try:
            w, h = uia.GetVirtualScreenSize()
            return f"{w}x{h}"
        except Exception:
            return "?"

    # ---------------------------------------------------------------- 标签解析

    def resolve_label(self, label: int) -> dict[str, Any]:
        item = self._labels.get(int(label))
        if item is None:
            raise KeyError(
                f"标签 {label} 不存在或已失效（最近一次快照在 "
                f"{time.strftime('%H:%M:%S', time.localtime(self._snapshot_ts)) if self._snapshot_ts else '从未'}）。"
                "请先调用 uia_snapshot 再重试。"
            )
        return item

    def describe_label(self, label: int) -> str:
        it = self._labels.get(int(label))
        if not it:
            return f"label {label}"
        return f'[{label}] {it["control_type"].lower()} "{it["name"]}"'

    # ---------------------------------------------------------------- WaitFor

    def _find_sync(self, predicate_name: str, needle: str, control_type: str,
                   use_dom: bool, max_elements: int, exclude: set[str]) -> dict[str, Any] | None:
        res = self._snapshot_sync(use_dom, max_elements, exclude)
        meta = res["meta"]
        needle_l = (needle or "").lower()
        ctype_l = (control_type or "").lower()

        def match(item: dict[str, Any]) -> bool:
            name = (item.get("name") or "").lower()
            ctrl = (item.get("control_type") or "").lower()
            if ctype_l and ctype_l not in ctrl:
                return False
            if needle_l and needle_l not in name:
                return False
            return True

        if predicate_name == "window":
            title = (meta.get("active_title") or "").lower()
            return meta if (needle_l and needle_l in title) else None

        for item in self._labels.values():
            if match(item):
                return item
        return None

    def wait_for(self, *, condition: str = "element_exists", name: str = "",
                 control_type: str = "", timeout_s: float = 10.0,
                 interval_s: float = 0.6, use_dom: bool = False,
                 max_elements: int = 150,
                 exclude: list[str] | None = None) -> dict[str, Any]:
        excl = {e.strip().lower() for e in (exclude or []) if e and e.strip()}
        deadline = time.time() + max(0.1, float(timeout_s))
        attempts = 0
        last_err = ""
        while True:
            attempts += 1
            try:
                hit = self._call(self._find_sync, condition, name, control_type,
                                 use_dom, max_elements, excl)
            except Exception as exc:
                hit, last_err = None, str(exc)
            if hit:
                return {"ok": True, "matched": True, "attempts": attempts,
                        "waited_s": round(timeout_s - max(0.0, deadline - time.time()), 3),
                        "element": hit}
            if time.time() >= deadline:
                return {"ok": True, "matched": False, "attempts": attempts,
                        "waited_s": round(float(timeout_s), 3),
                        "condition": condition, "name": name,
                        "control_type": control_type,
                        "note": "超时未匹配", "last_error": last_err}
            time.sleep(min(interval_s, max(0.05, deadline - time.time())))


# --------------------------------------------------------------------------- 剪贴板

def _clipboard_retry(fn, attempts: int = 8, delay: float = 0.05):
    """剪贴板同一时刻只能被一个进程打开，失败就重试。"""
    last: Exception | None = None
    for _ in range(attempts):
        try:
            return fn()
        except Exception as exc:  # pywintypes.error 等
            last = exc
            time.sleep(delay)
    raise RuntimeError(f"剪贴板被占用，重试 {attempts} 次仍失败：{last}")


def clipboard_get(max_chars: int = 20000) -> dict[str, Any]:
    import win32clipboard

    def _do() -> str:
        win32clipboard.OpenClipboard()
        try:
            if win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_UNICODETEXT):
                return win32clipboard.GetClipboardData(win32clipboard.CF_UNICODETEXT)
            return ""
        finally:
            win32clipboard.CloseClipboard()

    text = _clipboard_retry(_do) or ""
    truncated = len(text) > max_chars
    return {"ok": True, "chars": len(text), "truncated": truncated,
            "text": text[:max_chars]}


def clipboard_set(text: str) -> dict[str, Any]:
    import win32clipboard

    def _do() -> None:
        win32clipboard.OpenClipboard()
        try:
            win32clipboard.EmptyClipboard()
            win32clipboard.SetClipboardData(win32clipboard.CF_UNICODETEXT, text)
        finally:
            win32clipboard.CloseClipboard()

    _clipboard_retry(_do)
    return {"ok": True, "chars": len(text)}
