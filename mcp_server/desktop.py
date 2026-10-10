"""桌面输入与显示控制：点击、输入文字、快捷键，以及屏幕常亮。

为什么不用 pyautogui：
* 本机没装（网络受限，装依赖麻烦），而且它依赖一串小包；
* pyautogui 的 ``typewrite`` 只支持 ASCII，中文根本输不进去。

直接用 Win32 ``SendInput`` 反而更好：零依赖，且能按 ``KEYEVENTF_UNICODE``
把任意 Unicode 字符（中文、emoji）当成按键发出去，不依赖输入法。

坐标约定：全部用**真实屏幕坐标**，与 ``screenshot`` 返回的 ``meta.left/top``
一致。多显示器时按整个虚拟桌面归一化到 0..65535 再发送。

一个必须知道的限制：如果会话已经**锁屏**，输入会送到锁屏界面而不是桌面，
GUI 操作必然无效。``session_locked()`` 用来提前发现这种情况并给出明确报错，
而不是让调用方对着"点了没反应"猜。
"""

from __future__ import annotations

import ctypes
import re
import subprocess
import time
from ctypes import wintypes

user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

ULONG_PTR = ctypes.c_ulonglong if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_ulong


# --------------------------------------------------------------------------
# 异常
# --------------------------------------------------------------------------


class DesktopError(Exception):
    """GUI 操作的前置校验失败：坐标越界、按键名不认识、参数类型不对等。

    server 层把它转成 ``{"error": "bad_request"}``，而不是笼统的
    internal_error，方便 Agent 自己纠正参数后重试。
    """


class SessionLocked(DesktopError):
    """会话已锁屏。此时输入会被送到锁屏界面，GUI 操作必然无效。"""


# --------------------------------------------------------------------------
# SendInput 结构
# --------------------------------------------------------------------------


class MOUSEINPUT(ctypes.Structure):
    _fields_ = [
        ("dx", wintypes.LONG),
        ("dy", wintypes.LONG),
        ("mouseData", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ULONG_PTR),
    ]


class KEYBDINPUT(ctypes.Structure):
    _fields_ = [
        ("wVk", wintypes.WORD),
        ("wScan", wintypes.WORD),
        ("dwFlags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ULONG_PTR),
    ]


class HARDWAREINPUT(ctypes.Structure):
    _fields_ = [
        ("uMsg", wintypes.DWORD),
        ("wParamL", wintypes.WORD),
        ("wParamH", wintypes.WORD),
    ]


class _INPUTUNION(ctypes.Union):
    _fields_ = [("mi", MOUSEINPUT), ("ki", KEYBDINPUT), ("hi", HARDWAREINPUT)]


class INPUT(ctypes.Structure):
    _fields_ = [("type", wintypes.DWORD), ("u", _INPUTUNION)]


INPUT_MOUSE = 0
INPUT_KEYBOARD = 1

KEYEVENTF_EXTENDEDKEY = 0x0001
KEYEVENTF_KEYUP = 0x0002
KEYEVENTF_UNICODE = 0x0004

MOUSEEVENTF_MOVE = 0x0001
MOUSEEVENTF_LEFTDOWN = 0x0002
MOUSEEVENTF_LEFTUP = 0x0004
MOUSEEVENTF_RIGHTDOWN = 0x0008
MOUSEEVENTF_RIGHTUP = 0x0010
MOUSEEVENTF_MIDDLEDOWN = 0x0020
MOUSEEVENTF_MIDDLEUP = 0x0040
MOUSEEVENTF_WHEEL = 0x0800
MOUSEEVENTF_VIRTUALDESK = 0x4000
MOUSEEVENTF_ABSOLUTE = 0x8000

SM_XVIRTUALSCREEN = 76
SM_YVIRTUALSCREEN = 77
SM_CXVIRTUALSCREEN = 78
SM_CYVIRTUALSCREEN = 79

ES_SYSTEM_REQUIRED = 0x00000001
ES_DISPLAY_REQUIRED = 0x00000002
ES_CONTINUOUS = 0x80000000

SPI_SETSCREENSAVEACTIVE = 0x0011
SPIF_UPDATEINIFILE = 0x01
SPIF_SENDCHANGE = 0x02

DESKTOP_READOBJECTS = 0x0001
DESKTOP_SWITCHDESKTOP = 0x0100

user32.SendInput.argtypes = [wintypes.UINT, ctypes.c_void_p, ctypes.c_int]
user32.SendInput.restype = wintypes.UINT
user32.SystemParametersInfoW.argtypes = [wintypes.UINT, wintypes.UINT,
                                         ctypes.c_void_p, wintypes.UINT]
user32.SystemParametersInfoW.restype = wintypes.BOOL
user32.OpenInputDesktop.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
user32.OpenInputDesktop.restype = wintypes.HANDLE
user32.CloseDesktop.argtypes = [wintypes.HANDLE]
user32.CloseDesktop.restype = wintypes.BOOL
kernel32.SetThreadExecutionState.argtypes = [wintypes.ULONG]
kernel32.SetThreadExecutionState.restype = wintypes.ULONG


# --------------------------------------------------------------------------
# 虚拟桌面与坐标
# --------------------------------------------------------------------------


def virtual_desktop() -> tuple[int, int, int, int]:
    """整个虚拟桌面的 (left, top, width, height)，多显示器时为并集。"""
    return (
        user32.GetSystemMetrics(SM_XVIRTUALSCREEN),
        user32.GetSystemMetrics(SM_YVIRTUALSCREEN),
        user32.GetSystemMetrics(SM_CXVIRTUALSCREEN),
        user32.GetSystemMetrics(SM_CYVIRTUALSCREEN),
    )


def screen_info() -> dict:
    left, top, width, height = virtual_desktop()
    return {
        "virtual_left": left,
        "virtual_top": top,
        "virtual_width": width,
        "virtual_height": height,
        "cursor": cursor_position(),
        "session_locked": session_locked(),
    }


def cursor_position() -> dict:
    point = wintypes.POINT()
    user32.GetCursorPos(ctypes.byref(point))
    return {"x": point.x, "y": point.y}


def session_locked() -> bool:
    """会话是否已锁屏。锁屏时输入送到的是锁屏界面，GUI 操作无效。"""
    handle = user32.OpenInputDesktop(0, False, DESKTOP_READOBJECTS | DESKTOP_SWITCHDESKTOP)
    if not handle:
        return True
    user32.CloseDesktop(handle)
    return False


def _normalize(x: int, y: int) -> tuple[int, int]:
    left, top, width, height = virtual_desktop()
    nx = int(round((x - left) * 65535 / max(1, width - 1)))
    ny = int(round((y - top) * 65535 / max(1, height - 1)))
    return max(0, min(65535, nx)), max(0, min(65535, ny))


# --------------------------------------------------------------------------
# 事件构造
# --------------------------------------------------------------------------


def _send_inputs(inputs: list[INPUT]) -> None:
    if not inputs:
        return
    count = len(inputs)
    array = (INPUT * count)(*inputs)
    sent = user32.SendInput(count, ctypes.byref(array), ctypes.sizeof(INPUT))
    if sent != count:
        raise OSError(
            f"SendInput 只发送了 {sent}/{count} 个事件"
            f"（错误码 {ctypes.get_last_error()}）。"
            "常见原因：目标进程权限更高（以管理员运行），或会话已锁屏。"
        )


def _vk_input(vk: int, *, up: bool = False, extended: bool = False) -> INPUT:
    flags = 0
    if up:
        flags |= KEYEVENTF_KEYUP
    if extended:
        flags |= KEYEVENTF_EXTENDEDKEY
    return INPUT(type=INPUT_KEYBOARD,
                 u=_INPUTUNION(ki=KEYBDINPUT(wVk=vk, wScan=0, dwFlags=flags,
                                             time=0, dwExtraInfo=0)))


def _unicode_input(unit: int, *, up: bool = False) -> INPUT:
    flags = KEYEVENTF_UNICODE | (KEYEVENTF_KEYUP if up else 0)
    return INPUT(type=INPUT_KEYBOARD,
                 u=_INPUTUNION(ki=KEYBDINPUT(wVk=0, wScan=unit, dwFlags=flags,
                                             time=0, dwExtraInfo=0)))


def _mouse_input(flags: int, dx: int = 0, dy: int = 0, data: int = 0) -> INPUT:
    return INPUT(type=INPUT_MOUSE,
                 u=_INPUTUNION(mi=MOUSEINPUT(dx=dx, dy=dy, mouseData=data,
                                             dwFlags=flags, time=0, dwExtraInfo=0)))


def _move_input(x: int, y: int) -> INPUT:
    nx, ny = _normalize(x, y)
    return _mouse_input(MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
                        dx=nx, dy=ny)


def _utf16_units(ch: str) -> list[int]:
    """把字符拆成 UTF-16 码元；BMP 外的字符要拆成代理对。"""
    code = ord(ch)
    if code <= 0xFFFF:
        return [code]
    code -= 0x10000
    return [0xD800 + (code >> 10), 0xDC00 + (code & 0x3FF)]


VK_RETURN = 0x0D
VK_TAB = 0x09

# 按键名 -> (虚拟键码, 是否扩展键)
_EXTENDED = {
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,  # PgUp PgDn End Home ←↑→↓
    0x2D, 0x2E, 0x2C, 0x90, 0x6F,                    # Ins Del PrtSc NumLock 小键盘/
    0x5B, 0x5C,                                      # Win 键
}

_NAMED_KEYS: dict[str, int] = {
    "ctrl": 0x11, "control": 0x11, "alt": 0x12, "shift": 0x10,
    "win": 0x5B, "windows": 0x5B, "super": 0x5B, "meta": 0x5B,
    "enter": 0x0D, "return": 0x0D, "tab": 0x09, "esc": 0x1B, "escape": 0x1B,
    "space": 0x20, "spacebar": 0x20, "backspace": 0x08, "back": 0x08,
    "delete": 0x2E, "del": 0x2E, "insert": 0x2D, "ins": 0x2D,
    "home": 0x24, "end": 0x23, "pageup": 0x21, "pgup": 0x21,
    "pagedown": 0x22, "pgdn": 0x22, "up": 0x26, "down": 0x28,
    "left": 0x25, "right": 0x27, "capslock": 0x14, "numlock": 0x90,
    "scrolllock": 0x91, "printscreen": 0x2C, "prtsc": 0x2C, "pause": 0x13,
    "apps": 0x5D, "menu": 0x5D, "sleep": 0x5F,
    "`": 0xC0, "-": 0xBD, "=": 0xBB, "[": 0xDB, "]": 0xDD, "\\": 0xDC,
    ";": 0xBA, "'": 0xDE, ",": 0xBC, ".": 0xBE, "/": 0xBF,
    "plus": 0xBB, "minus": 0xBD, "comma": 0xBC, "period": 0xBE,
    "slash": 0xBF, "semicolon": 0xBA, "quote": 0xDE,
    "backtick": 0xC0, "grave": 0xC0, "bracketleft": 0xDB, "bracketright": 0xDD,
    "backslash": 0xDC, "caps": 0x14,
}
for _i in range(1, 25):
    _NAMED_KEYS[f"f{_i}"] = 0x70 + _i - 1


def lookup_key(name: str) -> tuple[int, bool]:
    """把按键名转成 (虚拟键码, 是否扩展键)。无法识别时抛 DesktopError。"""
    key = (name or "").strip().lower()
    if not key:
        raise DesktopError("按键名为空")

    if key in _NAMED_KEYS:
        vk = _NAMED_KEYS[key]
        return vk, vk in _EXTENDED

    # 单个字母 / 数字
    if len(key) == 1:
        if "a" <= key <= "z":
            return ord(key.upper()), False
        if "0" <= key <= "9":
            return ord(key), False

    # 也接受十六进制写法，如 vk:0x41
    match = re.fullmatch(r"vk:(0x[0-9a-f]+|\d+)", key)
    if match:
        vk = int(match.group(1), 0)
        if not 0 <= vk <= 0xFF:
            raise DesktopError(f"虚拟键码超出范围：{vk}")
        return vk, vk in _EXTENDED

    raise DesktopError(f"无法识别的按键名：{name!r}。"
                       f"可用：字母数字、ctrl/alt/shift/win、enter/tab/esc/space、"
                       f"f1-f24、方向键、home/end/pageup/pagedown、"
                       f"delete/insert/backspace，或 vk:0x41 这种写法")


def split_hotkey(keys) -> list[str]:
    """把 ``"ctrl+shift+s"`` 或 ``["ctrl", "shift", "s"]`` 拆成按键名列表。

    纯函数，不发按键，所以测试可以放心调用。
    """
    if isinstance(keys, str):
        parts = [part.strip() for part in keys.split("+")]
    else:
        try:
            parts = [str(part).strip() for part in keys]
        except TypeError as exc:
            raise DesktopError("keys 必须是字符串或字符串列表") from exc
    parts = [part for part in parts if part]
    if not parts:
        raise DesktopError('keys 为空。例如 "ctrl+c" 或 ["win", "r"]')
    return parts


def parse_hotkey(keys) -> list[tuple[int, bool]]:
    """把按键名解析成 ``[(虚拟键码, 是否扩展键)]``。纯函数。"""
    return [lookup_key(part) for part in split_hotkey(keys)]


# --------------------------------------------------------------------------
# 三个操作
# --------------------------------------------------------------------------


def _char_inputs(ch: str) -> list[INPUT]:
    if ch == "\r":
        return []
    if ch == "\n":
        return [_vk_input(VK_RETURN), _vk_input(VK_RETURN, up=True)]
    if ch == "\t":
        return [_vk_input(VK_TAB), _vk_input(VK_TAB, up=True)]
    out: list[INPUT] = []
    for unit in _utf16_units(ch):
        out.append(_unicode_input(unit))
        out.append(_unicode_input(unit, up=True))
    return out


def type_text(text: str, interval_ms: int = 0) -> dict:
    """把 text 当成键盘输入发出去。支持中文等任意 Unicode。"""
    if not isinstance(text, str):
        raise DesktopError("text 必须是字符串")
    if not text:
        return {"typed_chars": 0, "interval_ms": 0}
    if session_locked():
        raise SessionLocked("当前会话已锁屏，键盘输入不会到达桌面。请先解锁。")

    interval_ms = max(0, min(int(interval_ms or 0), 5000))

    if interval_ms > 0:
        for ch in text:
            _send_inputs(_char_inputs(ch))
            time.sleep(interval_ms / 1000.0)
    else:
        inputs: list[INPUT] = []
        for ch in text:
            inputs.extend(_char_inputs(ch))
        _send_inputs(inputs)

    return {
        "typed_chars": len(text),
        "interval_ms": interval_ms,
        "preview": text[:80],
    }


_BUTTONS = {
    "left": (MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP),
    "right": (MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP),
    "middle": (MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP),
}


def click(x: int, y: int, button: str = "left", clicks: int = 1,
          interval_ms: int = 0) -> dict:
    """把鼠标移到真实屏幕坐标 (x, y) 并点击。clicks=0 表示只移动不点击。"""
    try:
        x, y = int(x), int(y)
    except (TypeError, ValueError) as exc:
        raise DesktopError(f"x/y 必须是整数：{x!r}, {y!r}") from exc

    button = (button or "left").strip().lower()
    if button not in _BUTTONS:
        raise DesktopError(f"button 只能是 left/right/middle，收到 {button!r}")

    clicks = max(0, min(int(clicks or 0), 3))
    left, top, width, height = virtual_desktop()
    if not (left <= x < left + width and top <= y < top + height):
        raise DesktopError(
            f"坐标 ({x}, {y}) 超出屏幕范围。当前虚拟桌面："
            f"x ∈ [{left}, {left + width - 1}]，y ∈ [{top}, {top + height - 1}]。"
            "注意要用 screenshot 返回的真实屏幕坐标（real_x = left + round(x / scale)）。"
        )
    if clicks and session_locked():
        raise SessionLocked("当前会话已锁屏，点击不会到达桌面。请先解锁。")

    down, up = _BUTTONS[button]
    inputs = [_move_input(x, y)]
    for _ in range(clicks):
        inputs.append(_mouse_input(down))
        inputs.append(_mouse_input(up))
    _send_inputs(inputs)

    if interval_ms:
        time.sleep(max(0, min(int(interval_ms), 5000)) / 1000.0)

    return {"x": x, "y": y, "button": button, "clicks": clicks,
            "cursor": cursor_position()}


def hotkey(keys, repeat: int = 1) -> dict:
    """按组合键。keys 可以是 "ctrl+shift+s" 或 ["ctrl", "shift", "s"]。"""
    names = split_hotkey(keys)
    resolved = [lookup_key(name) for name in names]
    repeat = max(1, min(int(repeat or 1), 100))
    if session_locked():
        raise SessionLocked("当前会话已锁屏，按键不会到达桌面。请先解锁。")

    inputs: list[INPUT] = []
    for _ in range(repeat):
        for vk, extended in resolved:
            inputs.append(_vk_input(vk, extended=extended))
        for vk, extended in reversed(resolved):
            inputs.append(_vk_input(vk, up=True, extended=extended))
    _send_inputs(inputs)

    return {"keys": names, "repeat": repeat,
            "resolved_vk": [vk for vk, _ in resolved]}


# --------------------------------------------------------------------------
# 显示、屏保与电源
# --------------------------------------------------------------------------


# 本进程（主线程）是否已开启「显示器常亮」。SetThreadExecutionState 是
# 按线程生效的，线程退出后设置就失效了，所以必须由一个长期存活的线程持有。
_keep_awake_active = False


def keep_display_awake() -> dict:
    """让显示器在本进程存活期间不熄屏、系统不睡眠。

    必须在长期存活的线程上调用（服务器是常驻进程，主线程正好满足）。
    这是软件层面最可靠的手段，且不需要管理员权限。

    注意 ``SetThreadExecutionState`` 的返回值是**上一次**的状态，第一次调用
    时上一次就是 0，跟「失败」分不清，所以这里连调两次，用第二次的返回值
    （应当带回 ES_CONTINUOUS）自证设置确实生效。
    """
    global _keep_awake_active

    flags = ES_CONTINUOUS | ES_DISPLAY_REQUIRED | ES_SYSTEM_REQUIRED
    previous = kernel32.SetThreadExecutionState(flags)
    after = kernel32.SetThreadExecutionState(flags)
    ok = bool(after & ES_CONTINUOUS)
    _keep_awake_active = ok
    return {"ok": ok, "previous_state": previous, "verified_state": after}


def allow_display_sleep() -> dict:
    """解除上面的保持，恢复系统默认的熄屏/睡眠行为。"""
    global _keep_awake_active

    previous = kernel32.SetThreadExecutionState(ES_CONTINUOUS)
    _keep_awake_active = False
    return {"ok": True, "previous_state": previous}


def disable_screensaver() -> dict:
    """关掉屏幕保护程序。只写 HKCU，不需要管理员。

    返回里带上改动前的原值，想恢复照着填回去即可。
    """
    import winreg

    result: dict = {"before": {}, "registry": None, "system_parameters": None}

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Control Panel\Desktop", 0,
                            winreg.KEY_READ | winreg.KEY_SET_VALUE) as key:
            for name in ("ScreenSaveActive", "ScreenSaveTimeOut"):
                try:
                    result["before"][name] = winreg.QueryValueEx(key, name)[0]
                except FileNotFoundError:
                    result["before"][name] = None
            winreg.SetValueEx(key, "ScreenSaveActive", 0, winreg.REG_SZ, "0")
            winreg.SetValueEx(key, "ScreenSaveTimeOut", 0, winreg.REG_SZ, "0")
        result["registry"] = "ok"
    except OSError as exc:
        result["registry"] = f"failed: {exc}"

    # SPI 是给已经跑起来的会话发通知，光写注册表不一定立刻生效
    ok = user32.SystemParametersInfoW(
        SPI_SETSCREENSAVEACTIVE, 0, None, SPIF_UPDATEINIFILE | SPIF_SENDCHANGE)
    result["system_parameters"] = "ok" if ok else f"failed: {ctypes.get_last_error()}"
    return result


# 动态锁（Dynamic Lock）的开关就在这里。它是 Windows 上最容易被忽略的
# 自动锁屏来源：屏幕/屏保/电源全配成「永不」之后，手机蓝牙一断照样锁屏。
_WINLOGON = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"


def disable_dynamic_lock() -> dict:
    """关掉「动态锁」：配对的手机离开蓝牙范围就自动锁屏。

    只写 HKCU，不需要管理员。返回改动前后的值，想恢复把 before 填回去即可
    （或在 设置 → 账户 → 登录选项 → 动态锁 里重新打开）。

    这是安全特性，关掉之后人走开电脑不会自动锁，请自行权衡。
    """
    import winreg

    result: dict = {"key": "HKCU\\" + _WINLOGON + "\\EnableGoodbye",
                    "before": None, "after": None, "error": None}
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _WINLOGON, 0,
                            winreg.KEY_READ | winreg.KEY_SET_VALUE) as key:
            try:
                result["before"] = winreg.QueryValueEx(key, "EnableGoodbye")[0]
            except FileNotFoundError:
                result["before"] = None
            winreg.SetValueEx(key, "EnableGoodbye", 0, winreg.REG_DWORD, 0)
            result["after"] = winreg.QueryValueEx(key, "EnableGoodbye")[0]
    except OSError as exc:
        result["error"] = str(exc)
    return result


_POWER_SETTINGS = (
    ("monitor-timeout-ac", "关显示器(交流)"),
    ("monitor-timeout-dc", "关显示器(电池)"),
    ("standby-timeout-ac", "睡眠(交流)"),
    ("standby-timeout-dc", "睡眠(电池)"),
    ("hibernate-timeout-ac", "休眠(交流)"),
    ("hibernate-timeout-dc", "休眠(电池)"),
)


def apply_power_tweaks() -> dict:
    """把当前电源方案里「关显示器 / 睡眠 / 休眠」的超时全设成「永不」。

    改的是电源方案本身，重启后依然有效，比 SetThreadExecutionState 更彻底。
    ``powercfg -change`` 改当前用户的方案通常不需要管理员，失败会把原因原样带回。
    """

    results: dict = {}
    for name, label in _POWER_SETTINGS:
        try:
            proc = subprocess.run(
                ["powercfg", "-change", name, "0"],
                capture_output=True, text=True, errors="replace", timeout=20,
                creationflags=0x08000000,  # CREATE_NO_WINDOW，不闪黑框
            )
        except (OSError, subprocess.SubprocessError) as exc:
            results[label] = f"failed: {exc}"
            continue
        if proc.returncode == 0:
            results[label] = "ok"
        else:
            detail = (proc.stderr or proc.stdout or "").strip().replace("\n", " ")
            results[label] = f"failed(rc={proc.returncode}): {detail[:120]}"
    results["all_ok"] = all(v == "ok" for k, v in results.items() if k != "all_ok")
    return results


def _scheme_setting(subgroup: str, setting: str) -> dict | None:
    """读电源方案里某一项的交流/直流索引。读不到就返回 None。

    powercfg 的输出是本地化的，所以不解析文字，只抓 0xXXXXXXXX 形式的索引。
    输出顺序固定为：最小可能值、最大可能值、增量……，当前交流索引、当前直流索引
    在最后，所以取最后两个。
    """

    try:
        proc = subprocess.run(
            ["powercfg", "-query", "SCHEME_CURRENT", subgroup, setting],
            capture_output=True, text=True, errors="replace", timeout=20,
            creationflags=0x08000000,
        )
    except (OSError, subprocess.SubprocessError):
        return None

    values = re.findall(r"0x[0-9a-fA-F]{8}", proc.stdout or "")
    if len(values) < 2:
        return None
    return {"ac": int(values[-2], 16), "dc": int(values[-1], 16)}


def display_settings() -> dict:
    """当前屏保与显示器电源设置，用来排查「为什么还会熄屏」。只读。"""
    import winreg

    out: dict = {}

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Control Panel\Desktop", 0,
                            winreg.KEY_READ) as key:
            for name in ("ScreenSaveActive", "ScreenSaveTimeOut", "SCRNSAVE.EXE",
                         "ScreenSaverIsSecure"):
                try:
                    out[name] = winreg.QueryValueEx(key, name)[0]
                except FileNotFoundError:
                    out[name] = None
    except OSError as exc:
        out["registry_error"] = str(exc)

    # 动态锁：配对的手机离开蓝牙范围就自动锁屏
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _WINLOGON, 0,
                            winreg.KEY_READ) as key:
            try:
                out["EnableGoodbye"] = winreg.QueryValueEx(key, "EnableGoodbye")[0]
            except FileNotFoundError:
                out["EnableGoodbye"] = None
    except OSError:
        pass

    # 电源方案里这几项的交流/直流索引（powercfg 输出是本地化的，只能靠 0x 值解析）
    video = _scheme_setting("SUB_VIDEO", "VIDEOIDLE")
    if video:
        out["video_idle_ac_s"] = video["ac"]
        out["video_idle_dc_s"] = video["dc"]

    lid = _scheme_setting("SUB_BUTTONS", "LIDACTION")
    if lid:
        out["lid_close_action"] = lid
        out["lid_close_action_values"] = "0=不采取任何操作 1=睡眠 2=休眠 3=关机"

    console = _scheme_setting("SUB_NONE", "CONSOLELOCK")
    if console:
        out["require_password_on_wakeup"] = console
        out["require_password_on_wakeup_values"] = "0=否 1=是"

    out["keep_awake_active"] = _keep_awake_active
    out["session_locked"] = session_locked()
    return out


def _jiggle_mouse() -> bool:
    """把鼠标挪开 1 像素再挪回来：净位移为 0，但足以让熄掉的显示器重新点亮。

    用绝对坐标而不是相对位移，避免光标正好贴在屏幕边缘时被裁掉、
    结果净位移不为 0 把光标留在别处。
    """
    left, top, width, height = virtual_desktop()
    pos = cursor_position()
    x, y = pos["x"], pos["y"]
    dx = 1 if x + 1 < left + width else -1
    try:
        _send_inputs([_move_input(x + dx, y), _move_input(x, y)])
        return True
    except OSError:
        return False


def wake_screen() -> dict:
    """唤醒显示器，并让它继续常亮。"""
    locked = session_locked()
    nudged = False if locked else _jiggle_mouse()
    return {
        "keep_awake": _keep_awake_active,
        "nudged": nudged,
        "session_locked": locked,
        "note": ("会话已锁屏，无法从锁屏界面点亮桌面；需要用户先解锁。"
                 if locked else
                 "已保持显示器常亮，并用 1 像素的鼠标位移触发点亮。"),
    }
