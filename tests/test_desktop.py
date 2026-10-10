"""desktop 模块的纯逻辑测试。

这里**故意不真发鼠标/键盘事件**：测试跑在开发机上，误点会点到别的窗口。
所以只测三类东西：

* 解析、坐标换算、事件构造这类纯函数；
* 会「先校验、后发送」的路径——校验失败时必然还没发送，所以安全；
* 只读的诊断函数。

真正把字符送进记事本的那部分验证，放在手工实测里做（见 README）。
"""

from __future__ import annotations

import pytest

from mcp_server import desktop


# ---------------------------------------------------------------- 按键名解析


def test_lookup_modifiers():
    assert desktop.lookup_key("ctrl")[0] == 0x11
    assert desktop.lookup_key("control")[0] == 0x11
    assert desktop.lookup_key("shift")[0] == 0x10
    assert desktop.lookup_key("alt")[0] == 0x12
    assert desktop.lookup_key("win")[0] == 0x5B


def test_lookup_letters_and_digits():
    assert desktop.lookup_key("a")[0] == 0x41
    assert desktop.lookup_key("A")[0] == 0x41
    assert desktop.lookup_key("5")[0] == 0x35


def test_lookup_function_keys():
    assert desktop.lookup_key("f1")[0] == 0x70
    assert desktop.lookup_key("f24")[0] == 0x87


def test_lookup_named_keys():
    assert desktop.lookup_key("enter")[0] == 0x0D
    assert desktop.lookup_key("esc")[0] == 0x1B
    assert desktop.lookup_key("pageup")[0] == 0x21
    assert desktop.lookup_key("pgdn")[0] == 0x22
    assert desktop.lookup_key("plus")[0] == 0xBB


def test_lookup_marks_extended_keys():
    # 方向键 / Delete / Win 键必须带 KEYEVENTF_EXTENDEDKEY，否则某些程序收不到
    assert desktop.lookup_key("left") == (0x25, True)
    assert desktop.lookup_key("delete") == (0x2E, True)
    assert desktop.lookup_key("win") == (0x5B, True)
    assert desktop.lookup_key("a") == (0x41, False)
    assert desktop.lookup_key("f24") == (0x87, False)


def test_lookup_vk_hex_form():
    assert desktop.lookup_key("vk:0x41")[0] == 0x41
    assert desktop.lookup_key("vk:65")[0] == 0x41


@pytest.mark.parametrize("bad", ["", "   ", "notakey", "vk:0x1FF", "vk:abc"])
def test_lookup_rejects_garbage(bad):
    with pytest.raises(desktop.DesktopError):
        desktop.lookup_key(bad)


# ---------------------------------------------------------------- 组合键拆分


def test_split_hotkey_string():
    assert desktop.split_hotkey("ctrl+shift+s") == ["ctrl", "shift", "s"]


def test_split_hotkey_list():
    assert desktop.split_hotkey(["win", "r"]) == ["win", "r"]


def test_split_hotkey_trims_and_drops_blanks():
    assert desktop.split_hotkey(" ctrl + c ") == ["ctrl", "c"]


@pytest.mark.parametrize("bad", ["", "   ", "+", [], ["", "  "]])
def test_split_hotkey_rejects_empty(bad):
    with pytest.raises(desktop.DesktopError):
        desktop.split_hotkey(bad)


def test_split_hotkey_rejects_non_iterable():
    with pytest.raises(desktop.DesktopError):
        desktop.split_hotkey(12345)


def test_parse_hotkey_resolves_vk():
    assert desktop.parse_hotkey("ctrl+shift+s") == [(0x11, False), (0x10, False), (0x53, False)]
    assert desktop.parse_hotkey(["win", "r"]) == [(0x5B, True), (0x52, False)]


# ---------------------------------------------------------------- 坐标换算


@pytest.fixture
def monitor_1920(monkeypatch):
    monkeypatch.setattr(desktop, "virtual_desktop", lambda: (0, 0, 1920, 1080))


def test_normalize_hits_both_corners(monitor_1920):
    assert desktop._normalize(0, 0) == (0, 0)
    assert desktop._normalize(1919, 1079) == (65535, 65535)


def test_normalize_center_is_near_half(monitor_1920):
    nx, ny = desktop._normalize(960, 540)
    assert 32700 <= nx <= 32850
    assert 32700 <= ny <= 32850


def test_normalize_clamps_out_of_range(monitor_1920):
    assert desktop._normalize(-500, -500) == (0, 0)
    assert desktop._normalize(99999, 99999) == (65535, 65535)


def test_normalize_respects_negative_origin(monkeypatch):
    # 主屏在右、副屏在左时虚拟桌面左上角是负数
    monkeypatch.setattr(desktop, "virtual_desktop", lambda: (-1920, 0, 3840, 1080))
    assert desktop._normalize(-1920, 0) == (0, 0)
    assert desktop._normalize(1919, 1079) == (65535, 65535)


def test_move_input_uses_virtual_desktop(monitor_1920):
    event = desktop._move_input(1919, 1079)
    assert event.type == desktop.INPUT_MOUSE
    assert event.u.mi.dx == 65535
    assert event.u.mi.dy == 65535
    for flag in (desktop.MOUSEEVENTF_MOVE, desktop.MOUSEEVENTF_ABSOLUTE,
                 desktop.MOUSEEVENTF_VIRTUALDESK):
        assert event.u.mi.dwFlags & flag


# ---------------------------------------------------------------- 事件构造


def test_char_inputs_plain_char_is_unicode_pair():
    events = desktop._char_inputs("a")
    assert len(events) == 2
    assert all(event.type == desktop.INPUT_KEYBOARD for event in events)
    assert all(event.u.ki.wVk == 0 for event in events)
    assert [event.u.ki.wScan for event in events] == [0x61, 0x61]
    assert events[0].u.ki.dwFlags & desktop.KEYEVENTF_UNICODE
    assert not events[0].u.ki.dwFlags & desktop.KEYEVENTF_KEYUP
    assert events[1].u.ki.dwFlags & desktop.KEYEVENTF_KEYUP


def test_char_inputs_chinese_goes_through_unicode():
    events = desktop._char_inputs("中")
    assert [event.u.ki.wScan for event in events] == [0x4E2D, 0x4E2D]


def test_char_inputs_emoji_uses_surrogate_pair():
    events = desktop._char_inputs("\U0001F600")
    assert [event.u.ki.wScan for event in events] == [0xD83D, 0xD83D, 0xDE00, 0xDE00]


def test_utf16_units_bmp_is_single_unit():
    assert desktop._utf16_units("a") == [0x61]
    assert desktop._utf16_units("中") == [0x4E2D]


def test_utf16_units_non_bmp_splits():
    assert desktop._utf16_units("\U0001F600") == [0xD83D, 0xDE00]


def test_char_inputs_newline_uses_vk_return():
    events = desktop._char_inputs("\n")
    assert [event.u.ki.wVk for event in events] == [desktop.VK_RETURN, desktop.VK_RETURN]
    assert not events[0].u.ki.dwFlags & desktop.KEYEVENTF_KEYUP
    assert events[1].u.ki.dwFlags & desktop.KEYEVENTF_KEYUP


def test_char_inputs_tab_uses_vk_tab():
    events = desktop._char_inputs("\t")
    assert [event.u.ki.wVk for event in events] == [desktop.VK_TAB, desktop.VK_TAB]


def test_char_inputs_drops_carriage_return():
    # Windows 的换行是 \r\n，\r 不能重复发一次回车
    assert desktop._char_inputs("\r") == []


def test_vk_input_extended_flag():
    assert desktop._vk_input(0x25, extended=True).u.ki.dwFlags & desktop.KEYEVENTF_EXTENDEDKEY
    assert not desktop._vk_input(0x25).u.ki.dwFlags & desktop.KEYEVENTF_EXTENDEDKEY


# ------------------------------------------------- 只校验、不发送的失败路径


def test_type_text_rejects_non_string():
    with pytest.raises(desktop.DesktopError):
        desktop.type_text(123)


def test_type_text_empty_is_noop():
    # 空串在校验后立刻返回，不会走到 session_locked / SendInput
    assert desktop.type_text("") == {"typed_chars": 0, "interval_ms": 0}


def test_click_rejects_bad_button():
    with pytest.raises(desktop.DesktopError):
        desktop.click(10, 10, button="thumb")


def test_click_rejects_non_numeric_coordinates():
    with pytest.raises(desktop.DesktopError):
        desktop.click("a", "b")


@pytest.mark.parametrize("x,y", [(-99999, -99999), (9_999_999, 9_999_999)])
def test_click_rejects_out_of_range_before_sending(x, y):
    # 越界检查排在 session_locked / SendInput 之前，所以这里不会真的点下去
    with pytest.raises(desktop.DesktopError):
        desktop.click(x, y)



# ---------------------------------------------------------------- 只读诊断


def test_display_settings_is_read_only_snapshot():
    info = desktop.display_settings()
    assert "keep_awake_active" in info
    assert "session_locked" in info
    # 屏保键在 HKCU 下总是存在，值可能是 None
    assert "ScreenSaveActive" in info
    # 电源索引要么没读出来，要么是整数秒
    for key in ("video_idle_ac_s", "video_idle_dc_s"):
        assert key not in info or isinstance(info[key], int)


def test_screen_info_reports_virtual_desktop():
    info = desktop.screen_info()
    assert info["virtual_width"] > 0
    assert info["virtual_height"] > 0
    assert isinstance(info["cursor"], dict)
    assert isinstance(info["session_locked"], bool)


def test_display_settings_reports_dynamic_lock():
    # 只读：动态锁的开关位（真去改它会把用户刚打开的设置又关掉，所以测试不碰）
    info = desktop.display_settings()
    assert "EnableGoodbye" in info
    assert info["EnableGoodbye"] in (None, 0, 1)


def test_disable_dynamic_lock_targets_the_right_key():
    # 不真写注册表：只确认函数存在且签名正确（真正的写操作留到启动流程里做）
    assert callable(desktop.disable_dynamic_lock)
    assert desktop._WINLOGON.endswith("CurrentVersion\\Winlogon")


def test_display_settings_reports_lid_and_console_lock():
    # 只读：这两项决定「合盖会不会锁屏、唤醒要不要 PIN」，是排错的关键线索
    info = desktop.display_settings()
    for key in ("lid_close_action", "require_password_on_wakeup"):
        value = info.get(key)
        assert value is None or set(value) == {"ac", "dc"}


def test_scheme_setting_parses_last_two_indices(monkeypatch):
    # powercfg 输出里「最小/最大可能值」也带 0x，必须取最后两个才是交流/直流
    fake = (
        "  最小可能的设置: 0x00000000\n"
        "  最大可能的设置: 0xffffffff\n"
        "  可能的设置增量: 0x00000001\n"
        "  当前交流电源设置索引: 0x00000000\n"
        "  当前直流电源设置索引: 0x00000001\n"
    )

    class Done:
        stdout = fake

    monkeypatch.setattr(desktop.subprocess, "run", lambda *a, **k: Done())
    assert desktop._scheme_setting("SUB_BUTTONS", "LIDACTION") == {"ac": 0, "dc": 1}


def test_scheme_setting_returns_none_when_unreadable(monkeypatch):
    class Done:
        stdout = "电源方案 GUID: 381b4222  (平衡)\n"

    monkeypatch.setattr(desktop.subprocess, "run", lambda *a, **k: Done())
    assert desktop._scheme_setting("SUB_NONE", "CONSOLELOCK") is None
