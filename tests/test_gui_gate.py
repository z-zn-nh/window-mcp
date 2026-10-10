"""GUI 工具的闸门测试：分级 → 放行 / 审批 / 拒绝。

这里**故意不碰真实桌面**：把 desktop 里的发送函数换成只做记录的替身，
只验证 server 层这条链路。真实点击、输入的效果靠手工实测（见 README）。
"""

from __future__ import annotations

import asyncio
import json

import pytest

from mcp_server import desktop
from mcp_server.config import Config
from mcp_server.server import Server


@pytest.fixture
def fake_desktop(monkeypatch):
    """把 desktop 的发送函数换成替身，返回调用记录列表。"""
    recorded: list[tuple] = []

    def fake_type_text(text, interval_ms=0):
        recorded.append(("type_text", text, interval_ms))
        return {"typed_chars": len(text), "interval_ms": interval_ms}

    def fake_click(x, y, button="left", clicks=1, interval_ms=0):
        recorded.append(("click", x, y, button, clicks, interval_ms))
        return {"x": x, "y": y, "button": button, "clicks": clicks}

    def fake_hotkey(keys, repeat=1):
        recorded.append(("hotkey", keys, repeat))
        return {"keys": keys, "repeat": repeat}

    def fake_wake_screen():
        recorded.append(("wake_screen",))
        return {"keep_awake": True, "nudged": True, "session_locked": False}

    replacements = {
        "type_text": fake_type_text,
        "click": fake_click,
        "hotkey": fake_hotkey,
        "wake_screen": fake_wake_screen,
    }
    for name, replacement in replacements.items():
        monkeypatch.setattr(desktop, name, replacement)
    return recorded


def make_server(tmp_path, **overrides) -> Server:
    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    settings = dict(
        tokens=["t" * 24],
        work_dir=str(work),
        log_dir=str(tmp_path / "logs"),
        state_dir=str(tmp_path / "state"),
        rate_per_minute=10000,
        rate_high_per_hour=10000,
    )
    settings.update(overrides)
    cfg = Config(**settings)
    cfg.ensure_dirs()
    return Server(cfg)


# ---------------------------------------------------------------- 注册与默认


def test_gui_tools_are_registered(tmp_path):
    srv = make_server(tmp_path)
    names = {tool.name for tool in asyncio.run(srv.mcp.list_tools())}
    assert {"type_text", "click", "hotkey", "wake_screen"} <= names
    # 19 个原有工具 + 7 个新增（uia_snapshot/wait_for/click/type、
    # clipboard_get/set、agent_status）
    assert len(names) == 26


def test_tool_prefix_is_applied(tmp_path):
    """两个同名 MCP 并行跑时靠前缀区分；内部/审计仍用不带前缀的原名。"""
    srv = make_server(tmp_path, tool_prefix="wb_")
    names = {tool.name for tool in asyncio.run(srv.mcp.list_tools())}
    assert all(n.startswith("wb_") for n in names), sorted(names)
    assert len(names) == 26
    # 前缀只影响对外名字，审计日志里应仍是不带前缀的原名
    srv.type_text("hi")
    files = list((tmp_path / "logs").glob("audit-*.jsonl"))
    assert files, "没有生成审计日志"
    logged = [json.loads(line)["tool"]
              for line in files[0].read_text(encoding="utf-8").splitlines()
              if line.strip()]
    assert "type_text" in logged
    assert "wb_type_text" not in logged


def test_tool_prefix_rejects_bad_characters(tmp_path):
    with pytest.raises(ValueError):
        Config(tokens=["t" * 24], tool_prefix="wb-")  # 连字符非法


def test_gui_tool_schemas(tmp_path):
    srv = make_server(tmp_path)
    schemas = {tool.name: tool.inputSchema for tool in asyncio.run(srv.mcp.list_tools())}
    assert schemas["type_text"]["required"] == ["text"]
    assert set(schemas["click"]["required"]) == {"x", "y"}
    assert schemas["hotkey"]["required"] == ["keys"]
    assert not schemas["wake_screen"].get("required")


def test_gui_default_is_no_approval(tmp_path, fake_desktop):
    srv = make_server(tmp_path)
    result = srv.type_text("hello 中文")
    assert result["typed_chars"] == 8  # "hello " + 中文
    assert fake_desktop == [("type_text", "hello 中文", 0)]
    assert srv.approvals.list_pending() == []


def test_click_default_is_no_approval(tmp_path, fake_desktop):
    srv = make_server(tmp_path)
    result = srv.click(100, 200, button="right", clicks=2)
    assert result["clicks"] == 2
    assert fake_desktop == [("click", 100, 200, "right", 2, 0)]


def test_hotkey_and_wake_screen_default_is_no_approval(tmp_path, fake_desktop):
    srv = make_server(tmp_path)
    srv.hotkey("ctrl+c")
    srv.wake_screen()
    assert fake_desktop == [("hotkey", "ctrl+c", 1), ("wake_screen",)]


# ---------------------------------------------------------------- 分级行为


def test_gui_level_x_denies_everything(tmp_path, fake_desktop):
    srv = make_server(tmp_path, gui_level="X")
    results = [srv.type_text("x"), srv.click(1, 1), srv.hotkey("esc"), srv.wake_screen()]
    for result in results:
        assert result["error"] == "denied_by_policy"
        assert result["level"] == "X"
    assert fake_desktop == []


def test_gui_level_h_requires_approval_then_executes(tmp_path, fake_desktop):
    srv = make_server(tmp_path, gui_level="H")
    pending = srv.hotkey("ctrl+v")
    assert pending["status"] == "pending_approval"
    assert fake_desktop == []  # 没批准之前不许动桌面

    srv.approvals.decide(pending["approval_id"], approve=True, actor="tester")
    executed = srv.approval_status(pending["approval_id"])
    assert executed["status"] == "executed"
    assert fake_desktop == [("hotkey", "ctrl+v", 1)]


def test_gui_level_h_rejection_does_not_touch_desktop(tmp_path, fake_desktop):
    srv = make_server(tmp_path, gui_level="H")
    pending = srv.click(5, 5)
    srv.approvals.decide(pending["approval_id"], approve=False, actor="tester")
    status = srv.approval_status(pending["approval_id"])
    assert status["status"] == "rejected"
    assert fake_desktop == []


# ---------------------------------------------------------------- 错误映射


def test_locked_session_returns_specific_error(tmp_path, monkeypatch):
    def boom(*_args, **_kwargs):
        raise desktop.SessionLocked("当前会话已锁屏，键盘输入不会到达桌面。")

    monkeypatch.setattr(desktop, "type_text", boom)
    srv = make_server(tmp_path)
    result = srv.type_text("x")
    assert result["error"] == "session_locked"
    assert "锁屏" in result["message"]


def test_bad_arguments_become_bad_request(tmp_path, monkeypatch):
    def boom(*_args, **_kwargs):
        raise desktop.DesktopError("坐标 (9999999, 9999999) 超出屏幕范围。")

    monkeypatch.setattr(desktop, "click", boom)
    srv = make_server(tmp_path)
    result = srv.click(9999999, 9999999)
    assert result["error"] == "bad_request"
    assert "超出屏幕" in result["message"]


# ---------------------------------------------------------------- 参数护栏


def test_type_text_too_long_rejected(tmp_path, fake_desktop):
    srv = make_server(tmp_path, gui_max_chars=10)
    result = srv.type_text("x" * 11)
    assert result["error"] == "bad_request"
    assert fake_desktop == []


def test_type_text_slow_interval_rejected(tmp_path, fake_desktop):
    srv = make_server(tmp_path)
    # 1000 字符 × 1000 ms = 1000 秒，远超单次调用时限
    result = srv.type_text("x" * 1000, interval_ms=1000)
    assert result["error"] == "bad_request"
    assert fake_desktop == []


def test_type_text_non_string_rejected(tmp_path, fake_desktop):
    srv = make_server(tmp_path)
    result = srv.type_text(None)  # type: ignore[arg-type]
    assert result["error"] == "bad_request"
    assert fake_desktop == []


def test_gui_calls_do_not_consume_high_rate_quota(tmp_path, fake_desktop):
    # 高危额度只有 1 次/小时；普通 GUI 操作走 R 档，不该被它拦住
    srv = make_server(tmp_path, rate_high_per_hour=1)
    for _ in range(5):
        assert "error" not in srv.type_text("hi")
    assert len(fake_desktop) == 5
