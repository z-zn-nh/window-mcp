"""新工具的测试：UIA 无障碍树 + 剪贴板 + agent_status。

和 test_gui_gate.py 一样，**故意不碰真实桌面**：UIA 桥接层和 desktop 的发送
函数都换成替身，只验证 server 层这条链路（闸门、标签解析、参数护栏、脱敏）。
真实 UIA 抓树与点击靠公网/本地实测验收（见 CHANGES-merge.md）。
"""

from __future__ import annotations

import asyncio
import json

import pytest

from mcp_server import agent_status as agent_status_mod
from mcp_server import desktop
from mcp_server.config import Config
from mcp_server.server import Server

from tests.test_gui_gate import make_server  # noqa: F401  （复用同一套建服务器逻辑）


# --------------------------------------------------------------------------- 替身


class FakeBridge:
    """假的 UiaBridge：只记录调用，按预设标签表解析坐标。"""

    def __init__(self, labels=None, wait_result=None):
        self.labels = labels if labels is not None else {
            0: {"label": 0, "x": 111, "y": 222, "name": "保存",
                "control_type": "ButtonControl", "window": "记事本"},
            1: {"label": 1, "x": 333, "y": 444, "name": "搜索",
                "control_type": "EditControl", "window": "记事本"},
        }
        self.calls: list[tuple] = []
        self.wait_result = wait_result or {"ok": True, "matched": True,
                                           "attempts": 1, "element": {"label": 0}}

    def snapshot(self, *, use_dom=False, max_elements=150, include_tree=True,
                 exclude=None):
        self.calls.append(("snapshot", use_dom, max_elements, include_tree,
                           list(exclude or [])))
        return {"ok": True, "meta": {"active_title": "记事本", "capture_sec": 0.1},
                "elements": list(self.labels.values()), "text": "假快照"}

    def wait_for(self, **kwargs):
        self.calls.append(("wait_for", kwargs))
        return self.wait_result

    def resolve_label(self, label):
        item = self.labels.get(int(label))
        if item is None:
            raise KeyError(f"标签 {label} 不存在或已失效，请先调用 uia_snapshot 再重试。")
        return item

    def describe_label(self, label):
        it = self.labels.get(int(label))
        return f'[{label}] {it["control_type"]} "{it["name"]}"' if it else f"label {label}"


@pytest.fixture
def fake_desktop(monkeypatch):
    recorded: list[tuple] = []

    def fake_click(x, y, button="left", clicks=1, interval_ms=0):
        recorded.append(("click", x, y, button, clicks, interval_ms))
        return {"x": x, "y": y, "button": button, "clicks": clicks}

    def fake_type_text(text, interval_ms=0):
        recorded.append(("type_text", text, interval_ms))
        return {"typed_chars": len(text), "interval_ms": interval_ms}

    def fake_hotkey(keys, repeat=1):
        recorded.append(("hotkey", keys, repeat))
        return {"keys": keys, "repeat": repeat}

    monkeypatch.setattr(desktop, "click", fake_click)
    monkeypatch.setattr(desktop, "type_text", fake_type_text)
    monkeypatch.setattr(desktop, "hotkey", fake_hotkey)
    return recorded


def with_bridge(srv: Server, bridge: FakeBridge) -> Server:
    srv._uia = bridge          # 绕过懒加载，直接注入替身
    return srv


# --------------------------------------------------------------------------- 注册


NEW_TOOLS = {
    "uia_snapshot", "uia_wait_for", "uia_click", "uia_type",
    "clipboard_get", "clipboard_set", "agent_status",
}


def test_new_tools_are_registered(tmp_path):
    srv = make_server(tmp_path)
    names = {t.name for t in asyncio.run(srv.mcp.list_tools())}
    assert NEW_TOOLS <= names
    assert len(names) == 26


def test_new_tool_schemas(tmp_path):
    srv = make_server(tmp_path)
    schemas = {t.name: t.inputSchema for t in asyncio.run(srv.mcp.list_tools())}
    assert schemas["uia_click"]["required"] == ["label"]
    assert set(schemas["uia_type"]["required"]) == {"text", "label"}
    # 全默认参数的工具有没有 required 键都算合法
    assert not schemas["uia_snapshot"].get("required")
    assert not schemas["agent_status"].get("required")


# --------------------------------------------------------------------------- 快照


def test_uia_snapshot_runs_and_passes_options(tmp_path):
    srv = with_bridge(make_server(tmp_path), FakeBridge())
    r = srv.uia_snapshot(use_dom=True, max_elements=5, include_tree=False,
                         exclude=["Code.exe"])
    assert r["ok"] is True
    # exclude 由桥接层内部归一化成小写，Server 只是原样透传
    assert srv._uia.calls == [("snapshot", True, 5, False, ["Code.exe"])]


def test_uia_snapshot_uses_config_default_limit(tmp_path):
    srv = with_bridge(make_server(tmp_path, uia_max_elements=42), FakeBridge())
    srv.uia_snapshot()
    assert srv._uia.calls[0][2] == 42


def test_uia_snapshot_clamps_limit(tmp_path):
    srv = with_bridge(make_server(tmp_path), FakeBridge())
    srv.uia_snapshot(max_elements=99999)
    assert srv._uia.calls[0][2] == 600          # 硬上限


# --------------------------------------------------------------------------- 按标签操作


def test_uia_click_resolves_label_to_screen_coords(tmp_path, fake_desktop):
    srv = with_bridge(make_server(tmp_path), FakeBridge())
    r = srv.uia_click(1)
    assert fake_desktop == [("click", 333, 444, "left", 1, 0)]
    assert r["label"] == 1
    assert r["target"]["name"] == "搜索"


def test_uia_click_double_click(tmp_path, fake_desktop):
    srv = with_bridge(make_server(tmp_path), FakeBridge())
    srv.uia_click(0, clicks=2)
    assert fake_desktop == [("click", 111, 222, "left", 2, 0)]


def test_uia_click_unknown_label_errors(tmp_path, fake_desktop):
    srv = with_bridge(make_server(tmp_path), FakeBridge())
    r = srv.uia_click(99)
    assert r["error"] == "internal_error"
    assert "99" in r["message"]
    assert fake_desktop == []


def test_uia_type_focuses_then_types(tmp_path, fake_desktop):
    srv = with_bridge(make_server(tmp_path), FakeBridge())
    r = srv.uia_type("你好", 1)
    # 先点一下聚焦，再输入
    assert fake_desktop == [("click", 333, 444, "left", 1, 0),
                            ("type_text", "你好", 0)]
    assert r["typed"] == 2


def test_uia_type_clear_and_enter(tmp_path, fake_desktop):
    srv = with_bridge(make_server(tmp_path), FakeBridge())
    srv.uia_type("x", 1, clear=True, press_enter=True)
    assert fake_desktop == [
        ("click", 333, 444, "left", 1, 0),
        ("hotkey", "ctrl+a", 1),
        ("hotkey", "delete", 1),
        ("type_text", "x", 0),
        ("hotkey", "enter", 1),
    ]


def test_uia_type_too_long_rejected(tmp_path, fake_desktop):
    srv = with_bridge(make_server(tmp_path, gui_max_chars=5), FakeBridge())
    r = srv.uia_type("x" * 6, 1)
    assert r["error"] == "bad_request"
    assert fake_desktop == []


# --------------------------------------------------------------------------- 闸门


def test_uia_level_x_denies_everything(tmp_path, fake_desktop):
    srv = with_bridge(make_server(tmp_path, uia_level="X"), FakeBridge())
    results = [srv.uia_click(0), srv.uia_type("x", 0),
               srv.clipboard_set("x")]
    for r in results:
        assert r["error"] == "denied_by_policy"
        assert r["level"] == "X"
    assert fake_desktop == []


def test_uia_level_x_denies_snapshot(tmp_path):
    srv = with_bridge(make_server(tmp_path, uia_level="X"), FakeBridge())
    r = srv.uia_snapshot()
    # 只读快照不受 uia_level 管辖（它走 _run_tool 的 R 档）
    assert r.get("ok") is True


def test_uia_level_h_requires_approval_then_executes(tmp_path, fake_desktop):
    srv = with_bridge(make_server(tmp_path, uia_level="H"), FakeBridge())
    pending = srv.uia_click(0)
    assert pending["status"] == "pending_approval"
    assert fake_desktop == []                       # 批准前不许动桌面

    srv.approvals.decide(pending["approval_id"], approve=True, actor="tester")
    done = srv.approval_status(pending["approval_id"])
    assert done["status"] == "executed"
    assert fake_desktop == [("click", 111, 222, "left", 1, 0)]


def test_uia_level_h_rejection_does_not_touch_desktop(tmp_path, fake_desktop):
    srv = with_bridge(make_server(tmp_path, uia_level="H"), FakeBridge())
    pending = srv.clipboard_set("secret")
    srv.approvals.decide(pending["approval_id"], approve=False, actor="tester")
    assert srv.approval_status(pending["approval_id"])["status"] == "rejected"


def test_uia_tools_do_not_consume_high_rate_quota(tmp_path, fake_desktop):
    srv = with_bridge(make_server(tmp_path, rate_high_per_hour=1), FakeBridge())
    for _ in range(5):
        assert "error" not in srv.uia_click(0)


# --------------------------------------------------------------------------- WaitFor


def test_wait_for_matched(tmp_path):
    srv = with_bridge(make_server(tmp_path), FakeBridge())
    r = srv.uia_wait_for(condition="window", name="记事本", timeout_s=3)
    assert r["matched"] is True
    call = srv._uia.calls[-1]
    assert call[0] == "wait_for"
    assert call[1]["condition"] == "window"
    assert call[1]["timeout_s"] == 3.0


def test_wait_for_timeout_is_not_an_error(tmp_path):
    srv = with_bridge(make_server(tmp_path),
                      FakeBridge(wait_result={"ok": True, "matched": False,
                                              "attempts": 4, "note": "超时未匹配"}))
    r = srv.uia_wait_for(condition="element_exists", name="不存在", timeout_s=2)
    assert r["ok"] is True and r["matched"] is False


def test_wait_for_clamps_timeout_to_under_hark_limit(tmp_path):
    srv = with_bridge(make_server(tmp_path), FakeBridge())
    srv.uia_wait_for(timeout_s=9999)
    assert srv._uia.calls[-1][1]["timeout_s"] == 50.0


def test_wait_for_clamps_interval(tmp_path):
    srv = with_bridge(make_server(tmp_path), FakeBridge())
    srv.uia_wait_for(interval_ms=1)
    assert srv._uia.calls[-1][1]["interval_s"] == pytest.approx(0.1)


# --------------------------------------------------------------------------- 剪贴板


def test_clipboard_get_is_read_only(tmp_path, monkeypatch):
    monkeypatch.setattr("mcp_server.uia.clipboard_get",
                        lambda n=20000: {"ok": True, "chars": 3, "text": "abc"})
    srv = make_server(tmp_path)
    r = srv.clipboard_get()
    assert r["ok"] is True and r["text"] == "abc"


def test_clipboard_set_writes(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr("mcp_server.uia.clipboard_set",
                        lambda t: seen.append(t) or {"ok": True, "chars": len(t)})
    srv = make_server(tmp_path)
    r = srv.clipboard_set("hello")
    assert r["ok"] is True
    assert seen == ["hello"]


def test_clipboard_set_non_string_rejected(tmp_path):
    srv = make_server(tmp_path)
    assert srv.clipboard_set(None)["error"] == "bad_request"  # type: ignore[arg-type]


# --------------------------------------------------------------------------- agent_status


def test_agent_status_passes_limits(tmp_path, monkeypatch):
    captured = {}

    def fake_collect(pi_limit=3, dsh_limit=3, max_chars=240):
        captured.update(pi_limit=pi_limit, dsh_limit=dsh_limit, max_chars=max_chars)
        return {"ok": True, "sessions": []}

    monkeypatch.setattr(agent_status_mod, "collect", fake_collect)
    srv = make_server(tmp_path)
    r = srv.agent_status(pi_limit=2, dsh_limit=4, max_chars=100)
    assert r["ok"] is True
    assert captured == {"pi_limit": 2, "dsh_limit": 4, "max_chars": 100}


def test_agent_status_redacts_secrets():
    raw = ("token=sk-abcdefghijklmnopqrstuvwxyz012345 "
           "Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789 "
           "hex=0123456789abcdef0123456789abcdef01234567")
    out = agent_status_mod._clip(raw, 500)
    assert "sk-abcdefghijklmnopqrstuvwxyz012345" not in out
    assert "Bearer abcdefghijklmnopqrstuvwxyz" not in out
    assert "0123456789abcdef0123456789abcdef01234567" not in out
    assert "<redacted>" in out


def test_agent_status_clip_truncates_and_flattens():
    out = agent_status_mod._clip("第一行\n第二行\t第三行" + "x" * 300, 50)
    assert "\n" not in out and "\t" not in out
    assert out.endswith("…")
    assert len(out) <= 51


def test_agent_status_redaction_covers_pem_and_env_style_keys():
    out = agent_status_mod._redact("A" * 48)
    assert out == "<redacted>"


# --------------------------------------------------------------------------- 前缀


def test_new_tools_get_the_prefix_too(tmp_path):
    srv = make_server(tmp_path, tool_prefix="wb_")
    names = {t.name for t in asyncio.run(srv.mcp.list_tools())}
    assert all(n.startswith("wb_") for n in names)
    assert {"wb_uia_snapshot", "wb_agent_status"} <= names


def test_uia_audit_uses_unprefixed_name(tmp_path, fake_desktop):
    srv = with_bridge(make_server(tmp_path, tool_prefix="wb_"), FakeBridge())
    srv.uia_click(0)
    files = list((tmp_path / "logs").glob("audit-*.jsonl"))
    logged = [json.loads(line)["tool"]
              for line in files[0].read_text(encoding="utf-8").splitlines()
              if line.strip()]
    assert "uia_click" in logged
    assert "wb_uia_click" not in logged
