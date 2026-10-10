"""工具白名单在 **MCP 边界**上的强制（端到端，真起 uvicorn）。

这是整个面板功能的验收核心：白名单必须是服务端强制，而不是「面板上看起来被禁了」。

* ``tools/call`` 越权 → 403，请求根本到不了工具函数；
* ``tools/list`` 只列出允许的工具（响应被缓冲后过滤）；
* 判定用**内部名**，所以改 ``tool_prefix`` 不会让已有白名单失效；
* 被拒的调用要进审计（记工具名，**不记参数值**）；
* **白名单不替代审批策略**：允许了 run_command 的 bot 去跑危险命令，
  仍然照旧走审批，而不是直接执行。
"""

from __future__ import annotations

import json
import socket
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn

from mcp_server.app import App
from mcp_server.bots import ALL, BotStore
from mcp_server.config import Config
from mcp_server.server import Server

STATIC_TOKEN = "S" * 64
ADMIN_TOKEN = "admin-token-abcdefghijklmnopqrstuvwxyz"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def mcp(tmp_path):
    """真起一个 MCP 服务器；prefix 用 wb_，与生产一致。"""
    work = tmp_path / "work"
    work.mkdir()
    cfg = Config(
        host="127.0.0.1", port=free_port(), path="/mcp", tool_prefix="wb_",
        tokens=[STATIC_TOKEN], admin_token=ADMIN_TOKEN,
        read_roots=[str(work)], write_roots=[str(work)], work_dir=str(work),
        log_dir=str(tmp_path / "logs"), state_dir=str(tmp_path / "state"),
        rate_per_minute=100000, rate_high_per_hour=100000,
    )
    cfg.ensure_dirs()
    server = Server(cfg)
    app = App(server)
    uv = uvicorn.Server(uvicorn.Config(app, host=cfg.host, port=cfg.port,
                                      log_level="warning", access_log=False))
    thread = threading.Thread(target=uv.run, daemon=True)
    thread.start()

    url = f"http://127.0.0.1:{cfg.port}/mcp"
    deadline = time.time() + 25
    while time.time() < deadline:
        try:
            if httpx.get(f"http://127.0.0.1:{cfg.port}/healthz", timeout=1,
                         headers={"Authorization": f"Bearer {STATIC_TOKEN}"}
                         ).status_code == 200:
                break
        except httpx.HTTPError:
            pass
        time.sleep(0.05)
    else:
        raise RuntimeError("测试服务器起不来")

    holder = type("Ctx", (), {})()
    holder.cfg, holder.server, holder.app, holder.url = cfg, server, app, url
    holder.bots = app.bots
    holder.audit_file = Path(cfg.log_path) / time.strftime("audit-%Y-%m-%d.jsonl")
    yield holder
    uv.should_exit = True
    thread.join(5)


def rpc(ctx, token, method, params=None, rid=1):
    body = {"jsonrpc": "2.0", "id": rid, "method": method}
    if params is not None:
        body["params"] = params
    return httpx.post(ctx.url, json=body, timeout=30, headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    })


def tool_names(response) -> list[str]:
    try:
        return [t["name"] for t in response.json()["result"]["tools"]]
    except Exception:
        return []


def new_bot(ctx, name, allow, **extra):
    public, token = ctx.bots.create(name, allow=allow, **extra)
    return public, token


# ---------------------------------------------------------------- 越权

def test_whitelisted_bot_sees_only_its_tools(mcp):
    _, token = new_bot(mcp, "reader", ["system_info", "read_file"])
    response = rpc(mcp, token, "tools/list")
    assert response.status_code == 200
    names = tool_names(response)
    assert sorted(names) == ["wb_read_file", "wb_system_info"]


def test_whitelisted_bot_gets_403_on_other_tools(mcp):
    _, token = new_bot(mcp, "reader", ["system_info"])
    response = rpc(mcp, token, "tools/call",
                   {"name": "wb_run_command", "arguments": {"command": "Get-Date"}})
    assert response.status_code == 403
    body = response.json()
    assert body["error"] == "tool_not_allowed"
    assert body["tool"] == "wb_run_command"


def test_whitelisted_bot_can_call_its_own_tool(mcp):
    _, token = new_bot(mcp, "reader", ["system_info"])
    response = rpc(mcp, token, "tools/call", {"name": "wb_system_info", "arguments": {}})
    assert response.status_code == 200
    assert "hostname" in response.text


def test_whitelist_does_not_block_non_tool_methods(mcp):
    _, token = new_bot(mcp, "reader", ["system_info"])
    assert rpc(mcp, token, "initialize", {"protocolVersion": "2025-06-18",
                                          "capabilities": {},
                                          "clientInfo": {"name": "t", "version": "1"}}
               ).status_code == 200
    assert rpc(mcp, token, "ping").status_code in (200, 202)
    assert rpc(mcp, token, "tools/list").status_code == 200


def test_internal_name_is_checked_even_without_prefix(mcp):
    """不带前缀直接写内部名，同样要过白名单——不能靠「换个写法」绕过。"""
    _, token = new_bot(mcp, "reader", ["system_info"])
    assert rpc(mcp, token, "tools/call",
               {"name": "run_command", "arguments": {"command": "whoami"}}
               ).status_code == 403
    assert rpc(mcp, token, "tools/call",
               {"name": "system_info", "arguments": {}}).status_code == 200


def test_unknown_tool_name_is_rejected_by_whitelist(mcp):
    _, token = new_bot(mcp, "reader", ["system_info"])
    assert rpc(mcp, token, "tools/call",
               {"name": "wb_nope", "arguments": {}}).status_code == 403


def test_batch_request_is_checked(mcp):
    _, token = new_bot(mcp, "reader", ["system_info"])
    response = httpx.post(mcp.url, timeout=30, headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }, json=[
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
         "params": {"name": "wb_system_info", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "wb_run_command", "arguments": {"command": "whoami"}}},
    ])
    assert response.status_code == 403


# ---------------------------------------------------------------- 全量 / 静态

def test_full_access_bot_sees_everything(mcp):
    _, token = new_bot(mcp, "full", [ALL])
    assert len(tool_names(rpc(mcp, token, "tools/list"))) == 26
    assert rpc(mcp, token, "tools/call",
               {"name": "wb_system_info", "arguments": {}}).status_code == 200


def test_static_token_is_never_filtered(mcp):
    assert len(tool_names(rpc(mcp, STATIC_TOKEN, "tools/list"))) == 26


def test_prefix_change_does_not_invalidate_stored_whitelist(tmp_path):
    """白名单存的是内部名：改 tool_prefix 之后老 bot 不该失效。"""
    work = tmp_path / "work"
    work.mkdir()
    cfg = Config(host="127.0.0.1", port=free_port(), tool_prefix="zz_",
                 tokens=[STATIC_TOKEN], admin_token=ADMIN_TOKEN,
                 read_roots=[str(work)], write_roots=[str(work)], work_dir=str(work),
                 log_dir=str(tmp_path / "logs"), state_dir=str(tmp_path / "state"))
    cfg.ensure_dirs()
    server = Server(cfg)
    app = App(server)
    _, token = app.bots.create("reader", allow=["system_info"])
    uv = uvicorn.Server(uvicorn.Config(app, host=cfg.host, port=cfg.port,
                                      log_level="warning", access_log=False))
    thread = threading.Thread(target=uv.run, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{cfg.port}/mcp"
        deadline = time.time() + 25
        while time.time() < deadline:
            try:
                if httpx.get(f"http://127.0.0.1:{cfg.port}/healthz", timeout=1,
                             headers={"Authorization": f"Bearer {STATIC_TOKEN}"}
                             ).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(0.05)
        response = httpx.post(url, timeout=30, headers={
            "Authorization": f"Bearer {token}", "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream"},
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert tool_names(response) == ["zz_system_info"]
    finally:
        uv.should_exit = True
        thread.join(5)


# ---------------------------------------------------------------- 状态

def test_disabled_bot_gets_403(mcp):
    public, token = new_bot(mcp, "reader", ["system_info"])
    mcp.bots.update(public["id"], {"enabled": False})
    response = rpc(mcp, token, "tools/list")
    assert response.status_code == 403
    assert response.json()["error"] == "token_disabled"


def test_expired_bot_gets_403(mcp):
    public, token = new_bot(mcp, "reader", ["system_info"])
    mcp.bots.update(public["id"], {"expires_at": "2020-01-01"})
    response = rpc(mcp, token, "tools/list")
    assert response.status_code == 403
    assert response.json()["error"] == "token_expired"


def test_unknown_token_gets_401(mcp):
    assert rpc(mcp, "not-a-real-token", "tools/list").status_code == 401


def test_healthz_works_for_whitelisted_bot(mcp):
    _, token = new_bot(mcp, "reader", ["system_info"])
    url = mcp.url.rsplit("/mcp", 1)[0] + "/healthz"
    response = httpx.get(url, timeout=10, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200


def test_changes_take_effect_without_restart(mcp):
    public, token = new_bot(mcp, "reader", ["system_info"])
    target = str(Path(mcp.cfg.work_dir) / "x.txt")
    assert rpc(mcp, token, "tools/call",
               {"name": "wb_read_file", "arguments": {"path": target}}
               ).status_code == 403
    mcp.bots.update(public["id"], {"allow": ["system_info", "read_file"]})
    assert rpc(mcp, token, "tools/call",
               {"name": "wb_read_file", "arguments": {"path": target}}
               ).status_code == 200
    mcp.bots.update(public["id"], {"allow": ["system_info"]})
    assert rpc(mcp, token, "tools/call",
               {"name": "wb_read_file", "arguments": {"path": target}}
               ).status_code == 403


# ---------------------------------------------------------------- 审计

def test_denied_call_is_audited_without_argument_values(mcp):
    _, token = new_bot(mcp, "reader", ["system_info"])
    rpc(mcp, token, "tools/call", {
        "name": "wb_write_file",
        "arguments": {"path": "D:/window-mcp/workspace/secret.txt",
                      "content": "TOP-SECRET-BODY"}})
    lines = [json.loads(x) for x in mcp.audit_file.read_text(encoding="utf-8").splitlines()
             if x.strip()]
    denied = [x for x in lines if x.get("decision") == "denied"]
    assert denied, "越权调用必须留痕"
    record = denied[-1]
    assert record["token"] == "reader"
    assert record["tool"] == "write_file"
    assert record["arg_keys"] == ["content", "path"]
    dumped = json.dumps(lines, ensure_ascii=False)
    assert "TOP-SECRET-BODY" not in dumped, "参数内容不能进审计"
    assert token not in dumped, "token 值不能进审计"


def test_allowed_call_is_audited_with_tool_name(mcp):
    _, token = new_bot(mcp, "reader", ["system_info"])
    rpc(mcp, token, "tools/call", {"name": "wb_system_info", "arguments": {}})
    lines = [json.loads(x) for x in mcp.audit_file.read_text(encoding="utf-8").splitlines()
             if x.strip()]
    calls = [x for x in lines if x.get("kind") == "tool_call" and x.get("tool") == "system_info"]
    assert calls and calls[-1]["token"] == "reader"
    assert calls[-1]["decision"] == "allowed"


def test_access_log_records_denied_reason(mcp):
    _, token = new_bot(mcp, "reader", ["system_info"])
    rpc(mcp, token, "tools/call", {"name": "wb_run_command",
                                   "arguments": {"command": "whoami"}})
    access = (Path(mcp.cfg.log_path) / "access.log").read_text(encoding="utf-8")
    entries = [json.loads(x) for x in access.splitlines() if x.strip()]
    denied = [e for e in entries if e.get("status") == 403]
    assert denied and denied[-1]["token"] == "reader"
    assert denied[-1]["denied"]
    assert token not in access


# ---------------------------------------------------------------- 审批策略仍然生效

def test_danger_policy_still_applies_to_bots(mcp):
    """白名单放行了 run_command、档位也设成「放行」，不等于可以跳过危险命令审批。

    危险命令（这里用删除类）必须照旧落成 pending_approval，而不是被直接执行。
    注意：如果档位是默认的「审批」，请求会在 MCP 入口就被挂起等人点，
    根本走不到这一层——这里专门把档位设成放行，测的是**内层**那道闸门。
    """
    _, token = new_bot(mcp, "runner", ["run_command"],
                       policy={"run_command": "allow"})
    response = rpc(mcp, token, "tools/call", {
        "name": "wb_run_command",
        "arguments": {"command": "Remove-Item -Recurse -Force D:/tmp/whatever"}})
    assert response.status_code == 200
    body = response.json()
    payload = json.dumps(body, ensure_ascii=False)
    assert "pending_approval" in payload, payload[:400]
    # MCP 把工具返回值包在 result.content[0].text 里（是一段 JSON 文本）
    inner = json.loads(body["result"]["content"][0]["text"])
    assert inner["status"] == "pending_approval"
    assert inner["approval_id"]


def test_safe_command_runs_for_bot_allowed_to_run(mcp):
    _, token = new_bot(mcp, "runner", ["run_command"],
                       policy={"run_command": "allow"})
    response = rpc(mcp, token, "tools/call", {
        "name": "wb_run_command", "arguments": {"command": "whoami"}})
    assert response.status_code == 200
    assert "pending_approval" not in json.dumps(response.json(), ensure_ascii=False)
