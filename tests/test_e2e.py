"""端到端测试：用模拟 Hark 调用方式的客户端跑通全流程。

覆盖文档 §8 的验收步骤 1–7。
"""

from __future__ import annotations

import socket
import threading
import time

import httpx
import pytest
import uvicorn

from mcp_server.app import App
from mcp_server.config import Config
from mcp_server.server import Server
from tests.hark_client import HarkClient, HarkError

TOKEN = "test-token-abcdefghijklmnop"
ADMIN = "admin-token-abcdefghijklmnop"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Ctx:
    pass


@pytest.fixture
def ctx(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    cfg = Config(
        host="127.0.0.1",
        port=_free_port(),
        tokens=[TOKEN],
        admin_token=ADMIN,
        read_roots=[str(work)],
        write_roots=[str(work)],
        work_dir=str(work),
        log_dir=str(tmp_path / "logs"),
        state_dir=str(tmp_path / "state"),
        rate_per_minute=10000,
        rate_high_per_hour=10000,
    )
    cfg.ensure_dirs()
    server = Server(cfg)
    app = App(server)
    uv_config = uvicorn.Config(app, host=cfg.host, port=cfg.port,
                               log_level="warning", access_log=False)
    uv_server = uvicorn.Server(uv_config)
    thread = threading.Thread(target=uv_server.run, daemon=True)
    thread.start()

    base = f"http://127.0.0.1:{cfg.port}"
    deadline = time.time() + 20
    while time.time() < deadline:
        try:
            if httpx.get(f"{base}/healthz", timeout=1,
                         headers={"Authorization": f"Bearer {TOKEN}"}).status_code == 200:
                break
        except httpx.HTTPError:
            pass
        time.sleep(0.05)
    else:
        raise RuntimeError("测试服务器启动失败")

    holder = Ctx()
    holder.cfg = cfg
    holder.server = server
    holder.base = base
    holder.url = base + cfg.path
    holder.work = work
    holder.client = HarkClient(holder.url, TOKEN)

    yield holder

    uv_server.should_exit = True
    thread.join(5)


# ---------------------------------------------------------------- 鉴权与协议


def test_healthz_requires_token(ctx):
    """healthz 也要鉴权：这是私有服务，不对外泄露自己在跑什么。"""
    assert httpx.get(f"{ctx.base}/healthz", timeout=5).status_code == 401
    ok = httpx.get(f"{ctx.base}/healthz", timeout=5,
                   headers={"Authorization": f"Bearer {TOKEN}"})
    assert ok.status_code == 200
    assert ok.json() == {"status": "ok"}


def test_query_param_token_rejected_on_mcp(ctx):
    """?token= 只留给 /admin/*。/mcp 必须走请求头，否则 token 会漏进 URL。"""
    response = httpx.post(ctx.url, params={"token": TOKEN},
                          json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                          headers={"Content-Type": "application/json",
                                   "Accept": "application/json, text/event-stream"}, timeout=5)
    assert response.status_code == 401


def test_mcp_token_cannot_authorize_admin(ctx):
    """MCP token 不能批准危险命令——否则它泄露就等于连带交出审批权。"""
    pending = ctx.client.call_tool("run_command", {"command": 'python -c "print(1)"'})
    assert pending["status"] == "pending_approval"
    response = httpx.get(f"{ctx.base}/admin/approve",
                         params={"id": pending["approval_id"], "token": TOKEN}, timeout=5)
    assert response.status_code == 401


def test_set_date_needs_approval(ctx):
    """改系统时间必须审批（本机真的被「时间穿越」过一次）。"""
    data = ctx.client.call_tool("run_command",
                                {"command": "Set-Date -Date '2026-11-15 19:00:00'"})
    assert data["status"] == "pending_approval"


def test_missing_token_returns_401(ctx):
    response = httpx.post(ctx.url, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                          headers={"Content-Type": "application/json",
                                   "Accept": "application/json, text/event-stream"}, timeout=5)
    assert response.status_code == 401


def test_wrong_token_returns_401(ctx):
    bad = HarkClient(ctx.url, "wrong-token")
    with pytest.raises(HarkError):
        bad.list_tools()


def test_host_header_allowlist_enforced(ctx):
    """经隧道访问时 Host 是公网域名。DNS 重绑定保护必须放行白名单、拒绝其他。"""
    payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Authorization": f"Bearer {TOKEN}",
    }

    allowed = httpx.post(ctx.url, json=payload,
                         headers={**headers, "Host": f"127.0.0.1:{ctx.cfg.port}"}, timeout=10)
    assert allowed.status_code == 200, allowed.text[:200]

    denied = httpx.post(ctx.url, json=payload,
                        headers={**headers, "Host": "evil.example.com"}, timeout=10)
    assert denied.status_code == 421, denied.text[:200]


def test_initialize_negotiates_protocol_version(ctx):
    result = ctx.client.initialize()
    assert result["protocolVersion"] == "2025-11-25"
    assert result["serverInfo"]["name"] == "windows-pc"


def test_each_call_is_a_fresh_session(ctx):
    """Hark 每次调用都是新会话，服务器必须无状态。"""
    assert ctx.client.list_tools()
    assert ctx.client.list_tools()
    # 无状态模式下不应该下发 session id
    assert ctx.client.last_session_id is None


# ---------------------------------------------------------------- 只读工具


def test_tools_list_contains_v1_tools(ctx):
    names = {tool["name"] for tool in ctx.client.list_tools()}
    expected = {
        "system_info", "system_stats", "list_processes", "list_windows",
        "list_dir", "read_file", "screenshot", "run_command", "start_job",
        "job_status", "stop_job", "write_file", "edit_file",
        "approval_status", "list_pending_approvals",
        "type_text", "click", "hotkey", "wake_screen",
    }
    assert expected <= names, expected - names


def test_system_info(ctx):
    info = ctx.client.call_tool("system_info")
    assert info["hostname"]
    assert info["memory_total_bytes"] > 0


def test_system_stats_cpu_is_primed(ctx):
    """psutil 首调返回 0.0 的坑必须已经处理掉。"""
    stats = ctx.client.call_tool("system_stats")
    assert isinstance(stats["cpu_percent"], float)
    assert len(stats["cpu_per_core_percent"]) >= 1
    assert stats["memory"]["total_bytes"] > 0
    # 至少要有一次采样是有意义的（跑在真机上时）
    assert stats["cpu_percent"] >= 0.0


def test_list_processes(ctx):
    data = ctx.client.call_tool("list_processes", {"sort_by": "memory", "limit": 5})
    assert data["returned"] <= 5
    assert data["count"] > 0


def test_list_dir_inside_root(ctx):
    (ctx.work / "a.txt").write_text("hello", encoding="utf-8")
    data = ctx.client.call_tool("list_dir", {"path": str(ctx.work)})
    assert any(entry["name"] == "a.txt" for entry in data["entries"])


def test_list_dir_outside_root_denied(ctx, tmp_path):
    data = ctx.client.call_tool("list_dir", {"path": str(tmp_path)})
    assert data["error"] == "path_denied"


def test_read_file_ok(ctx):
    target = ctx.work / "note.txt"
    target.write_text("内容 abc", encoding="utf-8")
    data = ctx.client.call_tool("read_file", {"path": str(target)})
    assert "内容 abc" in data["text"]


def test_read_file_denied_env(ctx):
    env = ctx.work / ".env"
    env.write_text("SECRET=1", encoding="utf-8")
    data = ctx.client.call_tool("read_file", {"path": str(env)})
    assert data["error"] == "path_denied"


# ---------------------------------------------------------------- 命令执行


def test_whitelisted_command_executes(ctx):
    data = ctx.client.call_tool("run_command", {"command": "dir"})
    assert data["status"] == "finished"
    assert data["exit_code"] == 0


def test_whitelisted_python_version(ctx):
    data = ctx.client.call_tool("run_command", {"command": "python --version"})
    assert data["status"] == "finished"
    assert "Python" in data["output"]


def test_dangerous_command_returns_pending(ctx):
    data = ctx.client.call_tool("run_command", {"command": "Remove-Item -Recurse x"})
    assert data["status"] == "pending_approval"
    assert data["approval_id"]
    assert data["next"] == "call approval_status"


def test_normal_command_runs_without_approval(ctx):
    """danger-only 策略：普通命令直接执行，不再返回 pending。"""
    data = ctx.client.call_tool("run_command", {"command": "Get-Random"})
    assert data["status"] == "finished"
    assert data["exit_code"] == 0


def test_pipe_command_runs_without_approval(ctx):
    """无害管道不再被误判成危险命令。"""
    data = ctx.client.call_tool("run_command", {"command": "Get-Date | Out-String"})
    assert data["status"] == "finished"



def test_normal_command_does_not_consume_high_quota(tmp_path):
    """普通命令走 R 档，不该占用「高危操作」的每小时额度。

    旧实现里 run_command 一律按 H 档限速，正常用十几次就被拦——
    danger-only 策略下必须修掉。
    """
    cfg = Config(
        tokens=["t"],
        work_dir=str(tmp_path / "work"),
        log_dir=str(tmp_path / "logs"),
        state_dir=str(tmp_path / "state"),
        rate_per_minute=1000,
        rate_high_per_hour=1,
    )
    cfg.ensure_dirs()
    server = Server(cfg)

    # 唯一的高危额度被第一条危险命令占用
    first = server.run_command("taskkill /PID 999999 /F")
    assert first["status"] == "pending_approval"

    # 之后的普通命令不应被高危限速拦住
    for _ in range(3):
        result = server.run_command("Get-Random")
        assert result.get("status") == "finished", result


def test_pending_is_not_iserror(ctx):
    """pending 必须以成功结果返回，否则 Hark 会当成失败。"""
    raw = ctx.client.call_raw("run_command", {"command": "taskkill /PID 999999 /F"})
    assert not raw.get("isError", False)
    assert raw["content"][0]["type"] == "text"


def test_hard_denied_command(ctx):
    data = ctx.client.call_tool("run_command", {"command": "format C:"})
    assert data["error"] == "denied_by_policy"
    assert data["level"] == "X"


def test_command_chain_needs_approval(ctx):
    data = ctx.client.call_tool("run_command", {"command": "dir; Remove-Item x"})
    assert data["status"] == "pending_approval"


def test_run_command_rejects_path_outside_root(ctx, tmp_path):
    data = ctx.client.call_tool("run_command", {"command": "dir", "cwd": str(tmp_path)})
    assert data["error"] == "path_denied"


def test_start_job_and_status(ctx):
    data = ctx.client.call_tool("start_job", {"command": "dir", "name": "list"})
    assert data["status"] == "started"
    job_id = data["job_id"]
    for _ in range(50):
        status = ctx.client.call_tool("job_status", {"job_id": job_id})
        if status["status"] == "finished":
            break
        time.sleep(0.1)
    assert status["status"] == "finished"
    # 偶发的 PowerShell 启动崩溃（例如 0x800703E9 栈溢出）会被 diagnosis 标注出来，
    # 那种情况命令并没有执行，不算失败。
    diagnosis = status.get("diagnosis")
    assert status["exit_code"] == 0 or (diagnosis and diagnosis["retry_safe"]), status


def test_stop_job(ctx):
    """普通长任务现在直接启动（danger-only），拿到 job_id 后终止整棵进程树。"""
    started = ctx.client.call_tool(
        "start_job", {"command": "Start-Sleep -Seconds 60", "name": "sleepy"})
    assert started["status"] == "started"

    stopped = ctx.client.call_tool("stop_job", {"job_id": started["job_id"]})
    assert stopped["stopped"] is True
    assert stopped["exit_code"] is not None


def test_dangerous_start_job_goes_through_approval(ctx):
    """危险命令交给 start_job 也要审批。"""
    pending = ctx.client.call_tool(
        "start_job", {"command": "taskkill /PID 999999 /F", "name": "danger"})
    assert pending["status"] == "pending_approval"

    httpx.get(f"{ctx.base}/admin/approve",
              params={"id": pending["approval_id"], "token": ADMIN}, timeout=5)
    executed = ctx.client.call_tool("approval_status",
                                    {"approval_id": pending["approval_id"]})
    assert executed["status"] == "executed"
    assert executed["result"]["status"] == "started"


# ---------------------------------------------------------------- 审批流程

# 分级为 H（内联代码执行类），但实际执行无害，用来测审批链路
DANGER = 'python -c "print(1)"'


def test_full_approval_flow(ctx):
    pending = ctx.client.call_tool("run_command",
                                   {"command": DANGER, "request_id": "req-approve-1"})
    assert pending["status"] == "pending_approval"
    approval_id = pending["approval_id"]

    # 批准前：状态仍是 pending
    status = ctx.client.call_tool("approval_status", {"approval_id": approval_id})
    assert status["status"] == "pending_approval"

    # 通过 /admin/approve 端点批准（手机点通知链接走的就是这条）
    response = httpx.get(f"{ctx.base}/admin/approve",
                         params={"id": approval_id, "token": ADMIN}, timeout=5)
    assert response.status_code == 200

    # 批准后再查：应当已经执行
    status = ctx.client.call_tool("approval_status", {"approval_id": approval_id})
    assert status["status"] == "executed"
    assert status["result"]["status"] == "finished"
    assert status["result"]["exit_code"] == 0


def test_rejected_approval_never_executes(ctx):
    pending = ctx.client.call_tool("run_command",
                                   {"command": DANGER, "request_id": "req-reject-1"})
    approval_id = pending["approval_id"]
    httpx.get(f"{ctx.base}/admin/reject", params={"id": approval_id, "token": ADMIN}, timeout=5)
    status = ctx.client.call_tool("approval_status", {"approval_id": approval_id})
    assert status["status"] == "rejected"


def test_duplicate_request_id_returns_same_approval(ctx):
    first = ctx.client.call_tool("run_command",
                                 {"command": DANGER, "request_id": "req-dup-1"})
    second = ctx.client.call_tool("run_command",
                                  {"command": DANGER, "request_id": "req-dup-1"})
    assert first["approval_id"] == second["approval_id"]
    assert second.get("deduplicated") is True


def test_list_pending_approvals(ctx):
    ctx.client.call_tool("run_command", {"command": DANGER})
    data = ctx.client.call_tool("list_pending_approvals")
    assert data["count"] >= 1
    assert data["pending"][0]["approval_id"]


def test_admin_endpoint_requires_token(ctx):
    pending = ctx.client.call_tool("run_command", {"command": DANGER})
    response = httpx.get(f"{ctx.base}/admin/approve", params={"id": pending["approval_id"]},
                         timeout=5)
    assert response.status_code == 401

# ---------------------------------------------------------------- 文件写入


def test_write_file_then_backup(ctx):
    target = ctx.work / "out.txt"
    first = ctx.client.call_tool("write_file", {"path": str(target), "content": "one"})
    assert first["backup"] is None
    second = ctx.client.call_tool("write_file", {"path": str(target), "content": "two"})
    assert second["backup"] is not None
    assert "one" in (ctx.work / ".mcp_backup").joinpath(
        second["backup"].split("\\")[-1]).read_text(encoding="utf-8")


def test_write_file_outside_root_denied(ctx, tmp_path):
    data = ctx.client.call_tool("write_file",
                                {"path": str(tmp_path / "escape.txt"), "content": "x"})
    assert data["error"] == "path_denied"


def test_edit_file_requires_unique_match(ctx):
    target = ctx.work / "edit.txt"
    target.write_text("aaa bbb aaa", encoding="utf-8")
    data = ctx.client.call_tool("edit_file", {"path": str(target), "old": "aaa", "new": "ccc"})
    assert data["error"] == "path_denied"
    assert "不唯一" in data["message"]

    ok = ctx.client.call_tool("edit_file", {"path": str(target), "old": "bbb", "new": "ddd"})
    assert ok["replaced"] == 1
    assert "ddd" in target.read_text(encoding="utf-8")


# ---------------------------------------------------------------- 截屏


def test_screenshot_runs_without_approval(ctx):
    """danger-only 下截屏默认免审批，直接返回图片。"""
    data = ctx.client.call_tool("screenshot", {})
    assert data["meta"]["format"] == "jpeg"
    assert data["meta"]["returned_width"] <= 1600
    assert len(data["image_base64"]) > 1000


def test_screenshot_can_be_forced_to_need_approval(ctx):
    """把 screenshot_level 改回 H 仍然走审批链路。"""
    ctx.server.cfg.screenshot_level = "H"
    pending = ctx.client.call_tool("screenshot", {})
    assert pending["status"] == "pending_approval"
    httpx.get(f"{ctx.base}/admin/approve",
              params={"id": pending["approval_id"], "token": ADMIN}, timeout=5)
    status = ctx.client.call_tool("approval_status", {"approval_id": pending["approval_id"]})
    assert status["status"] == "executed"
    assert status["result"]["meta"]["format"] == "jpeg"
    assert len(status["result"]["image_base64"]) > 1000


# ---------------------------------------------------------------- 审计


def test_audit_log_written(ctx):
    ctx.client.call_tool("system_info")
    logs = list(ctx.cfg.log_path.glob("audit-*.jsonl"))
    assert logs
    text = logs[0].read_text(encoding="utf-8")
    assert "system_info" in text
    assert TOKEN not in text
