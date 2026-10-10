"""远程审批（三档策略里的 ``ask`` 档）的端到端验证。

这里验的是需求里最硬的那几条：

* ``ask`` 档调用会**阻塞**，直到手机端批准；超时自动拒绝并回明确错误；
* 批准之后这一次调用真的被执行，而且**只执行一次**（不会变成两次审批）；
* 「本 bot N 分钟内同类放行」确实放行后续同类调用；
* 会动鼠标键盘的工具共用一把全局锁，第二个 bot 只能排队；
* 审批接口只认面板登录态，**bot token 调不动它**；
* 推送内容里没有 token、也没有参数明文。

测试用 ``run_command`` 当「危险工具」而不是 ``click``：后者会真的动鼠标，
在跑测试的这台机器上会误点到别的东西。``run_command`` 走的是同一条闸门，
但它执行的是 ``whoami`` 这种无副作用的命令。
"""

from __future__ import annotations

import json
import socket
import threading
import time

import httpx
import pytest
import uvicorn

from mcp_server.app import App
from mcp_server.config import Config
from mcp_server.panel import COOKIE_NAME, PanelApp, PassphraseStore
from mcp_server.policy import (DEFAULT_POLICY, EXCLUSIVE_TOOLS, ToolLock,
                               level_for)
from mcp_server.remote_approval import (APPROVED, DENIED, PENDING, TIMEOUT,
                                        RemoteApprovalQueue, RuntimeSettings,
                                        approval_message)
from mcp_server.server import Server

STATIC_TOKEN = "S" * 64
ADMIN_TOKEN = "admin-token-abcdefghijklmnopqrstuvwxyz"
PASSPHRASE = "correct-horse-battery-staple"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


# ------------------------------------------------------------------ 纯逻辑

def test_default_policy_lets_readonly_through_and_asks_for_the_rest():
    assert DEFAULT_POLICY["screenshot"] == "allow"
    assert DEFAULT_POLICY["read_file"] == "allow"
    for tool in ("click", "type_text", "hotkey", "run_command", "write_file"):
        assert DEFAULT_POLICY.get(tool, "ask") == "ask", tool


def test_level_for_combines_whitelist_and_policy():
    allow = ("system_info", "run_command")
    assert level_for(allow, {}, "system_info") == "allow"      # 默认档：只读放行
    assert level_for(allow, {}, "run_command") == "ask"        # 默认档：其余 ask
    assert level_for(allow, {}, "write_file") == "deny"        # 不在白名单
    assert level_for(allow, {"run_command": "allow"}, "run_command") == "allow"
    assert level_for(allow, {"system_info": "deny"}, "system_info") == "deny"
    # 静态 token（allow 为 None）永远是全量放行
    assert level_for(None, {}, "run_command") == "allow"


def test_exclusive_tools_are_the_mouse_and_keyboard_ones():
    assert EXCLUSIVE_TOOLS == {"type_text", "click", "hotkey", "uia_click", "uia_type"}


def test_tool_lock_is_first_come_first_served():
    lock = ToolLock()
    first = lock.request("a", "click")
    second = lock.request("b", "click")
    assert lock.try_acquire(second) is False, "后到的不能插队"
    assert lock.try_acquire(first) is True
    assert lock.snapshot()["holder"]["bot"] == "a"
    assert lock.snapshot()["waiting"] == 1
    assert lock.try_acquire(second) is False, "有人持有就没人能拿"
    lock.release(first)
    assert lock.try_acquire(second) is True
    lock.release(second)
    assert lock.snapshot()["holder"] is None


def test_tool_lock_cancel_removes_from_queue():
    lock = ToolLock()
    ticket = lock.request("a", "click")
    lock.cancel(ticket)
    assert lock.snapshot() == {"holder": None, "queue": [], "waiting": 0}


def test_queue_decide_records_who_and_when(tmp_path):
    audit_events = []

    class FakeAudit:
        def approval(self, action, approval_id, tool, **kw):
            audit_events.append((action, approval_id, tool, kw))

        def note(self, kind, **fields):
            audit_events.append((kind, fields))

    queue = RemoteApprovalQueue(FakeAudit(), wait_s=60)
    item = queue.create(bot="phone", bot_id="b_1", tools=["run_command"],
                        summary="run_command: whoami", arg_keys=["command"])
    assert item.status == PENDING
    assert queue.pending_count() == 1
    decided = queue.decide(item.approval_id, True, actor="lanxinyao", via="panel")
    assert decided.status == APPROVED
    assert decided.decided_by == "lanxinyao"
    assert decided.decided_at is not None
    assert queue.pending_count() == 0
    # 决定必须留下「谁批的、结果如何」
    actions = [row[0] for row in audit_events]
    assert "approved" in actions
    approved = [row for row in audit_events if row[0] == "approved"][0]
    assert approved[3]["actor"] == "lanxinyao"
    assert approved[3]["result"] == "approved"
    assert approved[3]["keys"] == ["command"], "只记参数名，不记参数值"


def test_queue_timeout_is_recorded_as_timeout():
    queue = RemoteApprovalQueue(None, wait_s=60)
    item = queue.create(bot="a", bot_id="", tools=["click"], summary="click")
    item.expires_at = time.time() - 1          # 直接让它过期
    assert queue.sweep() == 1
    assert queue.get(item.approval_id).status == TIMEOUT
    assert queue.get(item.approval_id).decided_by == "timeout"


def test_auto_allow_expires_on_its_own():
    queue = RemoteApprovalQueue(None, wait_s=60)
    assert queue.auto_remaining("a", "click") == 0
    queue.grant_auto("a", "click", 10)
    assert queue.auto_remaining("a", "click") > 0
    assert queue.auto_remaining("a", "hotkey") == 0, "只放行同类，不放大到别的工具"
    assert queue.auto_remaining("b", "click") == 0, "只放行这个 bot"
    queue.grant_auto("a", "click", 0)
    assert queue.auto_remaining("a", "click") == 0
    assert queue.list_auto() == []


def test_runtime_settings_validate_and_persist(tmp_path):
    settings = RuntimeSettings(tmp_path / "panel-settings.json")
    assert settings.public()["approval_wait_s"] == 120
    updated = settings.update({"approval_wait_s": 45, "ntfy_topic": "wmcp-abc_1"})
    assert updated["approval_wait_s"] == 45
    with pytest.raises(ValueError):
        settings.update({"approval_wait_s": 5})
    with pytest.raises(ValueError):
        settings.update({"ntfy_topic": "有 空格"})
    with pytest.raises(ValueError):
        settings.update({"ntfy_server": "ftp://x"})
    with pytest.raises(ValueError):
        settings.update({"nope": 1})
    assert RuntimeSettings(tmp_path / "panel-settings.json").get()["approval_wait_s"] == 45
    # token 只回「有没有配」，不回值
    settings.update({"ntfy_token": "secret-value"})
    assert settings.public()["ntfy_token_set"] is True
    assert "secret-value" not in json.dumps(settings.public())


def test_push_message_has_no_token_and_no_argument_values():
    queue = RemoteApprovalQueue(None, wait_s=60)
    item = queue.create(bot="phone", bot_id="", tools=["run_command"],
                        summary="run_command: command=TOP-SECRET-CMD",
                        arg_keys=["command"])
    title, message = approval_message(item, "https://admin.example.com")
    assert "phone" in title and "run_command" in title
    assert "https://admin.example.com" in message
    assert "TOP-SECRET-CMD" not in message, "通知里不能出现参数内容"
    assert "command=" not in message, "通知里不该出现参数名"


# ------------------------------------------------------------------ 端到端

@pytest.fixture
def live(tmp_path):
    """真起 MCP 与面板两个 uvicorn（同一个进程、两个端口，与生产一致）。"""
    work = tmp_path / "work"
    work.mkdir()
    passphrase = tmp_path / "panel.passphrase"
    PassphraseStore(passphrase).set(PASSPHRASE)
    panel_port = free_port()
    cfg = Config(
        host="127.0.0.1", port=free_port(), path="/mcp", tool_prefix="wb_",
        tokens=[STATIC_TOKEN], admin_token=ADMIN_TOKEN,
        read_roots=[str(work)], write_roots=[str(work)], work_dir=str(work),
        log_dir=str(tmp_path / "logs"), state_dir=str(tmp_path / "state"),
        rate_per_minute=100000, rate_high_per_hour=100000,
        panel={"passphrase_file": str(passphrase), "port": panel_port,
               "lock_wait_s": 10},
    )
    cfg.ensure_dirs()
    server = Server(cfg)
    app = App(server)
    panel = PanelApp(cfg, server, [("system_info", "只读"), ("run_command", "命令"),
                                   ("click", "点击")], app.bots, None)
    mcp_uv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=cfg.port,
                                           log_level="warning", access_log=False))
    panel_uv = uvicorn.Server(uvicorn.Config(panel, host="127.0.0.1", port=panel_port,
                                             log_level="warning", access_log=False))
    threads = [threading.Thread(target=uv.run, daemon=True) for uv in (mcp_uv, panel_uv)]
    for thread in threads:
        thread.start()

    base = f"http://127.0.0.1:{panel_port}"
    deadline = time.time() + 25
    while time.time() < deadline:
        try:
            if httpx.get(f"{base}/healthz", timeout=1).status_code == 200:
                break
        except httpx.HTTPError:
            pass
        time.sleep(0.05)
    else:
        raise RuntimeError("测试服务器起不来")

    holder = type("Ctx", (), {})()
    holder.cfg, holder.server, holder.app, holder.panel = cfg, server, app, panel
    holder.base, holder.passphrase = base, PASSPHRASE
    holder.mcp_url = f"http://127.0.0.1:{cfg.port}{cfg.path}"
    yield holder
    mcp_uv.should_exit = True
    panel_uv.should_exit = True
    for thread in threads:
        thread.join(5)


def login(live) -> dict:
    response = httpx.post(f"{live.base}/api/login", json={"passphrase": live.passphrase},
                          headers={"X-Panel-Request": "1"}, timeout=30)
    cookie = response.cookies.get(COOKIE_NAME)
    return {"X-Panel-Request": "1", "Cookie": f"{COOKIE_NAME}={cookie}"}


def new_bot(live, name, policy, allow=None) -> str:
    public, token = live.app.bots.create(name, allow=allow, policy=policy)
    return token


def call_tool(live, token, name, args, timeout=60):
    return httpx.post(live.mcp_url, timeout=timeout, headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }, json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": name, "arguments": args}})


def call_method(live, token, method, params=None, timeout=30):
    return httpx.post(live.mcp_url, timeout=timeout, headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}})


def call_tool_async(live, token, name, args, timeout=60):
    """把会阻塞的调用放到后台线程，主线程好去面板上点批准。"""
    box: dict = {}

    def run():
        try:
            box["response"] = call_tool(live, token, name, args, timeout)
        except Exception as exc:  # 超时等
            box["error"] = exc

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread, box


def wait_pending(live, headers, count=1, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        data = httpx.get(f"{live.base}/api/approvals", headers=headers, timeout=10).json()
        if len(data["pending"]) >= count:
            return data
        time.sleep(0.15)
    raise AssertionError(f"等不到 {count} 条待审批")


def approve(live, headers, approval_id, decision="approve", remember=0):
    return httpx.post(f"{live.base}/api/approvals/decide", headers=headers, timeout=20,
                      json={"id": approval_id, "decision": decision,
                            "remember_minutes": remember})


# ------------------------------------------------------------- 阻塞 + 批准

def test_ask_tool_blocks_until_approved_then_runs_once(live):
    headers = login(live)
    token = new_bot(live, "phone", {"system_info": "allow", "run_command": "ask"})

    thread, box = call_tool_async(live, token, "wb_run_command", {"command": "whoami"})
    data = wait_pending(live, headers)
    item = data["pending"][0]
    assert item["bot"] == "phone"
    assert item["tool"] == "run_command"
    assert item["arg_keys"] == ["command"], "面板只显示参数名"
    assert "whoami" in item["summary"], "参数摘要是给人在面板上看的"
    assert item["expires_in_s"] > 0
    assert item["total_s"] > 0

    assert approve(live, headers, item["approval_id"]).status_code == 200
    thread.join(30)
    response = box["response"]
    assert response.status_code == 200
    body = response.json()
    assert "error" not in body, body
    inner = json.loads(body["result"]["content"][0]["text"])
    assert inner.get("output", "").strip(), "批准之后命令真的执行了"
    assert inner.get("status") != "pending_approval", "批准后不该再要一次审批"
    assert "output" in inner, inner

    # 只有一条记录，且是「已批准 → 执行」
    after = httpx.get(f"{live.base}/api/approvals", headers=headers, timeout=10).json()
    assert after["pending"] == []
    assert [a["status"] for a in after["recent"]] == [APPROVED]


def test_ask_tool_rejected_returns_clear_error_and_does_not_run(live):
    headers = login(live)
    token = new_bot(live, "phone", {"run_command": "ask"})

    thread, box = call_tool_async(live, token, "wb_run_command", {"command": "whoami"})
    item = wait_pending(live, headers)["pending"][0]
    assert approve(live, headers, item["approval_id"], "deny").status_code == 200
    thread.join(30)

    body = box["response"].json()
    assert "error" in body, body
    assert body["error"]["code"] == -32001
    assert "拒绝" in body["error"]["message"]
    assert body["error"]["data"]["reason"] == DENIED
    assert body["error"]["data"]["approval_id"] == item["approval_id"]

    # 审计里要留下「谁拒的」
    events = httpx.get(f"{live.base}/api/audit?result=approval_rejected",
                       headers=headers, timeout=10).json()["events"]
    assert events and events[-1]["bot"] == "phone"


def test_ask_tool_times_out_and_auto_rejects(live):
    headers = login(live)
    token = new_bot(live, "phone", {"run_command": "ask"})

    thread, box = call_tool_async(live, token, "wb_run_command", {"command": "whoami"})
    item = wait_pending(live, headers)["pending"][0]
    # 不用真等 120 秒：把截止时间直接推到过去，服务器下一次轮询就会判超时。
    live.server.remote.get(item["approval_id"]).expires_at = time.time() - 0.01
    thread.join(30)

    body = box["response"].json()
    assert body["error"]["data"]["reason"] == TIMEOUT
    assert "超时" in body["error"]["message"]
    assert "未执行" in body["error"]["message"]


def test_remember_lets_the_same_bot_tool_through_without_asking_again(live):
    headers = login(live)
    token = new_bot(live, "phone", {"run_command": "ask"})

    thread, box = call_tool_async(live, token, "wb_run_command", {"command": "whoami"})
    item = wait_pending(live, headers)["pending"][0]
    assert approve(live, headers, item["approval_id"], "approve", remember=10).status_code == 200
    thread.join(30)
    assert "error" not in box["response"].json()

    # 第二条同类调用：不该再产生待审批
    started = time.time()
    response = call_tool(live, token, "wb_run_command", {"command": "whoami"}, timeout=30)
    assert time.time() - started < 5, "同类放行之后不该还阻塞"
    assert response.status_code == 200
    assert "error" not in response.json()
    after = httpx.get(f"{live.base}/api/approvals", headers=headers, timeout=10).json()
    assert after["pending"] == []
    assert any(row["bot"] == "phone" and row["tool"] == "run_command"
               for row in after["auto"]), "面板上要看得到还剩下多久"


def test_two_bots_are_approved_and_rejected_independently(live):
    headers = login(live)
    token_a = new_bot(live, "bot-a", {"run_command": "ask"})
    token_b = new_bot(live, "bot-b", {"run_command": "ask"})

    thread_a, box_a = call_tool_async(live, token_a, "wb_run_command", {"command": "whoami"})
    thread_b, box_b = call_tool_async(live, token_b, "wb_run_command", {"command": "whoami"})
    pending = wait_pending(live, headers, count=2)["pending"]
    by_bot = {item["bot"]: item for item in pending}
    assert set(by_bot) == {"bot-a", "bot-b"}

    assert approve(live, headers, by_bot["bot-a"]["approval_id"], "approve").status_code == 200
    assert approve(live, headers, by_bot["bot-b"]["approval_id"], "deny").status_code == 200
    thread_a.join(30)
    thread_b.join(30)

    assert "error" not in box_a["response"].json(), "批准的那个要跑"
    assert box_b["response"].json()["error"]["data"]["reason"] == DENIED, "拒绝的那个不能跑"


def test_ask_batch_only_asks_once(live):
    """批量请求里只要有一条是 ask，也只该产生**一条**待审批。

    注：MCP SDK 本身不支持 JSON-RPC 批量（会回 -32602），所以这里验的是
    「闸门只挂起一次、只让人点一次」这件事，而不是批量真的被执行。
    """
    headers = login(live)
    token = new_bot(live, "phone", {"run_command": "ask"})
    box: dict = {}

    def run():
        box["response"] = httpx.post(live.mcp_url, timeout=60, headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }, json=[
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "wb_run_command", "arguments": {"command": "whoami"}}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
             "params": {"name": "wb_run_command", "arguments": {"command": "hostname"}}},
        ])

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    pending = wait_pending(live, headers)
    assert len(pending["pending"]) == 1, "一次批量只该产生一条待审批"
    assert pending["pending"][0]["tools"] == ["run_command"]
    approve(live, headers, pending["pending"][0]["approval_id"], "deny")
    thread.join(30)
    dumped = json.dumps(box["response"].json(), ensure_ascii=False)
    assert "-32001" in dumped, "被拒绝的批量不该被执行"
    assert '"id": 1' in dumped and '"id": 2' in dumped, "批量要逐条回，id 对得上"


def test_star_whitelist_bot_still_needs_approval(live):
    """``allow=["*"]`` 只是「工具全可见」，不能顺手把三档策略也一起关掉。

    生产上的 hark / cue / muse 就是这个形态（全量权限）。如果 "*" 能让策略短路，
    这次改动等于对它们完全没生效。
    """
    headers = login(live)
    public, token = live.app.bots.create("hark", allow=["*"])
    assert public["allow_all"] is True

    thread, box = call_tool_async(live, token, "wb_run_command", {"command": "whoami"})
    item = wait_pending(live, headers)["pending"][0]
    assert item["bot"] == "hark" and item["tool"] == "run_command"
    approve(live, headers, item["approval_id"], "deny")
    thread.join(30)
    assert box["response"].json()["error"]["data"]["reason"] == DENIED

    # 只读类仍然直接放行（默认档 = allow），不该被这条策略误伤
    response = call_tool(live, token, "wb_system_info", {})
    assert response.status_code == 200 and "error" not in response.json()
    # 审批档的工具仍然出现在 tools/list 里（只是调用要人点）
    names = [t["name"] for t in call_method(live, token, "tools/list")
             .json()["result"]["tools"]]
    assert "wb_run_command" in names
    assert "wb_system_info" in names
    # 工具名拼错：交给 SDK 回它自己的错误，不该挂起等人批一个不存在的工具
    typo = call_tool(live, token, "wb_nope_not_a_tool", {}, timeout=20)
    assert typo.status_code == 200
    assert "error" in typo.json() or typo.json()["result"].get("isError")


# ------------------------------------------------------------- 全局锁

def test_second_bot_queues_on_the_mouse_keyboard_lock_and_times_out(live):
    headers = login(live)
    # click 设成放行，这样它会直接走到全局锁那一层（不产生审批单）
    token = new_bot(live, "clicker", {"click": "allow"})

    # 先让「另一个 bot」把锁拿在手里
    ticket = live.server.tool_lock.request("other-bot", "type_text")
    assert live.server.tool_lock.try_acquire(ticket) is True

    data = httpx.get(f"{live.base}/api/approvals", headers=headers, timeout=10).json()
    assert data["lock"]["holder"]["bot"] == "other-bot"

    started = time.time()
    response = call_tool(live, token, "wb_click", {"x": 10, "y": 10}, timeout=40)
    assert time.time() - started >= 9, "必须真的排队等一会儿，而不是直接失败"
    body = response.json()
    assert body["error"]["data"]["reason"] == "busy"
    assert "另一个 bot" in body["error"]["message"]
    live.server.tool_lock.release(ticket)


def test_lock_state_is_visible_on_the_panel(live):
    headers = login(live)
    ticket = live.server.tool_lock.request("a", "click")
    live.server.tool_lock.try_acquire(ticket)
    live.server.tool_lock.request("b", "click")
    live.server.tool_lock.request("c", "uia_click")
    data = httpx.get(f"{live.base}/api/approvals", headers=headers, timeout=10).json()
    assert data["lock"]["holder"]["bot"] == "a"
    assert [row["bot"] for row in data["lock"]["queue"]] == ["b", "c"]
    live.server.tool_lock.cancel(ticket)


# ------------------------------------------------------------- 安全

def test_bot_token_cannot_touch_the_approval_api(live):
    token = new_bot(live, "phone", {"run_command": "ask"})
    headers = {"X-Panel-Request": "1", "Authorization": f"Bearer {token}"}

    for path in ("/api/approvals", "/api/settings", "/api/bots"):
        response = httpx.get(f"{live.base}{path}", headers=headers, timeout=10)
        assert response.status_code == 401, path
    decided = httpx.post(f"{live.base}/api/approvals/decide", headers=headers, timeout=10,
                         json={"id": "whatever", "decision": "approve"})
    assert decided.status_code == 401
    # 没登录的跨站表单请求：先过不了鉴权（401），根本走不到 CSRF 那一步
    assert httpx.post(f"{live.base}/api/approvals/decide", timeout=10,
                      json={"id": "x", "decision": "approve"}).status_code == 401
    # 有会话但没有 X-Panel-Request 头（跨站表单发不出自定义头）→ 403
    session = login(live)
    session.pop("X-Panel-Request")
    assert httpx.post(f"{live.base}/api/approvals/decide", headers=session, timeout=10,
                      json={"id": "x", "decision": "approve"}).status_code == 403


def test_approval_api_needs_the_panel_session(live):
    assert httpx.get(f"{live.base}/api/approvals", timeout=10).status_code == 401
    assert httpx.get(f"{live.base}/api/settings", timeout=10).status_code == 401
    headers = login(live)
    assert httpx.get(f"{live.base}/api/approvals", headers=headers,
                     timeout=10).status_code == 200


def test_bot_token_cannot_use_the_legacy_admin_endpoint(live):
    token = new_bot(live, "phone", {"run_command": "ask"})
    url = (f"http://127.0.0.1:{live.cfg.port}/admin/approve"
           f"?id=deadbeef&token={token}")
    assert httpx.get(url, timeout=10).status_code == 401
    url_ok = (f"http://127.0.0.1:{live.cfg.port}/admin/pending"
              f"?token={ADMIN_TOKEN}")
    assert httpx.get(url_ok, timeout=10).status_code == 200


# ------------------------------------------------------------- 面板设置

def test_settings_page_changes_the_wait_time_without_restart(live):
    headers = login(live)
    assert httpx.get(f"{live.base}/api/settings", headers=headers,
                     timeout=10).json()["approval_wait_s"] == 120
    updated = httpx.patch(f"{live.base}/api/settings", headers=headers, timeout=10,
                          json={"approval_wait_s": 30})
    assert updated.status_code == 200 and updated.json()["approval_wait_s"] == 30
    assert httpx.get(f"{live.base}/api/settings", headers=headers,
                     timeout=10).json()["approval_wait_s"] == 30
    # 面板改的值会真的用在下一次审批上
    token = new_bot(live, "phone", {"run_command": "ask"})
    thread, box = call_tool_async(live, token, "wb_run_command", {"command": "whoami"})
    item = wait_pending(live, headers)["pending"][0]
    assert item["total_s"] == 30
    approve(live, headers, item["approval_id"], "deny")
    thread.join(30)


def test_settings_rejects_bad_values(live):
    headers = login(live)
    for body in ({"approval_wait_s": 5}, {"approval_wait_s": "abc"},
                 {"ntfy_topic": "有 空格"}, {"ntfy_server": "ftp://x"},
                 {"nope": 1}):
        response = httpx.patch(f"{live.base}/api/settings", headers=headers, timeout=10,
                               json=body)
        assert response.status_code == 400, body


def test_notify_test_without_topic_explains_itself(live):
    headers = login(live)
    response = httpx.post(f"{live.base}/api/notify/test", headers=headers, timeout=20)
    assert response.status_code == 400
    assert "topic" in response.json()["error"]


# ------------------------------------------------------------- 面板数据

def test_bots_payload_exposes_per_tool_levels(live):
    headers = login(live)
    live.app.bots.create("phone", allow=["system_info", "run_command"],
                         policy={"run_command": "ask"})
    data = httpx.get(f"{live.base}/api/bots", headers=headers, timeout=10).json()
    bot = data["bots"][0]
    assert bot["levels"]["system_info"] == "allow"
    assert bot["levels"]["run_command"] == "ask"
    assert bot["levels"]["click"] == "deny", "不在白名单就是禁止"
    assert bot["today_calls"] >= 0
    assert "token" not in bot and "token_hash" not in bot
    assert len(bot["token_hint"]) >= 6


def test_deny_all_clears_the_queue(live):
    headers = login(live)
    token = new_bot(live, "phone", {"run_command": "ask"})
    thread, box = call_tool_async(live, token, "wb_run_command", {"command": "whoami"})
    wait_pending(live, headers)
    response = httpx.post(f"{live.base}/api/approvals/deny-all", headers=headers, timeout=20)
    assert response.status_code == 200 and response.json()["denied"] == 1
    thread.join(30)
    assert box["response"].json()["error"]["data"]["reason"] == DENIED
    assert httpx.get(f"{live.base}/api/approvals", headers=headers,
                     timeout=10).json()["pending"] == []


def test_audit_can_be_filtered_by_tool_and_result(live):
    headers = login(live)
    token = new_bot(live, "phone", {"system_info": "allow"})
    call_tool(live, token, "wb_system_info", {})
    events = httpx.get(f"{live.base}/api/audit?bot=phone&tool=system_info&result=allowed",
                       headers=headers, timeout=10).json()["events"]
    assert events and all(e["bot"] == "phone" for e in events)
    assert all(e["tool"] == "system_info" for e in events)
    assert all(e["decision"] == "allowed" for e in events)
    assert httpx.get(f"{live.base}/api/audit?tool=nothing_like_this",
                     headers=headers, timeout=10).json()["events"] == []
