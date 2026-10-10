"""管理面板的单测 + 端到端。

两条主线：

1. **鉴权**：口令（scrypt 哈希 + 会话 cookie）与 Cloudflare Access（RS256 验签）两条门，
   以及 ``both`` 模式那条「本机直连永远进得去、经 Cloudflare 必须带 JWT」的规则。
   这里故意把每种「应该拒绝」的组合都点一遍——面板要是能绕过鉴权，
   等于把「改 bot 权限、看审计」的界面挂在公网上。
2. **接口行为**：明文 token 只出现一次、二次确认删除、CSRF 头、登录节流、
   白名单分组展示。
"""

from __future__ import annotations

import base64
import json
import socket
import threading
import time

import httpx
import pytest
import uvicorn
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from mcp_server import config as config_module
from mcp_server.access import AccessVerifier
from mcp_server.app import App
from mcp_server.bots import BotStore
from mcp_server.config import Config
from mcp_server.panel import (
    COOKIE_NAME,
    LoginThrottle,
    PanelApp,
    PanelDisabled,
    PassphraseStore,
    hash_passphrase,
)
from mcp_server.server import Server

STATIC_TOKEN = "S" * 64
ADMIN_TOKEN = "admin-token-abcdefghijklmnopqrstuvwxyz"
PASSPHRASE = "correct-horse-battery-staple"
TEAM = "panel-test.cloudflareaccess.com"
AUD = "aud-tag-abcdef0123456789"
EMAIL = "admin@example.com"
KID = "kid-1"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


# ---------------------------------------------------------------- Access 造钥匙

def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@pytest.fixture(scope="module")
def rsa_keys():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private, private.public_key()


def _jwk(public_key, kid: str = KID) -> dict:
    nums = public_key.public_numbers()
    return {"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig",
            "n": _b64u(nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")),
            "e": _b64u(nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big"))}


def access_token(private_key, **claims) -> str:
    now = int(time.time())
    payload = {"aud": AUD, "iss": f"https://{TEAM}", "email": EMAIL,
               "sub": "sub-1", "type": "app",
               "iat": now - 10, "nbf": now - 10, "exp": now + 3600}
    payload.update(claims)
    header = {"alg": "RS256", "typ": "JWT", "kid": KID}
    signing_input = (f"{_b64u(json.dumps(header).encode())}."
                     f"{_b64u(json.dumps(payload).encode())}")
    signature = private_key.sign(signing_input.encode("ascii"),
                                 padding.PKCS1v15(), hashes.SHA256())
    return signing_input + "." + _b64u(signature)


# ---------------------------------------------------------------- 夹具

def make_cfg(tmp_path, **over) -> Config:
    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    kwargs = dict(
        host="127.0.0.1", port=free_port(), tokens=[STATIC_TOKEN],
        admin_token=ADMIN_TOKEN,
        read_roots=[str(work)], write_roots=[str(work)], work_dir=str(work),
        log_dir=str(tmp_path / "logs"), state_dir=str(tmp_path / "state"),
        rate_per_minute=100000, rate_high_per_hour=100000,
    )
    kwargs.update(over)
    cfg = Config(**kwargs)
    cfg.ensure_dirs()
    return cfg


@pytest.fixture
def pass_store(tmp_path):
    store = PassphraseStore(tmp_path / "panel.passphrase")
    store.set(PASSPHRASE)
    return store


def make_panel(cfg, *, bots=None, verifier=None, tools=None):
    server = Server(cfg)
    store = bots if bots is not None else BotStore(cfg.panel_settings.bots_file,
                                                  cfg.panel_settings.pepper_file)
    if bots is None:
        store.load()
    return PanelApp(cfg, server, tools if tools is not None
                    else [("system_info", "只读"), ("run_command", "危险")],
                    store, verifier)


def scope(path="/api/bots", method="GET", headers=None, query=b""):
    base = {"host": "127.0.0.1:8771"}
    base.update(headers or {})
    return {"type": "http", "method": method, "path": path,
            "headers": [(k.encode(), v.encode()) for k, v in base.items()],
            "client": ("127.0.0.1", 4242), "query_string": query,
            "scheme": "http", "http_version": "1.1"}


# ---------------------------------------------------------------- 口令存储

def test_hash_passphrase_format_and_no_plaintext(tmp_path):
    record = hash_passphrase(PASSPHRASE)
    assert record.startswith("scrypt$")
    assert PASSPHRASE not in record
    parts = record.split("$")
    assert len(parts) == 6 and len(parts[4]) == 32 and len(parts[5]) == 64


def test_hash_passphrase_uses_a_fresh_salt_each_time():
    assert hash_passphrase(PASSPHRASE) != hash_passphrase(PASSPHRASE)


def test_hash_passphrase_rejects_short_secrets():
    with pytest.raises(ValueError, match="至少 8"):
        hash_passphrase("short")


def test_passphrase_store_roundtrip(pass_store):
    assert pass_store.configured() is True
    assert pass_store.verify(PASSPHRASE) is True
    assert pass_store.verify(PASSPHRASE + "x") is False
    assert pass_store.verify("") is False
    raw = pass_store.path.read_text(encoding="utf-8")
    assert PASSPHRASE not in raw, "口令明文落盘了"


def test_passphrase_store_unconfigured(tmp_path):
    store = PassphraseStore(tmp_path / "missing")
    assert store.configured() is False
    assert store.verify("anything") is False


def test_passphrase_store_picks_up_external_change(pass_store):
    """改口令不该需要重启面板：文件 mtime 变了就要重读。"""
    assert pass_store.verify("new-passphrase-1234") is False
    pass_store.set("new-passphrase-1234")
    assert pass_store.verify("new-passphrase-1234") is True
    assert pass_store.verify(PASSPHRASE) is False


# ---------------------------------------------------------------- 登录节流

def test_throttle_allows_then_blocks_per_ip():
    throttle = LoginThrottle(per_ip=3, window_s=300)
    assert throttle.retry_after("1.2.3.4") == 0
    for _ in range(3):
        throttle.record_failure("1.2.3.4")
    assert throttle.retry_after("1.2.3.4") > 0
    assert throttle.retry_after("5.6.7.8") == 0, "别的 IP 不该被连坐"


def test_throttle_clear_resets():
    throttle = LoginThrottle(per_ip=2, window_s=300)
    throttle.record_failure("ip")
    throttle.record_failure("ip")
    assert throttle.retry_after("ip") > 0
    throttle.clear("ip")
    assert throttle.retry_after("ip") == 0


def test_throttle_global_cap_blocks_new_ips():
    throttle = LoginThrottle(per_ip=2, window_s=300, global_max=3)
    for index in range(3):
        throttle.record_failure(f"ip{index}")
    assert throttle.retry_after("fresh-ip") > 0, "换 IP 也不能无限猜"


def test_throttle_window_expires():
    throttle = LoginThrottle(per_ip=1, window_s=1)
def test_throttle_window_expires():
    throttle = LoginThrottle(per_ip=1, window_s=300)
    throttle.window_s = 1          # 构造时对窗口有最小值保护，这里直接改属性来测过期
    throttle.record_failure("ip")
    assert throttle.retry_after("ip") > 0
    time.sleep(1.1)
    assert throttle.retry_after("ip") == 0


# ---------------------------------------------------------------- 启动前检查

def test_panel_refuses_to_start_without_any_auth(tmp_path):
    cfg = make_cfg(tmp_path)
    with pytest.raises(PanelDisabled, match="一个鉴权方式都没有"):
        make_panel(cfg)


def test_panel_starts_with_passphrase_only(tmp_path, pass_store):
    cfg = make_cfg(tmp_path, panel={"passphrase_file": str(pass_store.path)})
    panel = make_panel(cfg)
    summary = panel.auth_summary()
    assert summary["passphrase_configured"] is True
    assert summary["access_configured"] is False


# ---------------------------------------------------------------- 会话 cookie

def test_session_cookie_roundtrip(tmp_path, pass_store):
    cfg = make_cfg(tmp_path, panel={"passphrase_file": str(pass_store.path)})
    panel = make_panel(cfg)
    value = panel._session_cookie("local")
    assert panel._session_valid(value) is True


def test_session_cookie_rejects_tampering(tmp_path, pass_store):
    cfg = make_cfg(tmp_path, panel={"passphrase_file": str(pass_store.path)})
    panel = make_panel(cfg)
    value = panel._session_cookie("local")
    blob, sig = value.rsplit(".", 1)
    assert panel._session_valid(f"{blob}.{'0' * len(sig)}") is False
    forged = base64.urlsafe_b64encode(
        json.dumps({"who": "local", "exp": int(time.time()) + 9999}).encode()
    ).rstrip(b"=").decode()
    assert panel._session_valid(f"{forged}.{sig}") is False, "换了载荷签名就对不上"
    assert panel._session_valid("garbage") is False
    assert panel._session_valid("") is False


def test_session_cookie_honours_ttl(tmp_path, pass_store):
    cfg = make_cfg(tmp_path, panel={"passphrase_file": str(pass_store.path),
                                    "session_ttl_s": 60})
    panel = make_panel(cfg)
    assert panel._session_valid(panel._session_cookie("local")) is True
    expired = panel._session_cookie("local")
    blob, sig = expired.rsplit(".", 1)
    payload = json.loads(base64.urlsafe_b64decode(blob + "=" * (-len(blob) % 4)))
    payload["exp"] = int(time.time()) - 1
    import hmac as _hmac
    import hashlib as _hashlib
    blob2 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    sig2 = _hmac.new(panel.session_key, blob2.encode(), _hashlib.sha256).hexdigest()
    assert panel._session_valid(f"{blob2}.{sig2}") is False, "过期会话必须失效"


# ---------------------------------------------------------------- 鉴权模式

def test_auth_passphrase_mode(tmp_path, pass_store):
    cfg = make_cfg(tmp_path, panel={"passphrase_file": str(pass_store.path),
                                    "auth_mode": "passphrase"})
    panel = make_panel(cfg)
    assert panel._authenticate(scope())[0] is False
    cookie = panel._session_cookie("local")
    ok, who, _ = panel._authenticate(scope(headers={"cookie": f"{COOKIE_NAME}={cookie}"}))
    assert ok is True and who == "local"


def test_auth_access_mode_requires_valid_jwt(tmp_path, rsa_keys):
    private, public = rsa_keys
    cfg = make_cfg(tmp_path, panel={
        "auth_mode": "access", "access_team": TEAM, "access_aud": AUD,
        "access_emails": [EMAIL]})
    verifier = AccessVerifier(team=TEAM, aud=AUD, emails=[EMAIL], jwks=[_jwk(public)])
    panel = make_panel(cfg, verifier=verifier)
    assert panel._authenticate(scope())[0] is False
    ok, who, _ = panel._authenticate(scope(headers={
        "cf-access-jwt-assertion": access_token(private), "cf-ray": "abc"}))
    assert ok is True and who == EMAIL
    # 签名不对 / aud 不对，一律不放行
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert panel._authenticate(scope(headers={
        "cf-access-jwt-assertion": access_token(other)}))[0] is False
    assert panel._authenticate(scope(headers={
        "cf-access-jwt-assertion": access_token(private, aud="wrong")}))[0] is False


def test_auth_both_mode_local_needs_only_passphrase(tmp_path, rsa_keys, pass_store):
    """本机直连（没有 cf-ray）只要口令——留一条修复路径，别把自己锁在外面。"""
    private, public = rsa_keys
    cfg = make_cfg(tmp_path, panel={
        "passphrase_file": str(pass_store.path), "auth_mode": "both",
        "access_team": TEAM, "access_aud": AUD, "access_emails": [EMAIL]})
    verifier = AccessVerifier(team=TEAM, aud=AUD, emails=[EMAIL], jwks=[_jwk(public)])
    panel = make_panel(cfg, verifier=verifier)
    cookie = panel._session_cookie("local")
    local = scope(headers={"cookie": f"{COOKIE_NAME}={cookie}"})
    assert panel._authenticate(local)[0] is True

    via_cf = scope(headers={"cookie": f"{COOKIE_NAME}={cookie}", "cf-ray": "abc"})
    assert panel._authenticate(via_cf)[0] is False, "经 Cloudflare 必须带有效 Access JWT"

    both = scope(headers={"cookie": f"{COOKIE_NAME}={cookie}", "cf-ray": "abc",
                          "cf-access-jwt-assertion": access_token(private)})
    assert panel._authenticate(both)[0] is True

    no_cookie = scope(headers={"cf-ray": "abc",
                               "cf-access-jwt-assertion": access_token(private)})
    assert panel._authenticate(no_cookie)[0] is False, "both 模式口令也要"


def test_auth_both_mode_without_access_configured_equals_passphrase(tmp_path, pass_store):
    cfg = make_cfg(tmp_path, panel={"passphrase_file": str(pass_store.path),
                                    "auth_mode": "both"})
    panel = make_panel(cfg)
    cookie = panel._session_cookie("local")
    assert panel._authenticate(scope(headers={
        "cookie": f"{COOKIE_NAME}={cookie}", "cf-ray": "abc"}))[0] is True


def test_auth_either_mode(tmp_path, rsa_keys, pass_store):
    private, public = rsa_keys
    cfg = make_cfg(tmp_path, panel={
        "passphrase_file": str(pass_store.path), "auth_mode": "either",
        "access_team": TEAM, "access_aud": AUD, "access_emails": [EMAIL]})
    verifier = AccessVerifier(team=TEAM, aud=AUD, emails=[EMAIL], jwks=[_jwk(public)])
    panel = make_panel(cfg, verifier=verifier)
    cookie = panel._session_cookie("local")
    assert panel._authenticate(scope(headers={"cookie": f"{COOKIE_NAME}={cookie}"}))[0] is True
    assert panel._authenticate(scope(headers={
        "cf-access-jwt-assertion": access_token(private)}))[0] is True
    assert panel._authenticate(scope())[0] is False


def test_client_ip_prefers_cloudflare_header(tmp_path, pass_store):
    cfg = make_cfg(tmp_path, panel={"passphrase_file": str(pass_store.path)})
    panel = make_panel(cfg)
    assert panel._client_ip(scope()) == "127.0.0.1"
    assert panel._client_ip(scope(headers={"cf-connecting-ip": "203.0.113.7"})) == "203.0.113.7"
    assert panel._client_ip(scope(headers={"x-forwarded-for": "198.51.100.9, 10.0.0.1"})) == "198.51.100.9"


# ---------------------------------------------------------------- 工具分组

def test_tools_payload_groups_and_prefix(tmp_path, pass_store):
    cfg = make_cfg(tmp_path, panel={"passphrase_file": str(pass_store.path)})
    panel = make_panel(cfg, tools=[("system_info", "只读"), ("read_file", "读"),
                                   ("run_command", "危险"), ("brand_new", "新的")])
    payload = panel._tools_payload()
    labels = [g["label"] for g in payload["groups"]]
    assert "只读监控" in labels and "命令与任务" in labels and "其他" in labels
    flat = {t["internal"]: t for g in payload["groups"] for t in g["tools"]}
    assert set(flat) == {"system_info", "read_file", "run_command", "brand_new"}
    assert flat["system_info"]["exposed"] == "system_info"
    assert flat["system_info"]["default"] is True
    assert flat["run_command"]["default"] is False
    assert flat["brand_new"]["default"] is False


def test_tools_payload_applies_configured_prefix(tmp_path, pass_store):
    cfg = make_cfg(tmp_path, tool_prefix="wb_",
                   panel={"passphrase_file": str(pass_store.path)})
    panel = make_panel(cfg, tools=[("system_info", "只读")])
    flat = [t for g in panel._tools_payload()["groups"] for t in g["tools"]]
    assert flat[0]["exposed"] == "wb_system_info"
    assert flat[0]["internal"] == "system_info"


# ---------------------------------------------------------------- 端到端

@pytest.fixture
def live(tmp_path, pass_store):
    panel_port = free_port()
    cfg = make_cfg(tmp_path, tool_prefix="wb_",
                   panel={"passphrase_file": str(pass_store.path),
                          "port": panel_port})
    server = Server(cfg)
    app = App(server)
    panel = PanelApp(cfg, server, [("system_info", "只读"), ("run_command", "危险")],
                     app.bots, None)
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
        raise RuntimeError("面板测试服务器起不来")

    holder = type("Ctx", (), {})()
    holder.cfg, holder.server, holder.app, holder.panel = cfg, server, app, panel
    holder.base, holder.passphrase = base, PASSPHRASE
    holder.mcp_url = f"http://127.0.0.1:{cfg.port}{cfg.path}"
    holder.bots_file = cfg.panel_settings.bots_file
    yield holder
    mcp_uv.should_exit = True
    panel_uv.should_exit = True
    for thread in threads:
        thread.join(5)


def login(live, passphrase=None):
    return httpx.post(f"{live.base}/api/login",
                      json={"passphrase": passphrase or live.passphrase},
                      headers={"X-Panel-Request": "1"}, timeout=30)


def test_e2e_page_and_health_are_public_but_data_is_not(live):
    page = httpx.get(f"{live.base}/", timeout=10)
    assert page.status_code == 200
    # 页面外壳（含 PWA 清单）不含任何数据，所以免鉴权；数据全在 /api/* 后面。
    assert "远程审批" in page.text
    assert "/manifest.webmanifest" in page.text
    assert httpx.get(f"{live.base}/healthz", timeout=10).status_code == 200
    assert httpx.get(f"{live.base}/manifest.webmanifest", timeout=10).status_code == 200
    assert httpx.get(f"{live.base}/icon-192.png", timeout=10).status_code == 200
    assert httpx.get(f"{live.base}/sw.js", timeout=10).status_code == 200
    assert httpx.get(f"{live.base}/api/session", timeout=10).status_code == 401
    assert httpx.get(f"{live.base}/api/bots", timeout=10).status_code == 401
    assert httpx.get(f"{live.base}/api/approvals", timeout=10).status_code == 401
    assert httpx.get(f"{live.base}/api/settings", timeout=10).status_code == 401


def test_e2e_login_requires_csrf_header_and_correct_passphrase(live):
    assert httpx.post(f"{live.base}/api/login", json={"passphrase": live.passphrase},
                      timeout=30).status_code == 403
    assert login(live, "wrong-passphrase").status_code == 401
    response = login(live)
    assert response.status_code == 200
    assert response.cookies.get(COOKIE_NAME)


def test_e2e_login_is_throttled(live):
    live.panel.throttle = LoginThrottle(per_ip=3, window_s=300)
    codes = [login(live, "wrong").status_code for _ in range(5)]
    assert 429 in codes, f"连续失败必须被节流，实际 {codes}"
    live.panel.throttle.clear("127.0.0.1")


def test_e2e_full_bot_lifecycle(live):
    cookie = login(live).cookies.get(COOKIE_NAME)
    headers = {"X-Panel-Request": "1", "Cookie": f"{COOKIE_NAME}={cookie}"}

    session = httpx.get(f"{live.base}/api/session", timeout=10, headers=headers)
    assert session.status_code == 200 and session.json()["who"] == "local"

    tools = httpx.get(f"{live.base}/api/tools", timeout=10, headers=headers).json()
    assert tools["groups"] and tools["total"] == 2

    created = httpx.post(f"{live.base}/api/bots", timeout=20, headers=headers, json={
        "name": "phone", "allow": ["system_info"], "note": "手机只读"})
    assert created.status_code == 201
    token = created.json()["token"]
    bot = created.json()["bot"]
    assert len(token) == 64

    listing = httpx.get(f"{live.base}/api/bots", timeout=10, headers=headers).json()
    assert [b["name"] for b in listing["bots"]] == ["phone"]
    for item in listing["bots"]:
        assert "token" not in item and "token_hash" not in item
    assert token not in json.dumps(listing), "列表接口不能回传明文 token"
    assert token not in json.dumps(listing)

    assert httpx.post(f"{live.base}/api/bots", timeout=20, headers=headers,
                      json={"name": "phone"}).status_code == 400

    patched = httpx.patch(f"{live.base}/api/bots/{bot['id']}", timeout=20, headers=headers,
                          json={"allow": ["system_info", "run_command"], "enabled": False})
    assert patched.status_code == 200
    assert patched.json()["bot"]["enabled"] is False

    rotated = httpx.post(f"{live.base}/api/bots/{bot['id']}/rotate", timeout=20,
                         headers=headers)
    assert rotated.status_code == 200
    new_token = rotated.json()["token"]
    assert new_token != token

    # 轮换/停用都立刻反映到 MCP 侧
    assert live.app.bots.verify(token)[0] is None
    assert live.app.bots.verify(new_token)[1] == "disabled"

    refused = httpx.request("DELETE", f"{live.base}/api/bots/{bot['id']}", timeout=20,
                            headers=headers, json={"confirm": "nope"})
    assert refused.status_code == 400
    assert httpx.request("DELETE", f"{live.base}/api/bots/{bot['id']}", timeout=20,
                         headers=headers,
                         json={"confirm": "phone"}).status_code == 200
    assert live.app.bots.total() == 0


def test_e2e_audit_endpoint_reports_calls_with_source_ip(live):
    """审计要能回答「哪个 bot、什么时候、调了什么、结果如何、从哪个 IP 来的」。

    来源 IP 是**请求上下文**里带下来的，所以这里用这个 bot 的 token 真打一次
    MCP 接口，而不是在测试线程里手写一条审计记录。
    """
    cookie = login(live).cookies.get(COOKIE_NAME)
    headers = {"X-Panel-Request": "1", "Cookie": f"{COOKIE_NAME}={cookie}"}
    created = httpx.post(f"{live.base}/api/bots", timeout=20, headers=headers,
                         json={"name": "audited",
                               "allow": ["system_info", "run_command"]})
    bot, token = created.json()["bot"], created.json()["token"]

    def call(tool, args):
        return httpx.post(live.mcp_url, timeout=25, headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }, json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                 "params": {"name": tool, "arguments": args}})

    assert call("wb_system_info", {}).status_code == 200
    denied = call("wb_write_file", {"path": "D:/window-mcp/workspace/x",
                                   "content": "TOP-SECRET-BODY"})
    assert denied.status_code == 403

    response = httpx.get(f"{live.base}/api/bots/{bot['id']}/audit", timeout=10,
                         headers=headers)
    assert response.status_code == 200
    events = response.json()["events"]
    assert events, "应该有调用记录"
    assert events[0]["bot"] == "audited"
    assert events[0]["tool"] == "system_info"
    assert events[0]["client"] == "127.0.0.1"
    assert events[0]["decision"] == "allowed"
    assert any(e["decision"] == "denied" for e in events), "被拒绝的调用也要记"
    dumped = json.dumps(events, ensure_ascii=False)
    assert "TOP-SECRET-BODY" not in dumped, "参数内容不能进审计"
    assert token not in dumped, "token 值不能进审计"

def test_e2e_rejects_unknown_host(live):
    response = httpx.get(f"{live.base}/api/session", timeout=10,
                         headers={"Host": "evil.example.com"})
    assert response.status_code == 421


def test_e2e_logout_clears_session(live):
    cookie = login(live).cookies.get(COOKIE_NAME)
    headers = {"X-Panel-Request": "1", "Cookie": f"{COOKIE_NAME}={cookie}"}
    assert httpx.get(f"{live.base}/api/session", timeout=10, headers=headers).status_code == 200
    assert httpx.post(f"{live.base}/api/logout", timeout=10, headers=headers).status_code == 200
    cleared = httpx.post(f"{live.base}/api/logout", timeout=10, headers=headers)
    assert "Max-Age=0" in cleared.headers.get("set-cookie", "")


def test_e2e_unknown_api_path_is_404(live):
    cookie = login(live).cookies.get(COOKIE_NAME)
    headers = {"X-Panel-Request": "1", "Cookie": f"{COOKIE_NAME}={cookie}"}
    assert httpx.get(f"{live.base}/api/nope", timeout=10, headers=headers).status_code == 404
    assert httpx.get(f"{live.base}/api/bots/nope-id", timeout=10,
                     headers=headers).status_code == 404


def test_e2e_config_rejects_bad_panel_settings(tmp_path):
    with pytest.raises(ValueError, match="未知配置项"):
        make_cfg(tmp_path, panel={"nope": 1})
    with pytest.raises(ValueError, match="未知配置项"):
        make_cfg(tmp_path, panel={"nope": 1})
    shared = free_port()
    with pytest.raises(ValueError, match="不能与 server.port 相同"):
        make_cfg(tmp_path, port=shared, panel={"port": shared})
    with pytest.raises(ValueError, match="127.0.0.1"):
        make_cfg(tmp_path, panel={"host": "0.0.0.0"})
    with pytest.raises(ValueError, match="auth_mode"):
        make_cfg(tmp_path, panel={"auth_mode": "nope"})
    assert config_module.PanelSettings().auth_mode == "both"
    assert config_module.PanelSettings().auth_mode == "both"
