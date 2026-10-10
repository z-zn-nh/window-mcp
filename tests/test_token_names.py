"""具名 token：名册解析、恒定时间比对、审计归属。

背景（2026-10-09）：要给另一个客户端（Cue）单独的 token，同时 Hark 手上那个继续有效。
老实现只有匿名 token 列表，审计日志里分不出「这次调用是谁发的」。本文件守住三件事：

1. name -> token 的名册（含「值放文件」写法），名字只做归属、不做授权判断；
2. 比对仍是恒定时间，且命中名字本身不因「第几个候选」而泄漏；
3. 审计/访问日志只记名字，**永不记 token 值**（这条是硬要求，用反证断言守住）。
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

from mcp_server import config as config_module
from mcp_server.app import App
from mcp_server.audit import AuditLog
from mcp_server.config import Config
from mcp_server.security import (
    current_token_name,
    match_token_name,
    set_token_name,
    token_matches,
)
from mcp_server.server import Server

HARK = "hark-token-abcdefghijklmnopqrstuvwxyz"
CUE = "cue-token-abcdefghijklmnopqrstuvwxyz"


# ---------------------------------------------------------------- 名册


def test_named_and_anonymous_tokens_both_present():
    cfg = Config(tokens=[HARK], named_tokens={"cue": CUE})
    assert cfg.token_entries() == [("cue", CUE), ("token-1", HARK)]
    assert cfg.token_names() == ["cue", "token-1"]


def test_anonymous_tokens_are_numbered_in_order():
    cfg = Config(tokens=["a" * 8, "b" * 8, "c" * 8])
    assert cfg.token_names() == ["token-1", "token-2", "token-3"]


def test_blank_values_are_dropped_from_the_roster():
    """编号取配置里的位置：tokens[1] 就是 token-2，审计里看到名字能对回 config.toml。"""
    cfg = Config(tokens=["", HARK, "   "], named_tokens={"cue": CUE, "empty": "  "})
    assert cfg.token_names() == ["cue", "token-2"]
    assert dict(cfg.token_entries())["token-2"] == HARK


def test_bad_or_duplicate_names_rejected():
    with pytest.raises(ValueError):
        Config(tokens=[HARK], named_tokens={"bad name": CUE})
    with pytest.raises(ValueError):
        Config(tokens=[HARK], named_tokens={"a" * 40: CUE})
    with pytest.raises(ValueError):
        # 同名会让审计归属失去意义，直接拒绝启动
        Config(tokens=[HARK], named_tokens={"cue": CUE}, token_files={"cue": "x.token"})


def test_admin_token_falls_back_to_unnamed_first():
    """留空 = 复用 tokens[0]（加具名 token 之前的语义），不会被具名 token 顶掉。"""
    cfg = Config(tokens=[HARK], named_tokens={"cue": CUE})
    assert cfg.admin_token == HARK


def test_admin_token_falls_back_to_named_when_no_anonymous():
    cfg = Config(named_tokens={"cue": CUE})
    assert cfg.admin_token == CUE


# ---------------------------------------------------------------- 文件里的值


def _write_config(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(body, encoding="utf-8")
    return path


def test_token_files_are_read_and_only_names_live_in_config(tmp_path):
    secret = tmp_path / "cue.token"
    secret.write_text(CUE + "\n", encoding="utf-8")
    cfg_path = _write_config(tmp_path, f"""
[server]
tokens = ["{HARK}"]
token_files = {{ cue = "{secret.as_posix()}" }}
work_dir = "{(tmp_path / 'work').as_posix()}"
log_dir = "{(tmp_path / 'logs').as_posix()}"
state_dir = "{(tmp_path / 'state').as_posix()}"
""")
    cfg = config_module.load(cfg_path)
    assert cfg.token_names() == ["cue", "token-1"]
    assert dict(cfg.token_entries())["cue"] == CUE  # 换行被 strip 掉
    assert not cfg.load_warnings
    # 配置文本里只有路径，没有值
    assert CUE not in cfg_path.read_text(encoding="utf-8")


def test_missing_token_file_is_skipped_not_fatal(tmp_path):
    """吊销手段就是删文件 + 重启：个别文件缺失不能拖垮整个服务，但要留下 warning。"""
    cfg_path = _write_config(tmp_path, f"""
[server]
tokens = ["{HARK}"]
token_files = {{ cue = "{(tmp_path / 'gone.token').as_posix()}" }}
work_dir = "{(tmp_path / 'work').as_posix()}"
log_dir = "{(tmp_path / 'logs').as_posix()}"
state_dir = "{(tmp_path / 'state').as_posix()}"
""")
    cfg = config_module.load(cfg_path)
    assert cfg.token_names() == ["token-1"]
    assert any("cue" in w and "已跳过" in w for w in cfg.load_warnings)


def test_empty_token_file_is_skipped(tmp_path):
    secret = tmp_path / "cue.token"
    secret.write_text("   \n", encoding="utf-8")
    cfg_path = _write_config(tmp_path, f"""
[server]
tokens = ["{HARK}"]
token_files = {{ cue = "{secret.as_posix()}" }}
work_dir = "{(tmp_path / 'work').as_posix()}"
log_dir = "{(tmp_path / 'logs').as_posix()}"
state_dir = "{(tmp_path / 'state').as_posix()}"
""")
    cfg = config_module.load(cfg_path)
    assert cfg.token_names() == ["token-1"]
    assert any("已跳过" in w for w in cfg.load_warnings)


def test_no_static_tokens_is_no_longer_fatal_at_load(tmp_path):
    """静态 token 全空不再让 config.load() 退出。

    原因：凭据现在也可以只存在于**面板管理的 bot 名册**里（state/bots.json），
    而 load() 看不到那份名册。这个不变量没有消失，只是搬到了 App 构造时——
    见下一个用例。config.toml 里仍然一个 token 都没有的话，
    ``token_entries()`` 就是空的（不报错）。
    """
    cfg_path = _write_config(tmp_path, "[server]\nwork_dir = \"\"\n")
    cfg = config_module.load(cfg_path)
    assert cfg.token_entries() == []
    assert cfg.token_names() == []


def test_no_credentials_at_all_is_fatal_at_app_start(tmp_path):
    """静态 token 与 bot 名册**都**空 → 拒绝启动（否则谁都进不来，服务等于不可用）。"""
    cfg = Config(
        host="127.0.0.1",
        port=_free_port(),
        tokens=[],
        read_roots=[str(tmp_path)],
        write_roots=[str(tmp_path)],
        work_dir=str(tmp_path),
        log_dir=str(tmp_path / "logs"),
        state_dir=str(tmp_path / "state"),
    )
    cfg.ensure_dirs()
    with pytest.raises(SystemExit):
        App(Server(cfg))


# ---------------------------------------------------------------- 比对


def test_match_token_name_returns_the_name():
    entries = [("cue", CUE), ("token-1", HARK)]
    assert match_token_name(CUE, entries) == "cue"
    assert match_token_name(HARK, entries) == "token-1"
    assert match_token_name("nope", entries) is None
    assert match_token_name("", entries) is None
    assert match_token_name(CUE, []) is None


def test_match_token_name_survives_malformed_input():
    """头里塞非 ASCII：compare_digest 会抛 TypeError，这里必须落成「不匹配」而不是 500。"""
    entries = [("cue", CUE)]
    assert match_token_name("中文-token", entries) is None
    assert not token_matches("中文-token", [CUE])
    assert token_matches(CUE, [CUE])


def test_match_token_name_compares_every_candidate(monkeypatch):
    """命中项在第一位时也必须把其余候选全比一遍（不提前返回）。

    「不提前返回」不是洁癖：命中位置会进耗时，而这里返回的名字还会落进审计。
    用真实的 hmac.compare_digest 调用计数来证明，而不是靠读代码。
    """
    from mcp_server import security as security_module

    calls: list[tuple[str, str]] = []
    real = security_module.hmac.compare_digest

    def counting(left, right):
        calls.append((left, right))
        return real(left, right)

    monkeypatch.setattr(security_module.hmac, "compare_digest", counting)
    entries = [("cue", CUE), ("token-1", HARK), ("token-2", "x" * 20)]
    assert match_token_name(CUE, entries) == "cue"
    assert len(calls) == len(entries)

    calls.clear()
    assert match_token_name("nope", entries) is None
    assert len(calls) == len(entries)


# ---------------------------------------------------------------- 审计 / 访问日志


def test_audit_records_token_name_and_never_the_value(tmp_path):
    audit = AuditLog(tmp_path)
    set_token_name("cue")
    audit.call("system_stats", {"request_id": "r1"}, "R", "executed", 5, "ok")
    set_token_name("")
    audit.note("startup", detail="no request context")

    lines = [json.loads(x) for x in (tmp_path / f"audit-{time.strftime('%Y-%m-%d')}.jsonl")
             .read_text(encoding="utf-8").splitlines()]
    assert lines[0]["token"] == "cue"
    assert lines[1]["token"] == "-"
    raw = json.dumps(lines, ensure_ascii=False)
    assert CUE not in raw and HARK not in raw


def test_current_token_name_defaults_to_empty():
    set_token_name("")
    assert current_token_name() == ""


# ---------------------------------------------------------------- 端到端：两个客户端各拿自己的 token


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def two_token_ctx(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    cfg = Config(
        host="127.0.0.1",
        port=_free_port(),
        tokens=[HARK],                      # 老 token 继续有效
        named_tokens={"cue": CUE},          # 新客户端
        admin_token="admin-token-abcdefghijklmnopqrstuvwxyz",
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
                         headers={"Authorization": f"Bearer {HARK}"}).status_code == 200:
                break
        except httpx.HTTPError:
            pass
        time.sleep(0.05)
    else:
        raise RuntimeError("测试服务器启动失败")

    holder = type("Ctx", (), {})()
    holder.cfg, holder.server, holder.base = cfg, server, base
    holder.url = base + cfg.path
    holder.log_dir = Path(cfg.log_dir)
    yield holder
    uv_server.should_exit = True
    thread.join(5)


def _call(base: str, token: str | None, path: str = "/healthz"):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return httpx.get(f"{base}{path}", headers=headers, timeout=5)


def test_two_clients_authorize_independently(two_token_ctx):
    base = two_token_ctx.base
    assert _call(base, None).status_code == 401          # 无 token
    assert _call(base, "garbage-token").status_code == 401  # 乱填
    assert _call(base, HARK).status_code == 200           # 老 token 依旧有效
    assert _call(base, CUE).status_code == 200            # 新 token 有效


def test_both_tokens_can_reach_mcp_and_are_attributed(two_token_ctx):
    """工具面也要能过，并且审计日志按 token 名归属、不含 token 值。"""
    # 先来一次不带 token 的请求：它必须记成 "-"，绝不能借用别人的身份出现在日志里
    assert _call(two_token_ctx.base, None).status_code == 401

    for token in (HARK, CUE):
        response = httpx.post(
            two_token_ctx.url,
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Authorization": f"Bearer {token}",
                     "Content-Type": "application/json",
                     "Accept": "application/json, text/event-stream"},
            timeout=10,
        )
        assert response.status_code == 200, response.text
        assert "system_stats" in response.text or "tools" in response.text

    access_log = (two_token_ctx.log_dir / "access.log").read_text(encoding="utf-8")
    entries = [json.loads(line) for line in access_log.splitlines() if line.strip()]
    tokens_seen = {entry.get("token") for entry in entries}
    assert "cue" in tokens_seen
    assert "token-1" in tokens_seen
    assert "-" in tokens_seen
    assert CUE not in access_log and HARK not in access_log


def test_malformed_token_header_returns_401_not_500(two_token_ctx):
    """头里带非 ASCII 字节：compare_digest 会抛 TypeError，必须落成 401 而不是 500。

    真实链路里能出现：HTTP 头是字节串，服务端按 latin-1 解码，于是 str 里就带上了 >127 的字符。
    httpx 会把 str 头按 ascii 编码而报错，所以这里直接发字节（等价于客户端原始报文）。
    """
    response = httpx.get(f"{two_token_ctx.base}/healthz", timeout=5,
                         headers={"Authorization": b"Bearer \xc3\xa4token"})
    assert response.status_code == 401

    audit_free = httpx.get(f"{two_token_ctx.base}/healthz", timeout=5,
                           headers={"Authorization": "Bearer " + CUE})
    assert audit_free.status_code == 200


def test_tool_call_audit_carries_the_client_name(two_token_ctx):
    """一次真实工具调用：审计记录里应出现 cue，而不是 token 值。"""
    import asyncio

    tools = asyncio.run(two_token_ctx.server.mcp.list_tools())
    name = next(t.name for t in tools if "system_stats" in t.name)
    response = httpx.post(
        two_token_ctx.url,
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/call",
              "params": {"name": name, "arguments": {}}},
        headers={"Authorization": f"Bearer {CUE}",
                 "Content-Type": "application/json",
                 "Accept": "application/json, text/event-stream"},
        timeout=15,
    )
    assert response.status_code == 200, response.text
    audit_file = two_token_ctx.log_dir / f"audit-{time.strftime('%Y-%m-%d')}.jsonl"
    assert audit_file.is_file(), "工具调用没有落审计"
    raw = audit_file.read_text(encoding="utf-8")
    assert CUE not in raw and HARK not in raw
    assert any(json.loads(line).get("token") == "cue"
               for line in raw.splitlines() if line.strip())
