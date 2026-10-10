"""bot token 名册（BotStore）与统一名册（TokenRegistry）的单测。

重点不是「功能能跑」，而是几条**不能破的安全性质**：

* 文件里永远只有哈希，没有明文 token；
* ``token_hint`` 由哈希派生，不泄漏 token 的任何字符；
* 白名单默认只读，``run_command`` / ``clipboard_get`` 这类不在默认集合里；
* 删除必须二次确认（输入名字），防误删；
* 文件损坏时能从 .bak 恢复，而不是让服务起不来。
"""

from __future__ import annotations

import json
import time

import pytest

from mcp_server.bots import (
    ALL,
    DEFAULT_ALLOW,
    BotStore,
    BotStoreError,
    parse_when,
    valid_name,
)
from mcp_server.tokens import TokenRegistry

TOKEN_A = "A" * 64
TOKEN_B = "B" * 64


@pytest.fixture
def store(tmp_path):
    s = BotStore(tmp_path / "bots.json", tmp_path / "bots.key")
    s.load()
    return s


# ---------------------------------------------------------------- 基本读写

def test_create_returns_plaintext_once_and_stores_only_hash(store):
    public, token = store.create("phone")
    assert len(token) == 64
    assert public["name"] == "phone"
    assert public["token_hint"] and len(public["token_hint"]) == 8
    # 公开表示里绝不能有哈希
    assert "token_hash" not in public

    raw = (store.path).read_text(encoding="utf-8")
    assert token not in raw, "明文 token 落盘了"
    assert store.hash_token(token) in raw, "哈希没写进去"
    assert len(store.get(public["id"]).token_hash) == 64


def test_hint_is_derived_from_hash_not_from_token(store):
    public, token = store.create("phone")
    digest = store.hash_token(token)
    assert public["token_hint"] == digest[:8]
    # hint 的字符不该出现在 token 里（极端但能证明它来自哈希）
    assert public["token_hint"] != token[:8]


def test_two_bots_have_different_hashes_and_hints(store):
    a, ta = store.create("a")
    b, tb = store.create("b")
    assert a["token_hint"] != b["token_hint"]
    assert store.hash_token(ta) != store.hash_token(tb)


def test_pepper_is_persisted_and_stable(tmp_path):
    path, pepper = tmp_path / "bots.json", tmp_path / "bots.key"
    first = BotStore(path, pepper)
    first.load()
    _, token = first.create("a")
    digest = first.hash_token(token)
    assert pepper.is_file()

    second = BotStore(path, pepper)
    second.load()
    assert second.hash_token(token) == digest, "pepper 变了，哈希就全废了"
    bot, status = second.verify(token)
    assert bot is not None and bot.name == "a" and status == "ok"


def test_load_creates_pepper_with_enough_entropy(tmp_path):
    s = BotStore(tmp_path / "b.json", tmp_path / "b.key")
    s.load()
    raw = bytes.fromhex((tmp_path / "b.key").read_text(encoding="utf-8").strip())
    assert len(raw) == 32


# ---------------------------------------------------------------- 校验

def test_verify_matches_and_rejects(store):
    _, token = store.create("phone")
    bot, status = store.verify(token)
    assert bot is not None and bot.name == "phone" and status == "ok"
    assert store.verify("wrong") == (None, "unknown")
    assert store.verify("") == (None, "empty")


def test_verify_does_not_match_a_prefix(store):
    _, token = store.create("phone")
    assert store.verify(token[:32])[0] is None
    assert store.verify(token + "x")[0] is None


def test_disabled_and_expired_report_status(store):
    public, token = store.create("phone")
    store.update(public["id"], {"enabled": False})
    assert store.verify(token)[1] == "disabled"
    store.update(public["id"], {"enabled": True})
    assert store.verify(token)[1] == "ok"
    store.update(public["id"], {"expires_at": "2020-01-01"})
    assert store.verify(token)[1] == "expired"
    store.update(public["id"], {"expires_at": None})
    assert store.verify(token)[1] == "ok"


def test_enabled_count_ignores_broken_bots(store):
    a, _ = store.create("a")
    b, _ = store.create("b")
    store.update(b["id"], {"enabled": False})
    assert store.total() == 2
    assert store.enabled_count() == 1


# ---------------------------------------------------------------- 白名单

def test_default_allow_is_read_only(store):
    public, _ = store.create("phone")
    assert tuple(public["allow"]) == DEFAULT_ALLOW
    assert public["allow_all"] is False
    for dangerous in ("run_command", "start_job", "write_file", "edit_file",
                      "type_text", "click", "hotkey", "clipboard_set",
                      "clipboard_get"):
        assert dangerous not in DEFAULT_ALLOW, f"{dangerous} 不该在默认只读集合里"
    for safe in ("screenshot", "list_windows", "read_file", "agent_status",
                 "system_info"):
        assert safe in DEFAULT_ALLOW


def test_allows_handles_wildcard_and_lists(store):
    public, _ = store.create("phone", allow=["read_file", "screenshot"])
    bot = store.get(public["id"])
    assert bot.allows("read_file") is True
    assert bot.allows("run_command") is False

    full, _ = store.create("full", allow=[ALL])
    assert store.get(full["id"]).allows("run_command") is True


def test_allow_accepts_comma_string_and_dedupes(store):
    public, _ = store.create("phone", allow="read_file, screenshot, read_file")
    assert tuple(public["allow"]) == ("read_file", "screenshot")


def test_empty_allow_falls_back_to_default(store):
    public, _ = store.create("phone", allow=[])
    assert tuple(public["allow"]) == DEFAULT_ALLOW


def test_update_rejects_unknown_fields(store):
    public, _ = store.create("phone")
    with pytest.raises(BotStoreError, match="不认识的字段"):
        store.update(public["id"], {"token_hash": "x"})


def test_update_can_change_whitelist_expiry_and_note(store):
    public, _ = store.create("phone")
    updated = store.update(public["id"], {
        "allow": ["read_file"], "expires_at": "2030-01-01", "note": "hi"})
    assert updated["allow"] == ["read_file"]
    assert updated["note"] == "hi"
    assert store.get(public["id"]).expires_at == parse_when("2030-01-01")


# ---------------------------------------------------------------- 名字

def test_name_validation():
    assert valid_name("hark") is True
    assert valid_name("phone-claude_2.x") is True
    assert valid_name("") is False
    assert valid_name("has space") is False
    assert valid_name("中文") is False
    assert valid_name("x" * 33) is False


def test_create_rejects_bad_and_duplicate_names(store):
    store.create("phone")
    with pytest.raises(BotStoreError, match="名字不合法"):
        store.create("bad name")
    with pytest.raises(BotStoreError, match="已存在"):
        store.create("phone")


# ---------------------------------------------------------------- 轮换 / 删除

def test_rotate_invalidates_old_token_immediately(store):
    public, old = store.create("phone")
    _, new = store.rotate(public["id"])
    assert new != old
    assert store.verify(old)[0] is None
    bot, status = store.verify(new)
    assert bot is not None and status == "ok"
    assert store.get(public["id"]).rotated_at is not None


def test_rotate_keeps_whitelist_and_metadata(store):
    public, _ = store.create("phone", allow=["read_file"], note="n")
    rotated, _ = store.rotate(public["id"])
    assert rotated["allow"] == ["read_file"]
    assert rotated["note"] == "n"


def test_delete_requires_exact_name_confirmation(store):
    public, _ = store.create("phone")
    with pytest.raises(BotStoreError, match="二次确认失败"):
        store.delete(public["id"], "phone2")
    with pytest.raises(BotStoreError, match="二次确认失败"):
        store.delete(public["id"], "")
    assert store.total() == 1
    snapshot = store.delete(public["id"], "phone")
    assert snapshot["name"] == "phone"
    assert store.total() == 0


def test_delete_missing_bot(store):
    with pytest.raises(BotStoreError, match="不存在"):
        store.delete("nope", "nope")


# ---------------------------------------------------------------- 迁移

def test_bootstrap_imports_existing_tokens_unchanged(store):
    imported = store.bootstrap([("hark", TOKEN_A), ("cue", TOKEN_B)],
                               protected=("hark",), allow_all=True)
    assert imported == ["hark", "cue"]
    bot, status = store.verify(TOKEN_A)
    assert bot is not None and bot.name == "hark" and status == "ok"
    assert bot.allow == (ALL,)
    assert bot.protected is True
    assert store.find_by_name("cue").protected is False


def test_bootstrap_is_idempotent(store):
    store.bootstrap([("hark", TOKEN_A)])
    assert store.bootstrap([("hark", TOKEN_B)]) == []
    assert store.verify(TOKEN_A)[1] == "ok", "重复迁移不该覆盖已有 token"
    assert store.verify(TOKEN_B)[0] is None


def test_bootstrap_skips_invalid_entries(store):
    assert store.bootstrap([("bad name", TOKEN_A), ("", TOKEN_B), ("ok", "")]) == []


# ---------------------------------------------------------------- 落盘健壮性

def test_survives_reload(store, tmp_path):
    public, token = store.create("phone", allow=["read_file"], note="n")
    again = BotStore(tmp_path / "bots.json", tmp_path / "bots.key")
    again.load()
    assert again.total() == 1
    assert again.verify(token)[0].name == "phone"
    assert again.get(public["id"]).allow == ("read_file",)


def test_corrupt_file_recovers_from_backup(store):
    store.create("one")
    store.create("two")            # 第二次保存会把第一版挪成 .bak
    store.path.write_text("{ this is not json", encoding="utf-8")
    recovered = BotStore(store.path, store.pepper_path)
    recovered.load()
    assert recovered.total() == 1, "应该恢复到上一版（只有 one）"
    assert recovered.warnings, "恢复这件事必须留下痕迹"


def test_corrupt_file_without_backup_is_fatal(store):
    store.create("one")
    backup = store.path.with_suffix(store.path.suffix + ".bak")
    if backup.is_file():
        backup.unlink()
    store.path.write_text("{ broken", encoding="utf-8")
    broken = BotStore(store.path, store.pepper_path)
    with pytest.raises(BotStoreError, match="损坏"):
        broken.load()


def test_missing_file_is_an_empty_store(tmp_path):
    s = BotStore(tmp_path / "nope.json", tmp_path / "nope.key")
    s.load()
    assert s.total() == 0
    assert s.warnings == []


def test_saved_file_shape(store):
    store.create("phone")
    data = json.loads(store.path.read_text(encoding="utf-8"))
    assert data["version"] == 1
    assert isinstance(data["bots"], list)
    assert set(data["bots"][0]) >= {"id", "name", "token_hash", "allow"}


# ---------------------------------------------------------------- 使用计数

def test_touch_counts_and_persists_eventually(store, tmp_path):
    public, _ = store.create("phone")
    store.touch(public["id"])
    store.touch(public["id"])
    assert store.get(public["id"]).call_count == 2
    assert store.get(public["id"]).last_used_at is not None
    store.flush_touch()
    again = BotStore(tmp_path / "bots.json", tmp_path / "bots.key")
    again.load()
    assert again.get(public["id"]).call_count == 2


def test_touch_unknown_bot_is_harmless(store):
    store.touch("nope")
    assert store.total() == 0


# ---------------------------------------------------------------- 时间解析

def test_parse_when_formats():
    assert parse_when(None) is None
    assert parse_when("") is None
    assert parse_when("2026-10-20") > 0
    assert parse_when("2026-10-20 12:30:00") > parse_when("2026-10-20")
    assert parse_when(1_800_000_000) == 1_800_000_000
    assert parse_when("2026-10-20T12:30") > 0
    with pytest.raises(ValueError, match="时间格式"):
        parse_when("not-a-date")


# ---------------------------------------------------------------- 统一名册

def test_registry_static_tokens_are_unrestricted(store):
    store.create("phone")
    registry = TokenRegistry([("token-1", TOKEN_A)], store)
    identity = registry.resolve(TOKEN_A)
    assert identity is not None
    assert identity.source == "config"
    assert identity.unrestricted is True
    assert identity.allows("run_command") is True


def test_registry_finds_bot_and_carries_whitelist(store):
    public, token = store.create("phone", allow=["read_file"])
    registry = TokenRegistry([("token-1", TOKEN_A)], store)
    identity = registry.resolve(token)
    assert identity is not None
    assert identity.name == "phone" and identity.source == "bot"
    assert identity.bot_id == public["id"]
    assert identity.unrestricted is False
    assert identity.allows("read_file") is True
    assert identity.allows("run_command") is False


def test_registry_prefers_static_over_bot_on_collision(store):
    public, token = store.create("phone")
    registry = TokenRegistry([("static", token)], store)
    assert registry.resolve(token).source == "config"


def test_registry_unknown_and_empty(store):
    registry = TokenRegistry([("token-1", TOKEN_A)], store)
    assert registry.resolve("nope") is None
    assert registry.resolve("") is None


def test_registry_reports_disabled_status(store):
    public, token = store.create("phone")
    store.update(public["id"], {"enabled": False})
    identity = TokenRegistry([], store).resolve(token)
    assert identity is not None and identity.status == "disabled"


def test_registry_usable_covers_both_sources(store, tmp_path):
    empty = TokenRegistry([], store)
    assert empty.usable() is False
    store.create("phone")
    assert empty.usable() is True
    assert TokenRegistry([("a", TOKEN_A)], None).usable() is True


def test_registry_names_and_describe(store):
    store.create("phone", allow=["read_file"])
    registry = TokenRegistry([("token-1", TOKEN_A)], store)
    assert registry.names() == ["token-1", "phone"]
    rows = registry.describe()
    assert {r["source"] for r in rows} == {"config", "bot"}


def test_registry_refresh_static(store):
    registry = TokenRegistry([("old", TOKEN_A)], store)
    registry.refresh_static([("new", TOKEN_B)])
    assert registry.resolve(TOKEN_A) is None
    assert registry.resolve(TOKEN_B).name == "new"
