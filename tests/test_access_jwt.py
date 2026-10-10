"""Cloudflare Access JWT 校验的单测。

完全离线：自己生成一对 RSA 密钥、自己造 JWKS、自己签 JWT，
所以既能测「正常放行」，也能测每一种**必须拒绝**的情况
（改 aud / 过期 / 签名不对 / alg=none / 邮箱不在名单里）。

「必须拒绝」比「正常放行」重要：Access 这道门要是能绕过去，
面板就等于挂在公网上。
"""

from __future__ import annotations

import base64
import json
import time

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from mcp_server.access import (
    AccessError,
    AccessVerifier,
    _norm_team,
    extract_token,
)

TEAM = "window-mcp-test.cloudflareaccess.com"
ISSUER = f"https://{TEAM}"
AUD = "aud-tag-0123456789abcdef"
EMAIL = "admin@example.com"
KID = "kid-1"


# ---------------------------------------------------------------- 造钥匙

def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _int_bytes(value: int) -> bytes:
    return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")


def _jwk(public_key, kid: str = KID) -> dict:
    nums = public_key.public_numbers()
    return {
        "kty": "RSA",
        "kid": kid,
        "alg": "RS256",
        "use": "sig",
        "n": _b64u(_int_bytes(nums.n)),
        "e": _b64u(_int_bytes(nums.e)),
    }


@pytest.fixture(scope="module")
def keys():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private, private.public_key()


def make_token(private_key, claims: dict | None = None, *,
               kid: str = KID, alg: str = "RS256",
               header_extra: dict | None = None, sign_with=None) -> str:
    now = int(time.time())
    payload = {
        "aud": AUD,
        "iss": ISSUER,
        "email": EMAIL,
        "sub": "user-sub-1",
        "type": "app",
        "iat": now - 10,
        "nbf": now - 10,
        "exp": now + 3600,
    }
    payload.update(claims or {})
    header = {"alg": alg, "typ": "JWT", "kid": kid}
    header.update(header_extra or {})
    signing_input = (
        f"{_b64u(json.dumps(header).encode())}."
        f"{_b64u(json.dumps(payload).encode())}"
    )
    if alg == "RS256":
        key = sign_with or private_key
        signature = key.sign(signing_input.encode("ascii"),
                             padding.PKCS1v15(), hashes.SHA256())
        return signing_input + "." + _b64u(signature)
    if alg == "none":
        return signing_input + "."
    return signing_input + "." + _b64u(b"not-a-real-signature")


def verifier(keys, **over) -> AccessVerifier:
    _, public = keys
    kwargs = dict(team=TEAM, aud=AUD, emails=[EMAIL], jwks=[_jwk(public)])
    kwargs.update(over)
    return AccessVerifier(**kwargs)


# ---------------------------------------------------------------- 正常路径

def test_valid_token_passes(keys):
    ver = verifier(keys)
    assert ver.configured() is True
    identity = ver.verify(make_token(keys[0]))
    assert identity.email == EMAIL
    assert identity.sub == "user-sub-1"
    assert identity.aud == (AUD,)
    assert identity.kind == "app"
    assert identity.issuer == ISSUER


def test_aud_as_list_is_accepted(keys):
    ver = verifier(keys)
    token = make_token(keys[0], {"aud": ["other-app", AUD]})
    assert ver.verify(token).email == EMAIL


def test_multiple_configured_auds(keys):
    ver = verifier(keys, aud=[AUD, "another"])
    assert ver.verify(make_token(keys[0])).email == EMAIL


def test_team_normalization(keys):
    assert _norm_team("https://x.cloudflareaccess.com/") == "x.cloudflareaccess.com"
    assert _norm_team("x.cloudflareaccess.com") == "x.cloudflareaccess.com"
    assert _norm_team("") == ""
    ver = verifier(keys, team="https://" + TEAM + "/")
    assert ver.verify(make_token(keys[0])).email == EMAIL


def test_jwks_from_file(keys, tmp_path):
    path = tmp_path / "jwks.json"
    path.write_text(json.dumps({"keys": [_jwk(keys[1])]}), encoding="utf-8")
    ver = AccessVerifier(team=TEAM, aud=AUD, emails=[EMAIL], jwks_file=path)
    assert ver.verify(make_token(keys[0])).email == EMAIL


def test_empty_email_allowlist_accepts_any(keys):
    ver = verifier(keys, emails=[])
    assert ver.verify(make_token(keys[0])).email == EMAIL


# ---------------------------------------------------------------- 必须拒绝

def test_rejects_wrong_aud(keys):
    ver = verifier(keys)
    with pytest.raises(AccessError, match="aud"):
        ver.verify(make_token(keys[0], {"aud": "someone-elses-app"}))


def test_rejects_missing_aud(keys):
    ver = verifier(keys)
    with pytest.raises(AccessError, match="aud"):
        ver.verify(make_token(keys[0], {"aud": None}))


def test_rejects_expired(keys):
    ver = verifier(keys)
    with pytest.raises(AccessError, match="过期"):
        ver.verify(make_token(keys[0], {"exp": int(time.time()) - 3600}))


def test_rejects_not_yet_valid(keys):
    ver = verifier(keys)
    with pytest.raises(AccessError, match="nbf"):
        ver.verify(make_token(keys[0], {"nbf": int(time.time()) + 3600}))


def test_rejects_wrong_issuer(keys):
    ver = verifier(keys)
    with pytest.raises(AccessError, match="iss"):
        ver.verify(make_token(keys[0], {"iss": "https://evil.example.com"}))


def test_rejects_missing_exp(keys):
    ver = verifier(keys)
    token = make_token(keys[0], {"exp": None})
    with pytest.raises(AccessError, match="exp"):
        ver.verify(token)


def test_rejects_alg_none(keys):
    """alg=none 是 JWT 最经典的伪造手法，必须直接拒。"""
    ver = verifier(keys)
    with pytest.raises(AccessError, match="RS256"):
        ver.verify(make_token(keys[0], alg="none"))


def test_rejects_alg_hs256(keys):
    """alg 混淆：拿公钥当 HMAC 密钥来签。也必须拒。"""
    ver = verifier(keys)
    with pytest.raises(AccessError, match="RS256"):
        ver.verify(make_token(keys[0], alg="HS256"))


def test_rejects_bad_signature(keys):
    """用另一把私钥签名：内容全对，签名不对，必须拒。"""
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ver = verifier(keys)
    with pytest.raises(AccessError, match="签名"):
        ver.verify(make_token(other))


def test_rejects_tampered_payload(keys):
    """签名合法，但把 payload 换掉（改邮箱）——签名就对不上了。"""
    ver = verifier(keys)
    good = make_token(keys[0])
    header, payload, signature = good.split(".")
    payload = _b64u(json.dumps({
        "aud": AUD, "iss": ISSUER, "email": "attacker@example.com",
        "exp": int(time.time()) + 3600,
    }).encode())
    with pytest.raises(AccessError, match="签名"):
        ver.verify(f"{header}.{payload}.{signature}")


def test_rejects_unknown_kid(keys):
    ver = verifier(keys)
    token = make_token(keys[0], kid="kid-does-not-exist")
    with pytest.raises(AccessError, match="kid"):
        ver.verify(token)


def test_rejects_email_not_allowed(keys):
    ver = verifier(keys, emails=["someone-else@example.com"])
    with pytest.raises(AccessError, match="邮箱"):
        ver.verify(make_token(keys[0]))


def test_rejects_missing_email_when_allowlist_set(keys):
    ver = verifier(keys)
    with pytest.raises(AccessError, match="email"):
        ver.verify(make_token(keys[0], {"email": None}))


def test_rejects_malformed_tokens(keys):
    ver = verifier(keys)
    for bad in ("", "not-a-jwt", "a.b", "a.b.c.d", "...."):
        with pytest.raises(AccessError):
            ver.verify(bad)


def test_rejects_oversized_token(keys):
    ver = verifier(keys)
    with pytest.raises(AccessError, match="过长"):
        ver.verify("x" * 9000)


def test_not_configured_when_aud_missing(keys):
    ver = verifier(keys, aud="")
    assert ver.configured() is False
    with pytest.raises(AccessError, match="未配置"):
        ver.verify(make_token(keys[0]))


def test_not_configured_when_team_missing(keys):
    ver = verifier(keys, team="")
    assert ver.configured() is False
    with pytest.raises(AccessError, match="未配置"):
        ver.verify(make_token(keys[0]))


def test_rejects_non_rsa_jwk(keys):
    ver = verifier(keys, jwks=[{"kty": "EC", "kid": KID, "n": "AA", "e": "AQAB"}])
    with pytest.raises(AccessError):
        ver.verify(make_token(keys[0]))


# ---------------------------------------------------------------- 取 token

def test_extract_token_prefers_header():
    headers = {"cf-access-jwt-assertion": "header-token"}
    cookies = {"CF_Authorization": "cookie-token"}
    assert extract_token(headers, cookies) == "header-token"


def test_extract_token_falls_back_to_cookie():
    assert extract_token({}, {"CF_Authorization": "cookie-token"}) == "cookie-token"


def test_extract_token_absent():
    assert extract_token({}, {}) == ""


# ---------------------------------------------------------------- 状态

def test_status_reports_keys(keys):
    ver = verifier(keys)
    ver.verify(make_token(keys[0]))
    status = ver.status()
    assert status["configured"] is True
    assert status["keys"] == 1
    assert status["emails"] == [EMAIL]
    assert status["last_error"] == ""
