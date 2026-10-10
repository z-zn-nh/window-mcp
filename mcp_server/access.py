"""Cloudflare Access JWT 校验（面板的第二道门）。

Cloudflare Access 在放行请求时会加一个头 ``Cf-Access-Jwt-Assertion``（也放在
``CF_Authorization`` cookie 里）。那个 JWT 是 RS256 签名的，**必须验签**——
只解析 payload 等于没校验：任何人自己造一个 ``{"email": "..."}`` 就能过。

这里做的事：
1. 从 ``https://<team>.cloudflareaccess.com/cdn-cgi/access/certs`` 拉 JWKS（缓存 + 落盘，
   离线也能用上次的键），按 ``kid`` 找公钥；
2. 用 ``cryptography`` 做 RS256 验签（**拒绝 ``alg: none`` / HS256**）；
3. 校验 ``aud``（Access 应用的 AUD 标签）、``iss``、``exp`` / ``nbf`` / ``iat``；
4. 校验 ``email`` 在允许名单里。

不依赖 PyJWT：只用 ``cryptography``，少一个依赖，行为也更可控（测试里可以完全离线地
自己造一对 RSA 密钥 + 自签 JWT 来验证）。
"""

from __future__ import annotations

import base64
import json
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

CERT_PATH = "/cdn-cgi/access/certs"
DEFAULT_LEEWAY = 120.0     # 时钟偏差容忍（本机时钟被「时间穿越」过，留宽一点）
DEFAULT_TTL = 3600.0       # JWKS 缓存 1 小时
MAX_TOKEN_LEN = 8192


class AccessError(Exception):
    """校验失败。消息会进日志，**不含 token 本身**。"""


@dataclass
class AccessIdentity:
    email: str
    sub: str = ""
    aud: tuple[str, ...] = ()
    kind: str = ""
    exp: float = 0.0
    issuer: str = ""


def _b64d(segment: str) -> bytes:
    pad = "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(segment + pad)
    except Exception as exc:
        raise AccessError(f"base64 解码失败：{type(exc).__name__}") from exc


def _json_seg(segment: str, what: str) -> dict:
    try:
        data = json.loads(_b64d(segment).decode("utf-8"))
    except Exception as exc:
        raise AccessError(f"{what} 不是合法 JSON：{type(exc).__name__}") from exc
    if not isinstance(data, dict):
        raise AccessError(f"{what} 不是 JSON 对象")
    return data


def _norm_team(team: str) -> str:
    """把 ``xxx.cloudflareaccess.com`` / ``https://xxx.cloudflareaccess.com`` 归一成 host。"""
    text = str(team or "").strip().rstrip("/")
    if not text:
        return ""
    if "://" in text:
        text = text.split("://", 1)[1]
    return text.split("/", 1)[0].strip()


def _public_key_from_jwk(jwk: dict):
    if str(jwk.get("kty", "")).upper() != "RSA":
        raise AccessError(f"JWKS 里的密钥不是 RSA（kty={jwk.get('kty')!r}）")
    try:
        n = int.from_bytes(_b64d(str(jwk["n"])), "big")
        e = int.from_bytes(_b64d(str(jwk["e"])), "big")
    except KeyError as exc:
        raise AccessError(f"JWKS 缺少字段：{exc}") from exc
    return rsa.RSAPublicNumbers(e, n).public_key()


class AccessVerifier:
    """验签 + 校验声明。``configured()`` 为假时调用方应跳过 Access 这道门。"""

    def __init__(self, team: str = "", aud: str | list[str] = "",
                 emails: list[str] | None = None,
                 jwks: list[dict] | None = None,
                 jwks_file: str | Path = "",
                 cache_file: str | Path = "",
                 leeway: float = DEFAULT_LEEWAY,
                 cache_ttl: float = DEFAULT_TTL,
                 timeout: float = 10.0) -> None:
        self.team = _norm_team(team)
        if isinstance(aud, str):
            auds = [aud] if aud.strip() else []
        else:
            auds = [str(x).strip() for x in (aud or []) if str(x).strip()]
        self.auds = tuple(auds)
        self.emails = tuple(str(e).strip().lower() for e in (emails or [])
                            if str(e).strip())
        self._jwks_override = jwks
        self.jwks_file = Path(jwks_file) if jwks_file else None
        self.cache_file = Path(cache_file) if cache_file else None
        self.leeway = float(leeway)
        self.cache_ttl = float(cache_ttl)
        self.timeout = float(timeout)

        self._keys: dict[str, object] = {}
        self._fetched_at = 0.0
        self._lock = threading.Lock()
        self.last_error = ""

    # ------------------------------------------------------------ 状态

    def configured(self) -> bool:
        """team + aud 都有才算配好。缺一个就当作「没开 Access 这道门」。"""
        return bool(self.team and self.auds)

    @property
    def issuer(self) -> str:
        return f"https://{self.team}" if self.team else ""

    def status(self) -> dict:
        return {
            "configured": self.configured(),
            "team": self.team,
            "aud_count": len(self.auds),
            "emails": list(self.emails),
            "keys": len(self._keys),
            "keys_age_s": (int(time.time() - self._fetched_at)
                           if self._fetched_at else None),
            "last_error": self.last_error,
        }

    # ------------------------------------------------------------ 取键

    def _load_jwks(self, force: bool = False) -> None:
        """把 JWKS 装进内存。三级来源：显式注入 > 本地文件 > 网络。"""
        with self._lock:
            fresh = (self._keys and time.time() - self._fetched_at < self.cache_ttl)
            if fresh and not force:
                return
            keys: list[dict] | None = None
            source = ""

            if self._jwks_override is not None:
                keys, source = list(self._jwks_override), "override"
            elif self.jwks_file is not None:
                keys, source = self._read_jwks_file(self.jwks_file), str(self.jwks_file)
            else:
                try:
                    keys, source = self._fetch_jwks(), "network"
                except Exception as exc:
                    self.last_error = f"JWKS 拉取失败：{type(exc).__name__}: {exc}"
                    # 网络不行就退回上次落盘的键，至少不是直接锁死
                    if self.cache_file is not None:
                        cached = self._read_jwks_file(self.cache_file, quiet=True)
                        if cached:
                            keys, source = cached, str(self.cache_file)

            if not keys:
                if not self._keys:
                    raise AccessError(self.last_error or "拿不到 JWKS，无法验签")
                return

            mapping: dict[str, object] = {}
            for jwk in keys:
                if not isinstance(jwk, dict):
                    continue
                kid = str(jwk.get("kid") or "")
                try:
                    mapping[kid] = _public_key_from_jwk(jwk)
                except AccessError:
                    continue
            if not mapping:
                raise AccessError("JWKS 里没有可用的 RSA 公钥")
            self._keys = mapping
            self._fetched_at = time.time()
            self.last_error = ""
            self._source = source
            if source == "network" and self.cache_file is not None:
                self._write_cache(keys)

    @staticmethod
    def _read_jwks_file(path: Path, quiet: bool = False) -> list[dict] | None:
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if isinstance(data, dict):
            data = data.get("keys")
        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]
        return None

    def _fetch_jwks(self) -> list[dict]:
        import httpx

        url = f"https://{self.team}{CERT_PATH}"
        with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
            resp = client.get(url, headers={"accept": "application/json"})
        resp.raise_for_status()
        data = resp.json()
        keys = data.get("keys") if isinstance(data, dict) else data
        if not isinstance(keys, list) or not keys:
            raise AccessError("JWKS 响应里没有 keys")
        return [x for x in keys if isinstance(x, dict)]

    def _write_cache(self, keys: list[dict]) -> None:
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.cache_file.with_suffix(self.cache_file.suffix + ".tmp")
            tmp.write_text(json.dumps({"keys": keys}, ensure_ascii=False),
                           encoding="utf-8")
            import os
            os.replace(tmp, self.cache_file)
        except OSError:
            pass

    def _key_for(self, kid: str):
        self._load_jwks()
        key = self._keys.get(kid) if kid else None
        if key is None:
            # 未知 kid：Cloudflare 可能刚轮换过签名密钥，强制刷新一次再找
            try:
                self._load_jwks(force=True)
            except AccessError:
                pass
            key = self._keys.get(kid) if kid else None
        if key is None and not kid and len(self._keys) == 1:
            key = next(iter(self._keys.values()))
        if key is None:
            raise AccessError("JWKS 里找不到该 kid 对应的公钥")
        return key

    # ------------------------------------------------------------ 校验

    def verify(self, token: str) -> AccessIdentity:
        if not self.configured():
            raise AccessError("未配置 Cloudflare Access（缺 team 或 aud）")
        text = str(token or "").strip()
        if not text:
            raise AccessError("缺少 Access JWT")
        if len(text) > MAX_TOKEN_LEN:
            raise AccessError("Access JWT 过长，拒绝")

        parts = text.split(".")
        if len(parts) != 3:
            raise AccessError("Access JWT 结构不对（不是三段）")
        header = _json_seg(parts[0], "JWT 头")
        payload = _json_seg(parts[1], "JWT 载荷")

        alg = str(header.get("alg") or "")
        if alg.upper() != "RS256":
            # 关键：拒绝 none / HS256 —— 否则「alg 混淆」可以直接伪造身份
            raise AccessError(f"签名算法不接受：{alg!r}（只接受 RS256）")

        kid = str(header.get("kid") or "")
        public_key = self._key_for(kid)
        signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
        try:
            public_key.verify(_b64d(parts[2]), signing_input,
                              padding.PKCS1v15(), hashes.SHA256())
        except InvalidSignature as exc:
            raise AccessError("Access JWT 签名验证失败") from exc
        except Exception as exc:
            raise AccessError(f"Access JWT 验签异常：{type(exc).__name__}") from exc

        now = time.time()
        exp = payload.get("exp")
        if exp is None:
            raise AccessError("Access JWT 没有 exp")
        try:
            exp_f = float(exp)
        except (TypeError, ValueError) as exc:
            raise AccessError("Access JWT 的 exp 不是数字") from exc
        if now > exp_f + self.leeway:
            raise AccessError("Access JWT 已过期")

        nbf = payload.get("nbf")
        if nbf is not None:
            try:
                if now + self.leeway < float(nbf):
                    raise AccessError("Access JWT 还没生效（nbf）")
            except (TypeError, ValueError):
                raise AccessError("Access JWT 的 nbf 不是数字") from None

        iss = str(payload.get("iss") or "")
        if self.issuer and iss.rstrip("/") != self.issuer:
            raise AccessError("Access JWT 的 iss 不匹配")

        raw_aud = payload.get("aud")
        if isinstance(raw_aud, str):
            auds = (raw_aud,)
        elif isinstance(raw_aud, list):
            auds = tuple(str(x) for x in raw_aud)
        else:
            auds = ()
        if not set(self.auds) & set(auds):
            raise AccessError("Access JWT 的 aud 不匹配（不是本应用的标签）")

        email = str(payload.get("email") or "").strip().lower()
        if self.emails:
            if not email:
                raise AccessError("Access JWT 里没有 email")
            if email not in self.emails:
                raise AccessError("该邮箱不在允许名单里")

        return AccessIdentity(
            email=email or str(payload.get("sub") or ""),
            sub=str(payload.get("sub") or ""),
            aud=auds,
            kind=str(payload.get("type") or ""),
            exp=exp_f,
            issuer=iss,
        )


def extract_token(headers: dict[str, str], cookies: dict[str, str]) -> str:
    """从请求头 / cookie 里取 Access JWT。头优先（cookie 可能被别的应用覆盖）。"""
    for key in ("cf-access-jwt-assertion", "cf_access_jwt_assertion"):
        value = headers.get(key)
        if value:
            return value.strip()
    for key in ("CF_Authorization", "cf_authorization"):
        value = cookies.get(key)
        if value:
            return value.strip()
    return ""
