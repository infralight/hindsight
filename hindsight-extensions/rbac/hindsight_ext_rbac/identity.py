"""Bearer credentials: opaque API tokens and OIDC ID tokens.

The control plane forwards the logged-in user's ID token; agents and bots send an
``hsp_`` API token. Nothing else in a request asserts identity.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import aiohttp
import jwt
from jwt import PyJWK

from hindsight_ext_rbac.store import TOKEN_PREFIX

_JWKS_TTL_SECONDS = 3600
_JWKS_MIN_REFRESH_SECONDS = 60
_HTTP_TIMEOUT_SECONDS = 10
# Google mints ID tokens with either form of its issuer.
_ISSUER_ALIASES = {"https://accounts.google.com": {"https://accounts.google.com", "accounts.google.com"}}


class CredentialError(Exception):
    """The credential does not identify anyone. The message is safe to return to the caller."""


@dataclass(frozen=True)
class OidcIdentity:
    email: str
    name: str


def is_api_token(credential: str) -> bool:
    return credential.startswith(TOKEN_PREFIX)


class OidcVerifier:
    def __init__(self, issuer: str, audiences: list[str], allowed_domains: list[str]) -> None:
        self._issuer = issuer.rstrip("/")
        self._accepted_issuers = _ISSUER_ALIASES.get(self._issuer, {self._issuer})
        self._audiences = audiences
        self._allowed_domains = {d.strip().lower() for d in allowed_domains}
        self._http: aiohttp.ClientSession | None = None
        self._jwks_uri: str | None = None
        self._keys: dict[str, PyJWK] = {}
        self._keys_fetched_at = 0.0

    async def start(self) -> None:
        self._http = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=_HTTP_TIMEOUT_SECONDS))

    async def close(self) -> None:
        if self._http is not None:
            await self._http.close()
            self._http = None

    async def _fetch_json(self, url: str) -> dict[str, Any]:
        if self._http is None:
            await self.start()
        assert self._http is not None
        async with self._http.get(url) as response:
            response.raise_for_status()
            return await response.json(content_type=None)

    async def _refresh_keys(self) -> None:
        jwks_uri = self._jwks_uri
        if jwks_uri is None:
            discovery = await self._fetch_json(f"{self._issuer}/.well-known/openid-configuration")
            jwks_uri = self._jwks_uri = str(discovery["jwks_uri"])
        jwks = await self._fetch_json(jwks_uri)
        keys: dict[str, PyJWK] = {}
        for data in jwks.get("keys", []):
            if data.get("kid") and data.get("kty") == "RSA":
                keys[data["kid"]] = PyJWK(data, algorithm="RS256")
        self._keys = keys
        self._keys_fetched_at = time.monotonic()

    async def _signing_key(self, kid: str) -> PyJWK:
        age = time.monotonic() - self._keys_fetched_at
        if not self._keys or age > _JWKS_TTL_SECONDS:
            await self._refresh_keys()
        elif kid not in self._keys and age > _JWKS_MIN_REFRESH_SECONDS:
            await self._refresh_keys()  # the issuer rotated its keys
        key = self._keys.get(kid)
        if key is None:
            raise CredentialError("Unknown signing key")
        return key

    async def verify(self, token: str) -> OidcIdentity:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as e:
            raise CredentialError("Malformed token") from e
        if header.get("alg") != "RS256" or not header.get("kid"):
            raise CredentialError("Unsupported token")
        try:
            key = await self._signing_key(header["kid"])
        except (aiohttp.ClientError, KeyError, TimeoutError) as e:
            raise CredentialError("Identity provider unavailable") from e
        try:
            claims = jwt.decode(
                token,
                key=key.key,
                algorithms=["RS256"],
                audience=self._audiences,
                options={"require": ["exp", "iss", "aud", "email"], "verify_iss": False},
            )
        except jwt.PyJWTError as e:
            raise CredentialError("Invalid token") from e
        if claims["iss"] not in self._accepted_issuers:
            raise CredentialError("Invalid token issuer")
        if claims.get("email_verified") not in (True, "true"):
            raise CredentialError("Email not verified")
        email = str(claims["email"]).strip().lower()
        domain = email.rpartition("@")[2]
        if domain not in self._allowed_domains:
            raise CredentialError("Email domain not allowed")
        return OidcIdentity(email=email, name=str(claims.get("name") or email))
