"""OIDC ID-token verification: only a token the configured issuer signed, for our
client, about a verified email in an allowed domain, identifies a user."""

import base64
import hashlib
import hmac
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from hindsight_ext_rbac.identity import CredentialError, OidcIdentity, OidcVerifier, is_api_token

ISSUER = "https://accounts.google.com"
CLIENT = "client-123.apps.googleusercontent.com"
DISCOVERY = f"{ISSUER}/.well-known/openid-configuration"
JWKS_URI = "https://www.googleapis.com/oauth2/v3/certs"

_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwk(key, kid: str) -> dict:
    data = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    return {**data, "kid": kid, "alg": "RS256", "use": "sig"}


def _claims(**overrides) -> dict:
    now = int(time.time())
    return {
        "iss": ISSUER,
        "aud": CLIENT,
        "sub": "1234",
        "email": "a@firefly.ai",
        "email_verified": True,
        "name": "A",
        "iat": now,
        "exp": now + 600,
        **overrides,
    }


def _token(claims: dict | None = None, key=_KEY, kid: str = "k1") -> str:
    return jwt.encode(claims or _claims(), key, algorithm="RS256", headers={"kid": kid})


@pytest.fixture
def verifier(monkeypatch):
    v = OidcVerifier(issuer=ISSUER, audiences=[CLIENT], allowed_domains=["firefly.ai"])
    calls: list[str] = []

    async def fake_fetch(url: str) -> dict:
        calls.append(url)
        if url == DISCOVERY:
            return {"issuer": ISSUER, "jwks_uri": JWKS_URI}
        if url == JWKS_URI:
            return {"keys": [_jwk(_KEY, "k1")]}
        raise AssertionError(url)

    monkeypatch.setattr(v, "_fetch_json", fake_fetch)
    v.fetches = calls  # type: ignore[attr-defined]
    return v


async def test_valid_token(verifier):
    assert await verifier.verify(_token()) == OidcIdentity(email="a@firefly.ai", name="A")


async def test_google_scheme_less_issuer_is_accepted(verifier):
    assert (await verifier.verify(_token(_claims(iss="accounts.google.com")))).email == "a@firefly.ai"


async def test_email_is_lowercased(verifier):
    assert (await verifier.verify(_token(_claims(email="A.B@Firefly.AI")))).email == "a.b@firefly.ai"


@pytest.mark.parametrize(
    "claims",
    [
        pytest.param(_claims(aud="someone-else"), id="wrong-audience"),
        pytest.param(_claims(iss="https://evil.example"), id="wrong-issuer"),
        pytest.param(_claims(exp=int(time.time()) - 10), id="expired"),
        pytest.param(_claims(email_verified=False), id="unverified-email"),
        pytest.param(_claims(email="x@evil.com"), id="foreign-domain"),
        pytest.param(_claims(email="x@firefly.ai.evil.com"), id="domain-suffix-trick"),
        pytest.param({k: v for k, v in _claims().items() if k != "email"}, id="no-email"),
    ],
)
async def test_rejected_claims(verifier, claims):
    with pytest.raises(CredentialError):
        await verifier.verify(_token(claims))


async def test_signed_by_another_key(verifier):
    with pytest.raises(CredentialError):
        await verifier.verify(_token(key=_OTHER_KEY))


async def test_hs256_with_public_key_as_secret_is_rejected(verifier):
    """Algorithm confusion: an HMAC token keyed with the (public) RSA key must not verify."""

    def b64(data: bytes) -> bytes:
        return base64.urlsafe_b64encode(data).rstrip(b"=")

    header = b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": "k1"}).encode())
    payload = b64(json.dumps(_claims()).encode())
    pem = _KEY.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    sig = b64(hmac.new(pem, header + b"." + payload, hashlib.sha256).digest())
    with pytest.raises(CredentialError):
        await verifier.verify((header + b"." + payload + b"." + sig).decode())


async def test_unknown_kid_refetches_once_then_fails(verifier):
    await verifier.verify(_token())  # warm the key cache
    verifier._keys_fetched_at -= 61  # past the refetch cooldown, inside the TTL
    with pytest.raises(CredentialError):
        await verifier.verify(_token(kid="rotated"))
    with pytest.raises(CredentialError):
        await verifier.verify(_token(kid="rotated"))
    # initial fetch + one refetch for the unknown kid; the second miss is inside the cooldown
    assert verifier.fetches.count(JWKS_URI) == 2


async def test_garbage_is_rejected(verifier):
    with pytest.raises(CredentialError):
        await verifier.verify("not-a-jwt")


def test_is_api_token():
    assert is_api_token("hsp_abc")
    assert not is_api_token("eyJhbGciOi.x.y")
    assert not is_api_token("")
