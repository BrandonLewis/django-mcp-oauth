"""RSA key material for the authorization server.

The private key signs access tokens (RS256); the public half is published as
JWKS so the resource server validates without any shared secret.
"""

import base64
import functools

import jwt
from cryptography.hazmat.primitives import serialization
from django_mcp_oauth import conf


def get_private_key_pem() -> str:
    pem = conf.get("MCP_OAUTH_PRIVATE_KEY")
    if not pem:
        raise RuntimeError(
            "MCP_OAUTH_PRIVATE_KEY is not configured. Run "
            "`python manage.py generate_oauth_keys` and set the env var."
        )
    return pem


def get_key_id() -> str:
    return conf.get("MCP_OAUTH_KEY_ID")


@functools.lru_cache(maxsize=4)
def _load_public_key(pem: str):
    """Derive the RSA public key from a private-key PEM.

    Cached on the PEM string so request-path callers (``build_jwks`` in a
    resource server's auth path) don't reparse the key every time. Keying on
    the PEM keeps it correct under ``override_settings`` and across key
    rotation — a new PEM is a new cache entry.
    """
    private = serialization.load_pem_private_key(pem.encode(), password=None)
    return private.public_key()


def _public_key():
    return _load_public_key(get_private_key_pem())


def _b64u_uint(value: int) -> str:
    length = (value.bit_length() + 7) // 8 or 1
    return base64.urlsafe_b64encode(value.to_bytes(length, "big")).rstrip(b"=").decode()


def build_jwks() -> dict:
    """Public-only JWKS document (RFC 7517)."""
    numbers = _public_key().public_numbers()
    return {
        "keys": [
            {
                "kty": "RSA",
                "n": _b64u_uint(numbers.n),
                "e": _b64u_uint(numbers.e),
                "use": "sig",
                "alg": "RS256",
                "kid": get_key_id(),
            }
        ]
    }


def sign_jwt(claims: dict) -> str:
    return jwt.encode(
        claims,
        get_private_key_pem(),
        algorithm="RS256",
        headers={"kid": get_key_id()},
    )
