"""Resource-server access-token validation.

Pure and synchronous: given a token and the parameters to check it against,
either return a ValidatedToken or raise TokenError. No Django request objects,
so it is trivially unit-testable and reusable from an ASGI middleware, a DRF
authentication class, or anything else.
"""

import json
from dataclasses import dataclass

import jwt
from jwt.algorithms import RSAAlgorithm


class TokenError(Exception):
    def __init__(self, description: str, error: str = "invalid_token"):
        super().__init__(description)
        self.error = error
        self.description = description


@dataclass
class ValidatedToken:
    subject: str
    scopes: list
    claims: dict


def _key_for(token: str, jwks: dict):
    header = jwt.get_unverified_header(token)
    kid = header.get("kid")
    if kid is None:
        raise TokenError("Token header missing 'kid'.")
    for jwk in jwks.get("keys", []):
        if jwk.get("kid") == kid:
            return RSAAlgorithm.from_jwk(json.dumps(jwk))
    raise TokenError("No matching signing key for token 'kid'.")


def validate_access_token(
    token,
    *,
    expected_audience,
    expected_issuer,
    jwks,
    required_scope,
):
    if not token:
        raise TokenError("Missing bearer token.")
    try:
        key = _key_for(token, jwks)
        claims = jwt.decode(
            token,
            key=key,
            algorithms=["RS256"],
            audience=expected_audience,
            issuer=expected_issuer,
            options={"require": ["exp", "iss", "aud", "sub"]},
        )
    except TokenError:
        raise
    except (jwt.PyJWTError, ValueError, TypeError) as exc:
        raise TokenError(f"Token validation failed: {exc}") from exc

    scope_claim = claims.get("scope")
    if isinstance(scope_claim, list | tuple):
        scopes = list(scope_claim)
    else:
        scopes = str(scope_claim or "").split()
    if required_scope not in scopes:
        raise TokenError(
            f"Token missing required scope '{required_scope}'.",
            error="insufficient_scope",
        )
    return ValidatedToken(subject=str(claims["sub"]), scopes=scopes, claims=claims)
