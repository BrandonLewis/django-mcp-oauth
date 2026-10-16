"""Resource-server helpers: resolve a bearer token to a user, and build the
RFC 6750 / RFC 9728 ``WWW-Authenticate`` challenge a 401 must carry.

Framework-agnostic strings and plain functions, so an ASGI middleware
(Starlette / the MCP SDK transport), a DRF authentication class
(:mod:`django_mcp_oauth.drf`) or a plain Django view can all share them.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError

from django_mcp_oauth import conf, keys
from django_mcp_oauth.validation import (
    TokenError,
    ValidatedToken,
    validate_access_token,
)


def resource_metadata_url() -> str:
    """Protected Resource Metadata URL for THIS resource server.

    Derived from the resource origin (``MCP_RESOURCE_URL``) rather than the
    authorization-server issuer, so the ``WWW-Authenticate`` pointer stays
    correct even when the issuer is on a different origin than the resource.
    """
    parts = urlsplit(conf.resource_url())
    return f"{parts.scheme}://{parts.netloc}/.well-known/oauth-protected-resource"


def hdr_quote(value: str) -> str:
    """Make *value* safe inside a quoted-string ``WWW-Authenticate`` auth-param.

    Escapes backslashes and double-quotes and strips CR/LF, so a description
    propagated from a third-party error message cannot break the header or
    inject additional content.
    """
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\r", " ").replace("\n", " ")


def www_authenticate(error: str = "invalid_token", description: str = "", *, include_error: bool = True) -> str:
    """The ``WWW-Authenticate`` header value for a 401.

    When *include_error* is False (credentials were absent entirely) the header
    MUST NOT carry an ``error`` parameter (RFC 6750 §3.1); it still points at
    the protected-resource metadata so an MCP client can discover the AS.
    """
    metadata_url = resource_metadata_url()
    if not include_error:
        return f'Bearer resource_metadata="{metadata_url}"'
    params = f'Bearer error="{hdr_quote(error)}", resource_metadata="{metadata_url}"'
    if description:
        params += f', error_description="{hdr_quote(description)}"'
    return params


def validate_bearer(token: str) -> ValidatedToken:
    """Validate a self-issued access token against this server's settings."""
    return validate_access_token(
        token,
        expected_audience=conf.resource_url(),
        expected_issuer=conf.issuer(),
        jwks=keys.build_jwks(),
        required_scope=conf.scope(),
    )


def user_from_bearer(token: str):
    """Validate *token* and resolve it to the bound, active Django user.

    Returns ``(user, validated)``. Raises :class:`TokenError` for a bad token
    and for a subject that is missing, inactive or not a valid primary key —
    the same ``invalid_token`` answer for all three, so the response does not
    reveal which accounts exist.
    """
    validated = validate_bearer(token)
    User = get_user_model()
    try:
        user = User.objects.filter(pk=validated.subject).first()
    except (ValueError, TypeError, ValidationError):
        user = None
    if user is None or not user.is_active:
        raise TokenError("Token subject not found.")
    return user, validated
