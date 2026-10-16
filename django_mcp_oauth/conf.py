"""Settings for django-mcp-oauth, read live so ``override_settings`` works.

Required:
    MCP_OAUTH_ISSUER       the authorization server's origin (``iss``), e.g.
                           ``https://example.com``
    MCP_RESOURCE_URL       the MCP resource server's URL (``aud``), e.g.
                           ``https://example.com/mcp``
    MCP_OAUTH_PRIVATE_KEY  RSA private key PEM that signs access tokens
                           (``manage.py generate_oauth_keys`` makes one)

Optional (defaults below):
    MCP_OAUTH_KEY_ID             ``kid`` published in JWKS and token headers
    MCP_OAUTH_SCOPE              the one scope the resource server requires
    MCP_OAUTH_ACCESS_TOKEN_TTL   seconds
    MCP_OAUTH_REFRESH_GRACE      seconds a just-rotated refresh token is still
                                 accepted (agents sharing a connection race on
                                 refresh); 0 disables the grace
    MCP_OAUTH_AUTHORIZE_USER     dotted path to ``callable(user) -> bool``: may
                                 this signed-in user authorize an MCP client?
                                 Default: any active account.
    MCP_OAUTH_CONSENT_TEMPLATE   template rendered on GET /oauth/authorize with
                                 ``grant``, ``client`` and ``scope`` in context
"""

from __future__ import annotations

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils.module_loading import import_string

DEFAULTS = {
    "MCP_OAUTH_KEY_ID": "mcp-oauth-1",
    "MCP_OAUTH_PRIVATE_KEY": "",
    "MCP_OAUTH_SCOPE": "mcp",
    "MCP_OAUTH_ACCESS_TOKEN_TTL": 3600,
    "MCP_OAUTH_REFRESH_GRACE": 60,
    "MCP_OAUTH_AUTHORIZE_USER": "django_mcp_oauth.conf.default_authorize_user",
    "MCP_OAUTH_CONSENT_TEMPLATE": "mcp_oauth/consent.html",
}


def get(name: str):
    return getattr(settings, name, DEFAULTS[name])


def _required(name: str) -> str:
    value = getattr(settings, name, None)
    if not value:
        raise ImproperlyConfigured(f"{name} is not configured.")
    return value


def issuer() -> str:
    return _required("MCP_OAUTH_ISSUER").rstrip("/")


def resource_url() -> str:
    return _required("MCP_RESOURCE_URL").rstrip("/")


def scope() -> str:
    return get("MCP_OAUTH_SCOPE")


def access_token_ttl() -> int:
    return int(get("MCP_OAUTH_ACCESS_TOKEN_TTL"))


def refresh_grace() -> int:
    return int(get("MCP_OAUTH_REFRESH_GRACE"))


def consent_template() -> str:
    return get("MCP_OAUTH_CONSENT_TEMPLATE")


def default_authorize_user(user) -> bool:
    """The default gate: any signed-in, active account may authorize a client."""
    return bool(user and user.is_authenticated and user.is_active)


def authorize_user(user) -> bool:
    """Run the product's gate (``MCP_OAUTH_AUTHORIZE_USER``) on *user*."""
    target = get("MCP_OAUTH_AUTHORIZE_USER")
    fn = import_string(target) if isinstance(target, str) else target
    return bool(fn(user))
