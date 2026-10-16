"""OAuth discovery documents: RFC 9728 (PRM), RFC 8414 (AS metadata), JWKS."""

from django.http import JsonResponse
from django.urls import reverse

from django_mcp_oauth import conf, keys


def protected_resource_metadata(request):
    """RFC 9728 — tells MCP clients which AS to use for this resource."""
    return JsonResponse(
        {
            "resource": conf.resource_url(),
            "authorization_servers": [conf.issuer()],
            "bearer_methods_supported": ["header"],
            "scopes_supported": [conf.scope()],
        }
    )


def authorization_server_metadata(request):
    """RFC 8414 — AS endpoints and capabilities."""
    base = conf.issuer()
    return JsonResponse(
        {
            "issuer": base,
            "authorization_endpoint": base + reverse("oauth-authorize"),
            "token_endpoint": base + reverse("oauth-token"),
            "registration_endpoint": base + reverse("oauth-register"),
            "jwks_uri": base + reverse("oauth-jwks"),
            "scopes_supported": [conf.scope()],
            "response_types_supported": ["code"],
            "grant_types_supported": [
                "authorization_code",
                "refresh_token",
                "client_credentials",
            ],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": [
                "none",
                "client_secret_basic",
                "client_secret_post",
            ],
        }
    )


def jwks(request):
    try:
        return JsonResponse(keys.build_jwks())
    except (RuntimeError, ValueError, TypeError):
        # RuntimeError: key not configured. ValueError/TypeError: malformed PEM
        # / key material. Return JSON either way so clients never get an HTML 500.
        return JsonResponse(
            {
                "error": "server_error",
                "error_description": "Signing key not configured or invalid.",
            },
            status=500,
        )
