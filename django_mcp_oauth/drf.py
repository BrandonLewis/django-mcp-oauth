"""Django REST Framework authentication class (optional: ``[drf]`` extra)."""

from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from django_mcp_oauth.resource import user_from_bearer
from django_mcp_oauth.validation import TokenError


class OAuth2ResourceServerAuthentication(BaseAuthentication):
    """Validate an OAuth 2.1 bearer JWT minted by this server for DRF endpoints."""

    def authenticate(self, request):
        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        parts = auth_header.split(" ", 1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return None
        try:
            user, validated = user_from_bearer(parts[1])
        except TokenError as exc:
            raise AuthenticationFailed(exc.description)
        except RuntimeError:
            raise AuthenticationFailed("OAuth not configured.")
        return (user, validated)

    def authenticate_header(self, request):
        return "Bearer"
