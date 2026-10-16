import secrets
import time

from authlib.integrations.django_oauth2 import AuthorizationServer
from authlib.oauth2.rfc7591 import ClientRegistrationEndpoint
from django_mcp_oauth import conf, keys
from django_mcp_oauth.grants import (
    PKCE_REQUIRED,
    AuthorizationCodeGrant,
    ClientCredentialsGrant,
    RefreshTokenGrant,
)
from django_mcp_oauth.models import OAuth2Client, OAuth2Token, hash_client_secret


def generate_access_token(client, grant_type, user, scope):
    """Mint an RS256 JWT access token bound to this resource server's audience."""
    now = int(time.time())
    claims = {
        "iss": conf.issuer(),
        "aud": conf.resource_url(),
        "sub": str(user.pk) if user is not None else client.client_id,
        "scope": scope or "",
        "client_id": client.client_id,
        "jti": secrets.token_urlsafe(16),
        "iat": now,
        "exp": now + conf.access_token_ttl(),
    }
    return keys.sign_jwt(claims)


def _bearer_token_generator(
    grant_type,
    client,
    user=None,
    scope=None,
    expires_in=None,
    include_refresh_token=True,
):
    """Full token dict generator for Authlib's AuthorizationServer."""
    # Clamp the requested scope to the client's registered allowed scope so no
    # grant type can issue a token with more scope than the client was
    # registered for. When no scope is requested (RFC 6749 allows it), default
    # to the client's full registered scope — otherwise the minted token would
    # carry an empty scope and be rejected by the resource server's
    # required-scope check, making it unusable by default.
    if client is not None:
        requested = scope or client.scope
        allowed = client.get_allowed_scope(requested)
    else:
        allowed = scope or ""
    access_token = generate_access_token(client=client, grant_type=grant_type, user=user, scope=allowed)
    expires_in = conf.access_token_ttl()

    token = {
        "token_type": "Bearer",
        "access_token": access_token,
        "expires_in": expires_in,
        "scope": allowed,
    }
    if include_refresh_token:
        token["refresh_token"] = secrets.token_urlsafe(48)
    return token


class ClientRegistration(ClientRegistrationEndpoint):
    """RFC 7591 Dynamic Client Registration endpoint.

    Open registration (no initial access token required) — acceptable for the
    public MCP client flow; clients are still gated at /oauth/authorize by the
    product's ``MCP_OAUTH_AUTHORIZE_USER`` check. Tighten by requiring an
    initial access token here if abuse appears.
    """

    def authenticate_token(self, request):
        # Return a truthy value to allow open registration without an IAT.
        return True

    def resolve_public_key(self, request):
        # No software_statement support; return None to skip JWT validation.
        return None

    def get_server_metadata(self):
        # Return None so Authlib skips metadata-based claims validation.
        return None

    @staticmethod
    def _is_public_client_request(request) -> bool:
        payload = (request.payload.data or {}) if request.payload else {}
        return payload.get("token_endpoint_auth_method") == "none"

    def generate_client_secret(self, request):
        # RFC 7591 §3.2.1: public clients MUST NOT be issued a client_secret.
        if self._is_public_client_request(request):
            return ""
        return super().generate_client_secret(request)

    def generate_client_info(self, request):
        # Authlib always serialises client_secret / client_secret_expires_at into
        # the DCR response, even for a public client where the secret is "".
        # A present-but-empty client_secret makes strict OAuth clients (the MCP
        # SDK among them) classify the client as confidential, select
        # client_secret_basic, and then fail. RFC 7591 §3.2.1 says the field
        # must be omitted entirely for public clients, so drop it.
        info = super().generate_client_info(request)
        if self._is_public_client_request(request):
            info.pop("client_secret", None)
            info.pop("client_secret_expires_at", None)
        return info

    def save_client(self, client_info, client_metadata, request):
        # Ensure public clients never persist a secret (defence-in-depth).
        is_public = client_metadata.get("token_endpoint_auth_method") == "none"
        raw_secret = "" if is_public else client_info.get("client_secret", "")
        client = OAuth2Client(
            client_id=client_info["client_id"],
            # Store the hashed secret; the DCR response still returns the
            # plaintext value because Authlib serialises client_info, not the
            # model field.
            client_secret=hash_client_secret(raw_secret),
            user=None,
        )
        client.set_client_metadata(client_metadata)
        client.save()
        return client


# kept for callers that imported the private name
_ClientRegistration = ClientRegistration

authorization = AuthorizationServer(OAuth2Client, OAuth2Token)
# Override the default bearer-token generator with our JWT-minting one.
authorization.register_token_generator("default", _bearer_token_generator)
authorization.register_grant(AuthorizationCodeGrant, [PKCE_REQUIRED])
authorization.register_grant(RefreshTokenGrant)
authorization.register_grant(ClientCredentialsGrant)
authorization.register_endpoint(ClientRegistration)
