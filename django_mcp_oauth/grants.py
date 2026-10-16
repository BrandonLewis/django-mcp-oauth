# NOTE (Authlib 1.7.x): the grants live in authlib.oauth2.rfc6749.grants, NOT in
# authlib.integrations.django_oauth2 (which only exports AuthorizationServer,
# ResourceProtector, BearerTokenValidator, RevocationEndpoint). The base grants
# require the persistence hooks below; the Django AuthorizationServer supplies
# query_client / save_token / generate_token itself.
import time

from django.core.exceptions import ObjectDoesNotExist

from authlib.oauth2.rfc6749.errors import InvalidClientError
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from authlib.oauth2.rfc6749.grants import (
    ClientCredentialsGrant as _ClientCredentialsGrant,
)
from authlib.oauth2.rfc6749.grants import RefreshTokenGrant as _RefreshTokenGrant
from authlib.oauth2.rfc7636 import CodeChallenge
from django_mcp_oauth import conf
from django_mcp_oauth.models import OAuth2AuthorizationCode, OAuth2Token


class AuthorizationCodeGrant(_AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["none", "client_secret_basic", "client_secret_post"]

    def save_authorization_code(self, code, request):
        return OAuth2AuthorizationCode.objects.create(
            code=code,
            client_id=request.client.client_id,
            redirect_uri=request.redirect_uri or "",
            scope=request.scope or "",
            user=request.user,
            code_challenge=request.payload.data.get("code_challenge"),
            code_challenge_method=request.payload.data.get("code_challenge_method"),
        )

    def query_authorization_code(self, code, client):
        try:
            item = OAuth2AuthorizationCode.objects.get(code=code, client_id=client.client_id)
        except OAuth2AuthorizationCode.DoesNotExist:
            return None
        if not item.is_expired():
            return item

    def delete_authorization_code(self, authorization_code):
        authorization_code.delete()

    def authenticate_user(self, authorization_code):
        return authorization_code.user


class RefreshTokenGrant(_RefreshTokenGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["none", "client_secret_basic", "client_secret_post"]

    def authenticate_refresh_token(self, refresh_token):
        try:
            item = OAuth2Token.objects.get(refresh_token=refresh_token)
        except OAuth2Token.DoesNotExist:
            return None
        if item.is_refresh_token_active():
            return item
        # Rotation grace: concurrent agents sharing a connection race on
        # refresh, and the losers replay the just-rotated token seconds
        # later. Accept the rotated token briefly so they aren't stranded
        # with a dead credential (invalid_grant -> 401 storms on the resource).
        grace = conf.refresh_grace()
        if grace and item.refresh_token_revoked_at and time.time() - item.refresh_token_revoked_at < grace:
            return item

    def authenticate_user(self, credential):
        return credential.user

    def revoke_old_credential(self, credential):
        # Keep the original revocation stamp on grace-window replays so the
        # grace runs from first rotation and cannot be extended forever.
        if not credential.refresh_token_revoked_at:
            credential.refresh_token_revoked_at = int(time.time())
            credential.save()


class ClientCredentialsGrant(_ClientCredentialsGrant):
    """RFC 6749 §4.4 client_credentials grant for headless / M2M clients.

    Every service client MUST be bound to a real Django user (``client.user``).
    The access token's ``sub`` claim is ``str(client.user.pk)`` so the resource
    server's validation path (``User.objects.get(pk=subject)``) works unchanged.

    Rejection rules
    ---------------
    * Client must authenticate with ``client_secret_basic`` or
      ``client_secret_post`` (public clients are rejected with 401
      ``invalid_client``).
    * The client's ``grant_types`` list must include ``client_credentials``
      (the Authlib base class enforces this with ``unauthorized_client``).
    * ``client.user`` must exist and be active; otherwise 401 ``invalid_client``.
    * No refresh token is ever issued.
    """

    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post"]

    def create_token_response(self):
        """Override to bind the token to the client's linked Django user."""
        client = self.request.client

        # Defensive access so a non-null user_id pointing at a deleted row
        # does not propagate as an unhandled RelatedObjectDoesNotExist / 500.
        try:
            bound_user = client.user
        except ObjectDoesNotExist:
            bound_user = None

        if bound_user is None or not bound_user.is_active:
            raise InvalidClientError("Service client has no active bound user.")

        # Clamp the requested scope to what this client is actually allowed.
        requested = self.request.payload.scope or ""
        allowed_scope = client.get_allowed_scope(requested)

        token = self.generate_token(
            user=bound_user,
            scope=allowed_scope,
            include_refresh_token=False,
        )
        self.save_token(token)
        return 200, token, self.TOKEN_RESPONSE_HEADER


PKCE_REQUIRED = CodeChallenge(required=True)
