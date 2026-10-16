import base64
import hashlib
import json
import secrets
from urllib.parse import parse_qs, urlparse

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from django_mcp_oauth import keys, validation
from tests.test_oauth_keys import TEST_KEY

User = get_user_model()
ISS = "http://testserver"
AUD = "http://testserver/mcp"


def _pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return verifier, challenge


@override_settings(
    MCP_OAUTH_PRIVATE_KEY=TEST_KEY,
    MCP_OAUTH_KEY_ID="test-kid",
    MCP_OAUTH_ISSUER=ISS,
    MCP_RESOURCE_URL=AUD,
)
class EndToEndFlowTests(TestCase):
    def setUp(self):
        # the default gate admits any active account
        self.user = User.objects.create_user(username="member", email="m@x.com", password="pw")

    def _register_client(self):
        resp = self.client.post(
            "/oauth/register",
            data=json.dumps(
                {
                    "client_name": "Claude Code",
                    "redirect_uris": ["http://localhost:8765/cb"],
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                    "token_endpoint_auth_method": "none",
                    "scope": "mcp",
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 201)
        return resp.json()["client_id"]

    def test_full_flow(self):
        client_id = self._register_client()
        verifier, challenge = _pkce()
        self.client.force_login(self.user)

        # Authorize (consent POST)
        resp = self.client.post(
            "/oauth/authorize",
            {
                "client_id": client_id,
                "response_type": "code",
                "redirect_uri": "http://localhost:8765/cb",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "scope": "mcp",
                "confirm": "yes",
            },
        )
        self.assertEqual(resp.status_code, 302)
        code = parse_qs(urlparse(resp["Location"]).query)["code"][0]

        # Token exchange (public client + PKCE verifier)
        resp = self.client.post(
            "/oauth/token",
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "http://localhost:8765/cb",
                "client_id": client_id,
                "code_verifier": verifier,
            },
        )
        self.assertEqual(resp.status_code, 200)
        token = resp.json()
        self.assertIn("access_token", token)
        self.assertIn("refresh_token", token)
        access = token["access_token"]

        # The minted token validates against our own resource-server rules.
        result = validation.validate_access_token(
            access,
            expected_audience=AUD,
            expected_issuer=ISS,
            jwks=keys.build_jwks(),
            required_scope="mcp",
        )
        self.assertEqual(result.subject, str(self.user.pk))

    def test_refresh_token_flow(self):
        """After the initial exchange, a refresh_token must produce a new access token."""
        client_id = self._register_client()
        verifier, challenge = _pkce()
        self.client.force_login(self.user)

        # Authorize
        resp = self.client.post(
            "/oauth/authorize",
            {
                "client_id": client_id,
                "response_type": "code",
                "redirect_uri": "http://localhost:8765/cb",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "scope": "mcp",
                "confirm": "yes",
            },
        )
        self.assertEqual(resp.status_code, 302)
        code = parse_qs(urlparse(resp["Location"]).query)["code"][0]

        # Initial token exchange
        resp = self.client.post(
            "/oauth/token",
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "http://localhost:8765/cb",
                "client_id": client_id,
                "code_verifier": verifier,
            },
        )
        self.assertEqual(resp.status_code, 200)
        initial_token = resp.json()
        refresh_token = initial_token["refresh_token"]

        # Refresh
        resp = self.client.post(
            "/oauth/token",
            {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": client_id,
            },
        )
        self.assertEqual(resp.status_code, 200)
        new_token = resp.json()
        self.assertIn("access_token", new_token)
        new_access = new_token["access_token"]

        # New access token must also be valid
        result = validation.validate_access_token(
            new_access,
            expected_audience=AUD,
            expected_issuer=ISS,
            jwks=keys.build_jwks(),
            required_scope="mcp",
        )
        self.assertEqual(result.subject, str(self.user.pk))

    def _obtain_token(self):
        """Register a client and run the full code+PKCE flow; returns
        (client_id, token_response_dict)."""
        client_id = self._register_client()
        verifier, challenge = _pkce()
        self.client.force_login(self.user)

        resp = self.client.post(
            "/oauth/authorize",
            {
                "client_id": client_id,
                "response_type": "code",
                "redirect_uri": "http://localhost:8765/cb",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "scope": "mcp",
                "confirm": "yes",
            },
        )
        self.assertEqual(resp.status_code, 302)
        code = parse_qs(urlparse(resp["Location"]).query)["code"][0]

        resp = self.client.post(
            "/oauth/token",
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "http://localhost:8765/cb",
                "client_id": client_id,
                "code_verifier": verifier,
            },
        )
        self.assertEqual(resp.status_code, 200)
        return client_id, resp.json()

    def _refresh(self, client_id, refresh_token):
        return self.client.post(
            "/oauth/token",
            {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": client_id,
            },
        )

    def test_rotated_refresh_token_stays_valid_within_grace_window(self):
        """Refresh tokens are single-use (rotated), but a concurrent agent
        that lost the refresh race replays the just-rotated token within
        seconds. Production logs show these replays as 400s followed by 401
        storms on /mcp. Within a short grace window the old token must still
        be accepted instead of stranding the client."""
        client_id, initial = self._obtain_token()
        old_refresh = initial["refresh_token"]

        # First refresh rotates the token.
        resp = self._refresh(client_id, old_refresh)
        self.assertEqual(resp.status_code, 200)

        # Replay of the rotated token within the grace window must succeed.
        resp = self._refresh(client_id, old_refresh)
        self.assertEqual(
            resp.status_code,
            200,
            f"rotated refresh token rejected within grace: {resp.content!r}",
        )
        self.assertIn("access_token", resp.json())

    def test_rotated_refresh_token_rejected_after_grace_window(self):
        """Outside the grace window the rotated token stays dead — the grace
        absorbs races, it does not disable rotation."""
        import time

        from django_mcp_oauth.models import OAuth2Token

        client_id, initial = self._obtain_token()
        old_refresh = initial["refresh_token"]

        resp = self._refresh(client_id, old_refresh)
        self.assertEqual(resp.status_code, 200)

        # Backdate the revocation beyond the grace window.
        OAuth2Token.objects.filter(refresh_token=old_refresh).update(refresh_token_revoked_at=int(time.time()) - 3600)

        resp = self._refresh(client_id, old_refresh)
        self.assertEqual(resp.status_code, 400)

    def test_grace_replay_does_not_extend_the_window(self):
        """Replaying within grace must not refresh the revocation timestamp —
        otherwise repeated replays keep a stolen token alive forever."""

        from django_mcp_oauth.models import OAuth2Token

        client_id, initial = self._obtain_token()
        old_refresh = initial["refresh_token"]

        resp = self._refresh(client_id, old_refresh)
        self.assertEqual(resp.status_code, 200)
        revoked_at = OAuth2Token.objects.get(refresh_token=old_refresh).refresh_token_revoked_at
        self.assertGreater(revoked_at, 0)

        # A grace-window replay succeeds but must keep the original stamp.
        resp = self._refresh(client_id, old_refresh)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(
            OAuth2Token.objects.get(refresh_token=old_refresh).refresh_token_revoked_at,
            revoked_at,
        )
