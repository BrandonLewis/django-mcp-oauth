import json
from base64 import b64encode

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from django_mcp_oauth.models import OAuth2Client
from tests.test_oauth_keys import TEST_KEY

User = get_user_model()

ISS = "http://testserver"
AUD = "http://testserver/mcp"

SETTINGS = {
    "MCP_OAUTH_PRIVATE_KEY": TEST_KEY,
    "MCP_OAUTH_KEY_ID": "test-kid",
    "MCP_OAUTH_ISSUER": ISS,
    "MCP_RESOURCE_URL": AUD,
    "MCP_OAUTH_SCOPE": "mcp",
}


@override_settings(**SETTINGS)
class DCRTests(TestCase):
    def test_register_public_client(self):
        body = {
            "client_name": "Claude Code",
            "redirect_uris": ["http://localhost:8765/cb"],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "scope": "mcp",
        }
        resp = self.client.post(
            "/oauth/register",
            data=json.dumps(body),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.json()
        self.assertTrue(data["client_id"])
        self.assertIn("http://localhost:8765/cb", data["redirect_uris"])

    def test_public_client_gets_no_secret(self):
        body = {
            "client_name": "Public MCP Client",
            "redirect_uris": ["http://localhost:9000/cb"],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "scope": "mcp",
        }
        resp = self.client.post(
            "/oauth/register",
            data=json.dumps(body),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.json()
        self.assertTrue(data["client_id"])
        # RFC 7591 §3.2.1: public clients must not receive a client_secret.
        # The key must be OMITTED entirely, not present-but-empty — a present
        # "client_secret": "" makes strict clients (e.g. the MCP OAuth client)
        # select client_secret_basic and then fail because the secret is blank.
        self.assertNotIn("client_secret", data)
        self.assertNotIn("client_secret_expires_at", data)


@override_settings(**SETTINGS)
class DCRSecretHashingTests(TestCase):
    """DCR-registered confidential clients have hashed secrets stored,
    but the DCR response returns the plaintext secret so clients can authenticate."""

    def _register_confidential(self):
        body = {
            "client_name": "Confidential Service",
            "redirect_uris": ["http://localhost:9876/cb"],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_basic",
            "scope": "mcp",
        }
        resp = self.client.post(
            "/oauth/register",
            data=json.dumps(body),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 201)
        return resp.json()

    def test_dcr_response_returns_plaintext_secret(self):
        """DCR response must include the plaintext client_secret so the client
        can use it immediately (RFC 7591 §3.2.1)."""
        data = self._register_confidential()
        # Confidential client should receive a client_secret in the response
        secret = data.get("client_secret", "")
        self.assertTrue(len(secret) > 0, "DCR response must include client_secret")
        # The response value must NOT be a hash (it's the plaintext for the client)
        self.assertFalse(
            secret.startswith("sha256$"),
            "DCR response must return the raw plaintext secret, not the hash",
        )

    def test_dcr_stored_secret_is_hashed(self):
        """The persisted model row must store only the hash, never plaintext."""
        data = self._register_confidential()
        client = OAuth2Client.objects.get(client_id=data["client_id"])
        self.assertTrue(
            client.client_secret.startswith("sha256$"),
            "stored client_secret must be hashed after DCR",
        )

    def test_dcr_confidential_client_can_authenticate_with_plaintext(self):
        """After DCR, the client can authenticate at the token endpoint using
        the plaintext secret returned in the DCR response."""
        user = User.objects.create_user(username="dcr_conf_user", email="dcc@x.com", password="pw")

        data = self._register_confidential()
        client_id = data["client_id"]
        plaintext_secret = data["client_secret"]

        self.client.force_login(user)

        import base64
        import hashlib
        import secrets
        from urllib.parse import parse_qs, urlparse

        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")

        # Authorize
        resp = self.client.post(
            "/oauth/authorize",
            {
                "client_id": client_id,
                "response_type": "code",
                "redirect_uri": "http://localhost:9876/cb",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "scope": "mcp",
                "confirm": "yes",
            },
        )
        self.assertEqual(resp.status_code, 302)
        code = parse_qs(urlparse(resp["Location"]).query)["code"][0]

        # Token exchange using the plaintext secret
        creds = f"{client_id}:{plaintext_secret}"
        auth_header = "Basic " + b64encode(creds.encode()).decode()
        resp = self.client.post(
            "/oauth/token",
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "http://localhost:9876/cb",
                "client_id": client_id,
                "code_verifier": verifier,
            },
            HTTP_AUTHORIZATION=auth_header,
        )
        self.assertEqual(
            resp.status_code,
            200,
            f"Token exchange must succeed with plaintext DCR secret; got {resp.json()}",
        )
