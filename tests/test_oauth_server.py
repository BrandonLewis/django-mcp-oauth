from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from django_mcp_oauth import keys, validation
from django_mcp_oauth.models import OAuth2Client
from django_mcp_oauth.server import _bearer_token_generator, generate_access_token
from tests.test_oauth_keys import TEST_KEY

User = get_user_model()
ISS = "https://as.example.test"
AUD = "https://as.example.test/mcp"


@override_settings(
    MCP_OAUTH_PRIVATE_KEY=TEST_KEY,
    MCP_OAUTH_KEY_ID="test-kid",
    MCP_OAUTH_ISSUER=ISS,
    MCP_RESOURCE_URL=AUD,
)
class TokenGeneratorTests(TestCase):
    def test_minted_token_validates(self):
        user = User.objects.create_user(username="u", password="x")
        client = OAuth2Client(user=user, client_id="cid")
        client.set_client_metadata({"scope": "mcp"})
        client.save()
        raw = generate_access_token(
            client=client,
            grant_type="authorization_code",
            user=user,
            scope="mcp",
        )
        result = validation.validate_access_token(
            raw,
            expected_audience=AUD,
            expected_issuer=ISS,
            jwks=keys.build_jwks(),
            required_scope="mcp",
        )
        self.assertEqual(result.subject, str(user.pk))

    def test_bearer_generator_includes_scope_and_ttl(self):
        user = User.objects.create_user(username="gen_user", password="x")
        client = OAuth2Client(user=user, client_id="gen-client")
        client.set_client_metadata({"scope": ""})
        client.save()
        token = _bearer_token_generator(
            grant_type="authorization_code",
            client=client,
            user=user,
            scope="",
            include_refresh_token=False,
        )
        self.assertIn("scope", token)
        self.assertEqual(token["scope"], "")
        self.assertEqual(token["token_type"], "Bearer")
        self.assertEqual(token["expires_in"], settings.MCP_OAUTH_ACCESS_TOKEN_TTL)


@override_settings(
    MCP_OAUTH_PRIVATE_KEY=TEST_KEY,
    MCP_OAUTH_KEY_ID="test-kid",
    MCP_OAUTH_ISSUER=ISS,
    MCP_RESOURCE_URL=AUD,
)
class BearerGeneratorScopeClampTests(TestCase):
    """#607 — _bearer_token_generator clamps scope to client's allowed scope."""

    def _make_client(self, username, client_id, registered_scope):
        user = User.objects.create_user(username=username, password="x")
        client = OAuth2Client(user=user, client_id=client_id)
        client.set_client_metadata({"scope": registered_scope})
        client.save()
        return user, client

    def test_disallowed_scope_is_dropped(self):
        """Client registered with 'mcp'; requesting 'mcp admin' yields only 'mcp'."""
        user, client = self._make_client("clamp1", "clamp-client-1", "mcp")
        token = _bearer_token_generator(
            grant_type="authorization_code",
            client=client,
            user=user,
            scope="mcp admin",
            include_refresh_token=False,
        )
        self.assertNotIn("admin", token["scope"].split())
        self.assertIn("mcp", token["scope"].split())

    def test_disallowed_scope_not_in_jwt(self):
        """JWT access_token must also carry only the clamped scope."""
        user, client = self._make_client("clamp2", "clamp-client-2", "mcp")
        token = _bearer_token_generator(
            grant_type="authorization_code",
            client=client,
            user=user,
            scope="mcp admin",
            include_refresh_token=False,
        )
        result = validation.validate_access_token(
            token["access_token"],
            expected_audience=AUD,
            expected_issuer=ISS,
            jwks=keys.build_jwks(),
            required_scope="mcp",
        )
        self.assertNotIn("admin", result.scopes)

    def test_allowed_subset_preserved(self):
        """Client registered with 'mcp read'; requesting only 'mcp' keeps 'mcp'."""
        user, client = self._make_client("clamp3", "clamp-client-3", "mcp read")
        token = _bearer_token_generator(
            grant_type="authorization_code",
            client=client,
            user=user,
            scope="mcp",
            include_refresh_token=False,
        )
        self.assertIn("mcp", token["scope"].split())
        self.assertNotIn("read", token["scope"].split())

    def test_matching_scope_unchanged(self):
        """Requesting exactly the registered scope ('mcp') passes through intact."""
        user, client = self._make_client("clamp4", "clamp-client-4", "mcp")
        token = _bearer_token_generator(
            grant_type="authorization_code",
            client=client,
            user=user,
            scope="mcp",
            include_refresh_token=False,
        )
        self.assertEqual(token["scope"], "mcp")
