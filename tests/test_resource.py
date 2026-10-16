"""Resource-server helpers: WWW-Authenticate challenges and bearer -> user."""

import time

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from django_mcp_oauth import keys, resource
from django_mcp_oauth.validation import TokenError
from tests.test_oauth_keys import TEST_KEY

User = get_user_model()
ISS = "https://as.example.test"
AUD = "https://rs.example.test/mcp"


def _token(**overrides):
    now = int(time.time())
    claims = {
        "iss": ISS,
        "aud": AUD,
        "sub": "7",
        "scope": "mcp",
        "iat": now,
        "exp": now + 900,
    }
    claims.update(overrides)
    return keys.sign_jwt(claims)


@override_settings(
    MCP_OAUTH_PRIVATE_KEY=TEST_KEY,
    MCP_OAUTH_KEY_ID="test-kid",
    MCP_OAUTH_ISSUER=ISS,
    MCP_RESOURCE_URL=AUD,
    MCP_OAUTH_SCOPE="mcp",
)
class ResourceHelperTests(TestCase):
    def test_metadata_url_derives_from_the_resource_origin_not_the_issuer(self):
        self.assertEqual(
            resource.resource_metadata_url(),
            "https://rs.example.test/.well-known/oauth-protected-resource",
        )

    def test_challenge_without_credentials_carries_no_error_param(self):
        header = resource.www_authenticate(include_error=False)
        self.assertEqual(
            header,
            'Bearer resource_metadata="https://rs.example.test/.well-known/oauth-protected-resource"',
        )

    def test_challenge_with_error_and_quoted_description(self):
        header = resource.www_authenticate("invalid_token", 'bad "quote"\r\nnext')
        self.assertTrue(header.startswith('Bearer error="invalid_token", resource_metadata='))
        self.assertIn('error_description="bad \\"quote\\"  next"', header)
        self.assertNotIn("\n", header)

    def test_user_from_bearer_resolves_the_subject(self):
        user = User.objects.create_user(username="u", password="x")
        got, validated = resource.user_from_bearer(_token(sub=str(user.pk)))
        self.assertEqual(got, user)
        self.assertEqual(validated.subject, str(user.pk))

    def test_user_from_bearer_rejects_unknown_inactive_and_malformed_subjects(self):
        with self.assertRaises(TokenError):
            resource.user_from_bearer(_token(sub="999999"))
        user = User.objects.create_user(username="gone", password="x", is_active=False)
        with self.assertRaises(TokenError):
            resource.user_from_bearer(_token(sub=str(user.pk)))
        with self.assertRaises(TokenError):
            resource.user_from_bearer(_token(sub="not-a-pk"))

    def test_user_from_bearer_propagates_scope_errors(self):
        with self.assertRaises(TokenError) as ctx:
            resource.user_from_bearer(_token(scope="other"))
        self.assertEqual(ctx.exception.error, "insufficient_scope")
