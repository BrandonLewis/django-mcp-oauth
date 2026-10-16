from django.test import TestCase, override_settings

from tests.test_oauth_keys import TEST_KEY


@override_settings(
    MCP_OAUTH_PRIVATE_KEY=TEST_KEY,
    MCP_OAUTH_KEY_ID="test-kid",
    MCP_OAUTH_ISSUER="https://as.example.test",
    MCP_OAUTH_SCOPE="mcp",
    MCP_RESOURCE_URL="https://as.example.test/mcp",
)
class OAuthMetadataTests(TestCase):
    def test_protected_resource_metadata(self):
        resp = self.client.get("/.well-known/oauth-protected-resource")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["resource"], "https://as.example.test/mcp")
        self.assertEqual(data["authorization_servers"], ["https://as.example.test"])
        self.assertEqual(data["bearer_methods_supported"], ["header"])
        self.assertIn("mcp", data["scopes_supported"])

    def test_authorization_server_metadata(self):
        resp = self.client.get("/.well-known/oauth-authorization-server")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["issuer"], "https://as.example.test")
        self.assertEqual(data["authorization_endpoint"], "https://as.example.test/oauth/authorize")
        self.assertEqual(data["token_endpoint"], "https://as.example.test/oauth/token")
        self.assertEqual(data["registration_endpoint"], "https://as.example.test/oauth/register")
        self.assertIn("S256", data["code_challenge_methods_supported"])
        self.assertIn("authorization_code", data["grant_types_supported"])

    def test_jwks(self):
        resp = self.client.get("/.well-known/jwks.json")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["keys"][0]["kid"], "test-kid")

    @override_settings(MCP_OAUTH_ISSUER="https://as.example.test/")
    def test_metadata_handles_trailing_slash_issuer(self):
        resp = self.client.get("/.well-known/oauth-authorization-server")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        # Endpoint URLs must not contain a double-slash after the scheme.
        for key in (
            "authorization_endpoint",
            "token_endpoint",
            "registration_endpoint",
            "jwks_uri",
        ):
            url = data[key]
            self.assertNotIn("//oauth", url, f"{key} has double slash: {url}")
            self.assertNotIn("//.well-known", url, f"{key} has double slash: {url}")
        # Specifically the authorize endpoint should be clean.
        self.assertEqual(data["authorization_endpoint"], "https://as.example.test/oauth/authorize")
        # PRM authorization_servers should also be normalized.
        prm_resp = self.client.get("/.well-known/oauth-protected-resource")
        self.assertEqual(prm_resp.status_code, 200)
        self.assertEqual(prm_resp.json()["authorization_servers"], ["https://as.example.test"])

    @override_settings(MCP_OAUTH_PRIVATE_KEY="")
    def test_jwks_returns_json_error_when_key_unset(self):
        resp = self.client.get("/.well-known/jwks.json")
        self.assertEqual(resp.status_code, 500)
        self.assertIn("application/json", resp["Content-Type"])
        self.assertEqual(resp.json()["error"], "server_error")

    @override_settings(
        MCP_OAUTH_PRIVATE_KEY=("-----BEGIN PRIVATE KEY-----\nnot-valid-key-material\n" "-----END PRIVATE KEY-----\n")
    )
    def test_jwks_returns_json_error_for_malformed_key(self):
        # Malformed PEM raises ValueError from the crypto loader; the view must
        # still return JSON, not Django's HTML 500.
        resp = self.client.get("/.well-known/jwks.json")
        self.assertEqual(resp.status_code, 500)
        self.assertIn("application/json", resp["Content-Type"])
        self.assertEqual(resp.json()["error"], "server_error")
