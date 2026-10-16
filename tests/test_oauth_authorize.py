"""/oauth/authorize: the login gate, the product's provisioning gate
(MCP_OAUTH_AUTHORIZE_USER) and the consent page (MCP_OAUTH_CONSENT_TEMPLATE)."""

import base64
import hashlib
import os

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from django_mcp_oauth.models import OAuth2Client
from tests.test_oauth_keys import TEST_KEY

User = get_user_model()


def _pkce_challenge() -> str:
    verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


@override_settings(MCP_OAUTH_PRIVATE_KEY=TEST_KEY, MCP_OAUTH_KEY_ID="test-kid")
class AuthorizeTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="member", email="m@x.com", password="pw")
        self.client_obj = OAuth2Client(user=self.user, client_id="cid")
        self.client_obj.set_client_metadata(
            {
                "redirect_uris": ["http://localhost:8765/cb"],
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
                "scope": "mcp",
            }
        )
        self.client_obj.save()

    def _authorize(self, **overrides):
        params = {
            "client_id": "cid",
            "response_type": "code",
            "redirect_uri": "http://localhost:8765/cb",
            "code_challenge": _pkce_challenge(),
            "code_challenge_method": "S256",
            "scope": "mcp",
        }
        params.update(overrides)
        return self.client.get("/oauth/authorize", params)

    def test_anonymous_redirected_to_login(self):
        resp = self._authorize()
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/accounts/login", resp["Location"])

    def test_default_gate_admits_an_active_account(self):
        self.client.force_login(self.user)
        resp = self._authorize()
        self.assertEqual(resp.status_code, 200)
        self.assertTemplateUsed(resp, "mcp_oauth/consent.html")

    def test_default_gate_refuses_an_inactive_account(self):
        self.user.is_active = False
        self.user.save()
        self.client.force_login(self.user)
        resp = self._authorize()
        # login_required sees the inactive user as anonymous and redirects to login
        self.assertEqual(resp.status_code, 302)

    @override_settings(MCP_OAUTH_AUTHORIZE_USER="tests.gates.deny_all")
    def test_product_gate_denial_is_a_proper_access_denied_redirect(self):
        self.client.force_login(self.user)
        resp = self._authorize(state="xyz")
        # A well-formed request from an unprovisioned user must produce a proper
        # OAuth2 access_denied redirect (302) — NOT a consent page or a 400.
        self.assertEqual(resp.status_code, 302)
        self.assertIn("error=access_denied", resp["Location"])
        self.assertIn("state=xyz", resp["Location"])

    @override_settings(MCP_OAUTH_AUTHORIZE_USER="tests.gates.deny_all")
    def test_product_gate_denial_without_a_safe_redirect_is_403(self):
        self.client.force_login(self.user)
        resp = self._authorize(redirect_uri="http://evil.example/cb")
        self.assertEqual(resp.status_code, 403)

    @override_settings(MCP_OAUTH_AUTHORIZE_USER="tests.gates.staff_only")
    def test_product_gate_receives_the_signed_in_user(self):
        self.client.force_login(self.user)
        self.assertEqual(self._authorize().status_code, 302)
        self.user.is_staff = True
        self.user.save()
        self.assertEqual(self._authorize().status_code, 200)

    def test_product_gate_may_be_a_callable_not_a_dotted_path(self):
        seen = []

        def gate(user):
            seen.append(user.pk)
            return True

        with override_settings(MCP_OAUTH_AUTHORIZE_USER=gate):
            self.client.force_login(self.user)
            self.assertEqual(self._authorize().status_code, 200)
        self.assertEqual(seen, [self.user.pk])

    @override_settings(MCP_OAUTH_CONSENT_TEMPLATE="custom/consent.html")
    def test_consent_template_is_overridable(self):
        self.client.force_login(self.user)
        resp = self._authorize()
        self.assertEqual(resp.status_code, 200)
        self.assertTemplateUsed(resp, "custom/consent.html")
        self.assertContains(resp, "CUSTOM CONSENT for cid (mcp)")

    def test_consent_denial_redirects_with_access_denied(self):
        os.environ.setdefault("AUTHLIB_INSECURE_TRANSPORT", "1")
        self.client.force_login(self.user)
        resp = self.client.post(
            "/oauth/authorize",
            {
                "client_id": "cid",
                "response_type": "code",
                "redirect_uri": "http://localhost:8765/cb",
                "code_challenge": _pkce_challenge(),
                "code_challenge_method": "S256",
                "scope": "mcp",
                "confirm": "no",
            },
        )
        self.assertEqual(resp.status_code, 302)
        self.assertIn("error=access_denied", resp["Location"])
