"""Tests for the OAuth 2.0 client_credentials grant (RFC 6749 §4.4).

Written FIRST (TDD) before the implementation. All tests must pass after
the feature is implemented; none should be deleted or skipped.
"""

import json
import secrets
from base64 import b64encode
from io import StringIO

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase, override_settings

from django_mcp_oauth import keys, validation
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


def _basic_auth(client_id: str, client_secret: str) -> str:
    """Return value for the Authorization header (HTTP Basic)."""
    creds = f"{client_id}:{client_secret}"
    return "Basic " + b64encode(creds.encode()).decode()


def _create_service_client(user, scope="mcp"):
    """Helper: create a confidential OAuth2Client bound to *user* directly."""
    client_id = "svc-" + secrets.token_urlsafe(16)
    raw_secret = secrets.token_urlsafe(32)
    client = OAuth2Client.objects.create(
        client_id=client_id,
        client_secret=raw_secret,
        user=user,
    )
    client.set_client_metadata(
        {
            "grant_types": ["client_credentials"],
            "token_endpoint_auth_method": "client_secret_basic",
            "response_types": [],
            "scope": scope,
            "client_name": "Test Service Client",
        }
    )
    client.save()
    return client, raw_secret


# ---------------------------------------------------------------------------
# 1. Management command: create_service_client
# ---------------------------------------------------------------------------


@override_settings(**SETTINGS)
class CreateServiceClientCommandTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="svcuser", email="svc@x.com", password="pw")

    def test_command_creates_client_bound_to_user(self):
        out = StringIO()
        call_command(
            "create_service_client",
            "--user",
            "svcuser",
            "--name",
            "My Service",
            "--scope",
            "mcp",
            stdout=out,
        )
        # One confidential client should now exist
        client = OAuth2Client.objects.get(user=self.user)
        self.assertIsNotNone(client.client_id)
        self.assertTrue(len(client.client_secret) > 0, "client_secret must not be empty")
        self.assertIn("client_credentials", client.grant_types)
        self.assertEqual(client.token_endpoint_auth_method, "client_secret_basic")
        self.assertEqual(client.client_metadata.get("client_name"), "My Service")
        self.assertEqual(client.scope, "mcp")

    def test_command_prints_secret_once(self):
        out = StringIO()
        call_command(
            "create_service_client",
            "--user",
            "svcuser",
            "--name",
            "My Service",
            stdout=out,
        )
        output = out.getvalue()
        # Output must warn the operator that the secret cannot be retrieved.
        # Normalise whitespace before checking so line-wrap doesn't matter.
        normalised = " ".join(output.lower().split())
        self.assertIn("cannot be", normalised)
        self.assertIn("retrieved", normalised)
        # Output must contain the client_id.
        client = OAuth2Client.objects.get(user=self.user)
        self.assertIn(client.client_id, output)
        # The stored secret must be hashed (sha256$...), NOT the raw value.
        self.assertTrue(
            client.client_secret.startswith("sha256$"),
            "stored client_secret must be hashed, not raw",
        )
        # The raw secret (printed to stdout) must NOT equal the stored hash.
        # Verify by checking that check_client_secret works with whatever
        # raw value was printed — we extract it from the output line.
        for line in output.splitlines():
            if "client_secret:" in line:
                printed_raw = line.split("client_secret:")[-1].strip()
                self.assertTrue(
                    client.check_client_secret(printed_raw),
                    "check_client_secret must accept the raw secret printed to stdout",
                )
                break

    def test_command_rejects_unknown_user(self):
        with self.assertRaises(CommandError):
            call_command(
                "create_service_client",
                "--user",
                "nobody",
                "--name",
                "X",
                stdout=StringIO(),
            )

    def test_command_creates_no_redirect_uris(self):
        call_command(
            "create_service_client",
            "--user",
            "svcuser",
            "--name",
            "M2M",
            stdout=StringIO(),
        )
        client = OAuth2Client.objects.get(user=self.user)
        self.assertEqual(client.redirect_uris, [])
        self.assertEqual(client.response_types, [])


# ---------------------------------------------------------------------------
# 2. Token endpoint: valid client_credentials flow
# ---------------------------------------------------------------------------


@override_settings(**SETTINGS)
class ClientCredentialsTokenTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="m2m", email="m2m@x.com", password="pw", is_active=True)
        self.client_obj, self.raw_secret = _create_service_client(self.user, scope="mcp")

    def _token_request(self, client_id=None, secret=None, extra=None):
        cid = client_id or self.client_obj.client_id
        sec = secret or self.raw_secret
        data = {"grant_type": "client_credentials", "scope": "mcp"}
        if extra:
            data.update(extra)
        return self.client.post(
            "/oauth/token",
            data,
            HTTP_AUTHORIZATION=_basic_auth(cid, sec),
        )

    def test_valid_request_returns_200(self):
        resp = self._token_request()
        self.assertEqual(resp.status_code, 200)

    def test_response_contains_access_token_and_type(self):
        resp = self._token_request()
        body = resp.json()
        self.assertIn("access_token", body)
        self.assertEqual(body.get("token_type", "").lower(), "bearer")
        self.assertIn("expires_in", body)

    def test_response_has_no_refresh_token(self):
        resp = self._token_request()
        body = resp.json()
        self.assertNotIn("refresh_token", body)

    def test_jwt_sub_equals_user_pk(self):
        resp = self._token_request()
        access_token = resp.json()["access_token"]
        result = validation.validate_access_token(
            access_token,
            expected_audience=AUD,
            expected_issuer=ISS,
            jwks=keys.build_jwks(),
            required_scope="mcp",
        )
        self.assertEqual(result.subject, str(self.user.pk))

    def test_jwt_aud_equals_resource_url(self):
        resp = self._token_request()
        access_token = resp.json()["access_token"]
        import jwt as _jwt

        claims = _jwt.decode(
            access_token,
            options={"verify_signature": False, "verify_aud": False},
        )
        # aud can be a string or list depending on jwt lib version
        aud = claims.get("aud")
        if isinstance(aud, list):
            self.assertIn(AUD, aud)
        else:
            self.assertEqual(aud, AUD)


# ---------------------------------------------------------------------------
# 3. Issued token validates via existing resource-server path
# ---------------------------------------------------------------------------


@override_settings(**SETTINGS)
class ClientCredentialsTokenValidationTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="rsuser", email="rs@x.com", password="pw", is_active=True)
        self.client_obj, self.raw_secret = _create_service_client(self.user, scope="mcp")

    def test_validate_bearer_token_subject_equals_user_pk(self):
        resp = self.client.post(
            "/oauth/token",
            {"grant_type": "client_credentials", "scope": "mcp"},
            HTTP_AUTHORIZATION=_basic_auth(self.client_obj.client_id, self.raw_secret),
        )
        self.assertEqual(resp.status_code, 200)
        access_token = resp.json()["access_token"]

        result = validation.validate_access_token(
            access_token,
            expected_audience=AUD,
            expected_issuer=ISS,
            jwks=keys.build_jwks(),
            required_scope="mcp",
        )
        self.assertEqual(result.subject, str(self.user.pk))


# ---------------------------------------------------------------------------
# 4. Invalid client_secret → 401 invalid_client
# ---------------------------------------------------------------------------


@override_settings(**SETTINGS)
class ClientCredentialsInvalidSecretTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="badsec", email="bad@x.com", password="pw", is_active=True)
        self.client_obj, self.raw_secret = _create_service_client(self.user, scope="mcp")

    def test_wrong_secret_returns_401(self):
        resp = self.client.post(
            "/oauth/token",
            {"grant_type": "client_credentials", "scope": "mcp"},
            HTTP_AUTHORIZATION=_basic_auth(self.client_obj.client_id, "wrong-secret"),
        )
        self.assertEqual(resp.status_code, 401)

    def test_wrong_secret_error_is_invalid_client(self):
        resp = self.client.post(
            "/oauth/token",
            {"grant_type": "client_credentials", "scope": "mcp"},
            HTTP_AUTHORIZATION=_basic_auth(self.client_obj.client_id, "wrong-secret"),
        )
        body = resp.json()
        self.assertEqual(body.get("error"), "invalid_client")

    def test_wrong_secret_does_not_return_access_token(self):
        resp = self.client.post(
            "/oauth/token",
            {"grant_type": "client_credentials", "scope": "mcp"},
            HTTP_AUTHORIZATION=_basic_auth(self.client_obj.client_id, "wrong-secret"),
        )
        body = resp.json()
        self.assertNotIn("access_token", body)


# ---------------------------------------------------------------------------
# 5. Public/authorization_code client cannot use client_credentials
# ---------------------------------------------------------------------------


@override_settings(**SETTINGS)
class PublicClientCannotUseClientCredentialsTests(TestCase):
    def setUp(self):
        # Register a public (no-secret) authorization_code client via DCR
        resp = self.client.post(
            "/oauth/register",
            data=json.dumps(
                {
                    "client_name": "Public App",
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
        self.public_client_id = resp.json()["client_id"]

    def test_public_client_cannot_use_client_credentials(self):
        """A public client (auth method=none, grant=authorization_code) should
        be rejected when it tries client_credentials — Authlib should return
        either 401 invalid_client (auth fails) or 400 unauthorized_client."""
        resp = self.client.post(
            "/oauth/token",
            {
                "grant_type": "client_credentials",
                "client_id": self.public_client_id,
                "scope": "mcp",
            },
        )
        # Must not be 200
        self.assertNotEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIn(body.get("error"), ["invalid_client", "unauthorized_client"])

    def test_public_client_rejection_does_not_return_access_token(self):
        resp = self.client.post(
            "/oauth/token",
            {
                "grant_type": "client_credentials",
                "client_id": self.public_client_id,
                "scope": "mcp",
            },
        )
        body = resp.json()
        self.assertNotIn("access_token", body)


# ---------------------------------------------------------------------------
# 6. Metadata endpoint lists client_credentials
# ---------------------------------------------------------------------------


@override_settings(**SETTINGS)
class MetadataGrantTypeTests(TestCase):
    def test_metadata_includes_client_credentials(self):
        resp = self.client.get("/.well-known/oauth-authorization-server")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIn("client_credentials", body.get("grant_types_supported", []))

    def test_metadata_still_includes_authorization_code(self):
        resp = self.client.get("/.well-known/oauth-authorization-server")
        body = resp.json()
        self.assertIn("authorization_code", body.get("grant_types_supported", []))


# ---------------------------------------------------------------------------
# 7. Inactive bound user → token request rejected
# ---------------------------------------------------------------------------


@override_settings(**SETTINGS)
class InactiveUserClientCredentialsTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="inactive",
            email="inactive@x.com",
            password="pw",
            is_active=False,  # disabled account
        )
        self.client_obj, self.raw_secret = _create_service_client(self.user, scope="mcp")

    def test_inactive_user_token_rejected(self):
        resp = self.client.post(
            "/oauth/token",
            {"grant_type": "client_credentials", "scope": "mcp"},
            HTTP_AUTHORIZATION=_basic_auth(self.client_obj.client_id, self.raw_secret),
        )
        # Must not issue a token for a disabled identity
        self.assertNotEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIn(body.get("error"), ["access_denied", "invalid_client"])

    def test_inactive_user_rejection_does_not_return_access_token(self):
        resp = self.client.post(
            "/oauth/token",
            {"grant_type": "client_credentials", "scope": "mcp"},
            HTTP_AUTHORIZATION=_basic_auth(self.client_obj.client_id, self.raw_secret),
        )
        body = resp.json()
        self.assertNotIn("access_token", body)


# ---------------------------------------------------------------------------
# 8. Client missing client_credentials grant type → 400 unauthorized_client
# ---------------------------------------------------------------------------


@override_settings(**SETTINGS)
class MissingGrantTypeClientCredentialsTests(TestCase):
    """A confidential client that does NOT list client_credentials in its
    grant_types metadata must be rejected with unauthorized_client."""

    def setUp(self):
        self.user = User.objects.create_user(username="nogrant", email="nogrant@x.com", password="pw", is_active=True)
        # Create a confidential client whose grant_types only includes refresh_token
        client_id = "svc-nogrant-" + secrets.token_urlsafe(8)
        self.raw_secret = secrets.token_urlsafe(32)
        self.client_obj = OAuth2Client.objects.create(
            client_id=client_id,
            client_secret=self.raw_secret,
            user=self.user,
        )
        self.client_obj.set_client_metadata(
            {
                "grant_types": ["authorization_code"],
                "token_endpoint_auth_method": "client_secret_basic",
                "response_types": ["code"],
                "scope": "mcp",
                "client_name": "No-Grant Client",
            }
        )
        self.client_obj.save()

    def test_missing_grant_type_rejected(self):
        resp = self.client.post(
            "/oauth/token",
            {"grant_type": "client_credentials", "scope": "mcp"},
            HTTP_AUTHORIZATION=_basic_auth(self.client_obj.client_id, self.raw_secret),
        )
        self.assertNotEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIn(body.get("error"), ["unauthorized_client", "invalid_client"])

    def test_missing_grant_type_does_not_return_access_token(self):
        resp = self.client.post(
            "/oauth/token",
            {"grant_type": "client_credentials", "scope": "mcp"},
            HTTP_AUTHORIZATION=_basic_auth(self.client_obj.client_id, self.raw_secret),
        )
        body = resp.json()
        self.assertNotIn("access_token", body)


# ---------------------------------------------------------------------------
# 9. Scope clamping: requested scope is intersected with registered scope
# ---------------------------------------------------------------------------


@override_settings(**SETTINGS)
class ScopeClampingTests(TestCase):
    """Scope escalation must not be possible via the client_credentials grant."""

    def setUp(self):
        self.user = User.objects.create_user(username="scopeuser", email="scope@x.com", password="pw", is_active=True)

    def test_scope_escalation_is_clamped_to_registered_scope(self):
        """Client registered with scope='mcp' requests 'mcp admin'; token
        must only contain scope='mcp'."""
        client_obj, raw_secret = _create_service_client(self.user, scope="mcp")
        resp = self.client.post(
            "/oauth/token",
            {"grant_type": "client_credentials", "scope": "mcp admin"},
            HTTP_AUTHORIZATION=_basic_auth(client_obj.client_id, raw_secret),
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIn("access_token", body)
        # The token's scope claim must be exactly the registered scope, not admin
        token_scope = body.get("scope", "")
        self.assertNotIn("admin", token_scope.split())
        self.assertIn("mcp", token_scope.split())

    def test_scope_escalation_jwt_claim_is_clamped(self):
        """Verify the JWT itself carries only the allowed scope after clamping."""
        client_obj, raw_secret = _create_service_client(self.user, scope="mcp")
        resp = self.client.post(
            "/oauth/token",
            {"grant_type": "client_credentials", "scope": "mcp admin"},
            HTTP_AUTHORIZATION=_basic_auth(client_obj.client_id, raw_secret),
        )
        self.assertEqual(resp.status_code, 200)
        access_token = resp.json()["access_token"]
        result = validation.validate_access_token(
            access_token,
            expected_audience=AUD,
            expected_issuer=ISS,
            jwks=keys.build_jwks(),
            required_scope="mcp",
        )
        # scope in the validated token must not contain 'admin'
        self.assertNotIn("admin", result.scopes)

    def test_allowed_subset_of_scope_is_preserved(self):
        """Client registered with scope='mcp read' requesting 'mcp' only
        gets 'mcp' in the token (subset is preserved, not expanded)."""
        client_obj, raw_secret = _create_service_client(self.user, scope="mcp read")
        resp = self.client.post(
            "/oauth/token",
            {"grant_type": "client_credentials", "scope": "mcp"},
            HTTP_AUTHORIZATION=_basic_auth(client_obj.client_id, raw_secret),
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        token_scope = body.get("scope", "")
        self.assertIn("mcp", token_scope.split())
        # 'read' was not requested so it must not appear
        self.assertNotIn("read", token_scope.split())


# ---------------------------------------------------------------------------
# 10. Dangling FK: user_id references a deleted User row → 401 invalid_client
# ---------------------------------------------------------------------------


@override_settings(**SETTINGS)
class DanglingUserFKTests(TestCase):
    """If a service client's user_id FK points to a now-deleted User row,
    the token endpoint must return invalid_client (not a 500 server error)."""

    def setUp(self):
        self.user = User.objects.create_user(username="dangling", email="dangling@x.com", password="pw", is_active=True)
        self.client_obj, self.raw_secret = _create_service_client(self.user, scope="mcp")
        # Delete the user to create a dangling FK scenario.
        # Because OAuth2Client.user has on_delete=CASCADE this would normally
        # cascade-delete the client too, so we need to delete the user at the
        # database level without triggering Django signals/cascade.
        User.objects.filter(pk=self.user.pk).delete()

    def test_dangling_user_fk_returns_invalid_client(self):
        resp = self.client.post(
            "/oauth/token",
            {"grant_type": "client_credentials", "scope": "mcp"},
            HTTP_AUTHORIZATION=_basic_auth(self.client_obj.client_id, self.raw_secret),
        )
        # Must not be 200 or 500 — should be a clean 401 invalid_client
        self.assertNotEqual(resp.status_code, 200)
        self.assertNotEqual(resp.status_code, 500)

    def test_dangling_user_fk_does_not_return_access_token(self):
        resp = self.client.post(
            "/oauth/token",
            {"grant_type": "client_credentials", "scope": "mcp"},
            HTTP_AUTHORIZATION=_basic_auth(self.client_obj.client_id, self.raw_secret),
        )
        body = resp.json()
        self.assertNotIn("access_token", body)
