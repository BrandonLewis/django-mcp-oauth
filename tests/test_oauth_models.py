from django.contrib.auth import get_user_model
from django.test import TestCase

from authlib.common.encoding import json_dumps
from django_mcp_oauth.models import OAuth2Client, OAuth2Token, hash_client_secret

User = get_user_model()


class OAuthModelsTests(TestCase):
    def test_client_roundtrip(self):
        user = User.objects.create_user(username="dev", password="x")
        client = OAuth2Client(user=user, client_id="abc")
        client.set_client_metadata(
            {
                "client_name": "Claude Code",
                "redirect_uris": ["http://localhost:8765/callback"],
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
            }
        )
        client.save()
        fetched = OAuth2Client.objects.get(client_id="abc")
        self.assertIn("http://localhost:8765/callback", fetched.redirect_uris)

    def test_revocation_is_field_specific(self):
        user = User.objects.create_user(username="rev_user", password="x")

        # refresh_token_revoked_at set, access_token_revoked_at = 0
        token_refresh_revoked = OAuth2Token.objects.create(
            user=user,
            client_id="c1",
            access_token="at-refresh-revoked",
            refresh_token="rt-refresh-revoked",
            token_type="Bearer",
            scope="read",
            access_token_revoked_at=0,
            refresh_token_revoked_at=1700000000,
            expires_in=3600,
        )
        self.assertFalse(
            token_refresh_revoked.is_revoked(),
            "access token should NOT be revoked when only refresh_token_revoked_at is set",
        )
        self.assertFalse(
            token_refresh_revoked.is_refresh_token_active(),
            "refresh token should be inactive when refresh_token_revoked_at is set",
        )

        # access_token_revoked_at set, refresh_token_revoked_at = 0
        token_access_revoked = OAuth2Token.objects.create(
            user=user,
            client_id="c1",
            access_token="at-access-revoked",
            refresh_token="rt-access-revoked",
            token_type="Bearer",
            scope="read",
            access_token_revoked_at=1700000000,
            refresh_token_revoked_at=0,
            expires_in=3600,
        )
        self.assertTrue(
            token_access_revoked.is_revoked(),
            "access token should be revoked when access_token_revoked_at is set",
        )
        self.assertTrue(
            token_access_revoked.is_refresh_token_active(),
            "refresh token should be active when only access_token_revoked_at is set",
        )

    def test_access_token_field_accepts_long_jwt(self):
        user = User.objects.create_user(username="jwt_user", password="x")
        long_token = "a" * 600
        token = OAuth2Token.objects.create(
            user=user,
            client_id="c-jwt",
            access_token=long_token,
            token_type="Bearer",
            scope="mcp",
            expires_in=3600,
        )
        fetched = OAuth2Token.objects.get(pk=token.pk)
        self.assertEqual(len(fetched.access_token), 600)
        self.assertEqual(fetched.access_token, long_token)

    def test_client_metadata_cache_cleared_on_refresh(self):
        user = User.objects.create_user(username="cache_user", password="x")
        client = OAuth2Client(user=user, client_id="cache-client")
        client.set_client_metadata({"redirect_uris": ["a"]})
        client.save()

        # Read client_metadata to populate the cache
        self.assertEqual(client.redirect_uris, ["a"])
        self.assertIn("_client_metadata_cache", client.__dict__)

        # Bypass the model to update the underlying column directly
        OAuth2Client.objects.filter(pk=client.pk).update(_client_metadata=json_dumps({"redirect_uris": ["b"]}))

        # refresh_from_db should clear the cache and reload
        client.refresh_from_db()
        self.assertEqual(
            client.redirect_uris,
            ["b"],
            "redirect_uris should reflect updated DB value after refresh_from_db",
        )


# ---------------------------------------------------------------------------
# client secret hashing + dual-verify
# ---------------------------------------------------------------------------


class HashClientSecretTests(TestCase):
    """Unit tests for hash_client_secret() helper."""

    def test_hash_produces_sha256_prefix(self):
        result = hash_client_secret("s3cr3t")
        self.assertTrue(result.startswith("sha256$"))

    def test_hash_is_deterministic(self):
        self.assertEqual(hash_client_secret("abc"), hash_client_secret("abc"))

    def test_empty_raw_returns_empty(self):
        self.assertEqual(hash_client_secret(""), "")

    def test_hash_length_fits_field(self):
        # "sha256$" (7) + 64-hex = 71 chars; field is max_length=120
        result = hash_client_secret("x" * 100)
        self.assertLessEqual(len(result), 120)
        self.assertEqual(len(result), 71)


class CheckClientSecretDualVerifyTests(TestCase):
    """check_client_secret handles hashed, plaintext, and public clients."""

    def setUp(self):
        self.user = User.objects.create_user(username="sec_user", password="x")

    def _client(self, client_id, stored_secret):
        c = OAuth2Client(user=self.user, client_id=client_id)
        c.client_secret = stored_secret
        c.set_client_metadata({"scope": "mcp"})
        c.save()
        return c

    def test_hashed_secret_accepts_correct_raw(self):
        raw = "correct-secret"
        client = self._client("hashed-1", hash_client_secret(raw))
        self.assertTrue(client.check_client_secret(raw))

    def test_hashed_secret_rejects_wrong_raw(self):
        client = self._client("hashed-2", hash_client_secret("correct"))
        self.assertFalse(client.check_client_secret("wrong"))

    def test_legacy_plaintext_accepts_correct(self):
        """Backward compat: pre-hashing plaintext row still authenticates."""
        raw = "legacy-plaintext"
        client = self._client("legacy-1", raw)
        self.assertTrue(client.check_client_secret(raw))

    def test_legacy_plaintext_rejects_wrong(self):
        client = self._client("legacy-2", "correct-plaintext")
        self.assertFalse(client.check_client_secret("wrong"))

    def test_public_client_empty_secret_rejects_any(self):
        """Public client (empty stored secret) must never authenticate."""
        client = self._client("public-1", "")
        self.assertFalse(client.check_client_secret(""))
        self.assertFalse(client.check_client_secret("anything"))

    def test_hashed_empty_raw_never_matches(self):
        """hash_client_secret('') == '' → public-client path, always False."""
        client = self._client("public-2", hash_client_secret(""))
        self.assertFalse(client.check_client_secret(""))


class CreateServiceClientHashTests(TestCase):
    """create_service_client management command stores the hashed secret."""

    def setUp(self):
        self.user = User.objects.create_user(username="cmd_sec_user", email="cmd@x.com", password="x")

    def test_command_stores_hashed_secret(self):
        from io import StringIO

        from django.core.management import call_command

        out = StringIO()
        call_command(
            "create_service_client",
            "--user",
            "cmd_sec_user",
            "--name",
            "Hashed Client",
            "--scope",
            "mcp",
            stdout=out,
        )
        client = OAuth2Client.objects.get(user=self.user)
        self.assertTrue(
            client.client_secret.startswith("sha256$"),
            "stored secret must be hashed",
        )

    def test_check_secret_with_printed_raw(self):
        """The raw secret printed to stdout must authenticate via check_client_secret."""
        from io import StringIO

        from django.core.management import call_command

        out = StringIO()
        call_command(
            "create_service_client",
            "--user",
            "cmd_sec_user",
            "--name",
            "Hashed Client 2",
            "--scope",
            "mcp",
            stdout=out,
        )
        output = out.getvalue()
        client = OAuth2Client.objects.get(user=self.user)
        printed_raw = None
        for line in output.splitlines():
            if "client_secret:" in line:
                printed_raw = line.split("client_secret:")[-1].strip()
                break
        self.assertIsNotNone(printed_raw, "stdout must contain client_secret line")
        self.assertTrue(client.check_client_secret(printed_raw))
        self.assertFalse(client.check_client_secret("wrong"))

    def test_stored_secret_not_equal_to_raw(self):
        """The stored (hashed) value must NOT equal the raw plaintext."""
        from io import StringIO

        from django.core.management import call_command

        out = StringIO()
        call_command(
            "create_service_client",
            "--user",
            "cmd_sec_user",
            "--name",
            "Hashed Client 3",
            "--scope",
            "mcp",
            stdout=out,
        )
        output = out.getvalue()
        client = OAuth2Client.objects.get(user=self.user)
        for line in output.splitlines():
            if "client_secret:" in line:
                printed_raw = line.split("client_secret:")[-1].strip()
                self.assertNotEqual(client.client_secret, printed_raw)
                break
