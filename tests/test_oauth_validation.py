import time

from django.test import TestCase, override_settings

import jwt
from django_mcp_oauth import keys, validation
from tests.test_oauth_keys import TEST_KEY

ISS = "https://as.example.test"
AUD = "https://as.example.test/mcp"


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


@override_settings(MCP_OAUTH_PRIVATE_KEY=TEST_KEY, MCP_OAUTH_KEY_ID="test-kid")
class ValidateAccessTokenTests(TestCase):
    def setUp(self):
        self.jwks = keys.build_jwks()

    def _validate(self, token):
        return validation.validate_access_token(
            token,
            expected_audience=AUD,
            expected_issuer=ISS,
            jwks=self.jwks,
            required_scope="mcp",
        )

    def test_valid_token(self):
        result = self._validate(_token())
        self.assertEqual(result.subject, "7")
        self.assertIn("mcp", result.scopes)

    def test_wrong_audience_rejected(self):
        with self.assertRaises(validation.TokenError):
            self._validate(_token(aud="https://evil.example/mcp"))

    def test_wrong_issuer_rejected(self):
        with self.assertRaises(validation.TokenError):
            self._validate(_token(iss="https://evil.example"))

    def test_expired_rejected(self):
        with self.assertRaises(validation.TokenError):
            self._validate(_token(exp=int(time.time()) - 10))

    def test_missing_scope_rejected(self):
        with self.assertRaises(validation.TokenError):
            self._validate(_token(scope="other"))

    def test_bad_signature_rejected(self):
        token = _token()
        tampered = token[:-3] + ("aaa" if token[-3:] != "aaa" else "bbb")
        with self.assertRaises(validation.TokenError):
            self._validate(tampered)

    def test_missing_kid_rejected(self):
        now = int(time.time())
        claims = {
            "iss": ISS,
            "aud": AUD,
            "sub": "7",
            "scope": "mcp",
            "iat": now,
            "exp": now + 900,
        }
        # Encode without a kid header so the token omits kid entirely.
        raw = jwt.encode(claims, keys.get_private_key_pem(), algorithm="RS256")
        with self.assertRaises(validation.TokenError):
            self._validate(raw)

    def test_malformed_jwks_raises_tokenerror(self):
        token = _token()
        with self.assertRaises(validation.TokenError):
            validation.validate_access_token(
                token,
                expected_audience=AUD,
                expected_issuer=ISS,
                jwks={},
                required_scope="mcp",
            )

    def test_list_valued_scope_accepted(self):
        now = int(time.time())
        claims = {
            "iss": ISS,
            "aud": AUD,
            "sub": "7",
            "scope": ["mcp", "read"],
            "iat": now,
            "exp": now + 900,
        }
        token = keys.sign_jwt(claims)
        result = self._validate(token)
        self.assertIn("mcp", result.scopes)
