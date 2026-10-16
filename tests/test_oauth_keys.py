import json

from django.test import TestCase, override_settings

import jwt
from django_mcp_oauth import keys


# A throwaway 2048-bit RSA key generated for tests only.
def _make_test_key():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


TEST_KEY = _make_test_key()


@override_settings(MCP_OAUTH_PRIVATE_KEY=TEST_KEY, MCP_OAUTH_KEY_ID="test-kid")
class OAuthKeysTests(TestCase):
    def test_jwks_exposes_public_key_only(self):
        jwks = keys.build_jwks()
        self.assertEqual(len(jwks["keys"]), 1)
        k = jwks["keys"][0]
        self.assertEqual(k["kty"], "RSA")
        self.assertEqual(k["kid"], "test-kid")
        self.assertEqual(k["alg"], "RS256")
        self.assertEqual(k["use"], "sig")
        self.assertNotIn("d", k)  # never expose the private exponent

    def test_sign_and_verify_roundtrip(self):
        token = keys.sign_jwt({"sub": "42", "iss": "https://x"})
        header = jwt.get_unverified_header(token)
        self.assertEqual(header["kid"], "test-kid")
        self.assertEqual(header["alg"], "RS256")
        # Real roundtrip: decode with public key derived from hand-built JWK.
        jwks = keys.build_jwks()
        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwks["keys"][0]))
        decoded = jwt.decode(
            token,
            key=public_key,
            algorithms=["RS256"],
            options={"verify_aud": False},
        )
        self.assertEqual(decoded["sub"], "42")
        self.assertEqual(decoded["iss"], "https://x")
