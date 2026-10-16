from django.core.management.base import BaseCommand

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class Command(BaseCommand):
    help = "Generate an RSA keypair for MCP OAuth token signing."

    def handle(self, *args, **options):
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        self.stdout.write("Set this in your environment (single line with \\n escapes or a " "multi-line secret):\n")
        self.stdout.write("MCP_OAUTH_PRIVATE_KEY:\n")
        self.stdout.write(pem)
