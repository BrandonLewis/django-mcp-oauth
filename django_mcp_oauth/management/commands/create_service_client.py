"""Management command: create_service_client

Creates a confidential OAuth2Client (client_credentials grant) bound to an
existing Django user. Use this to provision headless / M2M API clients that
authenticate directly to the MCP OAuth token endpoint without a browser flow.

Usage::

    python manage.py create_service_client \\
        --user <username> \\
        --name "My Service" \\
        [--scope "mcp other_scope"]

The command prints the ``client_id`` and ``client_secret`` ONCE.  Store them
securely — the secret cannot be retrieved after this point.
"""

import secrets
import time

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from django_mcp_oauth.models import OAuth2Client, hash_client_secret

User = get_user_model()


class Command(BaseCommand):
    help = "Create a confidential OAuth2 service client (client_credentials grant)"

    def add_arguments(self, parser):
        parser.add_argument(
            "--user",
            type=str,
            required=True,
            help="Username of the Django user to bind this client to",
        )
        parser.add_argument(
            "--name",
            type=str,
            required=True,
            help="Human-readable name for this client (stored as client_name)",
        )
        parser.add_argument(
            "--scope",
            type=str,
            default="",
            help="Space-separated list of allowed scopes (default: empty)",
        )

    def handle(self, *args, **options):
        username = options["user"]
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            raise CommandError(f"User '{username}' does not exist.")

        # Generate client credentials using the same approach as Authlib DCR:
        # client_id is a URL-safe random token; client_secret is a longer one.
        client_id = secrets.token_urlsafe(32)
        raw_secret = secrets.token_urlsafe(48)

        client = OAuth2Client(
            client_id=client_id,
            # Store the hashed secret; raw_secret is printed to stdout once for
            # the operator to copy into their secrets manager.
            client_secret=hash_client_secret(raw_secret),
            client_id_issued_at=int(time.time()),
            client_secret_expires_at=0,  # never expires
            user=user,
        )
        client.set_client_metadata(
            {
                "grant_types": ["client_credentials"],
                "token_endpoint_auth_method": "client_secret_basic",
                "response_types": [],
                "redirect_uris": [],
                "scope": options["scope"] or "",
                "client_name": options["name"],
            }
        )
        client.save()

        # Build the token endpoint URL for the operator's convenience.
        issuer = getattr(settings, "MCP_OAUTH_ISSUER", "").rstrip("/")
        token_url = issuer + "/oauth/token" if issuer else "/oauth/token"

        self.stdout.write(
            self.style.SUCCESS(
                f"\nService client created successfully.\n\n"
                f"  Client name:   {options['name']}\n"
                f"  Bound user:    {user.username}\n"
                f"  Scope:         {options['scope'] or '(none)'}\n"
                f"  client_id:     {client_id}\n"
                f"  client_secret: {raw_secret}\n\n"
                f"  Token endpoint: {token_url}\n\n"
                f"  IMPORTANT: Save the client_secret now — it cannot be\n"
                f"  retrieved later. Store it in a secrets manager or vault.\n"
            )
        )
