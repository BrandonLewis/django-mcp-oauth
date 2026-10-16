"""Initial schema — idempotent against tables that already exist.

A product adopting this app from an in-tree copy already has these three
tables under its own app's names. Its adoption migration renames them to this
app's names (``mcp_oauth_oauth2client`` etc.) and drops the models from its own
state; this migration then finds the tables present and records state only.
A fresh install creates them. Either way ``makemigrations --check`` is clean.
"""

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models

import authlib.oauth2.rfc6749.models

import django_mcp_oauth.models


class CreateModelIfMissing(migrations.CreateModel):
    """``CreateModel`` that leaves an existing table alone (see module doc).

    Reversing it never drops the table either: on an adopter, the table is the
    product's data and its own adoption migration renames it back once this
    one has been unapplied; on a fresh install an unapplied 0001 leaves an
    empty table behind, which is the safe side of the trade. Drop by hand.
    """

    def database_forwards(self, app_label, schema_editor, from_state, to_state):
        model = to_state.apps.get_model(app_label, self.name)
        with schema_editor.connection.cursor() as cursor:
            existing = schema_editor.connection.introspection.table_names(cursor)
        if model._meta.db_table in existing:
            return
        super().database_forwards(app_label, schema_editor, from_state, to_state)

    def database_backwards(self, app_label, schema_editor, from_state, to_state):
        return


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        CreateModelIfMissing(
            name="OAuth2AuthorizationCode",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("code", models.CharField(max_length=120, unique=True)),
                ("client_id", models.CharField(blank=True, default="", max_length=48)),
                ("redirect_uri", models.TextField(blank=True, default="")),
                ("response_type", models.TextField(blank=True, default="")),
                ("scope", models.TextField(blank=True, default="")),
                ("nonce", models.TextField(blank=True, null=True)),
                ("auth_time", models.IntegerField(default=django_mcp_oauth.models._now)),
                ("code_challenge", models.TextField(blank=True, null=True)),
                ("code_challenge_method", models.CharField(blank=True, max_length=48, null=True)),
                (
                    "user",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
                ),
            ],
            bases=(models.Model, authlib.oauth2.rfc6749.models.AuthorizationCodeMixin),
        ),
        CreateModelIfMissing(
            name="OAuth2Client",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("client_id", models.CharField(db_index=True, max_length=48, unique=True)),
                ("client_secret", models.CharField(blank=True, default="", max_length=120)),
                ("client_id_issued_at", models.IntegerField(default=0)),
                ("client_secret_expires_at", models.IntegerField(default=0)),
                ("_client_metadata", models.TextField(blank=True, db_column="client_metadata", default="")),
                (
                    "user",
                    models.ForeignKey(
                        null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL
                    ),
                ),
            ],
            bases=(models.Model, authlib.oauth2.rfc6749.models.ClientMixin),
        ),
        CreateModelIfMissing(
            name="OAuth2Token",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("client_id", models.CharField(blank=True, default="", max_length=48)),
                ("token_type", models.CharField(blank=True, default="", max_length=40)),
                ("access_token", models.TextField(unique=True)),
                ("refresh_token", models.CharField(blank=True, db_index=True, default="", max_length=255)),
                ("scope", models.TextField(blank=True, default="")),
                ("issued_at", models.IntegerField(default=django_mcp_oauth.models._now)),
                ("access_token_revoked_at", models.IntegerField(default=0)),
                ("refresh_token_revoked_at", models.IntegerField(default=0)),
                ("expires_in", models.IntegerField(default=0)),
                (
                    "user",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
                ),
            ],
            bases=(models.Model, authlib.oauth2.rfc6749.models.TokenMixin),
        ),
    ]
