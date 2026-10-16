import hashlib
import secrets
import time

from django.conf import settings
from django.db import models

from authlib.common.encoding import json_dumps, json_loads
from authlib.oauth2.rfc6749 import (
    AuthorizationCodeMixin,
    ClientMixin,
    TokenMixin,
    list_to_scope,
    scope_to_list,
)


def _now():
    return int(time.time())


def hash_client_secret(raw: str) -> str:
    """Return a one-way hash of *raw* suitable for storage.

    Returns an empty string when *raw* is empty (preserves public-client
    semantics where ``client_secret`` is intentionally blank). The stored
    format is ``"sha256$" + <64-hex-chars>`` (71 bytes), which fits the
    ``client_secret`` field (max_length=120).
    """
    if not raw:
        return ""
    return "sha256$" + hashlib.sha256(raw.encode()).hexdigest()


class OAuth2Client(models.Model, ClientMixin):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True)
    client_id = models.CharField(max_length=48, unique=True, db_index=True)
    client_secret = models.CharField(max_length=120, blank=True, default="")
    client_id_issued_at = models.IntegerField(default=0)
    client_secret_expires_at = models.IntegerField(default=0)
    _client_metadata = models.TextField(db_column="client_metadata", blank=True, default="")

    def __str__(self):
        return self.client_id

    @property
    def client_metadata(self):
        if "_client_metadata_cache" in self.__dict__:
            return self.__dict__["_client_metadata_cache"]
        if self._client_metadata:
            data = json_loads(self._client_metadata)
            self.__dict__["_client_metadata_cache"] = data
            return data
        return {}

    def set_client_metadata(self, value):
        self._client_metadata = json_dumps(value)
        self.__dict__.pop("_client_metadata_cache", None)

    def refresh_from_db(self, *args, **kwargs):
        self.__dict__.pop("_client_metadata_cache", None)
        return super().refresh_from_db(*args, **kwargs)

    @property
    def redirect_uris(self):
        return self.client_metadata.get("redirect_uris", [])

    @property
    def token_endpoint_auth_method(self):
        return self.client_metadata.get("token_endpoint_auth_method", "client_secret_basic")

    @property
    def grant_types(self):
        return self.client_metadata.get("grant_types", [])

    @property
    def response_types(self):
        return self.client_metadata.get("response_types", [])

    @property
    def scope(self):
        return self.client_metadata.get("scope", "")

    def get_client_id(self):
        return self.client_id

    def get_default_redirect_uri(self):
        if self.redirect_uris:
            return self.redirect_uris[0]
        return None

    def get_allowed_scope(self, scope):
        if not scope:
            return ""
        allowed = set(self.scope.split())
        scopes = scope_to_list(scope)
        return list_to_scope([s for s in scopes if s in allowed])

    def check_redirect_uri(self, redirect_uri):
        return redirect_uri in self.redirect_uris

    def check_client_secret(self, client_secret):
        stored = self.client_secret
        # Public clients have no secret; never authenticate a non-empty value.
        if not stored:
            return False
        if stored.startswith("sha256$"):
            return secrets.compare_digest(stored, hash_client_secret(client_secret))
        # Legacy plaintext fallback for rows created before hashing.
        return secrets.compare_digest(stored, client_secret)

    def check_endpoint_auth_method(self, method, endpoint):
        if endpoint == "token":
            return self.token_endpoint_auth_method == method
        return True

    def check_response_type(self, response_type):
        return response_type in self.response_types

    def check_grant_type(self, grant_type):
        return grant_type in self.grant_types


class OAuth2AuthorizationCode(models.Model, AuthorizationCodeMixin):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    code = models.CharField(max_length=120, unique=True)
    client_id = models.CharField(max_length=48, blank=True, default="")
    redirect_uri = models.TextField(blank=True, default="")
    response_type = models.TextField(blank=True, default="")
    scope = models.TextField(blank=True, default="")
    nonce = models.TextField(null=True, blank=True)
    auth_time = models.IntegerField(default=_now)
    code_challenge = models.TextField(null=True, blank=True)
    code_challenge_method = models.CharField(max_length=48, null=True, blank=True)

    def __str__(self):
        return self.code

    def is_expired(self):
        return self.auth_time + 300 < time.time()

    def get_redirect_uri(self):
        return self.redirect_uri

    def get_scope(self):
        return self.scope


class OAuth2Token(models.Model, TokenMixin):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    client_id = models.CharField(max_length=48, blank=True, default="")
    token_type = models.CharField(max_length=40, blank=True, default="")
    access_token = models.TextField(unique=True)
    refresh_token = models.CharField(max_length=255, blank=True, default="", db_index=True)
    scope = models.TextField(blank=True, default="")
    issued_at = models.IntegerField(default=_now)
    access_token_revoked_at = models.IntegerField(default=0)
    refresh_token_revoked_at = models.IntegerField(default=0)
    expires_in = models.IntegerField(default=0)

    def __str__(self):
        return self.access_token[:16] + "..."

    def check_client(self, client):
        return self.client_id == client.get_client_id()

    def get_scope(self):
        return self.scope

    def get_expires_in(self):
        return self.expires_in

    def is_revoked(self):
        return bool(self.access_token_revoked_at)

    def is_expired(self):
        if not self.expires_in:
            return False
        return self.issued_at + self.expires_in < time.time()

    def is_refresh_token_active(self):
        return not bool(self.refresh_token_revoked_at)

    def get_user(self):
        return self.user

    def get_client(self):
        return OAuth2Client.objects.filter(client_id=self.client_id).first()
