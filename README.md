# django-mcp-oauth

An OAuth 2.1 authorization server for MCP resource servers, as a Django app.

Built on Authlib's Django integration plus PyJWT/cryptography, with the MCP
profile wired on top:

- RFC 9728 protected-resource metadata, RFC 8414 authorization-server
  metadata, RFC 7517 JWKS — all under `/.well-known/`
- RFC 7591 dynamic client registration, with the public-client rule (a
  `token_endpoint_auth_method: none` client is never issued a secret, and the
  response omits the field as the RFC requires)
- Authorization-code grant with PKCE (S256) required, RS256 JWT access tokens
  bound to the resource audience
- Refresh-token rotation with a configurable grace window, so concurrent
  agents sharing a connection do not strand each other with a dead credential
- Client-credentials grant for service accounts, each bound to a Django user
- RFC 6750 / 9728 `WWW-Authenticate` challenges for the resource server
- Client secrets stored hashed

The one product decision — *may this signed-in user authorize an MCP
client?* — is a dotted-path setting. Everything else is configuration.

## Install

```bash
pip install django-mcp-oauth          # + [drf] for the REST Framework class
python manage.py generate_oauth_keys   # prints a private key PEM to set as MCP_OAUTH_PRIVATE_KEY
```

```python
INSTALLED_APPS += ["django_mcp_oauth"]

MCP_OAUTH_ISSUER = "https://example.com"          # the AS origin (iss)
MCP_RESOURCE_URL = "https://example.com/mcp"      # the MCP server (aud)
MCP_OAUTH_PRIVATE_KEY = os.environ["MCP_OAUTH_PRIVATE_KEY"]
MCP_OAUTH_AUTHORIZE_USER = "myapp.access.may_use_mcp"   # callable(user) -> bool
MCP_OAUTH_CONSENT_TEMPLATE = "myapp/consent.html"       # optional; receives grant, client, scope
```

```python
# urls.py — both lists at the site root
from django_mcp_oauth.urls import oauth_urlpatterns, wellknown_urlpatterns
urlpatterns += wellknown_urlpatterns + oauth_urlpatterns
```

Optional settings and their defaults are listed in `django_mcp_oauth/conf.py`.

## Resource server side

```python
from django_mcp_oauth.resource import user_from_bearer, www_authenticate
from django_mcp_oauth.validation import TokenError

try:
    user, validated = user_from_bearer(token)      # raises TokenError
except TokenError as exc:
    return JSONResponse({"error": exc.error}, status_code=401,
                        headers={"WWW-Authenticate": www_authenticate(exc.error, exc.description)})
```

`www_authenticate(include_error=False)` is the form for a request that carried
no credentials at all (RFC 6750 §3.1). For Django REST Framework, add
`django_mcp_oauth.drf.OAuth2ResourceServerAuthentication` to
`DEFAULT_AUTHENTICATION_CLASSES`.

## Service accounts

```bash
python manage.py create_service_client --user svc-bot --name "Nightly sync" --scope mcp
```

prints a `client_id` / `client_secret` pair once; the client authenticates to
`/oauth/token` with `grant_type=client_credentials` and gets a token whose
subject is the bound user.

## Adopting from an in-tree copy

If your product already carries these models under its own app (tables
`<app>_oauth2client`, `<app>_oauth2token`, `<app>_oauth2authorizationcode`),
rename the tables and drop the models from that app's migration state; this
app's initial migration finds the tables present and records state only:

```python
class Migration(migrations.Migration):
    dependencies = [("myapp", "000N_previous")]
    run_before = [("mcp_oauth", "0001_initial")]
    operations = [
        migrations.SeparateDatabaseAndState(
            database_operations=[
                migrations.RunSQL(
                    "ALTER TABLE myapp_oauth2client RENAME TO mcp_oauth_oauth2client",
                    reverse_sql="ALTER TABLE mcp_oauth_oauth2client RENAME TO myapp_oauth2client",
                ),
                # ... oauth2token, oauth2authorizationcode likewise
            ],
            state_operations=[
                migrations.DeleteModel("OAuth2Client"),
                migrations.DeleteModel("OAuth2Token"),
                migrations.DeleteModel("OAuth2AuthorizationCode"),
            ],
        )
    ]
```

Keep re-exporting `_now` from your old models module while historical
migrations reference it. Unapplying this app's initial migration never drops
the tables (so unapplying the adoption migration afterwards renames your
data back); on a fresh install, drop them by hand if you really mean to.

## Tests

```bash
pip install -e '.[test]'
pytest
```

## License

Apache-2.0.
