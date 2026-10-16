"""django-mcp-oauth — an OAuth 2.1 authorization server for MCP resource servers.

Built on Authlib's Django integration (``AuthorizationServer``, RFC 7591
``ClientRegistrationEndpoint``, RFC 7636 ``CodeChallenge``) and PyJWT/cryptography
for RS256 + JWKS, with the MCP profile wired on top: RFC 9728 protected-resource
metadata, RFC 8414 AS metadata, RFC 7517 JWKS, RFC 7591 dynamic client
registration with the public-client/no-secret rule, RFC 6750/9728
``WWW-Authenticate`` challenges, refresh-token rotation with a race-tolerant
grace window, and a client-credentials grant for service accounts bound to a
Django user.

The one product decision — *may this signed-in user authorize an MCP client?* —
is a dotted-path setting, ``MCP_OAUTH_AUTHORIZE_USER``. Everything else is
configuration (issuer, resource URL, key, scope, TTLs, consent template).
"""

__version__ = "0.1.0"
