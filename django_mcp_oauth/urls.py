"""URL patterns. Include both lists at the site root: the discovery documents
MUST live under ``/.well-known/`` (RFC 9728, RFC 8414), and the metadata
advertises the AS endpoints at ``/oauth/*`` of the issuer origin.

    from django_mcp_oauth.urls import oauth_urlpatterns, wellknown_urlpatterns
    urlpatterns += wellknown_urlpatterns + oauth_urlpatterns
"""

from django.urls import path

from django_mcp_oauth import metadata, views

wellknown_urlpatterns = [
    path(
        ".well-known/oauth-protected-resource",
        metadata.protected_resource_metadata,
        name="oauth-protected-resource",
    ),
    # MCP clients also probe the path-suffixed PRM form.
    path(
        ".well-known/oauth-protected-resource/mcp",
        metadata.protected_resource_metadata,
        name="oauth-protected-resource-mcp",
    ),
    path(
        ".well-known/oauth-authorization-server",
        metadata.authorization_server_metadata,
        name="oauth-authorization-server",
    ),
    path(".well-known/jwks.json", metadata.jwks, name="oauth-jwks"),
]

oauth_urlpatterns = [
    path("oauth/authorize", views.authorize_view, name="oauth-authorize"),
    path("oauth/token", views.token_view, name="oauth-token"),
    path("oauth/register", views.register_view, name="oauth-register"),
]

urlpatterns = wellknown_urlpatterns + oauth_urlpatterns
