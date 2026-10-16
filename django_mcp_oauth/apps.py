from django.apps import AppConfig


class McpOAuthConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "django_mcp_oauth"
    label = "mcp_oauth"
    verbose_name = "MCP OAuth"
