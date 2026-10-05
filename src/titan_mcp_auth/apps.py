"""App config for titan_mcp_auth. It has no models; django-oauth-toolkit owns the tables."""

from django.apps import AppConfig


class TitanMcpAuthConfig(AppConfig):
    """Registers the package's templates and its management command."""

    name = "titan_mcp_auth"
    verbose_name = "Titan MCP auth"
