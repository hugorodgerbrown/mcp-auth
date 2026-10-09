"""App config for mcp_auth. It has no models; django-oauth-toolkit owns the tables."""

from django.apps import AppConfig


class McpAuthConfig(AppConfig):
    """Registers the package's templates and its management command."""

    name = "mcp_auth"
    verbose_name = "MCP auth"

    def ready(self) -> None:
        """Let Claude connect although its client metadata lists the JWT-bearer grant."""
        from .grant_types import ignore_unsupported_grant_types

        ignore_unsupported_grant_types()
