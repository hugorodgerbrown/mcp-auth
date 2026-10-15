"""App config for mcp_auth. It has no models; django-oauth-toolkit owns the tables."""

from django.apps import AppConfig


class McpAuthConfig(AppConfig):
    """Registers the package's templates and its management command."""

    name = "mcp_auth"
    verbose_name = "MCP auth"

    def ready(self) -> None:
        """Let Claude and ChatGPT connect by their client metadata documents.

        Claude's lists the JWT-bearer grant; ChatGPT's prefers private_key_jwt.
        """
        from .auth_methods import accept_public_fallback
        from .grant_types import ignore_unsupported_grant_types

        ignore_unsupported_grant_types()
        accept_public_fallback()
