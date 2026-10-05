"""Shared OAuth 2.1 authentication for Titan's Django MCP servers.

A project adds ``mcp_auth`` and ``oauth2_provider`` to INSTALLED_APPS,
builds OAUTH2_PROVIDER with ``mcp_auth.conf.oauth2_settings``, includes
``mcp_auth.urls`` at the site root and wraps its MCP view in
``mcp_auth.resource.mcp_endpoint``. See README.md.
"""

__version__ = "0.1.0"
