"""The hardened django-oauth-toolkit preset, and the MCP_AUTH settings a project sets.

``oauth2_settings()`` returns the whole OAUTH2_PROVIDER dict, so every Titan
project gets the same token lifetimes, PKCE, RFC 9700 hardening, DCR and CIMD.
``MCP_AUTH`` holds what differs per project: the scope name, who may connect,
and which callbacks a client may register.
"""

from typing import Any

from django.conf import settings

# Claude's hosted apps, and a loopback port for Claude Code and other local clients.
CLAUDE_REDIRECT_URI_PATTERNS = [
    r"^https://claude\.ai/api/mcp/auth_callback$",
    r"^https://claude\.com/api/mcp/auth_callback$",
]
LOOPBACK_REDIRECT_URI_PATTERNS = [
    r"^http://(localhost|127\.0\.0\.1|\[::1\])(:\d+)?/[^?#]*$",
]
# Opt in by adding these to MCP_AUTH["REDIRECT_URI_PATTERNS"] (and the two
# origins to CONSENT_FORM_ACTION). Host-wide, as Traintracker allows them.
CHATGPT_REDIRECT_URI_PATTERNS = [
    r"^https://chatgpt\.com/[^?#]*$",
    r"^https://platform\.openai\.com/[^?#]*$",
]
DEFAULT_REDIRECT_URI_PATTERNS = CLAUDE_REDIRECT_URI_PATTERNS + LOOPBACK_REDIRECT_URI_PATTERNS

# Where the consent form may post and redirect to. Browsers apply CSP
# form-action to the redirect that follows a form post, so this must cover
# every allowlisted callback's origin.
DEFAULT_CONSENT_FORM_ACTION = [
    "https://claude.ai",
    "https://claude.com",
    "http://localhost:*",
    "http://127.0.0.1:*",
]

DEFAULTS: dict[str, Any] = {
    "SCOPE": "mcp",
    "CAN_CONNECT": "mcp_auth.policy.active_user",
    "REDIRECT_URI_PATTERNS": DEFAULT_REDIRECT_URI_PATTERNS,
    "CONSENT_FORM_ACTION": DEFAULT_CONSENT_FORM_ACTION,
    # Requests per minute: per user on the MCP endpoint, per IP on the OAuth
    # endpoints anyone can reach without signing in.
    "USER_RATE_PER_MINUTE": 60,
    "TOKEN_RATE_PER_MINUTE": 60,
    "REGISTER_RATE_PER_MINUTE": 10,
    "AUTHORIZE_RATE_PER_MINUTE": 30,
}


def mcp_auth_setting(name: str) -> Any:
    """Return one MCP_AUTH setting, falling back to the package default."""
    return getattr(settings, "MCP_AUTH", {}).get(name, DEFAULTS[name])


def oauth2_settings(
    *,
    resource_name: str,
    scope_description: str,
    scope: str = "mcp",
    **overrides: Any,
) -> dict[str, Any]:
    """Return OAUTH2_PROVIDER for an MCP server.

    ``scope`` must match MCP_AUTH["SCOPE"]. ``overrides`` replace preset keys
    one for one; anything the preset doesn't set keeps DOT's default.
    """
    preset: dict[str, Any] = {
        "SCOPES": {scope: scope_description, "offline_access": "Stay connected"},
        "DEFAULT_SCOPES": [scope],
        "ACCESS_TOKEN_EXPIRE_SECONDS": 60 * 60,
        "REFRESH_TOKEN_EXPIRE_SECONDS": 60 * 60 * 24 * 30,
        "ROTATE_REFRESH_TOKEN": True,
        # A replayed refresh token revokes the whole family. No grace period:
        # DOT can't combine one with hashed token storage.
        "REFRESH_TOKEN_REUSE_PROTECTION": True,
        "PKCE_REQUIRED": True,
        # RFC 8252: a loopback callback matches on any port, and "localhost"
        # counts as loopback. Claude Code binds a fresh port each run.
        "ALLOW_LOCALHOST_LOOPBACK": True,
        "COMPLIANT_BCP_RFC9700_PKCE_METHOD": True,
        "COMPLIANT_BCP_RFC9700_IMPLICIT_GRANT": True,
        "COMPLIANT_BCP_RFC9700_PASSWORD_GRANT": True,
        "COMPLIANT_BCP_RFC9700_ACCESS_TOKEN_TRANSPORT": True,
        "COMPLIANT_BCP_RFC9700_AUTHZ_RESPONSE_ISS": True,
        "COMPLIANT_BCP_RFC9700_TOKEN_STORAGE": True,
        "OAUTH2_RESPONSE_TYPES_SUPPORTED": ["code"],
        "OAUTH2_GRANT_TYPES_SUPPORTED": ["authorization_code", "refresh_token"],
        # "none" must be listed for Claude to use CIMD. The secret methods stay
        # because a DCR client may ask for one; PKCE is required either way.
        "OAUTH2_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED": [
            "none",
            "client_secret_post",
            "client_secret_basic",
        ],
        "OAUTH2_PROTECTED_RESOURCE_NAME": resource_name,
        "DCR_ENABLED": True,
        "DCR_REGISTRATION_PERMISSION_CLASSES": (
            "mcp_auth.permissions.AllowlistedRedirectRegistration",
        ),
        # A CIMD client's callbacks come from its fetched document; the
        # consent view refuses any that are off the allowlist.
        "CIMD_ENABLED": True,
    }
    return preset | overrides
