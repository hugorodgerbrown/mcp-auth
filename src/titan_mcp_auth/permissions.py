"""The redirect allowlist, and the DCR permission that enforces it.

Registration is open (RFC 7591), but only for callbacks on
TITAN_MCP["REDIRECT_URI_PATTERNS"], so a registration on its own can never
make this server send a signed-in user somewhere else.
"""

import json
import re

from django.http import HttpRequest

from .conf import titan_setting


def redirect_uri_allowed(uri: str) -> bool:
    """Return whether the server may send a browser to ``uri``."""
    return any(re.match(pattern, uri) for pattern in titan_setting("REDIRECT_URI_PATTERNS"))


def _all_allowed(body: bytes) -> bool:
    """Return whether a registration body names only allowlisted callbacks."""
    try:
        uris = json.loads(body).get("redirect_uris")
    except (ValueError, AttributeError):
        return False
    return (
        isinstance(uris, list)
        and bool(uris)
        and all(isinstance(u, str) and redirect_uri_allowed(u) for u in uris)
    )


class AllowlistedRedirectRegistration:
    """Let anyone register a client whose redirect URIs are all allowlisted."""

    def has_permission(self, request: HttpRequest) -> bool:
        """DCR_REGISTRATION_PERMISSION_CLASSES hook."""
        return _all_allowed(request.body)


def registration_allowed(request: HttpRequest) -> bool:
    """The same check, for an RFC 7592 update."""
    return _all_allowed(request.body)
