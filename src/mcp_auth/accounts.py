"""How the consent page names the signed-in account: MCP_AUTH["ACCOUNT_NAME"].

It names one of these, or a project's own `user -> str`.

A project that keeps no email address (only a key made from it) points the
setting at a function that returns what it does keep, such as a masked
address, so the page never shows a raw key.
"""

from typing import Any

from django.utils.module_loading import import_string

from .conf import mcp_auth_setting


def email_or_username(user: Any) -> str:
    """The account's email address, or its username when it has none."""
    return str(getattr(user, "email", "") or user.get_username())


def account_name(user: Any) -> str:
    """Return how the consent page names ``user``, under the project's rule."""
    return str(import_string(mcp_auth_setting("ACCOUNT_NAME"))(user))
