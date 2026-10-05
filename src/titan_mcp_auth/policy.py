"""Who may connect an MCP client. TITAN_MCP["CAN_CONNECT"] names one of these, or a project's own.

The rule runs twice: on the consent page, and on every MCP call, so taking a
permission away from a user cuts off their connected clients at once.
"""

from typing import Any

from django.utils.module_loading import import_string

from .conf import titan_setting


def active_user(user: Any) -> bool:
    """Any active account may connect."""
    return bool(user.is_active)


def superuser_only(user: Any) -> bool:
    """Only an active superuser may connect."""
    return bool(user.is_active and user.is_superuser)


def can_connect(user: Any) -> bool:
    """Return whether ``user`` may connect an MCP client, under the project's rule."""
    if user is None or not user.is_authenticated:
        return False
    rule = import_string(titan_setting("CAN_CONNECT"))
    return bool(rule(user))
