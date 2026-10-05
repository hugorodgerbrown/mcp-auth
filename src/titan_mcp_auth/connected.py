"""Connected apps: the clients a user has approved and still holds live tokens for.

A client counts as connected while the user holds an unexpired access token
or an unrevoked refresh token for it. Disconnecting revokes both, so the
client's next call is a 401 and it has to ask the user again.
"""

from typing import Any

from django.utils import timezone
from oauth2_provider.models import (
    get_access_token_model,
    get_application_model,
    get_grant_model,
    get_refresh_token_model,
)


def connected_apps(user: Any) -> list[Any]:
    """Return the applications ``user`` is connected to, by name."""
    access = get_access_token_model().objects.filter(user=user, expires__gt=timezone.now())
    refresh = get_refresh_token_model().objects.filter(user=user, revoked__isnull=True)
    ids = set(access.values_list("application_id", flat=True)) | set(
        refresh.values_list("application_id", flat=True)
    )
    return list(get_application_model().objects.filter(pk__in=ids).order_by("name", "pk"))


def disconnect(user: Any, application: Any) -> None:
    """Revoke every code and token ``user`` holds for ``application``."""
    for refresh in get_refresh_token_model().objects.filter(
        user=user, application=application, revoked__isnull=True
    ):
        refresh.revoke()  # also revokes the access token it issued
    for access in get_access_token_model().objects.filter(user=user, application=application):
        access.revoke()
    get_grant_model().objects.filter(user=user, application=application).delete()
