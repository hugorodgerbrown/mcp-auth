"""A fixed-window rate limit on Django's cache.

Deliberately small: no dependency, and it uses whatever cache the project
configures. With the default per-process LocMemCache the limit is per worker,
which still bounds guessing from one address.
"""

import time
from collections.abc import Callable
from functools import wraps
from typing import Any

from django.core.cache import cache
from django.http import HttpRequest, HttpResponse, JsonResponse

from .conf import titan_setting

WINDOW_SECONDS = 60


def over_limit(key: str, per_minute: int) -> bool:
    """Count one hit against ``key`` and return whether it is over ``per_minute``."""
    bucket = f"titan_mcp_auth:{key}:{int(time.time()) // WINDOW_SECONDS}"
    cache.add(bucket, 0, WINDOW_SECONDS)
    try:
        hits = cache.incr(bucket)
    except ValueError:  # evicted between add and incr
        cache.set(bucket, 1, WINDOW_SECONDS)
        hits = 1
    return hits > per_minute


def client_ip(request: HttpRequest) -> str:
    """The address the request came from, as Django sees it."""
    return str(request.META.get("REMOTE_ADDR", ""))


def too_many_requests() -> HttpResponse:
    """The 429 every limit answers with."""
    response = JsonResponse({"error": "rate_limited"}, status=429)
    response["Retry-After"] = str(WINDOW_SECONDS)
    return response


def limit_by_ip(group: str, setting: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Limit a view per client IP to TITAN_MCP[setting] requests a minute."""

    def decorator(view: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(view)
        def wrapped(request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
            if over_limit(f"{group}:{client_ip(request)}", titan_setting(setting)):
                return too_many_requests()
            return view(request, *args, **kwargs)

        return wrapped

    return decorator
