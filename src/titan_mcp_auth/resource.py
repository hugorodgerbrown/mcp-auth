"""``@mcp_endpoint``: a bearer token becomes ``request.user``, or a 401 starts discovery.

The MCP endpoint is the protected resource. A request passes only with an
unexpired access token that carries the project's scope, is bound to this
endpoint (RFC 8707), and belongs to a user the connect rule lets in.
Anything else is a 401 whose WWW-Authenticate header names the
protected-resource metadata for the exact path called, which is how an MCP
client finds where to send the user to sign in. Claude ignores that header
on any status but 401.
"""

from collections.abc import Callable
from functools import wraps
from typing import Any

from django.http import HttpRequest, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from oauth2_provider.oauth2_backends import get_oauthlib_core
from oauth2_provider.www_authenticate import build_bearer_challenge, challenge_status

from .conf import titan_setting
from .policy import can_connect
from .ratelimit import over_limit, too_many_requests

INVALID_TOKEN = {"error": "invalid_token"}


def _no_store(response: HttpResponse) -> HttpResponse:
    """Mark a response as never cacheable: it is per-request, per-user state."""
    response["Cache-Control"] = "no-store"
    return response


def unauthorised(request: HttpRequest, oauth2_error: dict[str, str] | None) -> HttpResponse:
    """The challenge: 401 (or 403 for a scope error) naming this path's resource metadata."""
    metadata = request.build_absolute_uri(f"/.well-known/oauth-protected-resource{request.path}")
    response = HttpResponse(status=challenge_status(oauth2_error))
    response["WWW-Authenticate"] = build_bearer_challenge(
        request, oauth2_error=oauth2_error, resource_metadata_url=metadata
    )
    return _no_store(response)


def mcp_endpoint(view: Callable[..., HttpResponse]) -> Callable[..., HttpResponse]:
    """Require a valid, audience-bound MCP token whose user passes the connect rule.

    The wrapped view runs with ``request.user`` set to the token's user and
    ``request.mcp_token`` to the access token. It is CSRF-exempt: it reads
    only the Authorization header, which a cross-site form cannot set, and
    ignores cookies. Only POST is offered (Streamable HTTP with no
    server-to-client stream).
    """

    @wraps(view)
    def wrapped(request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        if request.method != "POST":
            return HttpResponse(status=405, headers={"Allow": "POST"})
        valid, oauth = get_oauthlib_core().verify_request(request, scopes=[titan_setting("SCOPE")])
        if not valid:
            return unauthorised(request, getattr(oauth, "oauth2_error", None))
        token = oauth.access_token
        # DOT treats a token with no resource as good for any audience. Titan
        # does not: every token must name this endpoint.
        if not token.resource or not can_connect(oauth.user):
            return unauthorised(request, INVALID_TOKEN)
        if over_limit(f"mcp:user:{oauth.user.pk}", titan_setting("USER_RATE_PER_MINUTE")):
            return _no_store(too_many_requests())
        request.user = oauth.user
        request.mcp_token = token  # type: ignore[attr-defined]
        return _no_store(view(request, *args, **kwargs))

    return csrf_exempt(wrapped)  # nosemgrep: bearer header only, see docstring
