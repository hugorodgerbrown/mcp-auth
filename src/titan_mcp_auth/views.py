"""The consent page, the RFC 7592 update guard, and the connected-apps page.

Everything else under /oauth/ and /.well-known/ is django-oauth-toolkit's own
views, mounted by ``titan_mcp_auth.urls``.
"""

from typing import Any

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.http import HttpRequest, HttpResponse, HttpResponseBase, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.csp import CSP
from django.views.decorators.csp import csp_override
from django.views.decorators.http import require_POST
from oauth2_provider import views as oauth_views

from .conf import titan_setting
from .connected import connected_apps, disconnect
from .permissions import redirect_uri_allowed, registration_allowed
from .policy import can_connect


def _consent_csp() -> dict[str, Any]:
    """The site's CSP with form-action widened to the allowlisted callbacks.

    Browsers apply form-action to the redirect that follows a form post, so
    without this Allow would be blocked on its way back to the client.
    """
    policy = dict(getattr(settings, "SECURE_CSP", {}))
    policy["form-action"] = [CSP.SELF, *titan_setting("CONSENT_FORM_ACTION")]
    return policy


class ConsentView(oauth_views.AuthorizationView):
    """DOT's authorize view, held to the project's connect rule and the redirect allowlist."""

    template_name = "titan_mcp_auth/authorize.html"

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        """Refuse a user the rule shuts out, and any callback off the allowlist."""
        if request.user.is_authenticated and not can_connect(request.user):
            raise PermissionDenied
        # Belt and braces: whatever a client registered, or whatever its CIMD
        # document says, the code only ever goes to an allowlisted callback.
        redirect_uri = request.GET.get("redirect_uri") or request.POST.get("redirect_uri")
        if redirect_uri and not redirect_uri_allowed(redirect_uri):
            raise PermissionDenied
        view = csp_override(_consent_csp())(super().dispatch)
        response: HttpResponseBase = view(request, *args, **kwargs)
        return response

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add the callback host and whether it is the user's own machine."""
        context: dict[str, Any] = super().get_context_data(**kwargs)
        form = context.get("form")
        uri = str(form["redirect_uri"].value() or "") if form is not None else ""
        host = uri.split("://", 1)[-1].split("/", 1)[0]
        context["redirect_host"] = host
        context["redirect_is_loopback"] = host.split(":", 1)[0] in (
            "localhost",
            "127.0.0.1",
            "[::1]",
        )
        return context


class RegistrationManagementView(oauth_views.DynamicClientRegistrationManagementView):
    """RFC 7592 updates, held to the same allowlist as registration.

    DOT checks only the registration token on PUT, so without this a client
    could register a loopback callback and then swap in any URL.
    """

    def put(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        """Refuse an update that names a callback off the allowlist."""
        if not registration_allowed(request):
            return JsonResponse(
                {
                    "error": "invalid_redirect_uri",
                    "error_description": "Redirect URIs must be on this server's allowlist.",
                },
                status=400,
            )
        response: HttpResponse = super().put(request, *args, **kwargs)
        return response


@login_required
def connected_apps_view(request: HttpRequest) -> HttpResponse:
    """List the clients this user has connected, each with a Disconnect button."""
    return render(
        request, "titan_mcp_auth/connected_apps.html", {"apps": connected_apps(request.user)}
    )


@login_required
@require_POST
def disconnect_view(request: HttpRequest, application_id: int) -> HttpResponse:
    """Revoke every token this user holds for one client."""
    from oauth2_provider.models import get_application_model

    application = get_object_or_404(get_application_model(), pk=application_id)
    disconnect(request.user, application)
    return redirect("oauth2_provider:connected-apps")
