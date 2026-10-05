"""The OAuth URLs, included at the site root: ``path("", include("titan_mcp_auth.urls"))``.

Named as django-oauth-toolkit expects, so its metadata views can reverse
them. The well-known documents sit at the root, the rest under /oauth/.
The endpoints anyone can reach without signing in are rate limited per IP.
"""

from django.urls import path
from oauth2_provider import views as oauth_views

from . import views
from .ratelimit import limit_by_ip

app_name = "oauth2_provider"

urlpatterns = [
    path(
        ".well-known/oauth-authorization-server",
        oauth_views.OAuthServerMetadataView.as_view(),
        name="oauth-server-metadata",
    ),
    path(
        ".well-known/oauth-protected-resource",
        oauth_views.OAuthProtectedResourceMetadataView.as_view(),
        name="oauth-resource-metadata",
    ),
    path(
        ".well-known/oauth-protected-resource/<path:resource_path>",
        oauth_views.OAuthProtectedResourceMetadataView.as_view(),
        name="oauth-resource-metadata-path",
    ),
    path(
        "oauth/authorize/",
        limit_by_ip("authorize", "AUTHORIZE_RATE_PER_MINUTE")(views.ConsentView.as_view()),
        name="authorize",
    ),
    path(
        "oauth/token/",
        limit_by_ip("token", "TOKEN_RATE_PER_MINUTE")(oauth_views.TokenView.as_view()),
        name="token",
    ),
    path("oauth/revoke/", oauth_views.RevokeTokenView.as_view(), name="revoke-token"),
    path(
        "oauth/register/",
        limit_by_ip("register", "REGISTER_RATE_PER_MINUTE")(
            oauth_views.DynamicClientRegistrationView.as_view()
        ),
        name="dcr-register",
    ),
    path(
        "oauth/register/<str:client_id>/",
        views.RegistrationManagementView.as_view(),
        name="dcr-register-management",
    ),
    path("oauth/connected/", views.connected_apps_view, name="connected-apps"),
    path(
        "oauth/connected/<int:application_id>/disconnect/",
        views.disconnect_view,
        name="disconnect",
    ),
]
