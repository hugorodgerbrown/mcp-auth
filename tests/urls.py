"""URLs for the package's tests: the OAuth URLs and a one-method MCP endpoint."""

from django.http import HttpRequest, JsonResponse
from django.urls import include, path

from titan_mcp_auth.resource import mcp_endpoint


@mcp_endpoint
def mcp(request: HttpRequest) -> JsonResponse:
    """Answer any JSON-RPC message with an empty result, naming the user."""
    return JsonResponse(
        {"jsonrpc": "2.0", "id": 1, "result": {"user": request.user.get_username()}}
    )


urlpatterns = [
    path("", include("titan_mcp_auth.urls")),
    path("mcp", mcp, name="mcp"),
]
