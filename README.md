# titan-mcp-auth

Shared OAuth 2.1 authentication for Titan's Django MCP servers. One small
Django app on top of [django-oauth-toolkit](https://github.com/jazzband/django-oauth-toolkit)
3.4, so Claude (and Claude Code, and optionally ChatGPT) can add a Titan
project as a connector, and every MCP call runs as a Django user.

Design and the comparison of the three projects it came from:
[Titan MCP Auth](https://claude.ai/artifact/7yrBYbfqs9K7jtrebB1KCQ).

## What a project gets

- `/.well-known/oauth-protected-resource[/<path>]` and
  `/.well-known/oauth-authorization-server` (RFC 9728, RFC 8414)
- `/oauth/authorize/` (consent), `/oauth/token/`, `/oauth/revoke/`,
  `/oauth/register/` (DCR, RFC 7591/7592), CIMD client IDs
- `/oauth/connected/`: the user's connected apps, each with Disconnect
- `@mcp_endpoint`: wraps the project's MCP view
- `mint_mcp_token`: a token for curl in local development
- `titan_mcp_auth.testing.MCPAuthContract`: the contract suite every project runs

## The rules every project inherits

1. The MCP endpoint answers only to a bearer token. No anonymous tier.
2. A token is bound to the project's MCP URL (RFC 8707). A token with no
   resource, or another one, is refused.
3. PKCE S256 is required; only the authorization code and refresh grants exist.
4. A browser is only ever sent to an allowlisted callback: Claude's, or
   loopback on any port. ChatGPT is opt-in.
5. The consent page names the host the code goes to, and warns when it is
   the user's own machine.
6. `TITAN_MCP["CAN_CONNECT"]` runs at consent and on every call, so taking
   a permission away cuts off a user's clients at once.
7. Access tokens last an hour; refresh tokens 30 days, rotating. A replayed
   refresh token revokes the whole family.
8. Only hashes of codes and tokens are stored.
9. Per-IP limits on authorize, token and register; a per-user limit on the
   MCP endpoint.

## Adopting it

```toml
# pyproject.toml
dependencies = ["titan-mcp-auth @ git+https://github.com/hugorodgerbrown/mcp-auth@v0.1.0"]
```

```python
# settings.py
from titan_mcp_auth.conf import oauth2_settings

INSTALLED_APPS += [
    "your_app",  # before titan_mcp_auth, if it overrides its templates
    "titan_mcp_auth",
    "oauth2_provider",
]
OAUTH2_PROVIDER = oauth2_settings(
    resource_name="Your project",
    scope_description="What a connected app can do, in a phrase",
)
TITAN_MCP = {"CAN_CONNECT": "titan_mcp_auth.policy.active_user"}
LOGIN_URL = "/login/"  # the consent page sends signed-out users here
```

```python
# urls.py
urlpatterns = [
    path("", include("titan_mcp_auth.urls")),
    path("mcp", mcp, name="mcp"),
]

# views.py
from titan_mcp_auth.resource import mcp_endpoint


@mcp_endpoint
def mcp(request): ...  # request.user is the token's user; request.mcp_token the access token
```

```python
# tests/test_mcp_auth.py
from titan_mcp_auth.testing import MCPAuthContract


class TestMCPAuth(MCPAuthContract):
    mcp_path = "/mcp"

    def make_allowed_user(self, django_user_model): ...
    def make_refused_user(self, django_user_model): ...
```

Templates to override for the site's look: `titan_mcp_auth/base.html`
(layout), `titan_mcp_auth/authorize.html` (consent, context adds
`redirect_host` and `redirect_is_loopback`) and
`titan_mcp_auth/connected_apps.html`.

## Settings

`TITAN_MCP`, every key optional:

| Key | Default |
|-----|---------|
| `SCOPE` | `"mcp"` (pass the same `scope=` to `oauth2_settings`) |
| `CAN_CONNECT` | `"titan_mcp_auth.policy.active_user"`; also `superuser_only`, or any `user -> bool` |
| `REDIRECT_URI_PATTERNS` | Claude + loopback; add `CHATGPT_REDIRECT_URI_PATTERNS` to opt in |
| `CONSENT_FORM_ACTION` | CSP `form-action` origins for the consent page; must cover every callback |
| `USER_RATE_PER_MINUTE` | 60 MCP calls per user |
| `TOKEN_RATE_PER_MINUTE` | 60 per IP |
| `REGISTER_RATE_PER_MINUTE` | 10 per IP |
| `AUTHORIZE_RATE_PER_MINUTE` | 30 per IP |

The consent page sets its own `form-action` through Django's `csp_override`,
so it needs Django 6's built-in CSP (`SECURE_CSP`). Rate limits use the
default cache; with the per-process LocMemCache they are per worker.

## Local testing

```bash
TOKEN=$(uv run python manage.py mint_mcp_token --commit -v 0)
curl -s -X POST http://localhost:8000/mcp -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"ping"}'
```

## Developing

```bash
uv sync
uv run tox
```

Releases are git tags (`v0.1.0`); projects pin a tag.
