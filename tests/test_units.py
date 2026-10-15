"""Tests for the pieces the contract suite doesn't reach: limits, policies, the command."""

import json
from io import StringIO

import pytest
from django.core.cache import cache
from django.core.management import CommandError, call_command
from django.test import RequestFactory
from oauth2_provider.models import get_access_token_model

from mcp_auth import policy
from mcp_auth.conf import oauth2_settings
from mcp_auth.permissions import AllowlistedRedirectRegistration, redirect_uri_allowed
from mcp_auth.ratelimit import over_limit


@pytest.fixture(autouse=True)
def _fresh_cache():
    cache.clear()


@pytest.fixture
def owner(django_user_model):
    return django_user_model.objects.create_superuser("owner", password="pw")


def mint(*args):
    out = StringIO()
    call_command("mint_mcp_token", *args, stdout=out, stderr=StringIO())
    return out.getvalue().strip()


def test_preset_overrides_replace_keys():
    preset = oauth2_settings(
        resource_name="X", scope_description="Y", scope="tally", PKCE_REQUIRED=False
    )
    assert preset["SCOPES"] == {"tally": "Y", "offline_access": "Stay connected"}
    assert preset["PKCE_REQUIRED"] is False


@pytest.mark.parametrize(
    ("uri", "allowed"),
    [
        ("https://claude.ai/api/mcp/auth_callback", True),
        ("https://claude.com/api/mcp/auth_callback", True),
        ("http://localhost:53682/callback", True),
        ("http://127.0.0.1/cb", True),
        ("http://[::1]:9000/cb", False),
        ("https://claude.ai/api/mcp/auth_callback/extra", False),
        ("http://localhost.evil.example/cb", False),
        ("https://chatgpt.com/connector_platform_oauth_redirect", False),
    ],
)
def test_redirect_allowlist(uri, allowed):
    assert redirect_uri_allowed(uri) is allowed


def test_chatgpt_is_opt_in(settings):
    from mcp_auth.conf import CHATGPT_REDIRECT_URI_PATTERNS, DEFAULT_REDIRECT_URI_PATTERNS

    settings.MCP_AUTH = {
        "REDIRECT_URI_PATTERNS": DEFAULT_REDIRECT_URI_PATTERNS + CHATGPT_REDIRECT_URI_PATTERNS
    }
    assert redirect_uri_allowed("https://chatgpt.com/connector_platform_oauth_redirect")


@pytest.mark.parametrize("body", [b"not json", b"[]", json.dumps({"redirect_uris": "x"}).encode()])
def test_registration_with_a_bad_body_is_refused(body):
    request = RequestFactory().post("/oauth/register/", body, content_type="application/json")
    assert AllowlistedRedirectRegistration().has_permission(request) is False


def test_active_user_policy(settings, django_user_model):
    settings.MCP_AUTH = {"CAN_CONNECT": "mcp_auth.policy.active_user"}
    user = django_user_model.objects.create_user("guest")
    assert policy.can_connect(user)
    user.is_active = False
    assert not policy.can_connect(user)
    assert not policy.can_connect(None)


def test_over_limit_counts_per_window(settings):
    assert not any(over_limit("k", 3) for _ in range(3))
    assert over_limit("k", 3)


def test_ip_limit_on_registration(client, settings):
    settings.MCP_AUTH = {**settings.MCP_AUTH, "REGISTER_RATE_PER_MINUTE": 1}
    client.post("/oauth/register/", "{}", content_type="application/json")
    response = client.post("/oauth/register/", "{}", content_type="application/json")
    assert response.status_code == 429
    assert response["Retry-After"] == "60"


def test_user_limit_on_the_mcp_endpoint(client, owner, settings):
    settings.MCP_AUTH = {**settings.MCP_AUTH, "USER_RATE_PER_MINUTE": 1}
    token = mint("--commit", "--resource", "http://testserver/mcp")
    headers = {"Authorization": f"Bearer {token}"}
    assert (
        client.post("/mcp", "{}", content_type="application/json", headers=headers).status_code
        == 200
    )
    assert (
        client.post("/mcp", "{}", content_type="application/json", headers=headers).status_code
        == 429
    )


def test_mint_is_a_dry_run_without_commit(owner):
    assert mint() == ""
    assert not get_access_token_model().objects.exists()


def test_minted_token_calls_the_endpoint(client, owner):
    token = mint(
        "--commit", "--username", "owner", "--resource", "http://testserver/mcp", "-v", "0"
    )
    response = client.post(
        "/mcp", "{}", content_type="application/json", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.json()["result"] == {"user": "owner"}
    client.force_login(owner)
    assert b"Local token (mint_mcp_token)" in client.get("/oauth/connected/").content


def test_mint_refuses(django_user_model, owner):
    with pytest.raises(CommandError, match="No user"):
        mint("--username", "nobody")
    django_user_model.objects.create_user("guest")
    with pytest.raises(CommandError, match="may not connect"):
        mint("--username", "guest")
    django_user_model.objects.create_superuser("second")
    with pytest.raises(CommandError, match="--username"):
        mint()


def test_connected_apps_empty_state(client, owner):
    client.force_login(owner)
    assert b"No apps are connected" in client.get("/oauth/connected/").content


def consent_params(client):
    """Register a loopback client and return the authorize query for it."""
    from mcp_auth.testing import pkce_pair

    reg = client.post(
        "/oauth/register/",
        json.dumps(
            {
                "client_name": "Code",
                "redirect_uris": ["http://localhost:4567/cb"],
                "token_endpoint_auth_method": "none",
            }
        ),
        content_type="application/json",
    ).json()
    _, challenge = pkce_pair()
    return {
        "response_type": "code",
        "client_id": reg["client_id"],
        "redirect_uri": "http://localhost:4567/cb",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "scope": "mcp",
    }


def test_consent_warns_about_a_loopback_callback(client, owner):
    params = consent_params(client)
    client.force_login(owner)
    page = client.get("/oauth/authorize/", params)
    assert b"a program on your own computer" in page.content


def test_consent_says_who_is_signed_in(client, owner):
    owner.email = "owner@example.com"
    owner.save()
    params = consent_params(client)
    client.force_login(owner)
    page = client.get("/oauth/authorize/", params)
    assert b"Signed in as <strong>owner@example.com</strong>" in page.content
    assert page.context["consent_path"].startswith("/oauth/authorize/?")


def test_consent_names_an_account_without_email_by_username(client, owner):
    params = consent_params(client)
    client.force_login(owner)
    page = client.get("/oauth/authorize/", params)
    assert b"Signed in as <strong>owner</strong>" in page.content


def test_switching_account_signs_out_and_returns_to_consent(client, owner):
    params = consent_params(client)
    client.force_login(owner)
    consent = client.get("/oauth/authorize/", params).context["consent_path"]
    response = client.post("/oauth/switch-account/", {"next": consent})
    assert response.status_code == 302
    assert response["Location"] == consent
    assert response["Clear-Site-Data"] == '"cache"'
    assert "_auth_user_id" not in client.session
    # Signed out, the consent page now asks who you are.
    again = client.get(consent)
    assert again.status_code == 302
    assert again["Location"].startswith("/login/")


@pytest.mark.parametrize(
    "next_url",
    ["", "https://evil.example/oauth/authorize/", "//evil.example/oauth/authorize/", "/admin/"],
)
def test_switching_account_only_returns_to_the_consent_page(client, owner, next_url):
    client.force_login(owner)
    response = client.post("/oauth/switch-account/", {"next": next_url})
    assert response["Location"] == "/login/"
    assert "_auth_user_id" not in client.session


def test_switching_account_wants_a_post(client, owner):
    client.force_login(owner)
    assert client.get("/oauth/switch-account/").status_code == 405
    assert "_auth_user_id" in client.session


def test_an_expired_refresh_token_is_not_a_connection(owner):
    import datetime as dt

    from django.utils import timezone
    from oauth2_provider.models import get_application_model, get_refresh_token_model

    from mcp_auth.connected import connected_apps

    app = get_application_model().objects.create(
        name="Old client",
        client_type="public",
        authorization_grant_type="authorization-code",
        redirect_uris="http://localhost:4567/cb",
    )
    refresh = get_refresh_token_model().objects.create(
        user=owner, application=app, token="r1", token_checksum="c1"
    )
    assert connected_apps(owner) == [app]
    get_refresh_token_model().objects.filter(pk=refresh.pk).update(
        created=timezone.now() - dt.timedelta(days=31)
    )
    assert connected_apps(owner) == []
