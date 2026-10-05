"""The MCP auth contract: Claude's connector requirements, run against a project's own URLs.

Every Titan project runs it in its own suite, so a settings or URL change
that breaks a connector fails that project's build::

    from titan_mcp_auth.testing import MCPAuthContract

    class TestMCPAuth(MCPAuthContract):
        mcp_path = "/mcp"

        def make_allowed_user(self, django_user_model):
            return django_user_model.objects.create_superuser("owner", password="pw")

        def make_refused_user(self, django_user_model):
            return django_user_model.objects.create_user("guest", password="pw")

Needs pytest-django. The MCP view must answer a JSON-RPC ``ping``.
"""

import base64
import datetime as dt
import hashlib
import json
import secrets
from urllib.parse import parse_qs, urlparse

import pytest
from django.core.cache import cache
from django.utils import timezone
from oauth2_provider.models import (
    get_access_token_model,
    get_application_model,
    set_token_value,
)

from .conf import titan_setting

CALLBACK = "https://claude.ai/api/mcp/auth_callback"
OFF_LIST = "https://evil.example/callback"
PING = {"jsonrpc": "2.0", "id": 1, "method": "ping"}


def pkce_pair() -> tuple[str, str]:
    """Return a PKCE (verifier, S256 challenge)."""
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode()).digest()
    return verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


@pytest.mark.django_db
class MCPAuthContract:
    """Subclass, set ``mcp_path`` and the two user factories."""

    mcp_path = "/mcp"

    def make_allowed_user(self, django_user_model):
        """A user the project's connect rule lets in."""
        raise NotImplementedError

    def make_refused_user(self, django_user_model):
        """A user the project's connect rule shuts out."""
        raise NotImplementedError

    @pytest.fixture(autouse=True)
    def _fresh_rate_limits(self):
        """Rate-limit counters live in the cache; start each test with none."""
        cache.clear()

    # ---------- helpers ----------

    @property
    def mcp_url(self) -> str:
        return f"http://testserver{self.mcp_path}"

    def call(self, client, token, body=PING):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return client.post(
            self.mcp_path, data=json.dumps(body), content_type="application/json", headers=headers
        )

    def token_for(self, user, resource=None, expires_in=3600):
        app = get_application_model().objects.create(
            name="Claude",
            client_type="public",
            authorization_grant_type="authorization-code",
            redirect_uris=CALLBACK,
        )
        raw = secrets.token_urlsafe(32)
        token = get_access_token_model()(
            user=user,
            application=app,
            scope=titan_setting("SCOPE"),
            resource=[] if resource == "" else [resource or self.mcp_url],
            expires=timezone.now() + dt.timedelta(seconds=expires_in),
        )
        set_token_value(token, raw)
        token.save()
        return raw

    def register(self, client, redirect_uris):
        return client.post(
            "/oauth/register/",
            data=json.dumps(
                {
                    "client_name": "Claude",
                    "redirect_uris": redirect_uris,
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                    "token_endpoint_auth_method": "none",
                }
            ),
            content_type="application/json",
        )

    def authorize_params(self, client_id, challenge, redirect_uri=CALLBACK):
        return {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "xyz",
            "scope": f"{titan_setting('SCOPE')} offline_access",
            "resource": self.mcp_url,
        }

    # ---------- discovery ----------

    def test_no_token_is_a_401_naming_the_resource_metadata(self, client):
        response = self.call(client, None)
        assert response.status_code == 401
        expected = f"http://testserver/.well-known/oauth-protected-resource{self.mcp_path}"
        assert f'resource_metadata="{expected}"' in response["WWW-Authenticate"]
        assert response["Cache-Control"] == "no-store"

    def test_resource_metadata_echoes_the_url_called(self, client):
        doc = client.get(f"/.well-known/oauth-protected-resource{self.mcp_path}").json()
        assert doc["resource"] == self.mcp_url
        assert doc["authorization_servers"] == ["http://testserver"]

    def test_server_metadata_is_what_claude_needs(self, client):
        doc = client.get("/.well-known/oauth-authorization-server").json()
        assert doc["issuer"] == "http://testserver"
        assert doc["code_challenge_methods_supported"] == ["S256"]
        assert doc["grant_types_supported"] == ["authorization_code", "refresh_token"]
        assert doc["response_types_supported"] == ["code"]
        assert "none" in doc["token_endpoint_auth_methods_supported"]
        assert doc["client_id_metadata_document_supported"] is True
        assert "offline_access" in doc["scopes_supported"]
        assert doc["registration_endpoint"] == "http://testserver/oauth/register/"

    # ---------- registration and consent ----------

    @pytest.mark.parametrize(
        "uris",
        [
            [OFF_LIST],
            [CALLBACK, OFF_LIST],
            ["https://claude.ai.evil.example/api/mcp/auth_callback"],
            [],
        ],
    )
    def test_registration_refuses_callbacks_off_the_allowlist(self, client, uris):
        assert self.register(client, uris).status_code == 401
        assert not get_application_model().objects.exists()

    def test_registration_accepts_claude_and_loopback(self, client):
        assert self.register(client, [CALLBACK]).status_code == 201
        assert self.register(client, ["http://localhost:4567/callback"]).status_code == 201

    def test_registration_update_keeps_the_allowlist(self, client):
        reg = self.register(client, ["http://localhost:4567/callback"]).json()
        path = f"/oauth/register/{reg['client_id']}/"
        headers = {"Authorization": f"Bearer {reg['registration_access_token']}"}
        body = {"redirect_uris": [OFF_LIST], "token_endpoint_auth_method": "none"}
        response = client.put(path, json.dumps(body), "application/json", headers=headers)
        assert response.status_code == 400

    def test_authorize_needs_pkce(self, client, django_user_model):
        reg = self.register(client, [CALLBACK]).json()
        client.force_login(self.make_allowed_user(django_user_model))
        params = {"response_type": "code", "client_id": reg["client_id"], "redirect_uri": CALLBACK}
        response = client.get("/oauth/authorize/", params)
        assert response.status_code == 302
        assert "error=invalid_request" in response["Location"]
        assert "code=" not in response["Location"]

    def test_signed_out_user_goes_to_sign_in(self, client):
        reg = self.register(client, [CALLBACK]).json()
        _, challenge = pkce_pair()
        response = client.get(
            "/oauth/authorize/", self.authorize_params(reg["client_id"], challenge)
        )
        assert response.status_code == 302
        assert "/oauth/authorize/" in response["Location"]  # in the ?next= back

    def test_refused_user_cannot_consent(self, client, django_user_model):
        reg = self.register(client, [CALLBACK]).json()
        client.force_login(self.make_refused_user(django_user_model))
        _, challenge = pkce_pair()
        response = client.get(
            "/oauth/authorize/", self.authorize_params(reg["client_id"], challenge)
        )
        assert response.status_code == 403

    def test_consent_refuses_a_callback_off_the_allowlist(self, client, django_user_model):
        app = get_application_model().objects.create(
            name="Sneaky",
            client_type="public",
            authorization_grant_type="authorization-code",
            redirect_uris=OFF_LIST,
        )
        client.force_login(self.make_allowed_user(django_user_model))
        _, challenge = pkce_pair()
        params = self.authorize_params(app.client_id, challenge, redirect_uri=OFF_LIST)
        assert client.get("/oauth/authorize/", params).status_code == 403

    def test_consent_page_names_the_callback_host(self, client, django_user_model):
        reg = self.register(client, [CALLBACK]).json()
        client.force_login(self.make_allowed_user(django_user_model))
        _, challenge = pkce_pair()
        page = client.get("/oauth/authorize/", self.authorize_params(reg["client_id"], challenge))
        assert page.status_code == 200
        assert b"claude.ai" in page.content
        assert "https://claude.ai" in page.get("Content-Security-Policy", "https://claude.ai")

    # ---------- the whole connection ----------

    def test_connect_call_refresh_and_replay(self, client, django_user_model):
        """Register, consent, swap the code, call, refresh, then replay the old refresh token."""
        user = self.make_allowed_user(django_user_model)
        client_id = self.register(client, [CALLBACK]).json()["client_id"]
        verifier, challenge = pkce_pair()
        params = self.authorize_params(client_id, challenge)

        client.force_login(user)
        form = client.get("/oauth/authorize/", params).context["form"].initial
        approved = client.post(
            "/oauth/authorize/", {**{k: v for k, v in form.items() if v}, "allow": "Authorize"}
        )
        assert approved.status_code == 302
        back = urlparse(approved["Location"])
        assert f"{back.scheme}://{back.netloc}{back.path}" == CALLBACK
        query = parse_qs(back.query)
        assert query["state"] == ["xyz"]
        assert query["iss"] == ["http://testserver"]
        client.logout()

        exchange = {
            "grant_type": "authorization_code",
            "code": query["code"][0],
            "redirect_uri": CALLBACK,
            "client_id": client_id,
            "code_verifier": verifier,
            "resource": self.mcp_url,
        }
        tokens = client.post("/oauth/token/", exchange)
        assert tokens.status_code == 200, tokens.content
        assert self.call(client, tokens.json()["access_token"]).status_code == 200
        # A code is single use.
        assert client.post("/oauth/token/", exchange).status_code == 400

        first_refresh = tokens.json()["refresh_token"]
        refresh = {"grant_type": "refresh_token", "client_id": client_id}
        refreshed = client.post("/oauth/token/", {**refresh, "refresh_token": first_refresh})
        assert refreshed.status_code == 200, refreshed.content
        assert self.call(client, refreshed.json()["access_token"]).status_code == 200

        # Replaying the spent refresh token signs the whole connection out.
        replay = client.post("/oauth/token/", {**refresh, "refresh_token": first_refresh})
        assert replay.status_code == 400
        assert self.call(client, refreshed.json()["access_token"]).status_code == 401

    # ---------- the resource ----------

    def test_token_for_an_allowed_user_works(self, client, django_user_model):
        token = self.token_for(self.make_allowed_user(django_user_model))
        assert self.call(client, token).status_code == 200

    def test_token_for_a_refused_user_is_refused(self, client, django_user_model):
        token = self.token_for(self.make_refused_user(django_user_model))
        response = self.call(client, token)
        assert response.status_code == 401
        assert 'error="invalid_token"' in response["WWW-Authenticate"]

    def test_token_with_no_resource_is_refused(self, client, django_user_model):
        token = self.token_for(self.make_allowed_user(django_user_model), resource="")
        assert self.call(client, token).status_code == 401

    def test_token_for_another_resource_is_refused(self, client, django_user_model):
        user = self.make_allowed_user(django_user_model)
        token = self.token_for(user, resource="https://elsewhere.example/mcp")
        assert self.call(client, token).status_code == 401

    def test_expired_token_is_refused(self, client, django_user_model):
        token = self.token_for(self.make_allowed_user(django_user_model), expires_in=-1)
        assert self.call(client, token).status_code == 401

    def test_token_in_the_query_string_is_refused(self, client, django_user_model):
        token = self.token_for(self.make_allowed_user(django_user_model))
        response = client.post(
            f"{self.mcp_path}?access_token={token}",
            data=json.dumps(PING),
            content_type="application/json",
        )
        assert response.status_code == 401

    def test_only_post_is_offered(self, client, django_user_model):
        token = self.token_for(self.make_allowed_user(django_user_model))
        response = client.get(self.mcp_path, headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 405
        assert response["Allow"] == "POST"

    def test_disconnect_revokes_the_connection(self, client, django_user_model):
        user = self.make_allowed_user(django_user_model)
        token = self.token_for(user)
        client.force_login(user)
        app = get_application_model().objects.get()
        assert app.name.encode() in client.get("/oauth/connected/").content
        client.post(f"/oauth/connected/{app.pk}/disconnect/")
        client.logout()
        assert self.call(client, token).status_code == 401
