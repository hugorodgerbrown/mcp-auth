"""private_key_jwt for CIMD clients: registration, assertion checks, metadata."""

import json
import time

import pytest
from django.core.cache import cache
from oauth2_provider import cimd
from oauth2_provider.models import get_application_model

from mcp_auth.testing import (
    CHATGPT_CLIENT_ID,
    CHATGPT_METADATA,
    CLAUDE_METADATA,
    JWT_BEARER,
    client_assertion,
    public_jwks,
    serve_client_documents,
    signing_key,
)
from mcp_auth.validators import AssertionRefused, Validator, verify_assertion

TOKEN_URL = "http://testserver/oauth/token/"
AUDIENCES = {"http://testserver", TOKEN_URL}


@pytest.fixture(autouse=True)
def _fresh_cache():
    cache.clear()


@pytest.fixture
def key():
    return signing_key()


@pytest.fixture
def served(monkeypatch, key):
    serve_client_documents(monkeypatch, CHATGPT_METADATA, public_jwks(key))


# ---------- registration ----------


def test_a_private_key_jwt_client_registers_as_confidential():
    kwargs = cimd._build_application_kwargs(CHATGPT_METADATA)
    assert kwargs["client_type"] == "confidential"
    assert kwargs["redirect_uris"] == CHATGPT_METADATA["redirect_uris"][0]


def test_a_public_client_is_unchanged():
    assert "client_type" not in cimd._build_application_kwargs(CLAUDE_METADATA)


@pytest.mark.parametrize(
    "changes",
    [
        pytest.param({"jwks_uri": None}, id="no-keys"),
        pytest.param({"jwks_uri": "https://evil.example/jwks.json"}, id="keys-elsewhere"),
        pytest.param({"jwks_uri": "http://chatgpt.com/oauth/jwks.json"}, id="keys-over-http"),
        pytest.param({"jwks": {"nope": []}}, id="bad-inline-keys"),
        pytest.param({"token_endpoint_auth_signing_alg": "HS256"}, id="shared-secret-alg"),
        pytest.param({"client_secret": "shh"}, id="secret"),
        pytest.param({"token_endpoint_auth_method": "client_secret_post"}, id="secret-method"),
    ],
)
def test_a_document_we_could_not_verify_is_refused(changes):
    metadata = {k: v for k, v in (CHATGPT_METADATA | changes).items() if v is not None}
    with pytest.raises(cimd.CIMDError):
        cimd._build_application_kwargs(metadata)


def test_inline_keys_are_accepted(key):
    metadata = {k: v for k, v in CHATGPT_METADATA.items() if k != "jwks_uri"}
    kwargs = cimd._build_application_kwargs(metadata | {"jwks": public_jwks(key)})
    assert kwargs["client_type"] == "confidential"


def test_the_wrapper_is_installed_once():
    from mcp_auth.auth_methods import accept_private_key_jwt

    wrapped = cimd._build_application_kwargs
    accept_private_key_jwt()
    assert cimd._build_application_kwargs is wrapped


@pytest.mark.django_db
def test_registration_still_refuses_private_key_jwt(client):
    """DCR can't register keys, so only a metadata document may declare private_key_jwt."""
    body = {k: v for k, v in CHATGPT_METADATA.items() if k != "client_id"}
    body["redirect_uris"] = CLAUDE_METADATA["redirect_uris"]
    response = client.post("/oauth/register/", json.dumps(body), "application/json")
    assert response.status_code == 400


@pytest.mark.django_db
def test_metadata_names_the_assertion_algorithms(client):
    doc = client.get("/.well-known/oauth-authorization-server").json()
    assert "private_key_jwt" in doc["token_endpoint_auth_methods_supported"]
    assert doc["token_endpoint_auth_signing_alg_values_supported"] == ["RS256", "PS256", "ES256"]
    assert doc["revocation_endpoint_auth_signing_alg_values_supported"] == [
        "RS256",
        "PS256",
        "ES256",
    ]


# ---------- the assertion ----------


def test_a_good_assertion_verifies_once(served, key):
    assertion = client_assertion(key, TOKEN_URL)
    verify_assertion(assertion, CHATGPT_CLIENT_ID, AUDIENCES)
    with pytest.raises(AssertionRefused, match="already used"):
        verify_assertion(assertion, CHATGPT_CLIENT_ID, AUDIENCES)


@pytest.mark.parametrize(
    ("claims", "reason"),
    [
        pytest.param({"iss": "https://evil.example/c.json"}, "iss and sub", id="iss"),
        pytest.param({"sub": "someone"}, "iss and sub", id="sub"),
        pytest.param({"aud": "https://elsewhere.example"}, "aud", id="aud"),
        pytest.param({"aud": ["https://elsewhere.example", TOKEN_URL]}, None, id="aud-list"),
        pytest.param({"aud": 3}, "aud", id="aud-type"),
        pytest.param({"exp": int(time.time()) - 600}, "exp", id="expired"),
        pytest.param({"exp": int(time.time()) + 7200}, "exp", id="exp-too-far"),
        pytest.param({"exp": "soon"}, "exp", id="exp-type"),
        pytest.param({"iat": int(time.time()) + 600}, "iat", id="iat-future"),
        pytest.param({"nbf": int(time.time()) + 600}, "nbf", id="nbf-future"),
        pytest.param({"jti": ""}, "jti", id="no-jti"),
    ],
)
def test_claims_are_checked(served, key, claims, reason):
    assertion = client_assertion(key, TOKEN_URL, **claims)
    if reason is None:
        verify_assertion(assertion, CHATGPT_CLIENT_ID, AUDIENCES)
        return
    with pytest.raises(AssertionRefused, match=reason):
        verify_assertion(assertion, CHATGPT_CLIENT_ID, AUDIENCES)


def test_a_key_the_client_did_not_publish_is_refused(served):
    with pytest.raises(AssertionRefused, match="signature"):
        verify_assertion(client_assertion(signing_key(), TOKEN_URL), CHATGPT_CLIENT_ID, AUDIENCES)


def test_a_shared_secret_alg_is_refused(served):
    from jwcrypto import jwk, jwt

    secret = jwk.JWK.generate(kty="oct", size=256)
    token = jwt.JWT(header={"alg": "HS256"}, claims={"iss": CHATGPT_CLIENT_ID})
    token.make_signed_token(secret)
    with pytest.raises(AssertionRefused, match="alg"):
        verify_assertion(token.serialize(), CHATGPT_CLIENT_ID, AUDIENCES)


def test_an_alg_other_than_the_declared_one_is_refused(monkeypatch, key):
    serve_client_documents(
        monkeypatch,
        CHATGPT_METADATA | {"token_endpoint_auth_signing_alg": "ES256"},
        public_jwks(key),
    )
    with pytest.raises(AssertionRefused, match="declared"):
        verify_assertion(client_assertion(key, TOKEN_URL), CHATGPT_CLIENT_ID, AUDIENCES)


def test_a_rotated_key_is_fetched_again(monkeypatch, key):
    serve_client_documents(monkeypatch, CHATGPT_METADATA, public_jwks(key))
    verify_assertion(client_assertion(key, TOKEN_URL), CHATGPT_CLIENT_ID, AUDIENCES)
    rotated = signing_key(kid="next-key")
    serve_client_documents(monkeypatch, CHATGPT_METADATA, public_jwks(rotated))
    verify_assertion(client_assertion(rotated, TOKEN_URL), CHATGPT_CLIENT_ID, AUDIENCES)


def test_unknown_kids_refetch_at_most_once_a_minute(monkeypatch, key):
    serve_client_documents(monkeypatch, CHATGPT_METADATA, public_jwks(key))
    verify_assertion(client_assertion(key, TOKEN_URL), CHATGPT_CLIENT_ID, AUDIENCES)
    fetches = []
    monkeypatch.setattr(
        cimd.SafeMetadataFetcher, "fetch", lambda self, url: fetches.append(url) or ({}, 60)
    )
    for kid in ("made-up-1", "made-up-2", "made-up-3"):
        with pytest.raises(AssertionRefused):
            verify_assertion(
                client_assertion(signing_key(kid=kid), TOKEN_URL), CHATGPT_CLIENT_ID, AUDIENCES
            )
    assert fetches == [CHATGPT_CLIENT_ID]


@pytest.mark.parametrize(
    "metadata",
    [
        pytest.param(CHATGPT_METADATA | {"client_id": "https://other.example/c.json"}, id="id"),
        pytest.param(CHATGPT_METADATA | {"token_endpoint_auth_method": "none"}, id="went-public"),
    ],
)
def test_a_changed_document_is_refused(monkeypatch, key, metadata):
    serve_client_documents(monkeypatch, metadata, public_jwks(key))
    with pytest.raises(AssertionRefused, match=r"does not match|no longer declares"):
        verify_assertion(client_assertion(key, TOKEN_URL), CHATGPT_CLIENT_ID, AUDIENCES)


def test_a_failed_fetch_is_refused(monkeypatch, key):
    def fail(self, url):
        raise cimd.CIMDError("down")

    monkeypatch.setattr(cimd.SafeMetadataFetcher, "fetch", fail)
    with pytest.raises(AssertionRefused, match="keys"):
        verify_assertion(client_assertion(key, TOKEN_URL), CHATGPT_CLIENT_ID, AUDIENCES)


def test_rubbish_is_not_an_assertion(served):
    with pytest.raises(AssertionRefused, match="JWS"):
        verify_assertion("not.a.jwt", CHATGPT_CLIENT_ID, AUDIENCES)


# ---------- the validator ----------


def oauthlib_request(headers=None, **body):
    from oauthlib.common import Request

    headers = headers or {"HTTP_HOST": "testserver"}
    return Request("/oauth/token/", http_method="POST", body=body, headers=headers)


@pytest.fixture
def chatgpt(db, served):
    app = cimd.resolve_cimd_application(CHATGPT_CLIENT_ID, request=None)
    assert app is not None
    assert app.client_type == "confidential"
    return app


def test_the_validator_accepts_a_signed_client(chatgpt, key):
    request = oauthlib_request(
        client_assertion_type=JWT_BEARER, client_assertion=client_assertion(key, TOKEN_URL)
    )
    assert Validator().authenticate_client(request) is True
    assert request.client == chatgpt
    assert request.client_id == CHATGPT_CLIENT_ID


@pytest.mark.parametrize(
    "body",
    [
        pytest.param({"client_assertion_type": "urn:other"}, id="other-type"),
        pytest.param({"client_assertion_type": JWT_BEARER}, id="no-assertion"),
        pytest.param({"client_id": CHATGPT_CLIENT_ID}, id="client-id-only"),
        pytest.param(
            {"client_id": CHATGPT_CLIENT_ID, "client_secret": "guess"}, id="client-secret"
        ),
    ],
)
def test_the_validator_refuses_anything_but_an_assertion(chatgpt, body):
    assert Validator().authenticate_client(oauthlib_request(**body)) is False


def test_the_validator_refuses_a_mismatched_client_id(chatgpt, key):
    request = oauthlib_request(
        client_id="someone-else",
        client_assertion_type=JWT_BEARER,
        client_assertion=client_assertion(key, TOKEN_URL),
    )
    assert Validator().authenticate_client(request) is False


def test_the_validator_refuses_a_host_outside_allowed_hosts(chatgpt, key):
    """An assertion ChatGPT made for another server can't be replayed by naming that server."""
    request = oauthlib_request(
        headers={"HTTP_HOST": "evil.example"},
        client_assertion_type=JWT_BEARER,
        client_assertion=client_assertion(key, "http://evil.example/oauth/token/"),
    )
    assert Validator().authenticate_client(request) is False


@pytest.mark.django_db
def test_the_validator_refuses_an_assertion_for_a_client_without_keys(key):
    app = get_application_model().objects.create(
        name="Plain",
        client_type="confidential",
        authorization_grant_type="authorization-code",
        redirect_uris="https://claude.ai/api/mcp/auth_callback",
    )
    request = oauthlib_request(
        client_assertion_type=JWT_BEARER,
        client_assertion=client_assertion(key, TOKEN_URL, client_id=app.client_id),
    )
    assert Validator().authenticate_client(request) is False


@pytest.mark.django_db
def test_the_validator_still_takes_a_secret_from_a_registered_client():
    app = get_application_model().objects.create(
        name="Plain",
        client_type="confidential",
        authorization_grant_type="authorization-code",
        redirect_uris="https://claude.ai/api/mcp/auth_callback",
        client_secret="s3cret",
    )
    request = oauthlib_request(client_id=app.client_id, client_secret="s3cret")
    assert Validator().authenticate_client(request) is True


@pytest.mark.parametrize("assertion", ["garbage", "payload-not-object"])
def test_the_validator_refuses_an_unreadable_assertion(chatgpt, key, assertion):
    if assertion == "payload-not-object":
        from jwcrypto import jws

        signed = jws.JWS(b"[]")
        signed.add_signature(key, alg="RS256", protected={"alg": "RS256"})
        assertion = signed.serialize(compact=True)
    request = oauthlib_request(client_assertion_type=JWT_BEARER, client_assertion=assertion)
    assert Validator().authenticate_client(request) is False


def test_the_validator_refuses_a_secret_for_a_private_key_jwt_client(chatgpt):
    """Even a correct secret can't stand in for the key the client declared."""
    chatgpt.client_secret = "known"
    chatgpt.save()
    request = oauthlib_request(client_id=CHATGPT_CLIENT_ID, client_secret="known")
    assert Validator().authenticate_client(request) is False
