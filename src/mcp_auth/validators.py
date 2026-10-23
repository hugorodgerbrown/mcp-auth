"""Client authentication by signed assertion (RFC 7523 section 2.2) for CIMD clients.

A CIMD client that declares ``private_key_jwt`` (see ``auth_methods``) is
confidential, so the token and revocation endpoints accept it only with a
``client_assertion`` JWT signed by a key from its metadata document. The keys
are fetched with the toolkit's SSRF-hardened CIMD fetcher and cached for the
document's max-age; an unknown ``kid`` refetches them, at most once a minute,
for key rotation.
Each assertion's ``jti`` is single use.

It also holds a client registered by DCR or CIMD to the grants registration
offers (see ``grant_types``), so a client with no user behind it can only be
made by hand.
"""

import hashlib
import json
import logging
import time
from typing import Any
from urllib.parse import urlsplit

from django.core.cache import cache
from django.core.exceptions import DisallowedHost
from django.http import HttpRequest
from jwcrypto import jwk, jws, jwt
from jwcrypto.common import JWException
from oauth2_provider import cimd
from oauth2_provider.oauth2_validators import OAuth2Validator
from oauth2_provider.settings import oauth2_settings

from .auth_methods import PRIVATE_KEY_JWT, SIGNING_ALGORITHMS, check_private_key_jwt
from .grant_types import REGISTERED_GRANT_TYPES

logger = logging.getLogger(__name__)

JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
# How far a clock may drift, and the longest-lived assertion accepted, in seconds.
LEEWAY = 60
MAX_LIFETIME = 60 * 60
REFETCH_SECONDS = 60
CACHE_PREFIX = "mcp_auth:client_assertion:"


class AssertionRefused(Exception):
    """A client assertion was refused. Logged, never returned to the client."""


def _cache_key(kind: str, value: str) -> str:
    """Return a cache key for ``value``, hashed to keep within backend key limits."""
    return CACHE_PREFIX + kind + ":" + hashlib.sha256(value.encode()).hexdigest()


def _fetch_keys(client_id: str) -> tuple[jwk.JWKSet, str | None]:
    """Fetch a client's document and keys; return them with its declared signing alg."""
    fetcher = oauth2_settings.CIMD_METADATA_FETCHER()
    try:
        metadata, max_age = fetcher.fetch(client_id)
        if metadata.get("client_id") != client_id:
            raise AssertionRefused("document client_id does not match")
        if metadata.get("token_endpoint_auth_method") != PRIVATE_KEY_JWT:
            raise AssertionRefused("client no longer declares private_key_jwt")
        check_private_key_jwt(metadata)
        jwks = metadata.get("jwks")
        if jwks is None:
            jwks, keys_age = fetcher.fetch(metadata["jwks_uri"])
            max_age = min(max_age, keys_age)
        keys = jwk.JWKSet.from_json(json.dumps(jwks))
    except (cimd.CIMDError, JWException, ValueError, TypeError) as exc:
        raise AssertionRefused(f"could not load the client's keys: {exc}") from exc
    alg = metadata.get("token_endpoint_auth_signing_alg")
    cache.set(_cache_key("keys", client_id), (keys.export(private_keys=False), alg), max_age)
    return keys, alg


def _keys(client_id: str, kid: str | None) -> tuple[jwk.JWKSet, str | None]:
    """Return a client's keys, from the cache unless missing or lacking ``kid``."""
    cached = cache.get(_cache_key("keys", client_id))
    if cached is not None:
        keys = jwk.JWKSet.from_json(cached[0])
        # An unknown kid refetches, for rotation, at most once a minute a client:
        # otherwise a stream of made-up kids would be a stream of fetches.
        if (
            kid is None
            or keys.get_key(kid) is not None
            or not cache.add(_cache_key("refetch", client_id), True, REFETCH_SECONDS)
        ):
            return keys, cached[1]
    return _fetch_keys(client_id)


def _claims(assertion: str) -> dict[str, Any]:
    """Return an assertion's claims without verifying it, to learn who it claims to be."""
    try:
        token = jws.JWS()
        token.deserialize(assertion)
        claims: dict[str, Any] = json.loads(token.objects["payload"])
    except (JWException, ValueError, KeyError, TypeError) as exc:
        raise AssertionRefused("client_assertion is not a JWS") from exc
    if not isinstance(claims, dict):
        raise AssertionRefused("client_assertion claims are not an object")
    return claims


def verify_assertion(assertion: str, client_id: str, audiences: set[str]) -> None:
    """Verify an RFC 7523 client assertion for ``client_id`` or raise ``AssertionRefused``."""
    token = jws.JWS()
    try:
        token.deserialize(assertion)
        header = token.jose_header
    except (JWException, ValueError, TypeError) as exc:
        raise AssertionRefused("client_assertion is not a JWS") from exc
    alg = header.get("alg")
    if alg not in SIGNING_ALGORITHMS:
        raise AssertionRefused(f"assertion alg {alg!r} is not accepted")
    keys, declared = _keys(client_id, header.get("kid"))
    if declared is not None and alg != declared:
        raise AssertionRefused(f"assertion alg {alg!r} is not the declared {declared!r}")
    try:
        verified = jwt.JWT(jwt=assertion, key=keys, algs=[alg], check_claims=False)
        claims: dict[str, Any] = json.loads(verified.claims)
    except (JWException, ValueError, TypeError) as exc:
        raise AssertionRefused(f"assertion signature did not verify: {exc}") from exc

    if claims.get("iss") != client_id or claims.get("sub") != client_id:
        raise AssertionRefused("assertion iss and sub must both be the client_id")
    aud = claims.get("aud")
    aud = {aud} if isinstance(aud, str) else set(aud) if isinstance(aud, list) else set()
    if not aud & audiences:
        raise AssertionRefused("assertion aud is not this server")
    now = time.time()
    exp = claims.get("exp")
    if not isinstance(exp, int | float) or exp < now - LEEWAY or exp > now + MAX_LIFETIME:
        raise AssertionRefused("assertion exp is missing, past or too far ahead")
    for name in ("iat", "nbf"):
        when = claims.get(name)
        if when is not None and (not isinstance(when, int | float) or when > now + LEEWAY):
            raise AssertionRefused(f"assertion {name} is in the future")
    jti = claims.get("jti")
    if not isinstance(jti, str) or not jti:
        raise AssertionRefused("assertion has no jti")
    # add() only sets a missing key, so a second use of the same jti fails.
    if not cache.add(_cache_key("jti", f"{client_id} {jti}"), True, int(exp - now) + LEEWAY):
        raise AssertionRefused("assertion jti was already used")


def _audiences(request: Any) -> set[str]:
    """The ``aud`` values that name this server: its issuer or the endpoint called.

    The toolkit passes oauthlib a relative URI and the Django request's META as
    headers, so the host comes from those through Django's own ``get_host()``,
    which holds it to ALLOWED_HOSTS: an assertion made for another server can't
    be replayed here by sending its name in the Host header.
    """
    django_request = HttpRequest()
    django_request.META = dict(request.headers)
    try:
        host = django_request.get_host()
    except DisallowedHost as exc:
        raise AssertionRefused("request host is not allowed") from exc
    scheme = "https" if request.headers.get("X_DJANGO_OAUTH_TOOLKIT_SECURE") else "http"
    origin = f"{scheme}://{host}"
    return {origin, origin + "/", origin + urlsplit(request.uri).path}


class Validator(OAuth2Validator):
    """The toolkit's validator, plus private_key_jwt client assertions for CIMD clients."""

    def validate_grant_type(
        self, client_id: str, grant_type: str, client: Any, request: Any, *args: Any, **kwargs: Any
    ) -> bool:
        """Refuse a registered client any grant registration doesn't offer.

        Registration already refuses them; this also covers a row registered
        before it did. ``client_credentials`` and the rest are for clients made
        by hand, in the admin.
        """
        if (
            grant_type not in REGISTERED_GRANT_TYPES
            and request.client.registration_source != request.client.RegistrationSource.MANUAL
        ):
            return False
        allowed: bool = super().validate_grant_type(
            client_id, grant_type, client, request, *args, **kwargs
        )
        return allowed

    def authenticate_client(self, request: Any, *args: Any, **kwargs: Any) -> bool:
        """Authenticate by client assertion when one is sent, else as the toolkit does."""
        assertion_type = request._params.get("client_assertion_type")
        assertion = request._params.get("client_assertion")
        if assertion_type is None and assertion is None:
            authenticated: bool = super().authenticate_client(request, *args, **kwargs)
            # A private_key_jwt client has no secret anyone knows; refuse any other way in.
            if authenticated and self._needs_assertion(request.client):
                return False
            return authenticated
        if assertion_type != JWT_BEARER or not isinstance(assertion, str):
            return False
        try:
            client_id = _claims(assertion).get("iss")
            if not isinstance(client_id, str) or (
                request.client_id and request.client_id != client_id
            ):
                raise AssertionRefused("assertion iss does not match client_id")
            client = self._load_application(client_id, request)
            if client is None or not self._needs_assertion(client):
                raise AssertionRefused("client does not authenticate by private_key_jwt")
            verify_assertion(assertion, client_id, _audiences(request))
        except AssertionRefused as exc:
            logger.info("Client assertion refused: %s", exc)
            return False
        request.client_id = client_id
        return True

    @staticmethod
    def _needs_assertion(client: Any) -> bool:
        """True for a CIMD client registered as confidential, that is, by private_key_jwt."""
        return bool(
            client is not None
            and client.registration_source == client.RegistrationSource.CIMD
            and client.client_type == client.CLIENT_CONFIDENTIAL
        )
