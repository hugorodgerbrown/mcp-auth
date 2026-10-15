"""Register CIMD clients that authenticate with ``private_key_jwt``.

ChatGPT's client metadata document (``https://chatgpt.com/oauth/client.json``)
declares ``token_endpoint_auth_method: private_key_jwt`` and publishes its
public keys at ``jwks_uri``. The CIMD draft (section 8.2) makes such a client
confidential: the server MUST require RFC 7523 client authentication with the
key from its document. django-oauth-toolkit 3.4.1 refuses any method but
``none`` (django-oauth-toolkit issue 1845), so connecting stopped at "Invalid
client_id parameter value".

This registers such a client as confidential; ``validators.Validator`` then
accepts it at the token and revocation endpoints only with a client assertion
signed by one of its keys. Remove this once the toolkit does it.
"""

from typing import Any
from urllib.parse import urlparse

from oauth2_provider import cimd
from oauth2_provider.models import get_application_model

PRIVATE_KEY_JWT = "private_key_jwt"
# Asymmetric algorithms only: a shared-secret (HS*) or "none" assertion proves nothing.
SIGNING_ALGORITHMS = ("RS256", "PS256", "ES256")


def keys_location(metadata: dict[str, Any]) -> None:
    """Refuse a document whose keys are missing or hosted away from its client_id.

    Keys come inline (``jwks``) or from ``jwks_uri``, which must be https on the
    client_id's own origin, so the document can't point the server's fetcher
    at another host.
    """
    jwks, jwks_uri = metadata.get("jwks"), metadata.get("jwks_uri")
    if jwks is not None:
        if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
            raise cimd.CIMDError("jwks must be a JSON Web Key Set")
        return
    if not isinstance(jwks_uri, str):
        raise cimd.CIMDError("a private_key_jwt client must publish jwks or jwks_uri")
    keys, client = urlparse(jwks_uri), urlparse(str(metadata.get("client_id")))
    if keys.scheme != "https" or keys.netloc != client.netloc:
        raise cimd.CIMDError("jwks_uri must be https on the client_id's origin")


def check_private_key_jwt(metadata: dict[str, Any]) -> None:
    """Refuse a ``private_key_jwt`` document the validator couldn't verify assertions for."""
    keys_location(metadata)
    alg = metadata.get("token_endpoint_auth_signing_alg")
    if alg is not None and alg not in SIGNING_ALGORITHMS:
        raise cimd.CIMDError(f"unsupported token_endpoint_auth_signing_alg {alg!r}")


def accept_private_key_jwt() -> None:
    """Wrap the toolkit's CIMD check so a private_key_jwt client registers as confidential."""
    build = cimd._build_application_kwargs
    if getattr(build, "accepts_private_key_jwt", False):
        return

    def build_application_kwargs(metadata: dict[str, Any]) -> dict[str, Any]:
        """Check ``metadata`` as the toolkit does; a private_key_jwt client is confidential."""
        if metadata.get("token_endpoint_auth_method") != PRIVATE_KEY_JWT:
            kwargs: dict[str, Any] = build(metadata)
            return kwargs
        check_private_key_jwt(metadata)
        # Every other check (no client_secret, redirect_uris, grants) is the toolkit's.
        kwargs = build(metadata | {"token_endpoint_auth_method": "none"})
        # Applied after the toolkit sets the client public, so this wins.
        kwargs["client_type"] = get_application_model().CLIENT_CONFIDENTIAL
        return kwargs

    build_application_kwargs.accepts_private_key_jwt = True  # type: ignore[attr-defined]
    cimd._build_application_kwargs = build_application_kwargs
