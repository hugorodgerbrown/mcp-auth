"""Accept CIMD clients that prefer an auth method we don't offer but can go public.

ChatGPT's client metadata document (``https://chatgpt.com/oauth/client.json``)
prefers ``private_key_jwt`` in ``token_endpoint_auth_method`` and lists every
method it can use in ``token_endpoint_auth_methods_supported``: ``none`` and
``private_key_jwt``. It picks a method from that list and the ones the server
advertises, which never include ``private_key_jwt``, so it connects as a public
client on PKCE alone.

django-oauth-toolkit reads only the preference and refuses anything but
``none``, so connecting stopped at "Invalid client_id parameter value"
(django-oauth-toolkit issue 1845). When a document's list includes ``none``,
the client is registered as public, as Claude is. A document that doesn't list
``none`` is refused as before. Remove this once the toolkit does it.
"""

import logging
from typing import Any

from oauth2_provider import cimd

logger = logging.getLogger(__name__)

PUBLIC = "none"


def public_if_offered(metadata: dict[str, Any]) -> dict[str, Any]:
    """Return ``metadata`` asking for ``none`` when the client lists it as a method it can use."""
    preferred = metadata.get("token_endpoint_auth_method", PUBLIC)
    offered = metadata.get("token_endpoint_auth_methods_supported")
    if preferred == PUBLIC or not isinstance(offered, list) or PUBLIC not in offered:
        return metadata
    logger.info(
        "CIMD client %r prefers %r; registering it as public, which it also offers",
        metadata.get("client_id"),
        preferred,
    )
    return metadata | {"token_endpoint_auth_method": PUBLIC}


def accept_public_fallback() -> None:
    """Wrap the toolkit's CIMD metadata check so a client offering ``none`` is public."""
    build = cimd._build_application_kwargs
    if getattr(build, "accepts_public_fallback", False):
        return

    def build_application_kwargs(metadata: dict[str, Any]) -> dict[str, Any]:
        """Check ``metadata`` as the toolkit does, after choosing ``none`` where offered."""
        kwargs: dict[str, Any] = build(public_if_offered(metadata))
        return kwargs

    build_application_kwargs.accepts_public_fallback = True  # type: ignore[attr-defined]
    cimd._build_application_kwargs = build_application_kwargs
