"""Accept OAuth clients that list grant types the server doesn't offer.

django-oauth-toolkit turns a client's ``grant_types`` into the single grant
its Application row holds, ignoring only ``refresh_token``. Claude's client
metadata document (``https://claude.ai/oauth/mcp-oauth-client-metadata``)
also lists ``urn:ietf:params:oauth:grant-type:jwt-bearer``, so the toolkit
refused it and connecting stopped at "Invalid client_id parameter value".

RFC 7591 section 2 lets a server register less than a client asks for, so
these grants are ignored like ``refresh_token`` and the client is registered
for the authorization-code grant it also asks for. Remove this once the
toolkit does it.
"""

from oauth2_provider import cimd
from oauth2_provider.views import dynamic_client_registration

# Grants a client may list alongside authorization_code that we never issue.
UNSUPPORTED_GRANT_TYPES = frozenset({"urn:ietf:params:oauth:grant-type:jwt-bearer"})


def ignore_unsupported_grant_types() -> None:
    """Add the unsupported grants to the toolkit's ignored set, for CIMD and DCR alike."""
    cimd.IGNORED_GRANT_TYPES.update(UNSUPPORTED_GRANT_TYPES)
    dynamic_client_registration.IGNORED_GRANT_TYPES.update(UNSUPPORTED_GRANT_TYPES)
