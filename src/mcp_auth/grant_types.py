"""Register clients for the authorization-code grant, and nothing else.

django-oauth-toolkit turns a client's ``grant_types`` into the single grant
its Application row holds, ignoring only ``refresh_token``. Claude's client
metadata document (``https://claude.ai/oauth/mcp-oauth-client-metadata``)
also lists ``urn:ietf:params:oauth:grant-type:jwt-bearer``, so the toolkit
refused it and connecting stopped at "Invalid client_id parameter value".

RFC 7591 section 2 lets a server register less than a client asks for, so
these grants are ignored like ``refresh_token`` and the client is registered
for the authorization-code grant it also asks for. Remove this once the
toolkit does it.

The toolkit also registers any other grant it knows. Registration is open, so
a client asking for ``client_credentials`` would get a secret and tokens with
no user behind them. Every grant but the authorization code is refused at
registration, by DCR and CIMD alike; ``validators.Validator`` refuses them at
the token endpoint too, for any client not made by hand.
"""

import functools
from typing import Any

from django.http import JsonResponse
from oauth2_provider import cimd
from oauth2_provider.views import dynamic_client_registration

# Grants a client may list alongside authorization_code that we never issue.
UNSUPPORTED_GRANT_TYPES = frozenset({"urn:ietf:params:oauth:grant-type:jwt-bearer"})
# The only grants a client registered by DCR or CIMD may use (RFC 7591 names).
REGISTERED_GRANT_TYPES = frozenset({"authorization_code", "refresh_token"})
# The toolkit's Application.authorization_grant_type for the authorization code.
AUTHORIZATION_CODE = "authorization-code"


def _refused(dot_grant: str) -> str:
    """Say which grant was refused, by its RFC 7591 name."""
    names = {v: k for k, v in dynamic_client_registration.GRANT_TYPE_MAP.items()}
    return f"unsupported grant_type: {names.get(dot_grant, dot_grant)!r}"


def ignore_unsupported_grant_types() -> None:
    """Add the unsupported grants to the toolkit's ignored set, for CIMD and DCR alike."""
    cimd.IGNORED_GRANT_TYPES.update(UNSUPPORTED_GRANT_TYPES)
    dynamic_client_registration.IGNORED_GRANT_TYPES.update(UNSUPPORTED_GRANT_TYPES)


def register_authorization_code_only() -> None:
    """Wrap the toolkit's DCR and CIMD checks to refuse a client for any other grant."""
    dcr_build = dynamic_client_registration._build_application_kwargs
    if not getattr(dcr_build, "authorization_code_only", False):
        # wraps() carries over the flags of wrappers already in place.
        @functools.wraps(dcr_build)
        def build_dcr_kwargs(data: dict[str, Any]) -> tuple[Any, JsonResponse | None]:
            """Check ``data`` as the toolkit does, then refuse any grant but the code."""
            kwargs, error = dcr_build(data)
            if error is None and kwargs["authorization_grant_type"] != AUTHORIZATION_CODE:
                # RFC 7591 section 3.2.2.
                description = _refused(kwargs["authorization_grant_type"])
                return None, JsonResponse(
                    {"error": "invalid_client_metadata", "error_description": description},
                    status=400,
                )
            return kwargs, error

        build_dcr_kwargs.authorization_code_only = True  # type: ignore[attr-defined]
        dynamic_client_registration._build_application_kwargs = build_dcr_kwargs

    cimd_build = cimd._build_application_kwargs
    if not getattr(cimd_build, "authorization_code_only", False):

        @functools.wraps(cimd_build)
        def build_cimd_kwargs(metadata: dict[str, Any]) -> dict[str, Any]:
            """Check ``metadata`` as the toolkit does, then refuse any grant but the code."""
            kwargs: dict[str, Any] = cimd_build(metadata)
            if kwargs["authorization_grant_type"] != AUTHORIZATION_CODE:
                raise cimd.CIMDError(_refused(kwargs["authorization_grant_type"]))
            return kwargs

        build_cimd_kwargs.authorization_code_only = True  # type: ignore[attr-defined]
        cimd._build_application_kwargs = build_cimd_kwargs
