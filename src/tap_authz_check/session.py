"""Session exchange: turn a Stitch ``session_token`` into API session cookies.

Centralises the cookie bootstrap so the runner, bootstrap and classifier
never have to talk to ``/api/public/auth/*`` directly.

Endpoints (see ``AuthPublicWepApi.java`` + ``WebSecurityConfig.java``):

- ``GET  /api/public/auth/csrf-token``     forces ``XSRF-TOKEN`` cookie + returns
                                           ``{token, headerName, parameterName}``
                                           (CSRF double-submit cookie pattern).
- ``POST /api/public/auth/session``        body ``{"sessionToken": "<stytch>"}``;
                                           on success sets ``TAP_SESSION_JWT`` and
                                           ``TAP_REFRESH_TOKEN`` cookies.
- ``POST /api/public/auth/refresh-token``  body empty (refresh token comes from
                                           the ``TAP_REFRESH_TOKEN`` cookie);
                                           re-issues both session cookies.

The session JWT is short-lived (~5 min). The refresh token is longer (~30 min).
The auto-refresh hook in :class:`HttpClient` calls :func:`refresh_session` once
on 401 from a non-public endpoint.

No secret material is ever logged, printed, or persisted: the session token is
consumed once and discarded; cookie values stay inside ``httpx.Client``'s jar.
"""

from __future__ import annotations

from typing import Final

from .client import HttpClient

PUBLIC_AUTH_PREFIX: Final = "/api/public/auth"

COOKIE_SESSION_JWT: Final = "TAP_SESSION_JWT"
COOKIE_REFRESH_TOKEN: Final = "TAP_REFRESH_TOKEN"
COOKIE_XSRF: Final = "XSRF-TOKEN"

HEADER_XSRF: Final = "X-XSRF-TOKEN"


class SessionExchangeError(RuntimeError):
    """Raised when the backend refuses to issue a session for ``session_token``."""


def ensure_csrf(client: HttpClient) -> str | None:
    """Eagerly force the ``XSRF-TOKEN`` cookie by calling ``GET /csrf-token``.

    Returns the token value reported by the backend (which equals the cookie
    value thanks to ``CookieCsrfTokenRepository``), or ``None`` if the endpoint
    could not be reached. ``HttpClient`` re-reads the jar on every mutating
    request, so the side-effect (cookie set on the response) is what matters.
    """
    response = client.get(f"{PUBLIC_AUTH_PREFIX}/csrf-token")
    if response.error_message is not None:
        return None
    if response.status != 200:
        return None
    return client.jar_cookie(COOKIE_XSRF)


def establish_session(client: HttpClient, session_token: str) -> None:
    """POST ``session_token`` to ``/api/public/auth/session``; capture cookies."""
    if not session_token:
        raise SessionExchangeError(
            "session_token is empty; set TAP_AUTHZ_SESSION_TOKEN or SESSION_TOKEN"
        )
    response = client.request(
        "POST",
        f"{PUBLIC_AUTH_PREFIX}/session",
        json_body={"sessionToken": session_token},
    )
    if response.error_message is not None:
        raise SessionExchangeError(
            f"session exchange transport error: {response.error_message}"
        )
    if response.status != 200:
        snippet = (response.body_snippet or "")[:200]
        raise SessionExchangeError(
            f"session exchange returned {response.status}: {snippet}"
        )
    if not client.jar_cookie(COOKIE_SESSION_JWT):
        raise SessionExchangeError(
            f"session exchange succeeded but no {COOKIE_SESSION_JWT} cookie was set"
        )


def refresh_session(client: HttpClient) -> bool:
    """Call ``POST /refresh-token`` using the refresh cookie in the jar.

    Returns ``True`` if the backend issued a fresh session cookie pair, ``False``
    otherwise (network error, no refresh cookie, backend refused). Never raises
    so callers can decide how to react (typically: retry the original request
    once and stop on second 401).

    After a successful refresh, re-runs ``ensure_csrf`` because the CSRF token
    is derived from the session JWT (see ``SessionDerivedCsrfTokenRepository``)
    and rotates with it.
    """
    if not client.jar_cookie(COOKIE_REFRESH_TOKEN):
        return False
    response = client.request(
        "POST",
        f"{PUBLIC_AUTH_PREFIX}/refresh-token",
        json_body={},
    )
    if response.error_message is not None:
        return False
    if response.status != 200:
        return False
    if not client.jar_cookie(COOKIE_SESSION_JWT):
        return False
    ensure_csrf(client)
    return True


def establish_authenticated_client(
    *,
    base_url: str,
    session_token: str,
    timeout_seconds: float,
    delay_ms: int = 0,
    csrf_header: str = HEADER_XSRF,
    require_csrf: bool = True,
) -> HttpClient:
    """Build a fully authenticated ``HttpClient`` for the given session_token.

    When ``require_csrf`` is ``True`` (default), bootstrap fails with a clear
    error if the backend did not emit an ``XSRF-TOKEN`` cookie — otherwise
    mutating requests would silently 403 in the middle of a suite. Pass
    ``require_csrf=False`` for read-only smoke tests against deployments that
    exempt mutating paths from CSRF.
    """
    if not session_token:
        raise SessionExchangeError(
            "session_token missing: set TAP_AUTHZ_SESSION_TOKEN or SESSION_TOKEN "
            "(alias SESSION_TOKEN also accepted)"
        )
    client = HttpClient(
        base_url=base_url,
        timeout_seconds=timeout_seconds,
        delay_ms=delay_ms,
        csrf_header=csrf_header,
    )
    ensure_csrf(client)
    establish_session(client, session_token)
    if require_csrf and not client.jar_cookie(COOKIE_XSRF):
        client.close()
        raise SessionExchangeError(
            "session bootstrap succeeded but no XSRF-TOKEN cookie was emitted "
            "by /api/public/auth/csrf-token; mutating requests would fail CSRF. "
            "Disable CSRF enforcement with require_csrf=False or fix the backend."
        )
    return client


def is_public_auth_path(path: str) -> bool:
    """True for paths under ``/api/public/auth`` (CSRF ignored, no auth required)."""
    return path.startswith(PUBLIC_AUTH_PREFIX)
