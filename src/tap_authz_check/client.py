"""HTTP client wrapper with redaction, retry and CSRF/refresh support."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any, Final

import httpx

_REDACTED: Final = "[REDACTED]"
_SENSITIVE_HEADERS: Final = {"authorization", "cookie", "set-cookie", "x-xsrf-token"}
_BODY_SNIPPET_LIMIT: Final = 1024
_RETRY_STATUS: Final = {429, 502, 503, 504}
_MUTATING_METHODS: Final = {"POST", "PUT", "PATCH", "DELETE"}
_XSRF_COOKIE_NAME: Final = "XSRF-TOKEN"

RefreshFn = Callable[["HttpClient"], bool]


class HttpClient:
    """Thin wrapper over :class:`httpx.Client` with redaction, retry and CSRF.

    Auth model (post-migration):

    * No ``Authorization`` header is ever sent — backend reads the
      ``TAP_SESSION_JWT`` cookie via ``CookieJwtAuthenticationFilter``.
    * Cookies live in ``httpx.Client``'s jar; initial cookies come from
      ``session.establish_authenticated_client``.
    * For mutating methods, if the jar contains an ``XSRF-TOKEN`` cookie, the
      same value is echoed in the ``X-XSRF-TOKEN`` header (double-submit
      pattern configured in ``WebSecurityConfig.csrfTokenRepository``).
    * On a 401 from a non-public endpoint, the optional ``on_unauthorized``
      hook is invoked once (typically ``session.refresh_session``); on success
      the original request is replayed.
    """

    def __init__(
        self,
        base_url: str,
        timeout_seconds: float,
        delay_ms: int = 0,
        csrf_header: str = "X-XSRF-TOKEN",
        on_unauthorized: RefreshFn | None = None,
    ) -> None:
        self._base_url = base_url
        self._timeout = timeout_seconds
        self._delay_ms = delay_ms
        self._csrf_header = csrf_header
        self._on_unauthorized = on_unauthorized
        self._client = httpx.Client(
            base_url=base_url,
            timeout=timeout_seconds,
            follow_redirects=False,
            headers={"Accept-Encoding": "identity"},
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> HttpClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def get(self, path: str, *, headers: dict[str, str] | None = None) -> Response:
        return self._request("GET", path, headers=headers)

    def request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
        allow_retry: bool = True,
    ) -> Response:
        return self._request(
            method,
            path,
            headers=headers,
            json_body=json_body,
            allow_retry=allow_retry,
        )

    def jar_cookie(self, name: str) -> str | None:
        """Return the current value of ``name`` in the cookie jar (or None)."""
        return self._client.cookies.get(name)

    def set_refresh_hook(self, hook: RefreshFn | None) -> None:
        """Install (or clear) the on-unauthorized refresh hook."""
        self._on_unauthorized = hook

    def _request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None,
        json_body: dict[str, Any] | None = None,
        allow_retry: bool = True,
    ) -> Response:
        merged_headers = self._session_headers(method)
        if headers:
            merged_headers.update(headers)

        response = self._dispatch(method, path, merged_headers, json_body)

        if self._should_refresh(path, response):
            refreshed = bool(self._on_unauthorized and self._on_unauthorized(self))
            if refreshed:
                merged_headers = self._session_headers(method)
                if headers:
                    merged_headers.update(headers)
                response = self._dispatch(method, path, merged_headers, json_body)

        if allow_retry and response.status in _RETRY_STATUS:
            time.sleep(_backoff(1))
            response = self._dispatch(method, path, merged_headers, json_body)

        self._sleep_delay()
        return response

    def _dispatch(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
        json_body: dict[str, Any] | None,
    ) -> Response:
        start = time.monotonic()
        try:
            response = self._client.request(
                method, path, headers=headers, json=json_body
            )
        except httpx.TimeoutException as exc:
            return Response.from_error(path=path, duration_ms=_elapsed(start), reason=str(exc))
        except httpx.HTTPError as exc:
            return Response.from_error(path=path, duration_ms=_elapsed(start), reason=str(exc))
        _normalize_localhost_cookies(self._client)
        return Response.from_httpx(path=path, duration_ms=_elapsed(start), response=response)

    def _session_headers(self, method: str) -> dict[str, str]:
        headers: dict[str, str] = {}
        if method.upper() in _MUTATING_METHODS:
            xsrf = self._client.cookies.get(_XSRF_COOKIE_NAME)
            if xsrf:
                headers[self._csrf_header] = xsrf
        return headers

    @staticmethod
    def _should_refresh(path: str, response: Response) -> bool:
        if response.status != 401:
            return False
        from .session import is_public_auth_path

        return not is_public_auth_path(path)

    def _sleep_delay(self) -> None:
        if self._delay_ms > 0:
            time.sleep(self._delay_ms / 1000)


def _normalize_localhost_cookies(client: httpx.Client) -> None:
    """Rewrite single-label-domain cookies as host-only.

    ``httpx`` and Python's stdlib cookiejar conspire to mangle Set-Cookie
    headers with ``Domain=localhost`` (or ``Domain=127.0.0.1``) issued by
    the Spring backend on local deployments:

    1. httpx's ``_CookieCompatRequest`` reports the host as
       ``localhost:8082`` (with port), so the cookiejar stores the cookie
       with an effective domain of ``localhost.local`` for ``XSRF-TOKEN``
       (no Domain) and ``.localhost`` for the session cookies.
    2. Subsequent requests to ``localhost`` then fail to match, the
       ``Cookie:`` header never carries the session cookie, and protected
       endpoints respond with 401.

    We replace those entries with host-only cookies so they match any port
    on the host. Idempotent: only cookies that actually change are rewritten.
    """
    from http.cookiejar import Cookie

    jar = client.cookies.jar
    for cookie in list(jar):
        stripped = cookie.domain.lstrip(".")
        if stripped.startswith("localhost.local") or (
            cookie.domain_specified and "." not in stripped and stripped
        ):
            replacement = Cookie(
                version=0,
                name=cookie.name,
                value=cookie.value,
                port=None,
                port_specified=False,
                domain="",
                domain_specified=False,
                domain_initial_dot=False,
                path=cookie.path,
                path_specified=cookie.path_specified,
                secure=cookie.secure,
                expires=cookie.expires,
                discard=cookie.discard,
                comment=cookie.comment,
                comment_url=cookie.comment_url,
                rest=cookie._rest,
                rfc2109=False,
            )
            jar.clear(domain=cookie.domain, path=cookie.path, name=cookie.name)
            jar.set_cookie(replacement)


class Response:
    """Sanitized HTTP response wrapper."""

    __slots__ = (
        "body_snippet",
        "duration_ms",
        "error_message",
        "headers",
        "path",
        "status",
    )

    def __init__(
        self,
        path: str,
        status: int | None,
        headers: dict[str, str],
        body_snippet: str,
        duration_ms: int,
        error: str | None,
    ) -> None:
        self.path = path
        self.status = status
        self.headers = headers
        self.body_snippet = body_snippet
        self.duration_ms = duration_ms
        self.error_message = error

    @classmethod
    def from_httpx(cls, *, path: str, duration_ms: int, response: httpx.Response) -> Response:
        snippet = response.text[:_BODY_SNIPPET_LIMIT] if response.text else ""
        return cls(
            path=path,
            status=response.status_code,
            headers=_redact_headers(dict(response.headers)),
            body_snippet=snippet,
            duration_ms=duration_ms,
            error=None,
        )

    @classmethod
    def from_error(cls, *, path: str, duration_ms: int, reason: str) -> Response:
        return cls(
            path=path,
            status=None,
            headers={},
            body_snippet="",
            duration_ms=duration_ms,
            error=reason,
        )

    @property
    def ok(self) -> bool:
        return self.error_message is None and self.status is not None


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        key: (_REDACTED if key.lower() in _SENSITIVE_HEADERS else value)
        for key, value in headers.items()
    }


def _elapsed(start: float) -> int:
    return int((time.monotonic() - start) * 1000)


def _backoff(attempt: int) -> float:
    return 0.25 * (2 ** (attempt - 1))
