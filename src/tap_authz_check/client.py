"""HTTP client wrapper with redaction, retry and timeout controls."""

from __future__ import annotations

import time
from typing import Any

import httpx

_REDACTED = "[REDACTED]"
_SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie"}
_BODY_SNIPPET_LIMIT = 1024
_RETRY_STATUS = {429, 502, 503, 504}


class HttpClient:
    """Thin wrapper over :class:`httpx.Client` with redaction and retry."""

    def __init__(
        self,
        base_url: str,
        token: str,
        timeout_seconds: float,
        delay_ms: int = 0,
    ) -> None:
        self._base_url = base_url
        self._token = token
        if token:
            try:
                token.encode("ascii")
            except UnicodeEncodeError as exc:
                raise ValueError(
                    "token contains non-ASCII characters; rotate the JWT and ensure it is base64url-only"
                ) from exc
        self._timeout = timeout_seconds
        self._delay_ms = delay_ms
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

    def _request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None,
        json_body: dict[str, Any] | None = None,
        allow_retry: bool = True,
    ) -> Response:
        merged_headers = self._auth_headers()
        if headers:
            merged_headers.update(headers)

        attempt = 0
        max_attempts = 2 if allow_retry else 1
        last_exc: Exception | None = None

        while attempt < max_attempts:
            attempt += 1
            start = time.monotonic()
            try:
                response = self._client.request(
                    method,
                    path,
                    headers=merged_headers,
                    json=json_body,
                )
            except httpx.TimeoutException as exc:
                return Response.from_error(path=path, duration_ms=_elapsed(start), reason=str(exc))
            except httpx.HTTPError as exc:
                return Response.from_error(path=path, duration_ms=_elapsed(start), reason=str(exc))

            if allow_retry and attempt < max_attempts and response.status_code in _RETRY_STATUS:
                time.sleep(_backoff(attempt))
                continue

            self._sleep_delay()
            return Response.from_httpx(path=path, duration_ms=_elapsed(start), response=response)

        if last_exc is not None:
            return Response.from_error(path=path, duration_ms=0, reason=str(last_exc))
        return Response.from_error(path=path, duration_ms=0, reason="exhausted retries")

    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}"} if self._token else {}

    def _sleep_delay(self) -> None:
        if self._delay_ms > 0:
            time.sleep(self._delay_ms / 1000)


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
