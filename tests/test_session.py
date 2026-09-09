"""Offline tests for the session exchange module."""

from __future__ import annotations

import httpx
import respx

from tap_authz_check.client import HttpClient
from tap_authz_check.session import (
    COOKIE_SESSION_JWT,
    COOKIE_XSRF,
    HEADER_XSRF,
    SessionExchangeError,
    ensure_csrf,
    establish_authenticated_client,
    establish_session,
    is_public_auth_path,
    refresh_session,
)

BASE = "https://api.tap.mirror.capmotion.io"


def _build_client() -> HttpClient:
    return HttpClient(base_url=BASE, timeout_seconds=5.0, delay_ms=0)


def test_ensure_csrf_populates_jar() -> None:
    client = _build_client()
    try:
        with respx.mock(assert_all_called=False) as mock:
            mock.get(f"{BASE}/api/public/auth/csrf-token").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "token": "csrf-xyz",
                        "headerName": HEADER_XSRF,
                        "parameterName": "_csrf",
                    },
                    headers=[("Set-Cookie", "XSRF-TOKEN=csrf-xyz; Path=/")],
                )
            )
            token = ensure_csrf(client)
        assert token == "csrf-xyz"
        assert client.jar_cookie(COOKIE_XSRF) == "csrf-xyz"
    finally:
        client.close()


def test_establish_session_requires_cookie() -> None:
    client = _build_client()
    try:
        with respx.mock(assert_all_called=False) as mock:
            mock.post(f"{BASE}/api/public/auth/session").mock(
                return_value=httpx.Response(200, json={"success": True})
            )
            with __import__("pytest").raises(SessionExchangeError, match="TAP_SESSION_JWT"):
                establish_session(client, "tok-123")
    finally:
        client.close()


def test_establish_session_failure_propagates() -> None:
    client = _build_client()
    try:
        with respx.mock(assert_all_called=False) as mock:
            mock.post(f"{BASE}/api/public/auth/session").mock(
                return_value=httpx.Response(401, json={"error": "invalid"})
            )
            with __import__("pytest").raises(SessionExchangeError, match="401"):
                establish_session(client, "tok-123")
    finally:
        client.close()


def test_refresh_session_returns_false_without_refresh_cookie() -> None:
    client = _build_client()
    try:
        assert refresh_session(client) is False
    finally:
        client.close()


def test_refresh_session_updates_session_cookie() -> None:
    client = _build_client()
    try:
        with respx.mock(assert_all_called=False) as mock:
            mock.post(f"{BASE}/api/public/auth/session").mock(
                return_value=httpx.Response(
                    200,
                    json={"success": True},
                    headers=[
                        (
                            "Set-Cookie",
                            "TAP_SESSION_JWT=jwt-old; Path=/; HttpOnly; Max-Age=300",
                        ),
                        (
                            "Set-Cookie",
                            "TAP_REFRESH_TOKEN=ref-old; Path=/api/public/auth; HttpOnly; Max-Age=1800",
                        ),
                    ],
                )
            )
            establish_session(client, "tok-1")
        with respx.mock(assert_all_called=False) as mock:
            mock.post(f"{BASE}/api/public/auth/refresh-token").mock(
                return_value=httpx.Response(
                    200,
                    json={"success": True},
                    headers=[
                        (
                            "Set-Cookie",
                            "TAP_SESSION_JWT=jwt-new; Path=/; HttpOnly; Max-Age=300",
                        ),
                        (
                            "Set-Cookie",
                            "TAP_REFRESH_TOKEN=ref-new; Path=/api/public/auth; HttpOnly; Max-Age=1800",
                        ),
                    ],
                )
            )
            mock.get(f"{BASE}/api/public/auth/csrf-token").mock(
                return_value=httpx.Response(
                    200,
                    json={"token": "csrf-new", "headerName": HEADER_XSRF, "parameterName": "_csrf"},
                    headers=[("Set-Cookie", "XSRF-TOKEN=csrf-new; Path=/")],
                )
            )
            ok = refresh_session(client)
        assert ok is True
        assert client.jar_cookie(COOKIE_SESSION_JWT) == "jwt-new"
        assert client.jar_cookie(COOKIE_XSRF) == "csrf-new"
    finally:
        client.close()


def test_establish_authenticated_client_runs_full_flow() -> None:
    with respx.mock(assert_all_called=False) as mock:
        mock.get(f"{BASE}/api/public/auth/csrf-token").mock(
            return_value=httpx.Response(
                200,
                json={"token": "csrf", "headerName": HEADER_XSRF, "parameterName": "_csrf"},
                headers=[("Set-Cookie", "XSRF-TOKEN=csrf; Path=/")],
            )
        )
        mock.post(f"{BASE}/api/public/auth/session").mock(
            return_value=httpx.Response(
                200,
                json={"success": True},
                headers=[
                    (
                        "Set-Cookie",
                        "TAP_SESSION_JWT=jwt-final; Path=/; HttpOnly; Max-Age=300",
                    ),
                    (
                        "Set-Cookie",
                        "TAP_REFRESH_TOKEN=ref-final; Path=/api/public/auth; HttpOnly; Max-Age=1800",
                    ),
                ],
            )
        )
        client = establish_authenticated_client(
            base_url=BASE, session_token="abc", timeout_seconds=5.0
        )
    try:
        assert client.jar_cookie(COOKIE_XSRF) == "csrf"
        assert client.jar_cookie(COOKIE_SESSION_JWT) == "jwt-final"
    finally:
        client.close()


def test_establish_authenticated_client_requires_csrf_cookie() -> None:
    """Missing XSRF-TOKEN after exchange is a hard bootstrap error by default."""
    with respx.mock(assert_all_called=False) as mock:
        mock.get(f"{BASE}/api/public/auth/csrf-token").mock(
            return_value=httpx.Response(200, json={"token": "x", "headerName": "X-XSRF-TOKEN", "parameterName": "_csrf"})
        )
        mock.post(f"{BASE}/api/public/auth/session").mock(
            return_value=httpx.Response(
                200,
                json={"success": True},
                headers=[
                    ("Set-Cookie", "TAP_SESSION_JWT=jwt-final; Path=/; HttpOnly; Max-Age=300"),
                    ("Set-Cookie", "TAP_REFRESH_TOKEN=ref-final; Path=/api/public/auth; HttpOnly; Max-Age=1800"),
                ],
            )
        )
        with __import__("pytest").raises(SessionExchangeError, match="XSRF-TOKEN"):
            establish_authenticated_client(
                base_url=BASE, session_token="abc", timeout_seconds=5.0
            )


def test_establish_authenticated_client_can_skip_csrf_requirement() -> None:
    with respx.mock(assert_all_called=False) as mock:
        mock.get(f"{BASE}/api/public/auth/csrf-token").mock(
            return_value=httpx.Response(200, json={"token": "x", "headerName": "X-XSRF-TOKEN", "parameterName": "_csrf"})
        )
        mock.post(f"{BASE}/api/public/auth/session").mock(
            return_value=httpx.Response(
                200,
                json={"success": True},
                headers=[
                    ("Set-Cookie", "TAP_SESSION_JWT=jwt; Path=/; HttpOnly; Max-Age=300"),
                    ("Set-Cookie", "TAP_REFRESH_TOKEN=ref; Path=/api/public/auth; HttpOnly; Max-Age=1800"),
                ],
            )
        )
        client = establish_authenticated_client(
            base_url=BASE, session_token="abc", timeout_seconds=5.0, require_csrf=False
        )
    try:
        assert client.jar_cookie(COOKIE_SESSION_JWT) == "jwt"
    finally:
        client.close()


def test_establish_authenticated_client_rejects_empty_token() -> None:
    with __import__("pytest").raises(SessionExchangeError, match="missing"):
        establish_authenticated_client(base_url=BASE, session_token="", timeout_seconds=5.0)


def test_is_public_auth_path() -> None:
    assert is_public_auth_path("/api/public/auth/session")
    assert is_public_auth_path("/api/public/auth/refresh-token")
    assert is_public_auth_path("/api/public/auth/csrf-token")
    assert not is_public_auth_path("/api/user/me")
    assert not is_public_auth_path("/api/distribution-v2")


def test_normalize_localhost_cookies_rewrites_single_label_domain() -> None:
    """Domain=localhost / localhost.local cookies must become host-only."""
    import httpx

    from tap_authz_check.client import _normalize_localhost_cookies

    client = httpx.Client(base_url="http://localhost:8082", timeout=5.0)
    try:
        response = httpx.Response(
            200,
            headers=[
                ("Set-Cookie", "TAP_SESSION_JWT=jwt; Path=/; Domain=localhost; Max-Age=300"),
                ("Set-Cookie", "TAP_REFRESH_TOKEN=ref; Path=/api/public/auth; Domain=localhost; Max-Age=1800"),
            ],
            request=httpx.Request("POST", "http://localhost:8082/api/public/auth/session"),
        )
        client.cookies.extract_cookies(response)
        _normalize_localhost_cookies(client)
        for cookie in client.cookies.jar:
            assert cookie.domain == "", f"expected host-only, got {cookie.domain!r}"
            assert cookie.domain_specified is False
        # /api/user/me → matches Path=/, must carry TAP_SESSION_JWT
        req = client.build_request("GET", "/api/user/me")
        cookie_header = req.headers.get("cookie") or ""
        assert "TAP_SESSION_JWT=jwt" in cookie_header
        # /api/public/auth/refresh-token → matches both cookies
        req2 = client.build_request("POST", "/api/public/auth/refresh-token")
        cookie_header2 = req2.headers.get("cookie") or ""
        assert "TAP_SESSION_JWT=jwt" in cookie_header2
        assert "TAP_REFRESH_TOKEN=ref" in cookie_header2
    finally:
        client.close()


def test_normalize_localhost_cookies_leaves_fqdn_alone() -> None:
    """Multi-label domains (e.g. ``Domain=api.example.com``) must not be rewritten."""
    import httpx

    from tap_authz_check.client import _normalize_localhost_cookies

    client = httpx.Client(base_url="https://api.example.com", timeout=5.0)
    try:
        response = httpx.Response(
            200,
            headers=[
                ("Set-Cookie", "SID=abc; Path=/; Domain=api.example.com; Max-Age=300"),
            ],
            request=httpx.Request("POST", "https://api.example.com/api/public/auth/session"),
        )
        client.cookies.extract_cookies(response)
        _normalize_localhost_cookies(client)
        domains = [c.domain for c in client.cookies.jar]
        assert any("example.com" in d for d in domains), f"FQDN cookie lost: {domains}"
    finally:
        client.close()
