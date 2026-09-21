"""Offline tests for the runner using respx to mock HTTP traffic."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
import respx

from tap_authz_check.config import RunMode, Settings
from tap_authz_check.models import Classification
from tap_authz_check.runner import Runner

BASE = "https://api.tap.mirror.capmotion.io"
SESSION_TOKEN = "fake-session-token"


def _settings(**overrides: object) -> Settings:
    defaults = dict(
        base_url=BASE,
        session_token=SESSION_TOKEN,
        admin_session_token="",
        fixture_file=Path("fixtures/mirror.example.yaml"),
        timeout_seconds=5.0,
        mode=RunMode.AUDIT,
        delay_ms=0,
    )
    defaults.update(overrides)
    return Settings(**defaults)  # type: ignore[arg-type]


def _me_payload() -> dict:
    return {
        "id": "seller@example.test",
        "name": "Mark Seller",
        "companyName": "Test",
        "isAdmin": False,
        "clients": [{"client": "provider-A"}],
    }


def _mock_session_exchange(mock: respx.MockRouter, *, user_is_admin: bool = False) -> None:
    """Mock the Stitch→cookies exchange and the actor snapshot."""
    csrf_route = mock.get(f"{BASE}/api/public/auth/csrf-token").mock(
        return_value=httpx.Response(
            200,
            json={"token": "csrf-abc", "headerName": "X-XSRF-TOKEN", "parameterName": "_csrf"},
            headers=[("Set-Cookie", "XSRF-TOKEN=csrf-abc; Path=/")],
        )
    )
    session_route = mock.post(f"{BASE}/api/public/auth/session").mock(
        return_value=httpx.Response(
            200,
            json={"success": True},
            headers=[
                (
                    "Set-Cookie",
                    "TAP_SESSION_JWT=jwt-xyz; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=300",
                ),
                (
                    "Set-Cookie",
                    "TAP_REFRESH_TOKEN=ref-uvw; Path=/api/public/auth; HttpOnly; "
                    "Secure; SameSite=Lax; Max-Age=1800",
                ),
            ],
        )
    )
    me_route = mock.get(f"{BASE}/api/user/me").mock(
        return_value=httpx.Response(200, json={**_me_payload(), "isAdmin": user_is_admin})
    )
    assert csrf_route and session_route and me_route


def test_bootstrap_rejects_admin_session_token() -> None:
    with respx.mock(assert_all_called=False) as mock:
        _mock_session_exchange(mock, user_is_admin=True)
        runner = Runner(_settings())
        with pytest.raises(Exception) as exc_info:
            runner.run(Path("cases"), Path("fixtures/mirror.example.yaml"))
    assert "admin" in str(exc_info.value).lower()


def test_vulnerable_case_with_200_response() -> None:
    with respx.mock(assert_all_called=False) as mock:
        _mock_session_exchange(mock)
        mock.put(f"{BASE}/api/user").mock(return_value=httpx.Response(200, json={**_me_payload(), "isAdmin": True}))
        runner = Runner(_settings())
        report = runner.run(Path("cases/01_user_privilege_escalation.yaml"), Path("fixtures/mirror.example.yaml"))
    target = next(r for r in report.results if r.case_id == "PUT-user-isAdmin-escalation")
    assert target.classification is Classification.VULNERABLE


def test_fixed_case_with_403_response() -> None:
    with respx.mock(assert_all_called=False) as mock:
        _mock_session_exchange(mock)
        mock.put(f"{BASE}/api/user").mock(return_value=httpx.Response(403, json={"error": "forbidden"}))
        runner = Runner(_settings())
        report = runner.run(Path("cases/01_user_privilege_escalation.yaml"), Path("fixtures/mirror.example.yaml"))
    target = next(r for r in report.results if r.case_id == "PUT-user-isAdmin-escalation")
    assert target.classification is Classification.FIXED


def test_500_response_is_error_not_fixed() -> None:
    with respx.mock(assert_all_called=False) as mock:
        _mock_session_exchange(mock)
        mock.put(f"{BASE}/api/user").mock(return_value=httpx.Response(500, text="oops"))
        runner = Runner(_settings())
        report = runner.run(Path("cases/01_user_privilege_escalation.yaml"), Path("fixtures/mirror.example.yaml"))
    target = next(r for r in report.results if r.case_id == "PUT-user-isAdmin-escalation")
    assert target.classification is Classification.ERROR


def test_no_mutate_filters_mutating_cases() -> None:
    with respx.mock(assert_all_called=False) as mock:
        _mock_session_exchange(mock)
        runner = Runner(_settings(), no_mutate=True)
        report = runner.run(Path("cases/01_user_privilege_escalation.yaml"), Path("fixtures/mirror.example.yaml"))
    assert all(r.classification is Classification.SKIP for r in report.results)


def test_baseline_get_passes() -> None:
    with respx.mock(assert_all_called=False) as mock:
        _mock_session_exchange(mock)
        runner = Runner(_settings())
        report = runner.run(Path("cases/00_baseline.yaml"), Path("fixtures/mirror.example.yaml"))
    assert report.results[0].classification is Classification.FIXED
    assert report.results[0].response.status == 200


def test_dry_run_skips_network() -> None:
    runner = Runner(_settings(), dry_run=True)
    report = runner.run(Path("cases"), Path("fixtures/mirror.example.yaml"))
    assert report.results
    assert report.meta.actor == "<dry-run>"


def test_missing_session_token_returns_bootstrap_error() -> None:
    from tap_authz_check.bootstrap import BootstrapError

    runner = Runner(_settings(session_token=""))
    with pytest.raises(BootstrapError):
        runner.run(Path("cases/00_baseline.yaml"), Path("fixtures/mirror.example.yaml"))


def test_only_filter_isolates_suite() -> None:
    runner = Runner(_settings(), only=["01_*"], dry_run=True)
    report = runner.run(Path("cases"), Path("fixtures/mirror.example.yaml"))
    assert {r.suite for r in report.results} == {"user_privilege_escalation"}
    assert all(r.classification in {Classification.SKIP, Classification.PASSIVE} for r in report.results)


def test_discovery_suite_loads_from_directory() -> None:
    runner = Runner(_settings(), only=["99_*"], dry_run=True)
    report = runner.run(Path("cases"), Path("fixtures/mirror.example.yaml"))
    assert report.results == []


def test_mutating_call_sends_xsrf_header() -> None:
    """Mutating requests must echo XSRF-TOKEN as X-XSRF-TOKEN (double-submit)."""
    with respx.mock(assert_all_called=False) as mock:
        _mock_session_exchange(mock)
        captured: dict[str, str] = {}

        def _record(request: httpx.Request) -> httpx.Response:
            captured.update({k.lower(): v for k, v in request.headers.items()})
            return httpx.Response(403, json={"error": "forbidden"})

        mock.put(f"{BASE}/api/user").mock(side_effect=_record)
        runner = Runner(_settings())
        runner.run(Path("cases/01_user_privilege_escalation.yaml"), Path("fixtures/mirror.example.yaml"))
    assert captured.get("x-xsrf-token") == "csrf-abc"
    assert "authorization" not in captured


def test_401_triggers_single_refresh_retry() -> None:
    """A 401 on a protected endpoint triggers refresh-token then a single retry."""
    with respx.mock(assert_all_called=False) as mock:
        _mock_session_exchange(mock)
        refresh_calls = {"n": 0}

        def _refresh(request: httpx.Request) -> httpx.Response:
            refresh_calls["n"] += 1
            return httpx.Response(
                200,
                json={"success": True},
                headers=[
                    (
                        "Set-Cookie",
                        "TAP_SESSION_JWT=jwt-new; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=300",
                    ),
                    (
                        "Set-Cookie",
                        "TAP_REFRESH_TOKEN=ref-new; Path=/api/public/auth; HttpOnly; "
                        "Secure; SameSite=Lax; Max-Age=1800",
                    ),
                ],
            )

        refresh_route = mock.post(f"{BASE}/api/public/auth/refresh-token").mock(side_effect=_refresh)
        put_calls = {"n": 0}

        def _put(request: httpx.Request) -> httpx.Response:
            put_calls["n"] += 1
            if put_calls["n"] == 1:
                return httpx.Response(401, json={"error": "expired"})
            return httpx.Response(200, json={**_me_payload(), "isAdmin": True})

        mock.put(f"{BASE}/api/user").mock(side_effect=_put)
        runner = Runner(_settings(), only=["PUT-user-isAdmin-escalation"])
        report = runner.run(Path("cases/01_user_privilege_escalation.yaml"), Path("fixtures/mirror.example.yaml"))
    target = next(r for r in report.results if r.case_id == "PUT-user-isAdmin-escalation")
    assert target.classification is Classification.VULNERABLE
    assert refresh_calls["n"] == 1, "refresh-token must be called exactly once"
    assert put_calls["n"] == 2, "the PUT must be replayed once after refresh"
    assert refresh_route.called


def test_session_exchange_failure_is_bootstrap_error() -> None:
    """If /session returns non-200, runner raises BootstrapError before any case runs."""
    from tap_authz_check.bootstrap import BootstrapError

    with respx.mock(assert_all_called=False) as mock:
        mock.get(f"{BASE}/api/public/auth/csrf-token").mock(
            return_value=httpx.Response(200, json={"token": "t", "headerName": "X-XSRF-TOKEN", "parameterName": "_csrf"})
        )
        mock.post(f"{BASE}/api/public/auth/session").mock(
            return_value=httpx.Response(401, json={"error": "invalid"})
        )
        runner = Runner(_settings())
        with pytest.raises(BootstrapError):
            runner.run(Path("cases/00_baseline.yaml"), Path("fixtures/mirror.example.yaml"))
