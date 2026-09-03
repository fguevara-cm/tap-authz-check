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
TOKEN = "fake-token"


def _settings(**overrides: object) -> Settings:
    defaults = dict(
        base_url=BASE,
        token=TOKEN,
        admin_token="",
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


def test_bootstrap_rejects_admin_token() -> None:
    with respx.mock(assert_all_called=False) as mock:
        mock.get(f"{BASE}/api/user/me").mock(
            return_value=httpx.Response(200, json={**_me_payload(), "isAdmin": True})
        )
        runner = Runner(_settings())
        with pytest.raises(Exception) as exc_info:
            runner.run(Path("cases"), Path("fixtures/mirror.example.yaml"))
    assert "admin" in str(exc_info.value).lower()


def test_vulnerable_case_with_200_response() -> None:
    with respx.mock(assert_all_called=False) as mock:
        mock.get(f"{BASE}/api/user/me").mock(return_value=httpx.Response(200, json=_me_payload()))
        mock.put(f"{BASE}/api/user").mock(return_value=httpx.Response(200, json={** _me_payload(), "isAdmin": True}))
        runner = Runner(_settings())
        report = runner.run(Path("cases/01_user_privilege_escalation.yaml"), Path("fixtures/mirror.example.yaml"))
    target = next(r for r in report.results if r.case_id == "PUT-user-isAdmin-escalation")
    assert target.classification is Classification.VULNERABLE


def test_fixed_case_with_403_response() -> None:
    with respx.mock(assert_all_called=False) as mock:
        mock.get(f"{BASE}/api/user/me").mock(return_value=httpx.Response(200, json=_me_payload()))
        mock.put(f"{BASE}/api/user").mock(return_value=httpx.Response(403, json={"error": "forbidden"}))
        runner = Runner(_settings())
        report = runner.run(Path("cases/01_user_privilege_escalation.yaml"), Path("fixtures/mirror.example.yaml"))
    target = next(r for r in report.results if r.case_id == "PUT-user-isAdmin-escalation")
    assert target.classification is Classification.FIXED


def test_500_response_is_error_not_fixed() -> None:
    with respx.mock(assert_all_called=False) as mock:
        mock.get(f"{BASE}/api/user/me").mock(return_value=httpx.Response(200, json=_me_payload()))
        mock.put(f"{BASE}/api/user").mock(return_value=httpx.Response(500, text="oops"))
        runner = Runner(_settings())
        report = runner.run(Path("cases/01_user_privilege_escalation.yaml"), Path("fixtures/mirror.example.yaml"))
    target = next(r for r in report.results if r.case_id == "PUT-user-isAdmin-escalation")
    assert target.classification is Classification.ERROR


def test_no_mutate_filters_mutating_cases() -> None:
    with respx.mock(assert_all_called=False) as mock:
        mock.get(f"{BASE}/api/user/me").mock(return_value=httpx.Response(200, json=_me_payload()))
        runner = Runner(_settings(), no_mutate=True)
        report = runner.run(Path("cases/01_user_privilege_escalation.yaml"), Path("fixtures/mirror.example.yaml"))
    assert all(r.classification is Classification.SKIP for r in report.results)


def test_baseline_get_passes() -> None:
    with respx.mock(assert_all_called=False) as mock:
        mock.get(f"{BASE}/api/user/me").mock(return_value=httpx.Response(200, json=_me_payload()))
        runner = Runner(_settings())
        report = runner.run(Path("cases/00_baseline.yaml"), Path("fixtures/mirror.example.yaml"))
    assert report.results[0].classification is Classification.FIXED
    assert report.results[0].response.status == 200


def test_dry_run_skips_network() -> None:
    runner = Runner(_settings(), dry_run=True)
    report = runner.run(Path("cases"), Path("fixtures/mirror.example.yaml"))
    assert report.results  # at least one case rendered
    assert report.meta.actor == "<dry-run>"


def test_missing_token_returns_bootstrap_error() -> None:
    from tap_authz_check.bootstrap import BootstrapError

    runner = Runner(_settings(token=""))
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
    assert report.results
    assert all(r.suite == "discovery_catalog" for r in report.results)


def test_distribution_500_is_error() -> None:
    with respx.mock(assert_all_called=False) as mock:
        mock.get(f"{BASE}/api/user/me").mock(return_value=httpx.Response(200, json=_me_payload()))
        mock.get(f"{BASE}/api/distribution-v2").mock(return_value=httpx.Response(500, text="boom"))
        mock.get(f"{BASE}/api/distribution-payments/summary").mock(return_value=httpx.Response(403))
        mock.get(f"{BASE}/api/distribution-payments/by-context").mock(return_value=httpx.Response(403))
        mock.post(f"{BASE}/api/distribution-payments/summary").mock(return_value=httpx.Response(403))
        mock.get(f"{BASE}/api/payment-instructions/summary/search").mock(return_value=httpx.Response(403))
        mock.get(f"{BASE}/api/payment-instructions/by-context").mock(return_value=httpx.Response(403))
        mock.post(f"{BASE}/api/payment-instructions/start").mock(return_value=httpx.Response(403))
        mock.get(f"{BASE}/api/settlements/test-settlement-id").mock(return_value=httpx.Response(403))
        mock.get(f"{BASE}/api/settlements/findBySettlementNo/test-settlement-id").mock(return_value=httpx.Response(403))
        mock.post(f"{BASE}/api/settlements/findByAllIds").mock(return_value=httpx.Response(403))
        runner = Runner(_settings(), only=["GET-distribution-v2-list"])
        report = runner.run(
            Path("cases/04_distribution_treasury_payments.yaml"),
            Path("fixtures/mirror.example.yaml"),
        )
    target = next(r for r in report.results if r.case_id == "GET-distribution-v2-list")
    assert target.classification is Classification.ERROR


def test_distribution_403_is_fixed() -> None:
    with respx.mock(assert_all_called=False) as mock:
        mock.get(f"{BASE}/api/user/me").mock(return_value=httpx.Response(200, json=_me_payload()))
        mock.get(f"{BASE}/api/distribution-v2").mock(return_value=httpx.Response(403, json={"error": "forbidden"}))
        runner = Runner(_settings(), only=["GET-distribution-v2-list"])
        report = runner.run(
            Path("cases/04_distribution_treasury_payments.yaml"),
            Path("fixtures/mirror.example.yaml"),
        )
    target = next(r for r in report.results if r.case_id == "GET-distribution-v2-list")
    assert target.classification is Classification.FIXED
