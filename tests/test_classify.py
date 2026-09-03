"""Offline tests for the classify module."""

from __future__ import annotations

import pytest

from tap_authz_check.classify import classify
from tap_authz_check.client import Response
from tap_authz_check.models import Classification, Expectation


def _resp(status: int | None, body: str = "") -> Response:
    return Response(
        path="/x",
        status=status,
        headers={},
        body_snippet=body,
        duration_ms=10,
        error=None,
    )


def test_500_is_error_not_fixed() -> None:
    classification, _ = classify(
        response=_resp(500),
        method="PUT",
        case_required=True,
        mutate=False,
        destructive=False,
        vulnerable_if=Expectation(),
        fixed_if=Expectation(status_in=[403]),
        allow_destructive=True,
        no_mutate=False,
        missing_placeholders=[],
    )
    assert classification is Classification.ERROR


def test_403_with_expectation_is_fixed() -> None:
    classification, evidence = classify(
        response=_resp(403),
        method="PUT",
        case_required=True,
        mutate=True,
        destructive=False,
        vulnerable_if=Expectation(status_in=[200]),
        fixed_if=Expectation(status_in=[403]),
        allow_destructive=True,
        no_mutate=False,
        missing_placeholders=[],
    )
    assert classification is Classification.FIXED
    assert "403" in (evidence or "")


def test_200_matching_vulnerable_marks_vulnerable() -> None:
    classification, _ = classify(
        response=_resp(200, body='{"isAdmin": true}'),
        method="PUT",
        case_required=True,
        mutate=True,
        destructive=False,
        vulnerable_if=Expectation(status_in=[200]),
        fixed_if=Expectation(status_in=[403]),
        allow_destructive=True,
        no_mutate=False,
        missing_placeholders=[],
    )
    assert classification is Classification.VULNERABLE


def test_network_error_is_error() -> None:
    response = Response(path="/x", status=None, headers={}, body_snippet="", duration_ms=0, error="boom")
    classification, evidence = classify(
        response=response,
        method="GET",
        case_required=True,
        mutate=False,
        destructive=False,
        vulnerable_if=Expectation(),
        fixed_if=Expectation(status_in=[200]),
        allow_destructive=True,
        no_mutate=False,
        missing_placeholders=[],
    )
    assert classification is Classification.ERROR
    assert "boom" in (evidence or "")


def test_missing_placeholder_is_skip() -> None:
    classification, evidence = classify(
        response=_resp(200),
        method="GET",
        case_required=True,
        mutate=False,
        destructive=False,
        vulnerable_if=Expectation(),
        fixed_if=Expectation(),
        allow_destructive=True,
        no_mutate=False,
        missing_placeholders=["foreign_provider_id"],
    )
    assert classification is Classification.SKIP
    assert "foreign_provider_id" in (evidence or "")


def test_passive_get_without_expectations() -> None:
    classification, _ = classify(
        response=_resp(200),
        method="GET",
        case_required=False,
        mutate=False,
        destructive=False,
        vulnerable_if=Expectation(),
        fixed_if=Expectation(),
        allow_destructive=True,
        no_mutate=False,
        missing_placeholders=[],
    )
    assert classification is Classification.PASSIVE


def test_destructive_without_flag_is_skip() -> None:
    classification, evidence = classify(
        response=_resp(200),
        method="POST",
        case_required=True,
        mutate=False,
        destructive=True,
        vulnerable_if=Expectation(status_in=[200]),
        fixed_if=Expectation(status_in=[403]),
        allow_destructive=False,
        no_mutate=False,
        missing_placeholders=[],
    )
    assert classification is Classification.SKIP
    assert "destructive" in (evidence or "")


def test_must_change_field_detects_vulnerable() -> None:
    classification, _ = classify(
        response=_resp(200, body='{"isAdmin": true}'),
        method="PUT",
        case_required=True,
        mutate=True,
        destructive=False,
        vulnerable_if=Expectation(must_change={"isAdmin": True}),
        fixed_if=Expectation(),
        allow_destructive=True,
        no_mutate=False,
        missing_placeholders=[],
    )
    assert classification is Classification.VULNERABLE


@pytest.mark.parametrize("code", [502, 503, 504])
def test_5xx_never_fixed(code: int) -> None:
    classification, _ = classify(
        response=_resp(code),
        method="GET",
        case_required=True,
        mutate=False,
        destructive=False,
        vulnerable_if=Expectation(),
        fixed_if=Expectation(status_in=[200, 401, 403, 404, code]),
        allow_destructive=True,
        no_mutate=False,
        missing_placeholders=[],
    )
    assert classification is Classification.ERROR


def test_non_ascii_token_raises_value_error() -> None:
    from tap_authz_check.client import HttpClient

    bad_token = "header.payload.\u2026sig"
    with pytest.raises(ValueError, match="non-ASCII"):
        HttpClient(
            base_url="https://example.test",
            token=bad_token,
            timeout_seconds=1.0,
        )
