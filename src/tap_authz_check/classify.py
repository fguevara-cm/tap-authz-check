"""Classification rules: VULNERABLE / FIXED / ERROR / SKIP / PASSIVE."""

from __future__ import annotations

from typing import Any

from .client import Response
from .models import Classification, Expectation

_PASSIVE_METHODS = {"GET", "HEAD", "OPTIONS"}


def classify(
    *,
    response: Response,
    method: str,
    case_required: bool,
    mutate: bool,
    destructive: bool,
    vulnerable_if: Expectation,
    fixed_if: Expectation,
    allow_destructive: bool,
    no_mutate: bool,
    missing_placeholders: list[str],
) -> tuple[Classification, str | None]:
    if missing_placeholders:
        return Classification.SKIP, f"missing placeholder(s): {', '.join(missing_placeholders)}"

    if destructive and not allow_destructive:
        return Classification.SKIP, "destructive disabled (use --allow-destructive)"

    if mutate and no_mutate:
        return Classification.SKIP, "mutate disabled (drop --no-mutate to run)"

    if response.error_message is not None:
        return Classification.ERROR, f"network error: {response.error_message}"

    status = response.status

    if status is None:
        return Classification.ERROR, "no response status"

    if 500 <= status < 600:
        return Classification.ERROR, f"server error {status}"

    if method.upper() in _PASSIVE_METHODS and not vulnerable_if.status_in and not fixed_if.status_in:
        return Classification.PASSIVE, "no explicit expectation; passive probe"

    if vulnerable_if.status_in and status in vulnerable_if.status_in:
        return Classification.VULNERABLE, f"status {status} matched mark_vulnerable_if"

    if _matches_json(response, vulnerable_if.must_change):
        return Classification.VULNERABLE, "field changed in vulnerable direction"

    if fixed_if.status_in and status in fixed_if.status_in:
        return Classification.FIXED, f"status {status} matched expect_when_fixed"

    if _matches_json(response, fixed_if.must_equal):
        return Classification.FIXED, "expected field value present"

    if 400 <= status < 500:
        return Classification.FIXED, f"client error {status} treated as authorization denial"

    return Classification.PASSIVE, f"status {status} did not match explicit expectations"


def _matches_json(response: Response, expected: dict[str, Any]) -> bool:
    if not expected:
        return False
    snippet = response.body_snippet
    if not snippet:
        return False
    if not snippet.lstrip().startswith(("{", "[")):
        return False
    import json

    try:
        payload = json.loads(snippet)
    except json.JSONDecodeError:
        return False
    return _contains(payload, expected)


def _contains(payload: Any, expected: dict[str, Any]) -> bool:
    if not isinstance(payload, dict):
        return False
    for key, expected_value in expected.items():
        if key not in payload:
            return False
        actual = payload[key]
        if isinstance(expected_value, dict):
            if not _contains(actual, expected_value):
                return False
        elif actual != expected_value:
            return False
    return True
