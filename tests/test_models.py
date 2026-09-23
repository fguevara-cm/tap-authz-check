"""Offline tests for pydantic models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from tap_authz_check import models


def test_case_body_accepts_root_list() -> None:
    case = models.TestCase(id="X", method="DELETE", path="/api/x", body=["a", "b"])
    assert case.body == ["a", "b"]


def test_case_body_rejects_scalar() -> None:
    with pytest.raises(ValidationError):
        models.TestCase(id="X", method="DELETE", path="/api/x", body="not-a-container")