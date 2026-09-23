"""Pydantic models for cases, expectations and run results."""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class Classification(str, Enum):  # noqa: UP042
    VULNERABLE = "VULNERABLE"
    FIXED = "FIXED"
    ERROR = "ERROR"
    SKIP = "SKIP"
    PASSIVE = "PASSIVE"


class Expectation(BaseModel):
    status_in: list[int] = Field(default_factory=list)
    must_equal: dict[str, Any] = Field(default_factory=dict)
    must_remain: dict[str, Any] = Field(default_factory=dict)
    must_change: dict[str, Any] = Field(default_factory=dict)

    @field_validator("status_in")
    @classmethod
    def _validate_status(cls, value: list[int]) -> list[int]:
        for code in value:
            if code < 100 or code >= 600:
                raise ValueError(f"invalid HTTP status code: {code}")
        return value


class PostCheck(BaseModel):
    method: str = "GET"
    path: str
    assert_json: dict[str, Any] = Field(default_factory=dict)


class CleanupSpec(BaseModel):
    strategy: Literal["restore_user_snapshot", "none"] = "none"


class CaseDefaults(BaseModel):
    auth: Literal["low_priv", "admin", "any"] = "any"
    required: bool = True
    headers: dict[str, str] = Field(default_factory=dict)
    mutate: bool = False
    destructive: bool = False


class TestCase(BaseModel):
    id: str
    name: str | None = None
    category: str | None = None
    method: str
    path: str
    headers: dict[str, str] = Field(default_factory=dict)
    body: dict[str, Any] | list[Any] | None = None
    mutate: bool = False
    destructive: bool = False
    mark_vulnerable_if: Expectation = Field(default_factory=Expectation)
    expect_when_fixed: Expectation = Field(default_factory=Expectation)
    post_checks: list[PostCheck] = Field(default_factory=list)
    cleanup: CleanupSpec = Field(default_factory=CleanupSpec)
    required: bool = True

    @field_validator("method")
    @classmethod
    def _upper_method(cls, value: str) -> str:
        return value.upper()


class CaseSuite(BaseModel):
    version: int = 1
    suite: str
    finding: str = "PenTest-001"
    defaults: CaseDefaults = Field(default_factory=CaseDefaults)
    cases: list[TestCase]
    source_name: str | None = None

    @field_validator("cases")
    @classmethod
    def _unique_ids(cls, value: list[TestCase]) -> list[TestCase]:
        seen: set[str] = set()
        for case in value:
            if case.id in seen:
                raise ValueError(f"duplicate case id: {case.id}")
            seen.add(case.id)
        return value


class ActorSnapshot(BaseModel):
    email: str | None = None
    name: str | None = None
    company: str | None = None
    provider_ids: list[str] = Field(default_factory=list)
    client_ids: list[str] = Field(default_factory=list)
    is_admin: bool = False
    raw: dict[str, Any] = Field(default_factory=dict)


class FixtureData(BaseModel):
    environment: str = "mirror"
    foreign_provider_id: str | None = None
    victim_user_id: str | None = None
    trade_id: str | None = None
    invoice_id: str | None = None
    settlement_id: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict)


class ResponseEvidence(BaseModel):
    status: int | None = None
    body_snippet: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    duration_ms: int = 0
    error: str | None = None


class CaseResult(BaseModel):
    case_id: str
    suite: str
    category: str | None = None
    method: str
    path: str
    classification: Classification
    response: ResponseEvidence = Field(default_factory=ResponseEvidence)
    evidence: str | None = None
    post_check_json: dict[str, Any] | None = None
    duration_ms: int = 0


class RunSummary(BaseModel):
    vulnerable: int = 0
    fixed: int = 0
    error_count: int = 0
    skip: int = 0
    passive: int = 0


class RunMetadata(BaseModel):
    finding: str = "PenTest-001"
    mode: str = "audit"
    base_url: str
    actor: str
    started_at: str
    finished_at: str
    tool_version: str
    fixture: str | None = None


class RunReport(BaseModel):
    meta: RunMetadata
    summary: RunSummary
    results: list[CaseResult]
