"""Test runner: orchestrates suites, bootstrap, classification and cleanup."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__
from .bootstrap import BootstrapError, fetch_actor
from .classify import classify
from .client import HttpClient, Response
from .config import Settings
from .loader import load_fixture, load_suites
from .models import (
    ActorSnapshot,
    CaseResult,
    CaseSuite,
    Classification,
    FixtureData,
    ResponseEvidence,
    RunMetadata,
    RunReport,
    RunSummary,
    TestCase,
)
from .session import SessionExchangeError, establish_authenticated_client, refresh_session
from .templates import build_context, has_unresolved


class Runner:
    def __init__(
        self,
        settings: Settings,
        *,
        no_mutate: bool = False,
        allow_destructive: bool = False,
        force_admin_token: bool = False,
        only: list[str] | None = None,
        dry_run: bool = False,
        redact_bodies: bool = False,
        use_admin_token: bool = False,
    ) -> None:
        self._settings = settings
        self._no_mutate = no_mutate
        self._allow_destructive = allow_destructive
        self._force_admin_token = force_admin_token
        self._only = only or []
        self._dry_run = dry_run
        self._redact_bodies = redact_bodies
        self._use_admin_token = use_admin_token

    def run(self, cases_path: Path, fixture_path: Path) -> RunReport:
        started = datetime.now(UTC)
        fixture = load_fixture(fixture_path)
        suites = self._filter(load_suites(cases_path))

        actor: ActorSnapshot
        results: list[CaseResult]

        if self._dry_run:
            actor = ActorSnapshot(email="<dry-run>")
            results = self._execute_dry_run(suites, fixture)
        else:
            session_token = (
                self._settings.admin_session_token
                if self._use_admin_token and self._settings.admin_session_token
                else self._settings.session_token
            )
            if not session_token:
                raise BootstrapError(
                    "session_token missing: set TAP_AUTHZ_SESSION_TOKEN "
                    "(or SESSION_TOKEN) or pass --session-token"
                )
            try:
                client = establish_authenticated_client(
                    base_url=self._settings.base_url,
                    session_token=session_token,
                    timeout_seconds=self._settings.timeout_seconds,
                    delay_ms=self._settings.delay_ms,
                )
            except SessionExchangeError as exc:
                raise BootstrapError(f"session bootstrap failed: {exc}") from exc
            client.set_refresh_hook(refresh_session)
            with client:
                actor = fetch_actor(
                    client,
                    allow_admin=self._use_admin_token,
                    force_admin_token=self._force_admin_token,
                )
                results = self._execute_suites(client, suites, actor, fixture)
        finished = datetime.now(UTC)

        summary = self._summarize(results)
        meta = RunMetadata(
            mode=self._settings.mode.value,
            base_url=self._settings.base_url,
            actor=actor.email or "<unknown>",
            started_at=started.isoformat(),
            finished_at=finished.isoformat(),
            tool_version=__version__,
            fixture=str(fixture_path) if fixture_path.exists() else None,
        )
        return RunReport(meta=meta, summary=summary, results=results)

    def _execute_suites(
        self,
        client: HttpClient,
        suites: list[CaseSuite],
        actor: ActorSnapshot,
        fixture: FixtureData,
    ) -> list[CaseResult]:
        results: list[CaseResult] = []
        for suite in suites:
            for case in suite.cases:
                if not self._case_allowed(case, suite):
                    continue
                results.append(self._execute_case(client, suite, case, actor, fixture))
        return results

    def _execute_suites_offline(self) -> list[CaseResult]:
        return []

    def _execute_dry_run(
        self,
        suites: list[CaseSuite],
        fixture: FixtureData,
    ) -> list[CaseResult]:
        actor = ActorSnapshot(email="<dry-run>")
        ctx = build_context(actor, fixture)
        results: list[CaseResult] = []
        for suite in suites:
            for case in suite.cases:
                missing = self._collect_missing(case, ctx)
                if missing:
                    results.append(
                        self._result(
                            suite,
                            case,
                            Classification.SKIP,
                            Response(path=case.path, status=0, headers={}, body_snippet="", duration_ms=0, error=None),
                            "; ".join(missing),
                        )
                    )
                else:
                    results.append(
                        self._result(
                            suite,
                            case,
                            Classification.PASSIVE,
                            Response(path=case.path, status=0, headers={}, body_snippet="", duration_ms=0, error=None),
                            "dry-run",
                        )
                    )
        return results

    def _execute_case(
        self,
        client: HttpClient,
        suite: CaseSuite,
        case: TestCase,
        actor: ActorSnapshot,
        fixture: FixtureData,
    ) -> CaseResult:
        empty_response = Response(path=case.path, status=0, headers={}, body_snippet="", duration_ms=0, error=None)

        if case.mutate and self._no_mutate:
            return self._result(suite, case, Classification.SKIP, empty_response, "mutate disabled (drop --no-mutate to run)")
        if case.destructive and not self._allow_destructive:
            return self._result(suite, case, Classification.SKIP, empty_response, "destructive disabled (use --allow-destructive)")

        ctx = build_context(actor, fixture)
        missing = self._collect_missing(case, ctx)

        if missing:
            return self._result(suite, case, Classification.SKIP, empty_response, "; ".join(missing))

        if self._dry_run:
            return self._result(suite, case, Classification.PASSIVE, empty_response, "dry-run")

        method = case.method
        path = self._render(case.path, ctx)
        headers = {**suite.defaults.headers, **case.headers}
        body = self._render(case.body, ctx) if case.body is not None else None
        allow_retry = not case.mutate and not case.destructive

        response = client.request(
            method,
            path,
            headers=headers,
            json_body=body if isinstance(body, (dict, list)) else None,
            allow_retry=allow_retry,
        )

        post_check_payload = self._run_post_checks(client, case, ctx)

        classification, evidence = classify(
            response=response,
            method=method,
            case_required=case.required,
            mutate=case.mutate,
            destructive=case.destructive,
            vulnerable_if=case.mark_vulnerable_if,
            fixed_if=case.expect_when_fixed,
            allow_destructive=self._allow_destructive,
            no_mutate=self._no_mutate,
            missing_placeholders=[],
        )

        evidence_msg = evidence
        if post_check_payload is not None:
            evidence_msg = (evidence_msg or "") + f"; post_check={json.dumps(post_check_payload)}"

        return self._result(suite, case, classification, response, evidence_msg, post_check_payload)

    def _run_post_checks(
        self,
        client: HttpClient,
        case: TestCase,
        ctx: dict[str, Any],
    ) -> dict[str, Any] | None:
        if not case.post_checks:
            return None
        aggregated: dict[str, Any] = {}
        for check in case.post_checks:
            path = self._render(check.path, ctx)
            response = client.get(path)
            if response.body_snippet:
                try:
                    aggregated[check.path] = json.loads(response.body_snippet)
                except json.JSONDecodeError:
                    aggregated[check.path] = {"raw": response.body_snippet[:200]}
            else:
                aggregated[check.path] = {"status": response.status}
        return aggregated

    def _result(
        self,
        suite: CaseSuite,
        case: TestCase,
        classification: Classification,
        response: Response,
        evidence: str | None = None,
        post_check: dict[str, Any] | None = None,
    ) -> CaseResult:
        body_snippet = "" if self._redact_bodies else response.body_snippet
        return CaseResult(
            case_id=case.id,
            suite=suite.suite,
            category=case.category,
            method=case.method,
            path=case.path,
            classification=classification,
            response=ResponseEvidence(
                status=response.status,
                body_snippet=body_snippet,
                headers=response.headers,
                duration_ms=response.duration_ms,
                error=response.error_message,
            ),
            evidence=evidence,
            post_check_json=post_check,
            duration_ms=response.duration_ms,
        )

    def _case_allowed(self, case: TestCase, suite: CaseSuite | None = None) -> bool:
        if not self._only:
            return True
        targets: list[str] = [case.id, case.category or ""]
        if suite is not None:
            targets.append(suite.suite)
            if suite.source_name:
                targets.append(suite.source_name)
        return any(_matches(target, pattern) for target in targets for pattern in self._only)

    def _filter(self, suites: list[CaseSuite]) -> list[CaseSuite]:
        if not self._only:
            return suites
        kept: list[CaseSuite] = []
        for suite in suites:
            if any(_matches(suite.suite, pattern) or _matches(suite.source_name or "", pattern)
                   for pattern in self._only):
                kept.append(suite)
                continue
            cases = [c for c in suite.cases if self._case_allowed(c, suite)]
            if cases:
                kept.append(suite.model_copy(update={"cases": cases}))
        return kept

    def _collect_missing(self, case: TestCase, ctx: dict[str, Any]) -> list[str]:
        missing: set[str] = set()
        missing.update(has_unresolved(case.path, ctx))
        if case.body is not None:
            missing.update(has_unresolved(case.body, ctx))
        for check in case.post_checks:
            missing.update(has_unresolved(check.path, ctx))
        return sorted(missing)

    @staticmethod
    def _render(value: Any, ctx: dict[str, Any]) -> Any:
        from .templates import render_value

        return render_value(value, ctx)

    @staticmethod
    def _summarize(results: list[CaseResult]) -> RunSummary:
        summary = RunSummary()
        for result in results:
            if result.classification is Classification.VULNERABLE:
                summary.vulnerable += 1
            elif result.classification is Classification.FIXED:
                summary.fixed += 1
            elif result.classification is Classification.ERROR:
                summary.error_count += 1
            elif result.classification is Classification.SKIP:
                summary.skip += 1
            elif result.classification is Classification.PASSIVE:
                summary.passive += 1
        return summary


def _matches(value: str, pattern: str) -> bool:
    if pattern == value:
        return True
    if "*" in pattern:
        import fnmatch

        return fnmatch.fnmatchcase(value, pattern)
    return False
