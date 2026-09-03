"""Command-line interface for tap-authz-check."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .bootstrap import BootstrapError
from .config import RunMode, load_settings
from .report import render_console, write_json
from .runner import Runner


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tap-authz-check",
        description="Authorization testing tool for TAP API (PenTest-001).",
    )
    parser.add_argument("--base-url", help="API base URL (default from env)")
    parser.add_argument("--token", help="Bearer token of low-privilege user")
    parser.add_argument("--admin-token", help="Bearer token of admin user (positive controls)")
    parser.add_argument("--mode", choices=[m.value for m in RunMode], help="audit or verify")
    parser.add_argument(
        "--cases",
        default="cases",
        type=Path,
        help="Path to a YAML suite file or directory",
    )
    parser.add_argument("--only", action="append", default=[], help="Filter suite/case patterns")
    parser.add_argument("--fixture-file", type=Path, help="Fixture YAML file")
    parser.add_argument("--report", type=Path, help="Path to JSON report output")
    parser.add_argument("--junit-report", type=Path, help="Optional JUnit XML output")
    parser.add_argument("--no-mutate", action="store_true", help="Skip mutating cases")
    parser.add_argument(
        "--allow-destructive",
        action="store_true",
        help="Enable destructive cases (POST/DELETE /api/user)",
    )
    parser.add_argument(
        "--force-admin-token",
        action="store_true",
        help="Allow running with an admin token (positive controls)",
    )
    parser.add_argument("--compare-admin", action="store_true", help="Re-run cases with admin token")
    parser.add_argument("--delay-ms", type=int, help="Delay between requests in milliseconds")
    parser.add_argument("--timeout", type=float, help="HTTP timeout in seconds")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Render cases without sending requests",
    )
    parser.add_argument("--redact-bodies", action="store_true", help="Omit body snippets from report")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    overrides = {
        "base_url": args.base_url,
        "token": args.token,
        "admin_token": args.admin_token,
        "fixture_file": args.fixture_file,
        "timeout_seconds": args.timeout,
        "delay_ms": args.delay_ms,
        "mode": RunMode(args.mode) if args.mode else None,
    }
    settings = load_settings(**{k: v for k, v in overrides.items() if v is not None})

    runner = Runner(
        settings,
        no_mutate=args.no_mutate,
        allow_destructive=args.allow_destructive,
        force_admin_token=args.force_admin_token,
        only=args.only,
        dry_run=args.dry_run,
        redact_bodies=args.redact_bodies,
        use_admin_token=args.compare_admin,
    )

    try:
        report = runner.run(args.cases, settings.fixture_file)
    except BootstrapError as exc:
        print(f"bootstrap error: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"file not found: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # pragma: no cover - defensive
        print(f"unexpected error: {exc}", file=sys.stderr)
        return 3

    render_console(report)

    if args.report:
        write_json(report, args.report)

    if args.junit_report:
        _write_junit(report, args.junit_report)

    return _exit_code(settings.mode, report.summary.vulnerable, report.summary.error_count)


def _exit_code(mode: RunMode, vulnerable: int, errors: int) -> int:
    if mode is RunMode.VERIFY:
        if vulnerable > 0:
            return 1
        if errors > 0:
            return 3
        return 0
    if errors > 0:
        return 3
    return 0


def _write_junit(report, path: Path) -> None:  # pragma: no cover - optional
    import xml.etree.ElementTree as ET

    from .models import Classification

    suite = ET.Element("testsuite", attrib={"name": "tap-authz-check"})
    for result in report.results:
        case_el = ET.SubElement(
            suite,
            "testcase",
            attrib={
                "classname": result.suite,
                "name": result.case_id,
                "time": f"{result.duration_ms / 1000:.3f}",
            },
        )
        if result.classification in {Classification.VULNERABLE, Classification.ERROR}:
            ET.SubElement(
                case_el,
                "failure",
                attrib={"message": result.evidence or result.classification.value},
            )
        elif result.classification is Classification.SKIP:
            ET.SubElement(case_el, "skipped")
    tree = ET.ElementTree(suite)
    path.parent.mkdir(parents=True, exist_ok=True)
    tree.write(path, encoding="utf-8", xml_declaration=True)
