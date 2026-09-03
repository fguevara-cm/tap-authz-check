"""Console table rendering and JSON serialization."""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

from .models import CaseResult, Classification, RunReport

_CONSOLE = Console()


_SYMBOLS: dict[Classification, str] = {
    Classification.VULNERABLE: "FAIL",
    Classification.FIXED: "PASS",
    Classification.ERROR: "WARN",
    Classification.SKIP: "SKIP",
    Classification.PASSIVE: "INFO",
}


def render_console(report: RunReport) -> None:
    _CONSOLE.print(
        f"\nTAP AuthZ Check  mode={report.meta.mode}  "
        f"base={report.meta.base_url}  actor={report.meta.actor}\n"
    )
    table = Table(show_lines=False, header_style="bold")
    table.add_column("Status")
    table.add_column("Case")
    table.add_column("Method")
    table.add_column("Path")
    table.add_column("HTTP")
    table.add_column("Class")
    table.add_column("Duration (ms)")
    table.add_column("Evidence")

    for result in report.results:
        symbol = _SYMBOLS[result.classification]
        http = str(result.response.status) if result.response.status is not None else "-"
        table.add_row(
            symbol,
            result.case_id,
            result.method,
            result.path,
            http,
            result.classification.value,
            str(result.duration_ms),
            result.evidence or "",
        )

    _CONSOLE.print(table)
    s = report.summary
    _CONSOLE.print(
        "\nSummary: "
        f"vulnerable={s.vulnerable} fixed={s.fixed} "
        f"error={s.error_count} skip={s.skip} passive={s.passive}\n"
    )


def write_json(report: RunReport, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")


def print_pretty_json(report: RunReport) -> None:
    _CONSOLE.print_json(json.dumps(json.loads(report.model_dump_json()), indent=2))


def list_results(report: RunReport) -> list[CaseResult]:
    return report.results
