"""YAML and JSON loaders for cases, fixtures and reports."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .models import CaseSuite, FixtureData


def load_suite(path: Path) -> CaseSuite:
    """Parse a YAML suite file into a :class:`CaseSuite`."""
    raw = _read_yaml(path)
    suite = CaseSuite.model_validate(raw)
    if suite.source_name is None:
        suite.source_name = path.stem
    return suite


def load_suites(path: Path) -> list[CaseSuite]:
    """Load suites from a file or directory (non-recursive)."""
    if path.is_file():
        return [load_suite(path)]
    suites: list[CaseSuite] = []
    for child in sorted(path.glob("*.yaml")):
        suites.append(load_suite(child))
    for child in sorted(path.glob("*.yml")):
        suites.append(load_suite(child))
    if not suites:
        raise FileNotFoundError(f"no YAML suites found under {path}")
    return suites


def load_fixture(path: Path) -> FixtureData:
    """Parse a YAML fixture file. Missing file returns empty fixture."""
    if not path.exists():
        return FixtureData()
    raw = _read_yaml(path)
    extra = {k: v for k, v in raw.items() if k not in FixtureData.model_fields}
    base = {k: v for k, v in raw.items() if k in FixtureData.model_fields}
    return FixtureData(**base, extra=extra)


def _read_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a YAML mapping at top level")
    return data
