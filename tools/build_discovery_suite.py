"""Generate cases/99_discovery_catalog.yaml from tools/discovery_catalog.yaml.

Rules:
- only GET/HEAD/OPTIONS (no mutating methods)
- only /api/** paths (skip auth, static, magic-link, health)
- one case per (method, path), controller recorded as metadata
- {placeholder} tokens are stripped from the rendered path (the literal
  placeholder remains in the description, but the runner skips unresolved
  tokens).
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import yaml

EXCLUDE_PREFIXES = (
    "/api/public/auth",
    "/api/user/me",  # baseline (covered in 00)
)

METHODS_KEEP = {"GET", "HEAD", "OPTIONS"}
_PLACEHOLDER = re.compile(r"\{[^{}]+\}")


def _slugify(method: str, path: str, suffix: str = "") -> str:
    cleaned = _PLACEHOLDER.sub("", path)
    base = f"DISC-{method}-{cleaned}".replace("/", "-").strip("-")
    base = f"{base}-{_path_fingerprint(path)}"
    if suffix:
        base = f"{base}-{suffix}"
    return base[:120]


def _path_fingerprint(path: str) -> str:
    import hashlib

    return hashlib.sha1(path.encode("utf-8")).hexdigest()[:6]


def _placeholder_default(name: str) -> str:
    return "0"


def _render_path(path: str) -> str:
    return _PLACEHOLDER.sub(lambda m: "{" + _placeholder_default(m.group(0)[1:-1]) + "}", path)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build passive discovery suite from controller catalog")
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    catalog = yaml.safe_load(args.catalog.read_text(encoding="utf-8"))
    cases = []
    seen: set[tuple[str, str]] = set()
    duplicate_counter: dict[tuple[str, str], int] = {}
    for entry in catalog.get("cases", []):
        method = entry["method"]
        path = entry["path"]
        if method not in METHODS_KEEP:
            continue
        if not path.startswith("/api/"):
            continue
        if any(path.startswith(prefix) for prefix in EXCLUDE_PREFIXES):
            continue
        key = (method, path)
        if key in seen:
            duplicate_counter[key] = duplicate_counter.get(key, 1) + 1
            suffix = str(duplicate_counter[key])
            case_id = _slugify(method, path, suffix)
        else:
            seen.add(key)
            case_id = _slugify(method, path)
        cases.append(
            {
                "id": case_id,
                "name": f"{method} {path}",
                "category": "discovery",
                "controller": entry["controller"],
                "method": method,
                "path": path,
                "mutate": False,
                "required": False,
                "expect_when_fixed": {"status_in": [200, 401, 403, 404]},
            }
        )

    document = {
        "version": 1,
        "suite": "discovery_catalog",
        "finding": "PenTest-001",
        "note": "Generated from tools/discovery_catalog.yaml. Passive probes only (GET/HEAD/OPTIONS).",
        "defaults": {"auth": "any", "required": False, "headers": {"Content-Type": "application/json"}},
        "cases": cases,
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(yaml.safe_dump(document, sort_keys=False, width=4096, default_flow_style=False), encoding="utf-8")
    print(f"Wrote {len(cases)} discovery cases -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
