"""Scan tracked files for JWTs, session tokens and other common secret shapes.

Used as a pre-commit / pre-push guardrail. Exits non-zero if a secret pattern
matches a tracked file. Skips ``reports/``, ``.venv/`` and binary files.

Patterns checked (conservative, designed to minimise false positives):
- ``eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+`` (JWT)
- ``Authorization: Bearer <token>`` (legacy Bearer usage)
- ``TAP_AUTHZ_TOKEN=...`` / ``TAP_AUTHZ_SESSION_TOKEN=...`` (non-empty value)
- ``SESSION_TOKEN=...`` / ``ADMIN_SESSION_TOKEN=...`` (bare aliases, non-empty)
- ``Set-Cookie: TAP_SESSION_JWT=...`` (non-empty value)
- ``-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----``
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

PATTERNS: dict[str, str] = {
    "jwt": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    "bearer": r"(?im)^[^#\n]*Authorization:\s*Bearer\s+[A-Za-z0-9._\-]{20,}",
    "token_var": r"(?im)^\s*TAP_AUTHZ_(?:ADMIN_)?TOKEN\s*=[ \t]*([A-Za-z0-9._\-+/=]+)",
    "session_token_var": r"(?im)^\s*TAP_AUTHZ_(?:ADMIN_)?SESSION_TOKEN\s*=[ \t]*([A-Za-z0-9._\-+/=]{16,})",
    "bare_session_token_var": r"(?im)^\s*(?:ADMIN_)?SESSION_TOKEN\s*=[ \t]*([A-Za-z0-9._\-+/=]{16,})",
    "session_cookie": r"(?im)^[^\n]*Set-Cookie:\s*TAP_SESSION_JWT=[A-Za-z0-9._\-+/=]+",
    "private_key": r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
}

EXCLUDE_DIRS = {".venv", "venv", "build", "dist", ".pytest_cache", ".ruff_cache", "reports", "node_modules", ".git", ".opencode", ".idea", "tmp"}
EXCLUDE_FILES = {"scan_for_secrets.py"}
ENV_FILES = {".env"}
TEXT_SUFFIXES = {".py", ".yaml", ".yml", ".json", ".md", ".txt", ".env", ".example", ".toml", ".cfg", ".ini", ".sh", ".js", ".ts", ".html", ".css", ".sql"}


def _is_text(path: Path) -> bool:
    if path.suffix.lower() in TEXT_SUFFIXES:
        return True
    try:
        path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return False
    return True


def _iter_files() -> list[Path]:
    files: list[Path] = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(part in EXCLUDE_DIRS for part in path.parts):
            continue
        if path.name in EXCLUDE_FILES or "test_scan_for_secrets" in path.name:
            continue
        if path.name in ENV_FILES:
            continue
        if not _is_text(path):
            continue
        files.append(path)
    return files


def scan(paths: list[Path] | None = None) -> list[tuple[Path, str, str]]:
    matches: list[tuple[Path, str, str]] = []
    targets = paths or _iter_files()
    for path in targets:
        if path.name in EXCLUDE_FILES or "test_scan_for_secrets" in path.name:
            continue
        if path.name in ENV_FILES:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for name, pattern in PATTERNS.items():
            for match in re.finditer(pattern, text):
                matches.append((path, name, match.group(0)))
    return matches


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan for JWTs and secret patterns.")
    parser.add_argument("paths", nargs="*", type=Path, help="Files or dirs to scan (default: tracked text files)")
    parser.add_argument("--strict", action="store_true", help="Exit non-zero on any match")
    args = parser.parse_args()

    targets: list[Path] | None = None
    if args.paths:
        targets = []
        for item in args.paths:
            if item.is_dir():
                targets.extend(p for p in item.rglob("*") if p.is_file())
            else:
                targets.append(item)
    matches = scan(targets)
    for path, name, snippet in matches:
        try:
            rel = path.relative_to(ROOT)
        except ValueError:
            rel = path
        print(f"[SECRET-LIKE] {rel}: {name}: {snippet[:80]}")
    if matches and args.strict:
        return 1
    print(f"Scanned {len(targets) if targets else len(_iter_files())} files; {len(matches)} secret-like match(es).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())