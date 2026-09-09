"""Offline tests for the secret-scan tool."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
from pathlib import Path

_SCAN_PATH = Path(__file__).resolve().parents[1] / "tools" / "scan_for_secrets.py"
_spec = importlib.util.spec_from_file_location("scan_for_secrets", _SCAN_PATH)
assert _spec and _spec.loader
scan_for_secrets = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = scan_for_secrets
_spec.loader.exec_module(scan_for_secrets)
scan = scan_for_secrets.scan


def test_scan_detects_jwt() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "leak.txt"
        path.write_text("token: eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig", encoding="utf-8")
        matches = scan([path])
        assert any(name == "jwt" for _, name, _ in matches)


def test_scan_ignores_empty_env_template() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / ".env.example"
        path.write_text(
            "TAP_AUTHZ_SESSION_TOKEN=\nTAP_AUTHZ_ADMIN_SESSION_TOKEN=\n",
            encoding="utf-8",
        )
        matches = scan([path])
        assert matches == []


def test_scan_detects_bearer_header() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "log.txt"
        path.write_text("Authorization: Bearer abc123def456ghi789jkl012mno\n", encoding="utf-8")
        matches = scan([path])
        assert any(name == "bearer" for _, name, _ in matches)


def test_scan_detects_nonempty_token_var() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "leak.env"
        path.write_text("TAP_AUTHZ_TOKEN=eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig\n", encoding="utf-8")
        matches = scan([path])
        assert any(name == "token_var" for _, name, _ in matches)


def test_scan_detects_nonempty_session_token_var() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "leak.env"
        path.write_text("TAP_AUTHZ_SESSION_TOKEN=eyJhbGciOiJSUzI1NiJ9.signature_long_enough\n", encoding="utf-8")
        matches = scan([path])
        assert any(name == "session_token_var" for _, name, _ in matches)


def test_scan_detects_bare_session_token_var() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "leak.env"
        path.write_text("SESSION_TOKEN=eyJhbGciOiJSUzI1NiJ9.signature_long_enough\n", encoding="utf-8")
        matches = scan([path])
        assert any(name == "bare_session_token_var" for _, name, _ in matches)


def test_scan_detects_session_cookie_header() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "log.txt"
        path.write_text("Set-Cookie: TAP_SESSION_JWT=eyJhbGciOiJSUzI1NiJ9.signature\n", encoding="utf-8")
        matches = scan([path])
        assert any(name == "session_cookie" for _, name, _ in matches)


def test_scan_ignores_safe_content() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "safe.txt"
        path.write_text("just a normal README without secrets\n", encoding="utf-8")
        matches = scan([path])
        assert matches == []