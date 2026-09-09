"""Tests for Settings alias resolution and CLI override precedence."""

from __future__ import annotations

import os
from pathlib import Path

from tap_authz_check.config import Settings


def _clean_env() -> None:
    for k in list(os.environ):
        if "TOKEN" in k or "SESSION" in k or "TAP_AUTHZ" in k:
            os.environ.pop(k, None)


def test_empty_env() -> None:
    _clean_env()
    s = Settings(_env_file=None)
    assert s.session_token == ""
    assert s.admin_session_token == ""


def test_prefixed_session_token() -> None:
    _clean_env()
    os.environ["TAP_AUTHZ_SESSION_TOKEN"] = "abc"
    s = Settings(_env_file=None)
    assert s.session_token == "abc"


def test_bare_session_token_alias() -> None:
    _clean_env()
    os.environ["SESSION_TOKEN"] = "xyz"
    s = Settings(_env_file=None)
    assert s.session_token == "xyz"


def test_prefixed_wins_over_bare() -> None:
    _clean_env()
    os.environ["TAP_AUTHZ_SESSION_TOKEN"] = "prefixed"
    os.environ["SESSION_TOKEN"] = "bare"
    s = Settings(_env_file=None)
    assert s.session_token == "prefixed"


def test_admin_prefixed_wins_over_bare() -> None:
    _clean_env()
    os.environ["TAP_AUTHZ_ADMIN_SESSION_TOKEN"] = "admin-prefixed"
    os.environ["ADMIN_SESSION_TOKEN"] = "admin-bare"
    s = Settings(_env_file=None)
    assert s.admin_session_token == "admin-prefixed"


def test_admin_bare_only() -> None:
    _clean_env()
    os.environ["ADMIN_SESSION_TOKEN"] = "admin-bare"
    s = Settings(_env_file=None)
    assert s.admin_session_token == "admin-bare"


def test_kwarg_overrides_env() -> None:
    _clean_env()
    os.environ["TAP_AUTHZ_SESSION_TOKEN"] = "from-env"
    s = Settings(_env_file=None, session_token="from-kwarg")
    assert s.session_token == "from-kwarg"


def test_fixture_file_path_expansion() -> None:
    _clean_env()
    s = Settings(_env_file=None, fixture_file=Path("~/foo.yaml"))
    assert s.fixture_file == Path.home() / "foo.yaml"