"""Offline tests for templates."""

from __future__ import annotations

import pytest

from tap_authz_check.models import ActorSnapshot, FixtureData
from tap_authz_check.templates import (
    MissingPlaceholder,
    build_context,
    has_unresolved,
    render_string,
    render_value,
)


def _actor() -> ActorSnapshot:
    return ActorSnapshot(
        email="seller@example.test",
        name="Mark Seller",
        company="Test",
        provider_ids=["provider-A"],
        client_ids=["provider-A"],
        is_admin=False,
        raw={"id": "seller@example.test", "clients": [{"client": "provider-A"}]},
    )


def _fixture() -> FixtureData:
    return FixtureData(
        environment="mirror",
        foreign_provider_id="provider-FOREIGN",
        victim_user_id="victim@example.test",
    )


def test_render_string_replaces_known_placeholder() -> None:
    ctx = build_context(_actor(), _fixture())
    rendered = render_string("/users/{{actor_email}}", ctx)
    assert rendered == "/users/seller@example.test"


def test_render_value_handles_nested() -> None:
    ctx = build_context(_actor(), _fixture())
    payload = {"id": "{{actor_email}}", "clients": [{"client": "{{foreign_provider_id}}"}]}
    rendered = render_value(payload, ctx)
    assert rendered == {"id": "seller@example.test", "clients": [{"client": "provider-FOREIGN"}]}


def test_missing_placeholder_raises() -> None:
    ctx = build_context(ActorSnapshot(), FixtureData())
    with pytest.raises(MissingPlaceholder):
        render_string("{{foreign_provider_id}}", ctx)


def test_has_unresolved_returns_missing_keys() -> None:
    ctx = build_context(_actor(), FixtureData(foreign_provider_id=None))
    missing = has_unresolved({"x": "{{victim_user_id}}"}, ctx)
    assert missing == ["victim_user_id"]


def test_build_context_includes_clients_passthrough() -> None:
    ctx = build_context(_actor(), _fixture())
    assert ctx["actor_clients_passthrough"] == [{"client": "provider-A"}]


def test_build_context_includes_resource_fixture_ids() -> None:
    fixture = FixtureData(
        trade_id="trade-1",
        invoice_id="invoice-1",
        settlement_id="settlement-1",
    )
    ctx = build_context(_actor(), fixture)
    assert ctx["trade_id"] == "trade-1"
    assert ctx["invoice_id"] == "invoice-1"
    assert ctx["settlement_id"] == "settlement-1"


def test_render_value_preserves_native_type_for_full_placeholder() -> None:
    fixture = FixtureData(
        extra={
            "capacity_total": 20000000,
            "retainage_enabled": True,
            "rate_libor_maturities": ["ONE_WEEK", "TWO_MONTHS"],
        }
    )
    ctx = build_context(_actor(), fixture)
    assert render_value("{{capacity_total}}", ctx) == 20000000
    assert render_value("{{retainage_enabled}}", ctx) is True
    assert render_value("{{rate_libor_maturities}}", ctx) == ["ONE_WEEK", "TWO_MONTHS"]
    assert render_value("prefix-{{capacity_total}}", ctx) == "prefix-20000000"


def test_render_value_full_placeholder_missing_raises() -> None:
    ctx = build_context(_actor(), FixtureData())
    with pytest.raises(MissingPlaceholder):
        render_value("{{capacity_total}}", ctx)
