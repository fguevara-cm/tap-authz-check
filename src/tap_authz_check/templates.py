"""Placeholder rendering for paths, headers and JSON bodies."""

from __future__ import annotations

import re
from typing import Any

from .models import ActorSnapshot, FixtureData

_PLACEHOLDER = re.compile(r"\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}")


class MissingPlaceholder(ValueError):
    """Raised when a placeholder cannot be resolved."""

    def __init__(self, name: str) -> None:
        super().__init__(f"missing placeholder: {name}")
        self.name = name


def render_string(value: str, ctx: dict[str, Any]) -> str:
    def replace(match: re.Match[str]) -> str:
        key = match.group(1)
        if key not in ctx or ctx[key] in (None, ""):
            raise MissingPlaceholder(key)
        return str(ctx[key])

    return _PLACEHOLDER.sub(replace, value)


def render_value(value: Any, ctx: dict[str, Any]) -> Any:
    if isinstance(value, str):
        return render_string(value, ctx)
    if isinstance(value, list):
        return [render_value(item, ctx) for item in value]
    if isinstance(value, dict):
        return {key: render_value(item, ctx) for key, item in value.items()}
    return value


def build_context(actor: ActorSnapshot, fixture: FixtureData) -> dict[str, Any]:
    actor_clients = (
        actor.raw.get("clients")
        if isinstance(actor.raw, dict)
        else None
    )
    return {
        "actor_email": actor.email,
        "actor_name": actor.name,
        "actor_company": actor.company,
        "first_provider_id": actor.provider_ids[0] if actor.provider_ids else None,
        "foreign_provider_id": fixture.foreign_provider_id,
        "victim_user_id": fixture.victim_user_id,
        "victim_user_email": fixture.extra.get("victim_user_email"),
        "actor_clients_passthrough": actor_clients if actor_clients is not None else [],
    }


def has_unresolved(value: Any, ctx: dict[str, Any]) -> list[str]:
    missing: list[str] = []
    if isinstance(value, str):
        for match in _PLACEHOLDER.finditer(value):
            key = match.group(1)
            if key not in ctx or ctx[key] in (None, ""):
                missing.append(key)
        return missing
    if isinstance(value, list):
        for item in value:
            missing.extend(has_unresolved(item, ctx))
    elif isinstance(value, dict):
        for item in value.values():
            missing.extend(has_unresolved(item, ctx))
    return missing
