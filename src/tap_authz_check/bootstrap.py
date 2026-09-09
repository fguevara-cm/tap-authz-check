"""Bootstrap: GET /api/user/me snapshot with admin-session guardrail."""

from __future__ import annotations

from typing import Any

from .client import HttpClient
from .models import ActorSnapshot


def fetch_actor(
    client: HttpClient,
    *,
    allow_admin: bool = False,
    force_admin_token: bool = False,
) -> ActorSnapshot:
    """Return the actor snapshot. Abort conditions are surfaced via ``BootstrapError``."""

    response = client.get("/api/user/me")
    if response.error_message is not None:
        raise BootstrapError(f"/api/user/me failed: {response.error_message}")
    if response.status != 200:
        raise BootstrapError(
            f"/api/user/me returned {response.status}: {response.body_snippet[:200]}"
        )

    payload = _parse_json(response.body_snippet)
    snapshot = _build_snapshot(payload)

    if snapshot.is_admin and not (allow_admin or force_admin_token):
        raise BootstrapError(
            "actor is admin; aborting to avoid privilege escalation on a real admin "
            "(use --force-admin-token for positive controls with the admin session_token)"
        )

    return snapshot


def _parse_json(snippet: str) -> dict[str, Any]:
    import json

    try:
        data = json.loads(snippet)
    except json.JSONDecodeError as exc:
        raise BootstrapError(f"/api/user/me body is not JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise BootstrapError("/api/user/me body must be a JSON object")
    return data


def _build_snapshot(payload: dict[str, Any]) -> ActorSnapshot:
    clients = payload.get("clients") if isinstance(payload.get("clients"), list) else []
    providers_raw = payload.get("providers") if isinstance(payload.get("providers"), list) else []
    provider_ids = [
        entry["providerId"]
        for entry in providers_raw
        if isinstance(entry, dict) and isinstance(entry.get("providerId"), str)
    ]
    client_ids: list[str] = []
    for entry in clients:
        if not isinstance(entry, dict):
            continue
        client = entry.get("client")
        if isinstance(client, str):
            client_ids.append(client)
        elif isinstance(client, dict) and isinstance(client.get("id"), str):
            client_ids.append(client["id"])

    return ActorSnapshot(
        email=_as_str(payload.get("userName") or payload.get("id") or payload.get("email")),
        name=_as_str(payload.get("name")),
        company=_as_str(payload.get("companyName")),
        provider_ids=_dedup(provider_ids),
        client_ids=_dedup(client_ids),
        is_admin=bool(payload.get("isAdmin", False)),
        raw=payload,
    )


def _as_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _dedup(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in values:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


class BootstrapError(RuntimeError):
    """Raised when bootstrap cannot produce a valid actor snapshot."""
