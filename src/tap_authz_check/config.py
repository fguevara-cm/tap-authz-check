"""Runtime configuration loaded from env vars and CLI overrides."""

from __future__ import annotations

from enum import Enum
from pathlib import Path

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class RunMode(str, Enum):  # noqa: UP042
    AUDIT = "audit"
    VERIFY = "verify"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="TAP_AUTHZ_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
        populate_by_name=True,
    )

    base_url: str = Field(default="https://api.tap.mirror.capmotion.io")
    session_token: str = Field(
        default="",
        validation_alias=AliasChoices(
            "TAP_AUTHZ_SESSION_TOKEN", "SESSION_TOKEN", "session_token"
        ),
    )
    admin_session_token: str = Field(
        default="",
        validation_alias=AliasChoices(
            "TAP_AUTHZ_ADMIN_SESSION_TOKEN", "ADMIN_SESSION_TOKEN", "admin_session_token"
        ),
    )
    fixture_file: Path = Field(default=Path("fixtures/mirror.yaml"))
    timeout_seconds: float = Field(default=30.0, gt=0)
    mode: RunMode = Field(default=RunMode.AUDIT)
    delay_ms: int = Field(default=100, ge=0)

    @field_validator("base_url")
    @classmethod
    def _strip_trailing_slash(cls, value: str) -> str:
        return value.rstrip("/")

    @field_validator("fixture_file")
    @classmethod
    def _expand_path(cls, value: Path) -> Path:
        return value.expanduser()


def load_settings(**overrides: object) -> Settings:
    """Build settings applying CLI overrides."""
    data: dict[str, object] = {k: v for k, v in overrides.items() if v is not None}
    if "timeout" in data:
        data["timeout_seconds"] = data.pop("timeout")
    return Settings(**data)  # type: ignore[arg-type]
