"""Runtime configuration loaded from env vars and CLI overrides."""

from __future__ import annotations

from enum import Enum
from pathlib import Path

from pydantic import Field, field_validator
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
    )

    base_url: str = Field(default="https://api.tap.mirror.capmotion.io")
    token: str = Field(default="")
    admin_token: str = Field(default="")
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
    if "delay_ms" not in data:
        pass
    return Settings(**data)  # type: ignore[arg-type]
