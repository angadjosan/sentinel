"""Config loading for Sentinel — reads sentinel.yml and env vars."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal, Optional

import yaml
from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class SentinelConfigError(Exception):
    """Raised when a required configuration value is missing."""


def _load_yaml_config() -> dict[str, Any]:
    """Load sentinel.yml from CWD or ~/.config/sentinel/sentinel.yml."""
    candidates = [
        Path.cwd() / "sentinel.yml",
        Path.home() / ".config" / "sentinel" / "sentinel.yml",
    ]
    for path in candidates:
        if path.exists():
            with open(path) as fh:
                data = yaml.safe_load(fh) or {}
            return data
    return {}


class SentinelConfig(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    anthropic_api_key: Optional[str] = None
    github_token: Optional[str] = None
    output_dir: str = "./sentinel-report"
    fail_on: Literal["critical", "high", "medium", "low", "never"] = "high"
    dashboard_port: int = 4000
    dashboard_auto_open: bool = True
    redis_url: str = "redis://localhost:6379/0"
    github_webhook_secret: Optional[str] = None
    github_app_id: Optional[str] = None          # reads GITHUB_APP_ID
    github_app_private_key: Optional[str] = None  # reads GITHUB_APP_PRIVATE_KEY (PEM or base64)

    @model_validator(mode="before")
    @classmethod
    def merge_yaml_and_env(cls, values: Any) -> Any:
        """Merge YAML file values under env/explicit values (env wins)."""
        yaml_data = _load_yaml_config()
        # Start from YAML as base, then overlay explicit/env values
        merged: dict[str, Any] = {}
        merged.update(yaml_data)
        if isinstance(values, dict):
            # Only overlay keys that were explicitly provided (non-None)
            for k, v in values.items():
                if v is not None:
                    merged[k] = v
        # Env vars take highest priority — pydantic-settings handles those after
        # this validator, so we just make sure YAML fills in blanks.
        return merged

    def require_anthropic_key(self) -> str:
        """Return the Anthropic API key or raise SentinelConfigError."""
        key = self.anthropic_api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise SentinelConfigError(
                "Set ANTHROPIC_API_KEY or add anthropic_api_key to sentinel.yml"
            )
        return key


def load_config(
    *,
    output_dir: Optional[str] = None,
    fail_on: Optional[str] = None,
) -> SentinelConfig:
    """Load config from YAML + env, with optional CLI overrides."""
    overrides: dict[str, Any] = {}
    if output_dir is not None:
        overrides["output_dir"] = output_dir
    if fail_on is not None:
        overrides["fail_on"] = fail_on
    return SentinelConfig(**overrides)
