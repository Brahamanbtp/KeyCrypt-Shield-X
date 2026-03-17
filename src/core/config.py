"""Configuration model and loaders for KeyCrypt Shield X."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field, ValidationError, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class SecurityLevel(str, Enum):
    """Supported runtime security postures."""

    LOW = "LOW"
    NORMAL = "NORMAL"
    ELEVATED = "ELEVATED"
    CRITICAL = "CRITICAL"


class Config(BaseSettings):
    """Application configuration with env and file-based overrides."""

    security_level: SecurityLevel = SecurityLevel.NORMAL
    enable_quantum: bool = True
    enable_consciousness: bool = False
    encryption_algorithm: str = "AES-256-GCM"
    key_rotation_days: int = Field(default=30, ge=1, le=3650)
    storage_backend: str = "filesystem"

    model_config = SettingsConfigDict(
        env_prefix="KEYCRYPT_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        validate_default=True,
    )

    @field_validator("encryption_algorithm")
    @classmethod
    def validate_encryption_algorithm(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("encryption_algorithm cannot be empty")

        allowed_algorithms = {
            "AES-256-GCM",
            "CHACHA20-POLY1305",
            "KYBER-AES-GCM",
            "DILITHIUM-AES-GCM",
        }
        if normalized.upper() not in allowed_algorithms:
            raise ValueError(
                "encryption_algorithm must be one of "
                f"{', '.join(sorted(allowed_algorithms))}"
            )
        return normalized.upper()

    @field_validator("storage_backend")
    @classmethod
    def validate_storage_backend(cls, value: str) -> str:
        normalized = value.strip().lower()
        allowed_backends = {"filesystem", "sqlite", "postgres", "s3"}
        if normalized not in allowed_backends:
            raise ValueError(
                f"storage_backend must be one of {', '.join(sorted(allowed_backends))}"
            )
        return normalized

    @classmethod
    def from_yaml(cls, path: str | Path) -> "Config":
        """Load config from a YAML file and merge with environment variables."""
        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {file_path}")

        with file_path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}

        if not isinstance(data, dict):
            raise ValueError("YAML configuration must be a mapping/object")

        # BaseSettings applies environment variable overrides on initialization.
        return cls(**data)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the configuration."""
        return self.model_dump()


def load_config(config_path: str | Path | None = None) -> Config:
    """Convenience loader: read YAML when provided, otherwise use env/defaults."""
    if config_path is not None:
        return Config.from_yaml(config_path)
    return Config()


__all__ = ["SecurityLevel", "Config", "load_config", "ValidationError"]
