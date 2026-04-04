"""Pydantic-based input validation and sanitization models.

This module provides a standalone validation layer for file path, encryption,
and API request payloads.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator


MAX_PATH_LENGTH = 1024
DEFAULT_MAX_FILE_SIZE_BYTES = 512 * 1024 * 1024

_WINDOWS_ABSOLUTE_PATH_RE = re.compile(r"^[A-Za-z]:[\\/]")
_KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{1,127}$")
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_TRACE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")

_ALGORITHM_ALIASES = {
    "AES-256": "AES-256-GCM",
    "AES-GCM": "AES-256-GCM",
    "AESGCM": "AES-256-GCM",
    "CHACHA20": "CHACHA20-POLY1305",
    "XCHACHA20": "XCHACHA20-POLY1305",
    "KYBER": "KYBER-AES-GCM",
    "HYBRID": "KYBER-HYBRID",
    "HYBRID-KEM": "KYBER-HYBRID",
}

_SUPPORTED_ALGORITHMS = {
    "AES-256-GCM",
    "CHACHA20-POLY1305",
    "XCHACHA20-POLY1305",
    "KYBER-HYBRID",
    "KYBER-AES-GCM",
    "DILITHIUM-AES-GCM",
}


class FilePathInput(BaseModel):
    """Validate file path values, traversal safety, and size limits."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    path: str = Field(min_length=1, max_length=MAX_PATH_LENGTH)
    size_bytes: int = Field(ge=0)
    max_size_bytes: int = Field(default=DEFAULT_MAX_FILE_SIZE_BYTES, ge=1)

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        if "\x00" in value:
            raise ValueError("path cannot contain null bytes")

        if value.startswith(("/", "\\", "~")):
            raise ValueError("absolute or home-relative paths are not allowed")
        if _WINDOWS_ABSOLUTE_PATH_RE.match(value):
            raise ValueError("absolute Windows paths are not allowed")

        normalized = value.replace("\\", "/")
        parts = [segment for segment in normalized.split("/") if segment and segment != "."]

        if not parts:
            raise ValueError("path must contain at least one valid segment")
        if any(segment == ".." for segment in parts):
            raise ValueError("path traversal segments ('..') are not allowed")

        sanitized = "/".join(parts)
        if len(sanitized) > MAX_PATH_LENGTH:
            raise ValueError(f"sanitized path exceeds {MAX_PATH_LENGTH} characters")

        return sanitized

    @model_validator(mode="after")
    def validate_size_limit(self) -> "FilePathInput":
        if self.size_bytes > self.max_size_bytes:
            raise ValueError(
                f"size_bytes ({self.size_bytes}) exceeds max_size_bytes ({self.max_size_bytes})"
            )
        return self


class EncryptionInput(BaseModel):
    """Validate encryption-specific API fields."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    algorithm: str = Field(min_length=1, max_length=64)
    key_id: str | None = Field(default=None, min_length=2, max_length=128)

    @field_validator("algorithm")
    @classmethod
    def validate_algorithm_name(cls, value: str) -> str:
        normalized = value.strip().upper().replace("_", "-")
        canonical = _ALGORITHM_ALIASES.get(normalized, normalized)
        if canonical not in _SUPPORTED_ALGORITHMS:
            supported = ", ".join(sorted(_SUPPORTED_ALGORITHMS))
            raise ValueError(f"unsupported algorithm '{value}'. Supported values: {supported}")
        return canonical

    @field_validator("key_id")
    @classmethod
    def validate_key_id_format(cls, value: str | None) -> str | None:
        if value is None:
            return None

        candidate = value.strip()
        if not _KEY_ID_RE.fullmatch(candidate):
            raise ValueError(
                "key_id must match pattern ^[A-Za-z0-9][A-Za-z0-9._:-]{1,127}$"
            )
        return candidate


class APIRequest(BaseModel):
    """Validate aggregate API request inputs with nested schemas."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    user_id: str = Field(min_length=1, max_length=128)
    request_id: str | None = Field(default=None, max_length=128)
    trace_id: str | None = Field(default=None, max_length=128)
    file: FilePathInput
    encryption: EncryptionInput
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("user_id")
    @classmethod
    def validate_user_id(cls, value: str) -> str:
        if any(char.isspace() for char in value):
            raise ValueError("user_id cannot include whitespace")
        return value

    @field_validator("request_id")
    @classmethod
    def validate_request_id(cls, value: str | None) -> str | None:
        if value is None:
            return None

        candidate = value.strip()
        if not _REQUEST_ID_RE.fullmatch(candidate):
            raise ValueError(
                "request_id must match pattern ^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$"
            )
        return candidate

    @field_validator("trace_id")
    @classmethod
    def validate_trace_id(cls, value: str | None) -> str | None:
        if value is None:
            return None

        candidate = value.strip()
        if not _TRACE_ID_RE.fullmatch(candidate):
            raise ValueError(
                "trace_id must match pattern ^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$"
            )
        return candidate

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise TypeError("metadata must be a dictionary")
        return value


class InputValidator:
    """Facade helpers for strict Pydantic schema validation.

    Validation errors are surfaced as pydantic.ValidationError.
    """

    @staticmethod
    def validate_file_path(payload: FilePathInput | Mapping[str, Any]) -> FilePathInput:
        if isinstance(payload, FilePathInput):
            return payload
        return FilePathInput.model_validate(payload)

    @staticmethod
    def validate_encryption(payload: EncryptionInput | Mapping[str, Any]) -> EncryptionInput:
        if isinstance(payload, EncryptionInput):
            return payload
        return EncryptionInput.model_validate(payload)

    @staticmethod
    def validate_api_request(payload: APIRequest | Mapping[str, Any]) -> APIRequest:
        if isinstance(payload, APIRequest):
            return payload
        return APIRequest.model_validate(payload)


__all__ = [
    "ValidationError",
    "FilePathInput",
    "EncryptionInput",
    "APIRequest",
    "InputValidator",
]
