"""Policy schema definitions and validators.

This module provides a strict, type-safe schema layer for policy payloads,
including reusable validation helpers and schema document versioning.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Any, Literal, Mapping

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, ValidationError
from pydantic import field_validator, model_validator


_FIELD_PATH_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
_KEY_ROTATION_PATTERN = re.compile(r"^\d+[dhmw]$", re.IGNORECASE)


class Operator(str, Enum):
    """Supported condition operators."""

    EQUALS = "EQUALS"
    NOT_EQUALS = "NOT_EQUALS"
    GREATER_THAN = "GREATER_THAN"
    LESS_THAN = "LESS_THAN"
    CONTAINS = "CONTAINS"
    IN = "IN"
    MATCHES = "MATCHES"


class Condition(BaseModel):
    """Single condition predicate used by a policy rule."""

    field: str = Field(min_length=1)
    operator: Operator
    value: Any

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    @field_validator("field")
    @classmethod
    def _validate_field_path(cls, value: str) -> str:
        candidate = value.strip()
        if not candidate:
            raise ValueError("field cannot be empty")
        if _FIELD_PATH_PATTERN.fullmatch(candidate) is None:
            raise ValueError("field must be a dotted identifier path")
        return candidate

    @model_validator(mode="after")
    def _validate_value_for_operator(self) -> "Condition":
        if self.operator is Operator.IN:
            if not isinstance(self.value, (list, tuple, set)):
                raise ValueError("IN operator requires value to be a list, tuple, or set")
            if not self.value:
                raise ValueError("IN operator requires a non-empty value set")

        if self.operator is Operator.MATCHES:
            if not isinstance(self.value, str) or not self.value.strip():
                raise ValueError("MATCHES operator requires a non-empty regex string")
            try:
                re.compile(self.value)
            except re.error as exc:
                raise ValueError(f"invalid regex pattern for MATCHES: {exc}") from exc

        if self.operator in {Operator.GREATER_THAN, Operator.LESS_THAN}:
            if isinstance(self.value, bool) or not isinstance(self.value, (int, float)):
                raise ValueError(
                    "GREATER_THAN and LESS_THAN operators require an int or float value"
                )

        return self


class Action(BaseModel):
    """Action to execute when a policy rule matches."""

    algorithm: str = Field(
        min_length=1,
        validation_alias=AliasChoices("algorithm", "selected_algorithm"),
    )
    key_rotation: str = Field(
        min_length=1,
        validation_alias=AliasChoices("key_rotation", "key_rotation_schedule"),
    )
    compliance: list[str] = Field(
        default_factory=list,
        validation_alias=AliasChoices("compliance", "compliance_tags"),
    )
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    @field_validator("algorithm")
    @classmethod
    def _normalize_algorithm(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("algorithm cannot be empty")
        return normalized

    @field_validator("key_rotation")
    @classmethod
    def _normalize_key_rotation(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("key_rotation cannot be empty")
        if _KEY_ROTATION_PATTERN.fullmatch(normalized) is None:
            raise ValueError("key_rotation must look like '<int><d|h|m|w>' (for example '90d')")
        return normalized.lower()

    @field_validator("compliance")
    @classmethod
    def _normalize_compliance(cls, value: list[str]) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()

        for item in value:
            if not isinstance(item, str):
                raise ValueError("compliance entries must be strings")

            token = item.strip()
            if not token:
                raise ValueError("compliance entries cannot be empty")

            lowered = token.lower()
            if lowered in seen:
                continue
            seen.add(lowered)
            normalized.append(token)

        return normalized

    @field_validator("metadata")
    @classmethod
    def _validate_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise ValueError("metadata must be a dictionary")
        return value


class PolicyRule(BaseModel):
    """A policy rule composed of a condition and an action."""

    condition: Condition = Field(validation_alias=AliasChoices("condition", "match", "when", "if"))
    action: Action = Field(validation_alias=AliasChoices("action", "decision", "then"))

    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class Policy(BaseModel):
    """Top-level policy definition."""

    name: str = Field(min_length=1)
    version: str = Field(min_length=1)
    rules: list[PolicyRule] = Field(default_factory=list)
    default_action: Action = Field(
        validation_alias=AliasChoices("default_action", "default_decision", "default"),
    )

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    @field_validator("name", "version")
    @classmethod
    def _normalize_non_empty_string(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("value cannot be empty")
        return normalized


class PolicySchemaVersion(str, Enum):
    """Supported policy schema versions."""

    V1 = "1.0"
    V2 = "2.0"


class PolicySchemaDocument(BaseModel):
    """Base schema envelope for versioned policy documents."""

    schema_version: PolicySchemaVersion = PolicySchemaVersion.V1
    policy: Policy

    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class PolicySchemaDocumentV1(PolicySchemaDocument):
    """Policy schema document for version 1.0."""

    schema_version: Literal[PolicySchemaVersion.V1] = PolicySchemaVersion.V1


class PolicySchemaDocumentV2(PolicySchemaDocument):
    """Policy schema document for version 2.0."""

    schema_version: Literal[PolicySchemaVersion.V2] = PolicySchemaVersion.V2


SCHEMA_REGISTRY: dict[PolicySchemaVersion, type[PolicySchemaDocument]] = {
    PolicySchemaVersion.V1: PolicySchemaDocumentV1,
    PolicySchemaVersion.V2: PolicySchemaDocumentV2,
}


def parse_policy_document(payload: Mapping[str, Any]) -> PolicySchemaDocument:
    """Parse a versioned policy document into a typed schema model."""
    if not isinstance(payload, Mapping):
        raise TypeError("payload must be a mapping")

    raw_version = payload.get("schema_version", PolicySchemaVersion.V1.value)
    try:
        schema_version = PolicySchemaVersion(str(raw_version))
    except ValueError as exc:
        supported = ", ".join(item.value for item in PolicySchemaVersion)
        raise ValueError(f"unsupported schema_version '{raw_version}', expected one of: {supported}") from exc

    model_cls = SCHEMA_REGISTRY[schema_version]
    return model_cls.model_validate(payload)


def validate_condition(condition: Condition) -> bool:
    """Return True when a Condition object is semantically valid."""
    try:
        Condition.model_validate(condition.model_dump())
    except ValidationError:
        return False
    return True


def validate_action(action: Action) -> bool:
    """Return True when an Action object is semantically valid."""
    try:
        Action.model_validate(action.model_dump())
    except ValidationError:
        return False
    return True


__all__ = [
    "Operator",
    "Condition",
    "Action",
    "PolicyRule",
    "Policy",
    "PolicySchemaVersion",
    "PolicySchemaDocument",
    "PolicySchemaDocumentV1",
    "PolicySchemaDocumentV2",
    "SCHEMA_REGISTRY",
    "parse_policy_document",
    "validate_condition",
    "validate_action",
]
