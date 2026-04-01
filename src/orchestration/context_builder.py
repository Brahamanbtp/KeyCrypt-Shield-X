"""Builder utilities for constructing encryption execution contexts.

This module provides a typed `EncryptionContext` model and a fluent
`EncryptionContextBuilder` for assembling validated context objects.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Self


class DataClassification(str, Enum):
    """Data sensitivity classes used for encryption decisions."""

    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    SECRET = "SECRET"
    TOP_SECRET = "TOP_SECRET"


class PerformanceTarget(str, Enum):
    """Execution priorities used to tune provider and policy behavior."""

    SPEED = "SPEED"
    BALANCED = "BALANCED"
    SECURITY = "SECURITY"


@dataclass(frozen=True)
class EncryptionContext:
    """Execution context consumed by orchestration and policy layers.

    Attributes:
        user_id: Identifier for the requesting user/principal.
        data_classification: Sensitivity level for the payload.
        compliance_requirements: Compliance standards to enforce.
        performance_target: Runtime optimization objective.
        metadata: Additional contextual attributes.
    """

    user_id: str
    data_classification: DataClassification
    compliance_requirements: List[str] = field(default_factory=list)
    performance_target: PerformanceTarget = PerformanceTarget.BALANCED
    metadata: Dict[str, Any] = field(default_factory=dict)


class EncryptionContextBuilder:
    """Fluent builder for `EncryptionContext` with validation rules."""

    _TOP_SECRET_ALLOWED_STANDARDS = {
        "NIST-800-53-HIGH",
        "CMMC_LEVEL_3",
        "FIPS-140-3",
        "ITAR",
    }

    def __init__(self) -> None:
        self._user_id: str | None = None
        self._data_classification: DataClassification = DataClassification.INTERNAL
        self._compliance_requirements: list[str] = []
        self._performance_target: PerformanceTarget = PerformanceTarget.BALANCED
        self._metadata: dict[str, Any] = {}

    def with_user(self, user_id: str) -> Self:
        """Set user identifier for the context."""
        if not isinstance(user_id, str) or not user_id.strip():
            raise ValueError("user_id must be a non-empty string")

        self._user_id = user_id.strip()
        return self

    def with_classification(self, level: DataClassification) -> Self:
        """Set data classification level for the context."""
        if not isinstance(level, DataClassification):
            raise TypeError("level must be a DataClassification value")

        self._data_classification = level
        return self

    def with_compliance(self, *standards: str) -> Self:
        """Append one or more compliance requirements."""
        for standard in standards:
            if not isinstance(standard, str) or not standard.strip():
                raise ValueError("each compliance standard must be a non-empty string")

            normalized = self._normalize_standard(standard)
            if normalized not in self._compliance_requirements:
                self._compliance_requirements.append(normalized)

        return self

    def build(self) -> EncryptionContext:
        """Build and validate an immutable `EncryptionContext` instance."""
        if self._user_id is None:
            raise ValueError("user_id is required; call with_user() before build()")

        self._validate_top_secret_requirements(
            self._data_classification,
            self._compliance_requirements,
        )

        return EncryptionContext(
            user_id=self._user_id,
            data_classification=self._data_classification,
            compliance_requirements=list(self._compliance_requirements),
            performance_target=self._performance_target,
            metadata=dict(self._metadata),
        )

    @classmethod
    def _validate_top_secret_requirements(
        cls,
        classification: DataClassification,
        compliance_requirements: list[str],
    ) -> None:
        if classification != DataClassification.TOP_SECRET:
            return

        normalized = {cls._normalize_standard(item) for item in compliance_requirements}
        if not normalized.intersection(cls._TOP_SECRET_ALLOWED_STANDARDS):
            allowed = ", ".join(sorted(cls._TOP_SECRET_ALLOWED_STANDARDS))
            raise ValueError(
                "TOP_SECRET data requires at least one high-assurance compliance "
                f"standard: {allowed}"
            )

    @staticmethod
    def _normalize_standard(value: str) -> str:
        return value.strip().upper().replace(" ", "_")


__all__: list[str] = [
    "DataClassification",
    "PerformanceTarget",
    "EncryptionContext",
    "EncryptionContextBuilder",
]
