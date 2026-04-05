"""Real-time compliance validation for security-critical operations.

This module preserves standards-specific compliance validation logic while
extending it with pre-operation enforcement so non-compliant operations can be
blocked before execution.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Mapping, Sequence
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from src.utils.logging import get_logger, log_security_event


logger = get_logger("src.observability.compliance_validator")


class Operation(BaseModel):
    """Operation payload evaluated for compliance before execution."""

    model_config = ConfigDict(extra="allow", validate_assignment=True)

    operation_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    actor: str = Field(min_length=1)
    action: str = Field(min_length=1)
    resource: str = Field(min_length=1)

    encryption_enabled: bool = False
    encryption_strength_bits: int = Field(default=0, ge=0)
    key_rotation_days: int | None = Field(default=None, ge=0)
    audit_logging_enabled: bool = False

    deletion_capability: bool = False
    consent_obtained: bool = False
    data_minimization_enabled: bool = False

    contains_cardholder_data: bool = False
    cardholder_data_encrypted: bool = False
    keys_protected: bool = False
    access_restricted: bool = False

    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("operation_id", "actor", "action", "resource")
    @classmethod
    def _validate_non_empty_text(cls, value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("field must be a non-empty string")
        return value.strip()


class ComplianceResult(BaseModel):
    """Compliance validation result.

    Fields:
    - compliant: Whether all required checks passed.
    - violations: Human-readable list of failed checks.
    - recommendations: Automated remediation suggestions for violations.
    """

    model_config = ConfigDict(extra="forbid")

    compliant: bool
    violations: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class ComplianceViolationError(RuntimeError):
    """Raised when pre-operation enforcement blocks a non-compliant operation."""

    def __init__(self, *, operation: Operation, standards: Sequence[str], result: ComplianceResult) -> None:
        self.operation = operation
        self.standards = tuple(standards)
        self.result = result

        details = "; ".join(result.violations[:3])
        if len(result.violations) > 3:
            details += f"; +{len(result.violations) - 3} more"

        super().__init__(
            "pre-operation compliance validation failed for "
            f"{operation.operation_id} ({', '.join(self.standards)}): {details}"
        )


class ComplianceValidator:
    """Real-time compliance validator with optional operation blocking."""

    HIPAA_MIN_ENCRYPTION_BITS = 256
    HIPAA_MAX_KEY_ROTATION_DAYS = 90
    GDPR_MIN_ENCRYPTION_BITS = 128

    _STANDARD_ALIASES = {
        "hipaa": "hipaa",
        "gdpr": "gdpr",
        "pci": "pci-dss",
        "pci-dss": "pci-dss",
        "pci_dss": "pci-dss",
        "pci dss": "pci-dss",
        "pcidss": "pci-dss",
    }

    def __init__(
        self,
        *,
        block_non_compliant_operations: bool = True,
        actor_id: str = "compliance_validator",
    ) -> None:
        self._block_non_compliant_operations = bool(block_non_compliant_operations)
        self._actor_id = self._require_non_empty("actor_id", actor_id)

    def validate_hipaa_compliance(self, operation: Operation) -> ComplianceResult:
        """Validate HIPAA controls.

        Checks:
        - encryption strength >= 256-bit
        - key rotation <= 90 days
        - audit logging enabled
        """
        op = self._coerce_operation(operation)

        violations: list[str] = []
        recommendations: list[str] = []

        if not op.encryption_enabled:
            self._add_violation(
                violations,
                recommendations,
                "HIPAA requires encryption to be enabled.",
                "Enable authenticated encryption before operation execution.",
            )

        if op.encryption_strength_bits < self.HIPAA_MIN_ENCRYPTION_BITS:
            self._add_violation(
                violations,
                recommendations,
                f"HIPAA requires encryption strength >= {self.HIPAA_MIN_ENCRYPTION_BITS}-bit.",
                "Upgrade to at least 256-bit key strength (for example AES-256-GCM).",
            )

        if op.key_rotation_days is None:
            self._add_violation(
                violations,
                recommendations,
                "HIPAA requires key rotation policy to be configured (<= 90 days).",
                "Configure automated key rotation to run every 90 days or less.",
            )
        elif op.key_rotation_days > self.HIPAA_MAX_KEY_ROTATION_DAYS:
            self._add_violation(
                violations,
                recommendations,
                "HIPAA requires key rotation interval <= 90 days.",
                "Reduce key rotation interval to 90 days or less.",
            )

        if not op.audit_logging_enabled:
            self._add_violation(
                violations,
                recommendations,
                "HIPAA requires audit logging to be enabled.",
                "Enable immutable audit logging for this operation path.",
            )

        result = self._build_result(violations, recommendations)
        self._log_validation(standard="hipaa", operation=op, result=result)
        return result

    def validate_gdpr_compliance(self, operation: Operation) -> ComplianceResult:
        """Validate GDPR controls.

        Checks:
        - encryption
        - deletion capability
        - consent
        - data minimization
        """
        op = self._coerce_operation(operation)

        violations: list[str] = []
        recommendations: list[str] = []

        if not op.encryption_enabled:
            self._add_violation(
                violations,
                recommendations,
                "GDPR requires personal data processing to be encrypted.",
                "Enable encryption for GDPR-scoped operations.",
            )
        elif op.encryption_strength_bits < self.GDPR_MIN_ENCRYPTION_BITS:
            self._add_violation(
                violations,
                recommendations,
                f"GDPR encrypted processing requires >= {self.GDPR_MIN_ENCRYPTION_BITS}-bit strength.",
                "Increase encryption strength to at least 128-bit for personal data.",
            )

        if not op.deletion_capability:
            self._add_violation(
                violations,
                recommendations,
                "GDPR requires deletion capability (right to erasure).",
                "Implement and verify deletion workflows before executing the operation.",
            )

        if not op.consent_obtained:
            self._add_violation(
                violations,
                recommendations,
                "GDPR requires explicit consent prior to processing.",
                "Collect and store valid consent evidence before processing personal data.",
            )

        if not op.data_minimization_enabled:
            self._add_violation(
                violations,
                recommendations,
                "GDPR requires data minimization to be enforced.",
                "Restrict processing payload to minimum necessary attributes.",
            )

        result = self._build_result(violations, recommendations)
        self._log_validation(standard="gdpr", operation=op, result=result)
        return result

    def validate_pci_dss_compliance(self, operation: Operation) -> ComplianceResult:
        """Validate PCI-DSS controls.

        Checks:
        - cardholder data encrypted
        - keys protected
        - access restricted
        """
        op = self._coerce_operation(operation)

        violations: list[str] = []
        recommendations: list[str] = []

        if self._cardholder_data_in_scope(op) and not op.cardholder_data_encrypted:
            self._add_violation(
                violations,
                recommendations,
                "PCI-DSS requires cardholder data to be encrypted.",
                "Encrypt cardholder data at rest and in transit before processing.",
            )

        if not op.keys_protected:
            self._add_violation(
                violations,
                recommendations,
                "PCI-DSS requires cryptographic keys to be protected.",
                "Use HSM or managed KMS with strict key access controls.",
            )

        if not op.access_restricted:
            self._add_violation(
                violations,
                recommendations,
                "PCI-DSS requires access restrictions for cardholder systems.",
                "Apply least-privilege RBAC and deny-by-default policies.",
            )

        result = self._build_result(violations, recommendations)
        self._log_validation(standard="pci-dss", operation=op, result=result)
        return result

    def validate_pre_operation(self, operation: Operation, standards: Sequence[str]) -> ComplianceResult:
        """Validate and enforce compliance before operation execution.

        The operation is evaluated in real time against each requested standard.
        When blocking mode is enabled, non-compliant operations are rejected with
        ``ComplianceViolationError``.
        """
        op = self._coerce_operation(operation)
        normalized_standards = self._normalize_standards(standards)

        combined_violations: list[str] = []
        combined_recommendations: list[str] = []

        for standard in normalized_standards:
            result = self._validate_by_standard(op, standard)
            for violation in result.violations:
                if violation not in combined_violations:
                    combined_violations.append(violation)
            for recommendation in result.recommendations:
                if recommendation not in combined_recommendations:
                    combined_recommendations.append(recommendation)

        combined_result = self._build_result(combined_violations, combined_recommendations)

        if not combined_result.compliant and self._block_non_compliant_operations:
            self._log_pre_operation_decision(
                operation=op,
                standards=normalized_standards,
                result=combined_result,
                allowed=False,
            )
            raise ComplianceViolationError(
                operation=op,
                standards=normalized_standards,
                result=combined_result,
            )

        self._log_pre_operation_decision(
            operation=op,
            standards=normalized_standards,
            result=combined_result,
            allowed=True,
        )
        return combined_result

    def validate_operation_realtime(self, operation: Operation, standards: Sequence[str]) -> ComplianceResult:
        """Alias for real-time pre-operation compliance validation."""
        return self.validate_pre_operation(operation=operation, standards=standards)

    def _validate_by_standard(self, operation: Operation, standard: str) -> ComplianceResult:
        if standard == "hipaa":
            return self.validate_hipaa_compliance(operation)
        if standard == "gdpr":
            return self.validate_gdpr_compliance(operation)
        if standard == "pci-dss":
            return self.validate_pci_dss_compliance(operation)
        raise ValueError(f"unsupported compliance standard: {standard}")

    def _log_validation(self, *, standard: str, operation: Operation, result: ComplianceResult) -> None:
        log_security_event(
            "compliance_validation",
            severity="INFO" if result.compliant else "WARNING",
            actor=self._actor_id,
            target=operation.operation_id,
            details={
                "standard": standard,
                "operation_id": operation.operation_id,
                "resource": operation.resource,
                "compliant": result.compliant,
                "violations": result.violations,
            },
        )

    def _log_pre_operation_decision(
        self,
        *,
        operation: Operation,
        standards: Sequence[str],
        result: ComplianceResult,
        allowed: bool,
    ) -> None:
        log_security_event(
            "compliance_pre_operation_validation",
            severity="INFO" if allowed else "ERROR",
            actor=self._actor_id,
            target=operation.operation_id,
            details={
                "operation_id": operation.operation_id,
                "resource": operation.resource,
                "standards": list(standards),
                "allowed": allowed,
                "compliant": result.compliant,
                "violations": result.violations,
                "recommendations": result.recommendations,
            },
        )

    @staticmethod
    def _cardholder_data_in_scope(operation: Operation) -> bool:
        if operation.contains_cardholder_data:
            return True

        resource = operation.resource.lower()
        keywords = ("cardholder", "payment", "pan", "card", "pci")
        return any(token in resource for token in keywords)

    @staticmethod
    def _coerce_operation(operation: Operation | Mapping[str, Any]) -> Operation:
        if isinstance(operation, Operation):
            return operation
        if isinstance(operation, Mapping):
            return Operation.model_validate(dict(operation))
        raise TypeError("operation must be Operation or mapping-compatible payload")

    def _normalize_standards(self, standards: Sequence[str]) -> list[str]:
        if not isinstance(standards, (list, tuple, set)):
            raise TypeError("standards must be a sequence of standard names")

        normalized: list[str] = []
        for value in standards:
            if not isinstance(value, str) or not value.strip():
                raise ValueError("standards must contain non-empty strings")

            mapped = self._STANDARD_ALIASES.get(value.strip().lower())
            if mapped is None:
                raise ValueError(f"unsupported compliance standard: {value}")
            if mapped not in normalized:
                normalized.append(mapped)

        if not normalized:
            raise ValueError("at least one compliance standard is required")
        return normalized

    @staticmethod
    def _add_violation(
        violations: list[str],
        recommendations: list[str],
        violation: str,
        recommendation: str,
    ) -> None:
        if violation not in violations:
            violations.append(violation)
        if recommendation not in recommendations:
            recommendations.append(recommendation)

    @staticmethod
    def _build_result(violations: list[str], recommendations: list[str]) -> ComplianceResult:
        return ComplianceResult(
            compliant=len(violations) == 0,
            violations=list(violations),
            recommendations=list(recommendations),
        )

    @staticmethod
    def _require_non_empty(name: str, value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must be a non-empty string")
        return value.strip()


__all__ = [
    "ValidationError",
    "Operation",
    "ComplianceResult",
    "ComplianceViolationError",
    "ComplianceValidator",
]
