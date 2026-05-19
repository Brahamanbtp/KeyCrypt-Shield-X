"""Compliance framework with multi-standard validation and evidence capture."""

from __future__ import annotations

from dataclasses import dataclass, field, fields
from datetime import UTC, datetime
from typing import Any, Callable, Mapping, Sequence
from uuid import uuid4


@dataclass
class Operation:
    """Operational context evaluated against compliance requirements."""

    operation_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    actor: str = "unknown"
    action: str = "unknown"
    resource: str = "unknown"

    encryption_enabled: bool = False
    encryption_strength_bits: int = 0
    key_rotation_days: int | None = None
    audit_logging_enabled: bool = False

    deletion_capability: bool = False
    consent_obtained: bool = False
    data_minimization_enabled: bool = False

    contains_cardholder_data: bool = False
    cardholder_data_encrypted: bool = False
    keys_protected: bool = False
    access_restricted: bool = False

    monitoring_enabled: bool = False
    incident_response_plan: bool = False
    change_management_enabled: bool = False
    backup_enabled: bool = False
    availability_sla_percent: float | None = None

    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.actor = _require_non_empty("actor", self.actor)
        self.action = _require_non_empty("action", self.action)
        self.resource = _require_non_empty("resource", self.resource)

        if self.encryption_strength_bits < 0:
            raise ValueError("encryption_strength_bits must be >= 0")
        if self.key_rotation_days is not None and self.key_rotation_days < 0:
            raise ValueError("key_rotation_days must be >= 0")
        if self.availability_sla_percent is not None:
            if not 0.0 <= self.availability_sla_percent <= 100.0:
                raise ValueError("availability_sla_percent must be in range [0, 100]")

        if not isinstance(self.metadata, dict):
            raise TypeError("metadata must be a dict")

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> "Operation":
        if not isinstance(payload, Mapping):
            raise TypeError("payload must be a mapping")

        field_names = {item.name for item in fields(cls)}
        data = dict(payload)
        filtered = {key: value for key, value in data.items() if key in field_names}
        operation = cls(**filtered)

        extras = {key: value for key, value in data.items() if key not in field_names}
        if extras:
            operation.metadata.update(extras)

        metadata = data.get("metadata")
        if isinstance(metadata, Mapping):
            operation.metadata.update(dict(metadata))

        return operation


@dataclass(frozen=True)
class RequirementCheckResult:
    compliant: bool
    message: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ComplianceRequirement:
    requirement_id: str
    description: str
    version: str
    severity: str
    check: Callable[[Operation], RequirementCheckResult]
    remediation: str | None = None
    reference: str | None = None

    def __post_init__(self) -> None:
        if not self.requirement_id.strip():
            raise ValueError("requirement_id must be non-empty")
        if not self.description.strip():
            raise ValueError("description must be non-empty")
        if not self.version.strip():
            raise ValueError("version must be non-empty")
        if not self.severity.strip():
            raise ValueError("severity must be non-empty")


@dataclass(frozen=True)
class ComplianceViolation:
    standard: str
    standard_version: str
    requirement_id: str
    requirement_version: str
    severity: str
    message: str
    remediation: str | None
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ComplianceResult:
    standard: str
    standard_version: str
    compliant: bool
    violations: list[ComplianceViolation]
    evaluated_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True)
class Evidence:
    operation_id: str
    standard: str | None
    collected_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class SystemState:
    system_id: str
    assessed_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    operations: list[Operation] = field(default_factory=list)
    controls: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.system_id = _require_non_empty("system_id", self.system_id)
        if not isinstance(self.controls, dict):
            raise TypeError("controls must be a dict")
        if not isinstance(self.metadata, dict):
            raise TypeError("metadata must be a dict")


@dataclass(frozen=True)
class AuditReport:
    system_id: str
    generated_at: datetime
    standards: list[str]
    compliant: bool
    violations: list[ComplianceViolation]
    evidence: list[Evidence]
    summary: dict[str, Any]


class ComplianceStandard:
    """Base class for compliance standards with requirement versioning."""

    def __init__(self, *, name: str, version: str, requirements: Sequence[ComplianceRequirement]) -> None:
        if not name.strip():
            raise ValueError("name must be non-empty")
        if not version.strip():
            raise ValueError("version must be non-empty")
        if not isinstance(requirements, Sequence):
            raise TypeError("requirements must be a sequence")
        if not requirements:
            raise ValueError("requirements must be non-empty")

        self.name = name.strip()
        self.version = version.strip()
        self.requirements = list(requirements)

    def get_effective_requirements(self, version: str | None = None) -> list[ComplianceRequirement]:
        target_version = self.version if version is None else _require_non_empty("version", version)
        target_key = _version_key(target_version)

        grouped: dict[str, list[ComplianceRequirement]] = {}
        order: list[str] = []
        for requirement in self.requirements:
            req_id = requirement.requirement_id
            if req_id not in grouped:
                grouped[req_id] = []
                order.append(req_id)
            grouped[req_id].append(requirement)

        selected: list[ComplianceRequirement] = []
        for req_id in order:
            candidates = grouped[req_id]
            eligible = [item for item in candidates if _version_key(item.version) <= target_key]
            if not eligible:
                eligible = list(candidates)
            selected.append(max(eligible, key=lambda item: _version_key(item.version)))

        return selected

    def validate(self, operation: Operation | Mapping[str, Any]) -> ComplianceResult:
        op = _coerce_operation(operation)
        requirements = self.get_effective_requirements()
        violations: list[ComplianceViolation] = []

        for requirement in requirements:
            result = requirement.check(op)
            if result.compliant:
                continue
            violations.append(
                ComplianceViolation(
                    standard=self.name,
                    standard_version=self.version,
                    requirement_id=requirement.requirement_id,
                    requirement_version=requirement.version,
                    severity=requirement.severity,
                    message=result.message,
                    remediation=requirement.remediation,
                    evidence=dict(result.evidence),
                )
            )

        return ComplianceResult(
            standard=self.name,
            standard_version=self.version,
            compliant=len(violations) == 0,
            violations=violations,
        )


class HIPAAStandard(ComplianceStandard):
    """HIPAA requirements for healthcare data."""

    def __init__(self, *, version: str = "2024.1") -> None:
        super().__init__(name="HIPAA", version=version, requirements=_hipaa_requirements())


class GDPRStandard(ComplianceStandard):
    """GDPR requirements for personal data protection."""

    def __init__(self, *, version: str = "2024.1") -> None:
        super().__init__(name="GDPR", version=version, requirements=_gdpr_requirements())


class SOC2Standard(ComplianceStandard):
    """SOC 2 Type II trust services criteria."""

    def __init__(self, *, version: str = "2024.0") -> None:
        super().__init__(name="SOC2", version=version, requirements=_soc2_requirements())


class PCIDSSStandard(ComplianceStandard):
    """PCI-DSS requirements for cardholder data."""

    def __init__(self, *, version: str = "4.0") -> None:
        super().__init__(name="PCI-DSS", version=version, requirements=_pci_dss_requirements())


class ComplianceFramework:
    """Multi-standard compliance framework."""

    def __init__(self, standards: Sequence[ComplianceStandard] | None = None) -> None:
        self._standards: dict[str, ComplianceStandard] = {}
        for standard in standards or _default_standards():
            key = standard.name.strip().lower()
            self._standards[key] = standard

    def validate_compliance(self, operation: Operation, standard: ComplianceStandard) -> ComplianceResult:
        if not isinstance(standard, ComplianceStandard):
            raise TypeError("standard must be a ComplianceStandard")
        return standard.validate(operation)

    def check_all_requirements(self, operation: Operation) -> list[ComplianceViolation]:
        op = _coerce_operation(operation)
        violations: list[ComplianceViolation] = []
        for standard in self._standards.values():
            result = standard.validate(op)
            violations.extend(result.violations)
        return violations

    def generate_compliance_evidence(self, operation: Operation) -> Evidence:
        op = _coerce_operation(operation)
        results = {}
        for standard in self._standards.values():
            result = standard.validate(op)
            results[standard.name] = {
                "version": standard.version,
                "compliant": result.compliant,
                "violations": [violation.message for violation in result.violations],
                "requirement_versions": {
                    violation.requirement_id: violation.requirement_version
                    for violation in result.violations
                },
            }

        return Evidence(
            operation_id=op.operation_id,
            standard=None,
            details={
                "actor": op.actor,
                "action": op.action,
                "resource": op.resource,
                "timestamp": op.timestamp.isoformat(),
                "results": results,
            },
        )

    def audit_compliance_posture(self, system_state: SystemState) -> AuditReport:
        if not isinstance(system_state, SystemState):
            raise TypeError("system_state must be a SystemState")

        operations = system_state.operations
        if not operations:
            operations = [
                Operation(
                    actor="system",
                    action="audit",
                    resource=system_state.system_id,
                    metadata=dict(system_state.controls),
                )
            ]

        all_violations: list[ComplianceViolation] = []
        evidence: list[Evidence] = []
        summary: dict[str, Any] = {
            "operation_count": len(operations),
            "standards": {},
        }

        for standard in self._standards.values():
            standard_violations: list[ComplianceViolation] = []
            compliant_count = 0

            for operation in operations:
                result = standard.validate(operation)
                if result.compliant:
                    compliant_count += 1
                standard_violations.extend(result.violations)

                evidence.append(
                    Evidence(
                        operation_id=operation.operation_id,
                        standard=standard.name,
                        details={
                            "compliant": result.compliant,
                            "violations": [violation.message for violation in result.violations],
                            "requirement_versions": {
                                violation.requirement_id: violation.requirement_version
                                for violation in result.violations
                            },
                        },
                    )
                )

            all_violations.extend(standard_violations)
            summary["standards"][standard.name] = {
                "version": standard.version,
                "operations_checked": len(operations),
                "operations_compliant": compliant_count,
                "violations": len(standard_violations),
            }

        return AuditReport(
            system_id=system_state.system_id,
            generated_at=datetime.now(UTC),
            standards=sorted(standard.name for standard in self._standards.values()),
            compliant=len(all_violations) == 0,
            violations=all_violations,
            evidence=evidence,
            summary=summary,
        )


DEFAULT_FRAMEWORK: ComplianceFramework | None = None


def validate_compliance(operation: Operation, standard: ComplianceStandard) -> ComplianceResult:
    return standard.validate(operation)


def check_all_requirements(operation: Operation) -> list[ComplianceViolation]:
    return DEFAULT_FRAMEWORK.check_all_requirements(operation)


def generate_compliance_evidence(operation: Operation) -> Evidence:
    return DEFAULT_FRAMEWORK.generate_compliance_evidence(operation)


def audit_compliance_posture(system_state: SystemState) -> AuditReport:
    return DEFAULT_FRAMEWORK.audit_compliance_posture(system_state)


def _default_standards() -> list[ComplianceStandard]:
    return [HIPAAStandard(), GDPRStandard(), SOC2Standard(), PCIDSSStandard()]


def _coerce_operation(operation: Operation | Mapping[str, Any]) -> Operation:
    if isinstance(operation, Operation):
        return operation
    if isinstance(operation, Mapping):
        return Operation.from_mapping(operation)
    raise TypeError("operation must be Operation or mapping payload")


def _require_non_empty(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value.strip()


def _version_key(version: str) -> tuple[int, ...]:
    parts = []
    current = ""
    for char in version:
        if char.isdigit():
            current += char
        else:
            if current:
                parts.append(int(current))
                current = ""
    if current:
        parts.append(int(current))
    return tuple(parts or [0])


def _require_bool(field_name: str, expected: bool, message: str) -> Callable[[Operation], RequirementCheckResult]:
    def _check(operation: Operation) -> RequirementCheckResult:
        value = bool(getattr(operation, field_name))
        if value is expected:
            return RequirementCheckResult(True, "", {field_name: value})
        return RequirementCheckResult(False, message, {field_name: value})

    return _check


def _require_min_int(field_name: str, minimum: int, message: str) -> Callable[[Operation], RequirementCheckResult]:
    def _check(operation: Operation) -> RequirementCheckResult:
        value = getattr(operation, field_name)
        if value is None:
            return RequirementCheckResult(False, message, {field_name: value})
        if int(value) >= minimum:
            return RequirementCheckResult(True, "", {field_name: int(value)})
        return RequirementCheckResult(False, message, {field_name: int(value)})

    return _check


def _require_max_int(field_name: str, maximum: int, message: str) -> Callable[[Operation], RequirementCheckResult]:
    def _check(operation: Operation) -> RequirementCheckResult:
        value = getattr(operation, field_name)
        if value is None:
            return RequirementCheckResult(False, message, {field_name: value})
        if int(value) <= maximum:
            return RequirementCheckResult(True, "", {field_name: int(value)})
        return RequirementCheckResult(False, message, {field_name: int(value)})

    return _check


def _require_min_float(field_name: str, minimum: float, message: str) -> Callable[[Operation], RequirementCheckResult]:
    def _check(operation: Operation) -> RequirementCheckResult:
        value = getattr(operation, field_name)
        if value is None:
            return RequirementCheckResult(False, message, {field_name: value})
        if float(value) >= minimum:
            return RequirementCheckResult(True, "", {field_name: float(value)})
        return RequirementCheckResult(False, message, {field_name: float(value)})

    return _check


def _require_cardholder_encryption(operation: Operation) -> RequirementCheckResult:
    if not operation.contains_cardholder_data:
        return RequirementCheckResult(True, "", {"contains_cardholder_data": False})
    if operation.cardholder_data_encrypted:
        return RequirementCheckResult(True, "", {"cardholder_data_encrypted": True})
    return RequirementCheckResult(
        False,
        "PCI-DSS requires cardholder data to be encrypted.",
        {"cardholder_data_encrypted": False},
    )


def _hipaa_requirements() -> list[ComplianceRequirement]:
    return [
        ComplianceRequirement(
            requirement_id="hipaa.encryption.enabled",
            description="Encryption must be enabled for protected health information.",
            version="2013.1",
            severity="high",
            check=_require_bool(
                "encryption_enabled",
                True,
                "HIPAA requires encryption to be enabled.",
            ),
            remediation="Enable encryption for protected health information workflows.",
        ),
        ComplianceRequirement(
            requirement_id="hipaa.encryption.strength",
            description="Encryption strength must meet minimum thresholds.",
            version="2013.1",
            severity="high",
            check=_require_min_int(
                "encryption_strength_bits",
                256,
                "HIPAA requires at least 256-bit encryption strength.",
            ),
            remediation="Use a 256-bit encryption algorithm such as AES-256-GCM.",
        ),
        ComplianceRequirement(
            requirement_id="hipaa.key.rotation",
            description="Key rotation must occur within required cadence.",
            version="2013.1",
            severity="medium",
            check=_require_max_int(
                "key_rotation_days",
                90,
                "HIPAA requires key rotation every 90 days or less.",
            ),
            remediation="Reduce key rotation interval to 90 days or less.",
        ),
        ComplianceRequirement(
            requirement_id="hipaa.key.rotation",
            description="Updated key rotation cadence.",
            version="2024.1",
            severity="medium",
            check=_require_max_int(
                "key_rotation_days",
                60,
                "HIPAA updated guidance requires key rotation every 60 days or less.",
            ),
            remediation="Reduce key rotation interval to 60 days or less.",
        ),
        ComplianceRequirement(
            requirement_id="hipaa.audit.logging",
            description="Audit logging must be enabled.",
            version="2013.1",
            severity="high",
            check=_require_bool(
                "audit_logging_enabled",
                True,
                "HIPAA requires audit logging to be enabled.",
            ),
            remediation="Enable immutable audit logging for HIPAA-scoped operations.",
        ),
        ComplianceRequirement(
            requirement_id="hipaa.access.control",
            description="Access must be restricted to authorized users.",
            version="2013.1",
            severity="medium",
            check=_require_bool(
                "access_restricted",
                True,
                "HIPAA requires access restrictions for protected data.",
            ),
            remediation="Enforce least-privilege access controls.",
        ),
    ]


def _gdpr_requirements() -> list[ComplianceRequirement]:
    return [
        ComplianceRequirement(
            requirement_id="gdpr.encryption.enabled",
            description="Personal data processing must be encrypted.",
            version="2018.0",
            severity="high",
            check=_require_bool(
                "encryption_enabled",
                True,
                "GDPR requires encryption for personal data processing.",
            ),
            remediation="Enable encryption before processing personal data.",
        ),
        ComplianceRequirement(
            requirement_id="gdpr.encryption.strength",
            description="Encryption strength must meet minimum thresholds.",
            version="2018.0",
            severity="high",
            check=_require_min_int(
                "encryption_strength_bits",
                128,
                "GDPR requires at least 128-bit encryption strength.",
            ),
            remediation="Use encryption strength of 128 bits or higher.",
        ),
        ComplianceRequirement(
            requirement_id="gdpr.deletion",
            description="Deletion capability must be available.",
            version="2018.0",
            severity="high",
            check=_require_bool(
                "deletion_capability",
                True,
                "GDPR requires deletion capability (right to erasure).",
            ),
            remediation="Implement and verify deletion workflows.",
        ),
        ComplianceRequirement(
            requirement_id="gdpr.consent",
            description="Explicit consent must be obtained.",
            version="2018.0",
            severity="high",
            check=_require_bool(
                "consent_obtained",
                True,
                "GDPR requires explicit consent before processing.",
            ),
            remediation="Collect and store valid consent evidence.",
        ),
        ComplianceRequirement(
            requirement_id="gdpr.minimization",
            description="Data minimization controls must be enforced.",
            version="2018.0",
            severity="medium",
            check=_require_bool(
                "data_minimization_enabled",
                True,
                "GDPR requires data minimization controls.",
            ),
            remediation="Limit processing to the minimum necessary data.",
        ),
    ]


def _soc2_requirements() -> list[ComplianceRequirement]:
    return [
        ComplianceRequirement(
            requirement_id="soc2.audit.logging",
            description="Audit logging must be enabled.",
            version="2022.0",
            severity="high",
            check=_require_bool(
                "audit_logging_enabled",
                True,
                "SOC2 requires audit logging to be enabled.",
            ),
            remediation="Enable centralized audit logging and retention.",
        ),
        ComplianceRequirement(
            requirement_id="soc2.monitoring",
            description="Continuous monitoring must be enabled.",
            version="2022.0",
            severity="medium",
            check=_require_bool(
                "monitoring_enabled",
                True,
                "SOC2 requires monitoring and alerting to be enabled.",
            ),
            remediation="Enable monitoring and alerting coverage.",
        ),
        ComplianceRequirement(
            requirement_id="soc2.monitoring",
            description="Enhanced monitoring coverage.",
            version="2024.0",
            severity="medium",
            check=_require_bool(
                "monitoring_enabled",
                True,
                "SOC2 updated guidance requires proactive monitoring coverage.",
            ),
            remediation="Ensure monitoring covers availability, security, and change events.",
        ),
        ComplianceRequirement(
            requirement_id="soc2.change.management",
            description="Change management controls must be enforced.",
            version="2022.0",
            severity="medium",
            check=_require_bool(
                "change_management_enabled",
                True,
                "SOC2 requires change management controls.",
            ),
            remediation="Implement change approval and tracking workflows.",
        ),
        ComplianceRequirement(
            requirement_id="soc2.incident.response",
            description="Incident response plan must exist.",
            version="2022.0",
            severity="medium",
            check=_require_bool(
                "incident_response_plan",
                True,
                "SOC2 requires an incident response plan.",
            ),
            remediation="Document and test an incident response plan.",
        ),
        ComplianceRequirement(
            requirement_id="soc2.backup",
            description="Backup and recovery must be available.",
            version="2022.0",
            severity="medium",
            check=_require_bool(
                "backup_enabled",
                True,
                "SOC2 requires backup and recovery controls.",
            ),
            remediation="Enable backups and validate recovery procedures.",
        ),
        ComplianceRequirement(
            requirement_id="soc2.availability",
            description="Availability SLA must meet minimum threshold.",
            version="2022.0",
            severity="low",
            check=_require_min_float(
                "availability_sla_percent",
                99.0,
                "SOC2 requires availability SLA of at least 99.0 percent.",
            ),
            remediation="Document and meet availability SLA targets.",
        ),
    ]


def _pci_dss_requirements() -> list[ComplianceRequirement]:
    return [
        ComplianceRequirement(
            requirement_id="pci.cardholder.encryption",
            description="Cardholder data must be encrypted.",
            version="3.2",
            severity="high",
            check=_require_cardholder_encryption,
            remediation="Encrypt cardholder data at rest and in transit.",
        ),
        ComplianceRequirement(
            requirement_id="pci.keys.protected",
            description="Cryptographic keys must be protected.",
            version="3.2",
            severity="high",
            check=_require_bool(
                "keys_protected",
                True,
                "PCI-DSS requires cryptographic keys to be protected.",
            ),
            remediation="Use HSM or managed KMS for key protection.",
        ),
        ComplianceRequirement(
            requirement_id="pci.access.restricted",
            description="Access must be restricted.",
            version="3.2",
            severity="high",
            check=_require_bool(
                "access_restricted",
                True,
                "PCI-DSS requires restricted access to cardholder data.",
            ),
            remediation="Apply least-privilege access policies.",
        ),
        ComplianceRequirement(
            requirement_id="pci.audit.logging",
            description="Audit logging must be enabled.",
            version="3.2",
            severity="medium",
            check=_require_bool(
                "audit_logging_enabled",
                True,
                "PCI-DSS requires audit logging to be enabled.",
            ),
            remediation="Enable audit logging for cardholder data access.",
        ),
        ComplianceRequirement(
            requirement_id="pci.key.rotation",
            description="Key rotation cadence must meet policy.",
            version="3.2",
            severity="medium",
            check=_require_max_int(
                "key_rotation_days",
                90,
                "PCI-DSS requires key rotation every 90 days or less.",
            ),
            remediation="Rotate PCI keys within 90 days.",
        ),
        ComplianceRequirement(
            requirement_id="pci.key.rotation",
            description="Updated key rotation cadence.",
            version="4.0",
            severity="medium",
            check=_require_max_int(
                "key_rotation_days",
                60,
                "PCI-DSS 4.0 requires key rotation every 60 days or less.",
            ),
            remediation="Rotate PCI keys within 60 days.",
        ),
    ]


DEFAULT_FRAMEWORK = ComplianceFramework(standards=[HIPAAStandard(), GDPRStandard(), SOC2Standard(), PCIDSSStandard()])


__all__ = [
    "Operation",
    "RequirementCheckResult",
    "ComplianceRequirement",
    "ComplianceViolation",
    "ComplianceResult",
    "Evidence",
    "SystemState",
    "AuditReport",
    "ComplianceStandard",
    "HIPAAStandard",
    "GDPRStandard",
    "SOC2Standard",
    "PCIDSSStandard",
    "ComplianceFramework",
    "DEFAULT_FRAMEWORK",
    "validate_compliance",
    "check_all_requirements",
    "generate_compliance_evidence",
    "audit_compliance_posture",
]
