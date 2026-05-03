"""HIPAA-specific compliance implementation for healthcare workloads."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from typing import Any, Sequence


HIPAA_REQUIREMENT_VERSION = "2024.1"
HIPAA_MIN_ENCRYPTION_BITS = 256
HIPAA_MAX_KEY_ROTATION_DAYS = 90

_APPROVED_ALGORITHMS = {
    "aes-256-gcm",
    "aes-256-cbc",
    "aes-256-ctr",
    "aes-256-xts",
    "aes-256-siv",
    "chacha20-poly1305",
    "xchacha20-poly1305",
}

_DEFAULT_HIPAA_ROLES = {
    "admin",
    "billing",
    "clinician",
    "compliance",
    "doctor",
    "nurse",
    "pharmacist",
    "security",
}


@dataclass(frozen=True)
class User:
    """User context for HIPAA access-control evaluation."""

    user_id: str
    role: str
    department: str = "clinical"
    active: bool = True
    mfa_enabled: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "user_id", _require_non_empty("user_id", self.user_id))
        object.__setattr__(self, "role", _require_non_empty("role", self.role).lower())
        object.__setattr__(self, "department", _require_non_empty("department", self.department))


@dataclass(frozen=True)
class Resource:
    """Protected healthcare resource evaluated by HIPAA controls."""

    resource_id: str
    classification: str = "phi"
    allowed_roles: tuple[str, ...] = ("clinician", "doctor", "nurse", "billing", "compliance", "security")
    encrypted: bool = True
    encryption_algorithm: str = "aes-256-gcm"
    key_size_bits: int = 256
    key_age_days: int = 0
    audit_logging_enabled: bool = True
    breach_monitoring_enabled: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "resource_id", _require_non_empty("resource_id", self.resource_id))
        object.__setattr__(self, "classification", _require_non_empty("classification", self.classification).lower())
        object.__setattr__(self, "encryption_algorithm", _require_non_empty("encryption_algorithm", self.encryption_algorithm).lower())
        if self.key_size_bits < 0:
            raise ValueError("key_size_bits must be >= 0")
        if self.key_age_days < 0:
            raise ValueError("key_age_days must be >= 0")


@dataclass(frozen=True)
class HipaaAuditEvent:
    """Audit trail entry captured for HIPAA validation outcomes."""

    timestamp: datetime
    event_type: str
    subject_id: str
    resource_id: str
    success: bool
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class BreachNotification:
    """Automated breach detection output."""

    timestamp: datetime
    subject_id: str
    resource_id: str
    reason: str
    reported: bool
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Report:
    """HIPAA compliance report for an activity window."""

    generated_at: datetime
    start_date: date
    end_date: date
    requirement_version: str
    compliant: bool
    encryption_checks: list[dict[str, Any]]
    key_rotation_checks: list[dict[str, Any]]
    access_control_checks: list[dict[str, Any]]
    breach_notifications: list[BreachNotification]
    evidence: list[HipaaAuditEvent]
    baa_template: str
    violations: list[str] = field(default_factory=list)


class HIPAAComplianceFramework:
    """HIPAA compliance implementation with audit logging and BAA generation."""

    def __init__(
        self,
        *,
        covered_entity_name: str = "Covered Entity",
        business_associate_name: str = "Business Associate",
        requirement_version: str = HIPAA_REQUIREMENT_VERSION,
        seed_events: Sequence[HipaaAuditEvent] | None = None,
    ) -> None:
        self.covered_entity_name = _require_non_empty("covered_entity_name", covered_entity_name)
        self.business_associate_name = _require_non_empty("business_associate_name", business_associate_name)
        self.requirement_version = _require_non_empty("requirement_version", requirement_version)
        self._audit_trail: list[HipaaAuditEvent] = list(seed_events or [])

    def validate_hipaa_encryption(self, algorithm: str, key_size: int) -> bool:
        """Validate AES-256 or an equivalent algorithm with 256-bit keying."""
        normalized_algorithm = _require_non_empty("algorithm", algorithm).lower()
        if key_size < HIPAA_MIN_ENCRYPTION_BITS:
            compliant = False
        else:
            compliant = self._is_approved_encryption_algorithm(normalized_algorithm)

        self._record_event(
            event_type="encryption_validation",
            subject_id="system",
            resource_id="encryption-policy",
            success=compliant,
            details={"algorithm": normalized_algorithm, "key_size_bits": key_size},
        )
        return compliant

    def validate_hipaa_key_rotation(self, key_age_days: int) -> bool:
        """Validate HIPAA key-rotation cadence."""
        if key_age_days < 0:
            raise ValueError("key_age_days must be >= 0")

        compliant = key_age_days <= HIPAA_MAX_KEY_ROTATION_DAYS
        self._record_event(
            event_type="key_rotation_validation",
            subject_id="system",
            resource_id="key-management",
            success=compliant,
            details={"key_age_days": key_age_days, "max_allowed_days": HIPAA_MAX_KEY_ROTATION_DAYS},
        )
        return compliant

    def validate_hipaa_access_controls(self, user: User, resource: Resource) -> bool:
        """Validate role-based access and audit logging requirements."""
        if not isinstance(user, User):
            raise TypeError("user must be a User")
        if not isinstance(resource, Resource):
            raise TypeError("resource must be a Resource")

        allowed_roles = tuple(role.strip().lower() for role in resource.allowed_roles if role.strip())
        if not allowed_roles:
            allowed_roles = tuple(sorted(_DEFAULT_HIPAA_ROLES))

        role_allowed = user.role in allowed_roles or user.role in {"admin", "compliance", "security"}
        compliant = bool(
            user.active
            and user.mfa_enabled
            and resource.audit_logging_enabled
            and resource.encrypted
            and resource.key_size_bits >= HIPAA_MIN_ENCRYPTION_BITS
            and role_allowed
        )

        self._record_event(
            event_type="access_control_validation",
            subject_id=user.user_id,
            resource_id=resource.resource_id,
            success=compliant,
            details={
                "user_role": user.role,
                "allowed_roles": list(allowed_roles),
                "resource_classification": resource.classification,
                "audit_logging_enabled": resource.audit_logging_enabled,
                "encrypted": resource.encrypted,
                "key_size_bits": resource.key_size_bits,
                "breach_monitoring_enabled": resource.breach_monitoring_enabled,
            },
        )
        return compliant

    def generate_hipaa_compliance_report(self, start_date: date, end_date: date) -> Report:
        """Generate a HIPAA compliance report for the requested date range."""
        if not isinstance(start_date, date) or not isinstance(end_date, date):
            raise TypeError("start_date and end_date must be date instances")
        if start_date > end_date:
            raise ValueError("start_date must be <= end_date")

        events = [
            event
            for event in self._audit_trail
            if start_date <= event.timestamp.date() <= end_date
        ]

        encryption_checks = [self._event_summary(event) for event in events if event.event_type == "encryption_validation"]
        key_rotation_checks = [self._event_summary(event) for event in events if event.event_type == "key_rotation_validation"]
        access_control_checks = [self._event_summary(event) for event in events if event.event_type == "access_control_validation"]

        breach_notifications = [
            BreachNotification(
                timestamp=event.timestamp,
                subject_id=event.subject_id,
                resource_id=event.resource_id,
                reason=self._breach_reason(event),
                reported=True,
                details=dict(event.details),
            )
            for event in events
            if self._is_breach_event(event)
        ]

        violations = [notification.reason for notification in breach_notifications]
        compliant = not violations and all(item.get("success", False) for item in encryption_checks + key_rotation_checks + access_control_checks)

        return Report(
            generated_at=datetime.now(UTC),
            start_date=start_date,
            end_date=end_date,
            requirement_version=self.requirement_version,
            compliant=compliant,
            encryption_checks=encryption_checks,
            key_rotation_checks=key_rotation_checks,
            access_control_checks=access_control_checks,
            breach_notifications=breach_notifications,
            evidence=list(events),
            baa_template=self.generate_baa_template(),
            violations=violations,
        )

    def generate_baa_template(self, effective_date: date | None = None) -> str:
        """Generate a Business Associate Agreement template."""
        effective = effective_date or date.today()
        return (
            "Business Associate Agreement (BAA)\n"
            f"Version: {self.requirement_version}\n"
            f"Effective Date: {effective.isoformat()}\n\n"
            f"Covered Entity: {self.covered_entity_name}\n"
            f"Business Associate: {self.business_associate_name}\n\n"
            "1. Scope. The Business Associate may create, receive, maintain, or transmit Protected Health Information only for permitted purposes.\n"
            "2. Safeguards. The Business Associate must implement administrative, physical, and technical safeguards, including AES-256 or equivalent encryption, secure key management, and audit logging.\n"
            "3. Access Controls. Access to Protected Health Information must be role-based, least-privilege, and monitored.\n"
            "4. Breach Notification. The Business Associate must detect, report, and document breaches without unreasonable delay.\n"
            "5. Retention and Disposal. Protected Health Information must be retained and disposed of according to applicable law and policy.\n"
            "6. Subcontractors. Any subcontractor handling Protected Health Information must be bound to equivalent obligations.\n"
            "7. Termination. Upon termination, Protected Health Information must be returned or securely destroyed where feasible.\n"
        )

    def record_event(self, event: HipaaAuditEvent) -> None:
        """Append a prebuilt audit event to the HIPAA trail."""
        if not isinstance(event, HipaaAuditEvent):
            raise TypeError("event must be a HipaaAuditEvent")
        self._audit_trail.append(event)

    @property
    def audit_trail(self) -> list[HipaaAuditEvent]:
        return list(self._audit_trail)

    def _record_event(self, *, event_type: str, subject_id: str, resource_id: str, success: bool, details: dict[str, Any]) -> None:
        event = HipaaAuditEvent(
            timestamp=datetime.now(UTC),
            event_type=event_type,
            subject_id=subject_id,
            resource_id=resource_id,
            success=success,
            details=dict(details),
        )
        self._audit_trail.append(event)

    @staticmethod
    def _event_summary(event: HipaaAuditEvent) -> dict[str, Any]:
        return {
            "timestamp": event.timestamp.isoformat(),
            "event_type": event.event_type,
            "subject_id": event.subject_id,
            "resource_id": event.resource_id,
            "success": event.success,
            "details": dict(event.details),
        }

    @staticmethod
    def _breach_reason(event: HipaaAuditEvent) -> str:
        if event.event_type == "encryption_validation":
            return "Encryption policy violation"
        if event.event_type == "key_rotation_validation":
            return "Key rotation exceeds HIPAA maximum"
        if event.event_type == "access_control_validation":
            return "Access control violation"
        return "HIPAA breach detected"

    @staticmethod
    def _is_breach_event(event: HipaaAuditEvent) -> bool:
        return not event.success or bool(event.details.get("breach_detected")) or event.event_type == "breach_notification"

    @staticmethod
    def _is_approved_encryption_algorithm(algorithm: str) -> bool:
        if algorithm in _APPROVED_ALGORITHMS:
            return True
        return algorithm.startswith("aes-256") or algorithm.endswith("-256")


def _require_non_empty(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value.strip()


__all__ = [
    "HIPAA_REQUIREMENT_VERSION",
    "HIPAA_MIN_ENCRYPTION_BITS",
    "HIPAA_MAX_KEY_ROTATION_DAYS",
    "User",
    "Resource",
    "HipaaAuditEvent",
    "BreachNotification",
    "Report",
    "HIPAAComplianceFramework",
]
