"""SOC 2 compliance implementation with audit-framework support."""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from typing import Any, Mapping, Sequence

try:  # pragma: no cover - optional audit-framework boundary
    from src.observability.audit_event_schema import AuditEvent
except Exception:  # pragma: no cover - optional audit-framework boundary
    AuditEvent = Any  # type: ignore[assignment]

try:  # pragma: no cover - optional audit-framework boundary
    from src.observability.audit_storage import AuditFilter
except Exception:  # pragma: no cover - optional audit-framework boundary
    AuditFilter = None  # type: ignore[assignment]


SOC2_REQUIREMENT_VERSION = "2024.1"
SOC2_MIN_UPTIME_PERCENTAGE = 99.9


@dataclass(frozen=True)
class Period:
    """Audit period for SOC 2 Type II reporting."""

    start_date: date
    end_date: date

    def __post_init__(self) -> None:
        if not isinstance(self.start_date, date) or not isinstance(self.end_date, date):
            raise TypeError("start_date and end_date must be date instances")
        if self.start_date > self.end_date:
            raise ValueError("start_date must be <= end_date")


@dataclass(frozen=True)
class ControlValidation:
    """Validation result for one SOC 2 trust service criteria area."""

    criterion: str
    compliant: bool
    mapped_controls: list[str]
    findings: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SOC2Evidence:
    """Audit evidence captured for Type II testing."""

    timestamp: datetime
    source: str
    criterion: str
    description: str
    passed: bool
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AuditFinding:
    """Observation or exception identified during audit testing."""

    criterion: str
    control: str
    severity: str
    message: str
    remediation: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SOC2Report:
    """SOC 2 Type II audit report."""

    generated_at: datetime
    audit_period: Period
    requirement_version: str
    compliant: bool
    control_mapping: dict[str, list[str]]
    control_validations: dict[str, ControlValidation]
    evidence: list[SOC2Evidence]
    findings: list[AuditFinding]
    summary: dict[str, Any]


class SOC2ComplianceFramework:
    """SOC 2 compliance implementation with audit evidence support."""

    def __init__(
        self,
        *,
        system_name: str = "KeyCrypt Shield X",
        requirement_version: str = SOC2_REQUIREMENT_VERSION,
        system_controls: Mapping[str, Any] | None = None,
        audit_events: Sequence[AuditEvent] | None = None,
        audit_storage: Any | None = None,
        expected_data_hash: str | None = None,
    ) -> None:
        self.system_name = _require_non_empty("system_name", system_name)
        self.requirement_version = _require_non_empty("requirement_version", requirement_version)
        self._control_state = dict(system_controls or {})
        self._audit_events: list[AuditEvent] = list(audit_events or [])
        self._audit_storage = audit_storage
        self._expected_data_hash = _normalize_hash(expected_data_hash) if expected_data_hash else None
        self._control_mapping = _default_control_mapping()

    def validate_soc2_security_controls(self) -> ControlValidation:
        """Validate encryption, access controls, and monitoring."""
        encryption_at_rest = bool(self._control_state.get("encryption_at_rest", True))
        encryption_in_transit = bool(self._control_state.get("encryption_in_transit", True))
        access_controls = bool(self._control_state.get("access_controls", True))
        monitoring = bool(self._control_state.get("monitoring", True))

        findings: list[str] = []
        if not encryption_at_rest:
            findings.append("encryption at rest is disabled")
        if not encryption_in_transit:
            findings.append("encryption in transit is disabled")
        if not access_controls:
            findings.append("access controls are not enforced")
        if not monitoring:
            findings.append("monitoring and alerting are not enabled")

        compliant = not findings
        return ControlValidation(
            criterion="Security",
            compliant=compliant,
            mapped_controls=self._control_mapping["Security"],
            findings=findings,
            evidence={
                "encryption_at_rest": encryption_at_rest,
                "encryption_in_transit": encryption_in_transit,
                "access_controls": access_controls,
                "monitoring": monitoring,
            },
        )

    def validate_soc2_availability(self, uptime_percentage: float) -> bool:
        """Validate availability against 99.9% uptime and disaster recovery readiness."""
        if uptime_percentage < 0.0 or uptime_percentage > 100.0:
            raise ValueError("uptime_percentage must be in range [0.0, 100.0]")

        disaster_recovery = bool(self._control_state.get("disaster_recovery", True))
        uptime_ok = uptime_percentage >= SOC2_MIN_UPTIME_PERCENTAGE
        return bool(uptime_ok and disaster_recovery)

    def validate_soc2_processing_integrity(self, data_hash: str) -> bool:
        """Validate processing integrity using a canonical hash comparison."""
        normalized = _normalize_hash(data_hash)
        if self._expected_data_hash is None:
            self._expected_data_hash = normalized
            return True
        return normalized == self._expected_data_hash

    def generate_soc2_type2_report(self, audit_period: Period) -> SOC2Report:
        """Generate a SOC 2 Type II report for the requested audit period."""
        if not isinstance(audit_period, Period):
            raise TypeError("audit_period must be a Period")

        audit_events = self._collect_audit_events(audit_period)
        evidence = self._build_evidence(audit_events)

        security = self.validate_soc2_security_controls()
        availability_uptime = self._extract_uptime(audit_events)
        availability_ok = self.validate_soc2_availability(availability_uptime)
        integrity_ok = self.validate_soc2_processing_integrity(self._derive_period_hash(audit_events))

        confidentiality_ok = bool(
            self._control_state.get("encryption_at_rest", True)
            and self._control_state.get("encryption_in_transit", True)
        )
        privacy_ok = bool(self._control_state.get("privacy_policy_aligned", True))

        control_validations = {
            "Security": security,
            "Availability": ControlValidation(
                criterion="Availability",
                compliant=availability_ok,
                mapped_controls=self._control_mapping["Availability"],
                findings=[] if availability_ok else [f"uptime below {SOC2_MIN_UPTIME_PERCENTAGE}% or disaster recovery disabled"],
                evidence={"uptime_percentage": availability_uptime, "disaster_recovery": bool(self._control_state.get("disaster_recovery", True))},
            ),
            "Processing Integrity": ControlValidation(
                criterion="Processing Integrity",
                compliant=integrity_ok,
                mapped_controls=self._control_mapping["Processing Integrity"],
                findings=[] if integrity_ok else ["data hash does not match expected processing integrity baseline"],
                evidence={"period_hash": self._derive_period_hash(audit_events), "expected_hash": self._expected_data_hash},
            ),
            "Confidentiality": ControlValidation(
                criterion="Confidentiality",
                compliant=confidentiality_ok,
                mapped_controls=self._control_mapping["Confidentiality"],
                findings=[] if confidentiality_ok else ["encryption controls are incomplete"],
                evidence={
                    "encryption_at_rest": bool(self._control_state.get("encryption_at_rest", True)),
                    "encryption_in_transit": bool(self._control_state.get("encryption_in_transit", True)),
                },
            ),
            "Privacy": ControlValidation(
                criterion="Privacy",
                compliant=privacy_ok,
                mapped_controls=self._control_mapping["Privacy"],
                findings=[] if privacy_ok else ["privacy policy alignment missing"],
                evidence={"privacy_policy_aligned": bool(self._control_state.get("privacy_policy_aligned", True))},
            ),
        }

        findings = self._build_findings(control_validations)
        compliant = all(validation.compliant for validation in control_validations.values())
        summary = {
            "controls_tested": len(control_validations),
            "evidence_items": len(evidence),
            "exceptions": len(findings),
            "availability_uptime": availability_uptime,
        }

        return SOC2Report(
            generated_at=datetime.now(UTC),
            audit_period=audit_period,
            requirement_version=self.requirement_version,
            compliant=compliant,
            control_mapping={key: list(value) for key, value in self._control_mapping.items()},
            control_validations=control_validations,
            evidence=evidence,
            findings=findings,
            summary=summary,
        )

    def record_audit_event(self, event: AuditEvent) -> None:
        """Record an audit event for later Type II evidence collection."""
        if not isinstance(event, AuditEvent):
            raise TypeError("event must be an AuditEvent")
        self._audit_events.append(event)

    def _collect_audit_events(self, audit_period: Period) -> list[AuditEvent]:
        collected: dict[str, AuditEvent] = {}

        if self._audit_storage is not None and hasattr(self._audit_storage, "query_events"):
            filters = AuditFilter() if AuditFilter is not None else None
            events = self._query_audit_storage(filters, limit=500)
            for event in events:
                timestamp = getattr(event, "timestamp", None)
                if isinstance(timestamp, datetime):
                    event_date = timestamp.date()
                else:
                    event_date = None
                if event_date is None or audit_period.start_date <= event_date <= audit_period.end_date:
                    collected[getattr(event, "event_id", repr(event))] = event

        for event in self._audit_events:
            timestamp = getattr(event, "timestamp", None)
            if isinstance(timestamp, datetime) and audit_period.start_date <= timestamp.date() <= audit_period.end_date:
                collected[getattr(event, "event_id", repr(event))] = event

        return sorted(collected.values(), key=lambda item: getattr(item, "timestamp", datetime.now(UTC)))

    def _query_audit_storage(self, filters: Any, limit: int) -> list[AuditEvent]:
        storage = self._audit_storage
        if storage is None:
            return []

        query = getattr(storage, "query_events", None)
        if query is None:
            return []

        result = query(filters, limit)
        if asyncio.iscoroutine(result):
            return asyncio.run(result)
        return list(result)

    def _build_evidence(self, audit_events: Sequence[AuditEvent]) -> list[SOC2Evidence]:
        evidence: list[SOC2Evidence] = []
        for event in audit_events:
            payload = _event_payload(event)
            criterion = self._infer_criterion(payload)
            evidence.append(
                SOC2Evidence(
                    timestamp=_event_timestamp(event),
                    source=str(payload.get("event_type") or "audit"),
                    criterion=criterion,
                    description=str(payload.get("action") or payload.get("event_type") or "audit event"),
                    passed=True,
                    details=payload,
                )
            )
        return evidence

    def _build_findings(self, validations: Mapping[str, ControlValidation]) -> list[AuditFinding]:
        findings: list[AuditFinding] = []
        for criterion, validation in validations.items():
            for finding in validation.findings:
                findings.append(
                    AuditFinding(
                        criterion=criterion,
                        control=", ".join(validation.mapped_controls),
                        severity="high" if criterion in {"Security", "Availability", "Processing Integrity"} else "medium",
                        message=finding,
                        remediation=self._default_remediation(criterion),
                        evidence=dict(validation.evidence),
                    )
                )
        return findings

    def _extract_uptime(self, audit_events: Sequence[AuditEvent]) -> float:
        uptime_samples: list[float] = []
        for event in audit_events:
            payload = _event_payload(event)
            value = payload.get("uptime_percentage")
            if isinstance(value, (int, float)):
                uptime_samples.append(float(value))

        if uptime_samples:
            return sum(uptime_samples) / len(uptime_samples)

        value = self._control_state.get("uptime_percentage")
        if isinstance(value, (int, float)):
            return float(value)
        return 100.0 if bool(self._control_state.get("disaster_recovery", True)) else 99.0

    def _derive_period_hash(self, audit_events: Sequence[AuditEvent]) -> str:
        if self._expected_data_hash is not None:
            return self._expected_data_hash

        digest = hashlib.sha256()
        if not audit_events:
            digest.update(self.system_name.encode("utf-8"))
        for event in audit_events:
            digest.update(json.dumps(_event_payload(event), sort_keys=True, default=str).encode("utf-8"))
        return digest.hexdigest()

    @staticmethod
    def _infer_criterion(payload: Mapping[str, Any]) -> str:
        event_type = str(payload.get("event_type") or "").lower()
        resource = str(payload.get("resource") or "").lower()
        if any(token in event_type for token in ("access", "auth", "encryption", "key_rotation")) or "security" in resource:
            return "Security"
        if "availability" in event_type or "uptime" in payload:
            return "Availability"
        if "integrity" in event_type or "checksum" in payload or "hash" in payload:
            return "Processing Integrity"
        if "confidential" in resource or "secret" in resource:
            return "Confidentiality"
        return "Privacy"

    @staticmethod
    def _default_remediation(criterion: str) -> str:
        return {
            "Security": "Strengthen encryption, access controls, and monitoring coverage.",
            "Availability": "Improve disaster recovery readiness and availability monitoring.",
            "Processing Integrity": "Add checksum and reconciliation controls for critical processing paths.",
            "Confidentiality": "Ensure encryption at rest and in transit is consistently enforced.",
            "Privacy": "Align data handling, retention, and disclosure controls to the privacy policy.",
        }.get(criterion, "Review control design and operating effectiveness.")


def _default_control_mapping() -> dict[str, list[str]]:
    return {
        "Security": [
            "Encryption at rest",
            "Encryption in transit",
            "Role-based access control",
            "Centralized monitoring and alerting",
        ],
        "Availability": [
            "99.9% uptime target",
            "Disaster recovery plan",
            "Redundant infrastructure",
            "Backup verification",
        ],
        "Processing Integrity": [
            "Checksum and hash verification",
            "Input validation",
            "Reconciliation checks",
        ],
        "Confidentiality": [
            "Encryption at rest",
            "Encryption in transit",
            "Key management",
        ],
        "Privacy": [
            "Privacy policy alignment",
            "Data minimization",
            "Consent and notice management",
            "Retention controls",
        ],
    }


def _event_payload(event: Any) -> dict[str, Any]:
    if hasattr(event, "to_payload"):
        try:
            payload = event.to_payload()
            if isinstance(payload, dict):
                return payload
        except Exception:
            pass

    if isinstance(event, Mapping):
        return dict(event)

    payload: dict[str, Any] = {}
    for attr in ("event_id", "timestamp", "event_type", "actor", "resource", "action", "outcome"):
        value = getattr(event, attr, None)
        if value is not None:
            payload[attr] = value
    return payload


def _event_timestamp(event: Any) -> datetime:
    timestamp = getattr(event, "timestamp", None)
    if isinstance(timestamp, datetime):
        return timestamp if timestamp.tzinfo is not None else timestamp.replace(tzinfo=UTC)
    return datetime.now(UTC)


def _normalize_hash(data_hash: str) -> str:
    if not isinstance(data_hash, str) or not data_hash.strip():
        raise ValueError("data_hash must be a non-empty string")
    normalized = data_hash.strip().lower()
    if len(normalized) != 64:
        raise ValueError("data_hash must be a 64-character hexadecimal digest")
    int(normalized, 16)
    return normalized


def _require_non_empty(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value.strip()


__all__ = [
    "SOC2_REQUIREMENT_VERSION",
    "SOC2_MIN_UPTIME_PERCENTAGE",
    "Period",
    "ControlValidation",
    "SOC2Evidence",
    "AuditFinding",
    "SOC2Report",
    "SOC2ComplianceFramework",
]
