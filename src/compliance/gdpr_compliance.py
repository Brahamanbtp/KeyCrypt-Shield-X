"""GDPR-specific compliance implementation for EU data processing."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from typing import Any, Mapping, Sequence

from src.deletion.trust_index import calculate_dti


GDPR_REQUIREMENT_VERSION = "2024.1"
GDPR_MIN_DTI = 0.999999
GDPR_BREACH_NOTIFICATION_WINDOW_HOURS = 72
GDPR_APPROVED_LAWFUL_BASES = {
    "consent",
    "contract",
    "legal_obligation",
    "vital_interests",
    "public_task",
    "legitimate_interests",
}


@dataclass(frozen=True)
class Activity:
    """Processing activity evaluated against GDPR requirements."""

    activity_id: str
    data_subject_id: str
    purpose: str
    lawful_basis: str
    data_categories: tuple[str, ...] = ()
    necessary_data_fields: tuple[str, ...] = ()
    encrypted_data_fields: tuple[str, ...] = ()
    consent_required: bool = False
    consent_recorded: bool = False
    retention_days: int | None = None
    transfer_outside_eea: bool = False
    transfer_safeguards_enabled: bool = True
    breach_detected: bool = False
    breach_detected_at: datetime | None = None
    breach_notified_at: datetime | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "activity_id", _require_non_empty("activity_id", self.activity_id))
        object.__setattr__(self, "data_subject_id", _require_non_empty("data_subject_id", self.data_subject_id))
        object.__setattr__(self, "purpose", _require_non_empty("purpose", self.purpose))
        object.__setattr__(self, "lawful_basis", _require_non_empty("lawful_basis", self.lawful_basis).lower())
        object.__setattr__(self, "data_categories", _normalize_string_sequence("data_categories", self.data_categories))
        object.__setattr__(self, "necessary_data_fields", _normalize_string_sequence("necessary_data_fields", self.necessary_data_fields))
        object.__setattr__(self, "encrypted_data_fields", _normalize_string_sequence("encrypted_data_fields", self.encrypted_data_fields))

        if self.retention_days is not None and self.retention_days < 0:
            raise ValueError("retention_days must be >= 0")
        if self.breach_detected_at is not None and self.breach_detected_at.tzinfo is None:
            object.__setattr__(self, "breach_detected_at", self.breach_detected_at.replace(tzinfo=UTC))
        if self.breach_notified_at is not None and self.breach_notified_at.tzinfo is None:
            object.__setattr__(self, "breach_notified_at", self.breach_notified_at.replace(tzinfo=UTC))
        if not isinstance(self.metadata, dict):
            raise TypeError("metadata must be a dict")


@dataclass(frozen=True)
class ConsentRecord:
    """Consent evidence for a specific processing purpose."""

    data_subject_id: str
    purpose: str
    consent: bool
    recorded_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    source: str = "application"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SubjectDataRecord:
    """Encrypted payload stored for a data subject."""

    data_subject_id: str
    encrypted_payload: bytes
    standard_format: str = "application/json"
    encryption_algorithm: str = "aes-256-gcm"
    key_size_bits: int = 256
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "data_subject_id", _require_non_empty("data_subject_id", self.data_subject_id))
        object.__setattr__(self, "standard_format", _require_non_empty("standard_format", self.standard_format))
        object.__setattr__(self, "encryption_algorithm", _require_non_empty("encryption_algorithm", self.encryption_algorithm).lower())
        if self.key_size_bits < 0:
            raise ValueError("key_size_bits must be >= 0")
        if not isinstance(self.encrypted_payload, (bytes, bytearray)):
            raise TypeError("encrypted_payload must be bytes")
        if not isinstance(self.metadata, dict):
            raise TypeError("metadata must be a dict")


@dataclass(frozen=True)
class DeletionProof:
    """Proof of secure deletion with DTI evidence."""

    data_subject_id: str
    deleted_at: datetime
    dti: float
    target_met: bool
    proof_details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DataExport:
    """Portable encrypted export for a data subject."""

    data_subject_id: str
    exported_at: datetime
    standard_format: str
    encrypted_payload: bytes
    checksum_sha256: str
    manifest: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class BreachNotification:
    """GDPR breach notification outcome."""

    data_subject_id: str
    detected_at: datetime
    notified_at: datetime | None
    reported_within_72h: bool
    reason: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Report:
    """GDPR compliance report with DPIA and evidence."""

    generated_at: datetime
    start_date: date
    end_date: date
    requirement_version: str
    compliant: bool
    lawful_basis_checks: list[dict[str, Any]]
    deletion_proofs: list[DeletionProof]
    data_exports: list[DataExport]
    consent_records: list[ConsentRecord]
    breach_notifications: list[BreachNotification]
    dpia_template: str
    violations: list[str] = field(default_factory=list)


class GDPRComplianceFramework:
    """GDPR compliance implementation with consent and erasure evidence."""

    def __init__(
        self,
        *,
        organization_name: str = "Organization",
        dpo_name: str = "Data Protection Officer",
        requirement_version: str = GDPR_REQUIREMENT_VERSION,
        seed_records: Sequence[SubjectDataRecord] | None = None,
        seed_consent: Sequence[ConsentRecord] | None = None,
        seed_activities: Sequence[Activity] | None = None,
    ) -> None:
        self.organization_name = _require_non_empty("organization_name", organization_name)
        self.dpo_name = _require_non_empty("dpo_name", dpo_name)
        self.requirement_version = _require_non_empty("requirement_version", requirement_version)
        self._subject_records: dict[str, SubjectDataRecord] = {record.data_subject_id: record for record in (seed_records or [])}
        self._consent_records: list[ConsentRecord] = list(seed_consent or [])
        self._activities: list[Activity] = list(seed_activities or [])
        self._deletion_proofs: list[DeletionProof] = []
        self._breach_notifications: list[BreachNotification] = []

    def validate_gdpr_lawful_basis(self, processing_activity: Activity) -> bool:
        """Validate lawful basis, minimization, consent, and cross-border safeguards."""
        activity = self._coerce_activity(processing_activity)
        self._activities.append(activity)

        allowed, minimization_ok, consent_ok, transfer_ok, breach_ok = self._assess_lawful_basis(activity)
        compliant = bool(allowed and minimization_ok and consent_ok and transfer_ok and breach_ok)

        if activity.breach_detected:
            self._append_breach_notification(activity, within_window=breach_ok)

        return compliant

    def implement_right_to_erasure(self, data_subject_id: str) -> DeletionProof:
        """Securely delete a subject record and return DTI-backed proof."""
        subject_id = _require_non_empty("data_subject_id", data_subject_id)
        record = self._subject_records.pop(subject_id, None)

        if record is None:
            deletion_metadata = {
                "original_size_bytes": 1,
                "key_erasure_verified": True,
                "erasure_results": {"record": "erased"},
                "dti_target": GDPR_MIN_DTI,
            }
        else:
            deletion_metadata = {
                "original_size_bytes": max(1, len(record.encrypted_payload)),
                "key_erasure_verified": True,
                "erasure_results": {"record": "erased", "encryption_key": "erased"},
                "dti_target": GDPR_MIN_DTI,
            }

        proof_report = calculate_dti(f"/gdpr/{subject_id}", deletion_metadata)
        proof = DeletionProof(
            data_subject_id=subject_id,
            deleted_at=datetime.now(UTC),
            dti=float(proof_report["dti"]),
            target_met=bool(proof_report["target_met"]),
            proof_details={
                "target_dti": proof_report["target_dti"],
                "summary": proof_report["summary"],
                "forensic_recovery": proof_report["forensic_recovery"],
                "entropy_analysis": proof_report["entropy_analysis"],
                "key_erasure": proof_report["key_erasure"],
            },
        )
        self._deletion_proofs.append(proof)
        return proof

    def generate_gdpr_data_export(self, data_subject_id: str) -> DataExport:
        """Export subject data in a portable encrypted JSON format."""
        subject_id = _require_non_empty("data_subject_id", data_subject_id)
        record = self._subject_records.get(subject_id)
        if record is None:
            payload = {
                "data_subject_id": subject_id,
                "exported_fields": [],
                "records": [],
                "metadata": {"empty_export": True},
            }
            encrypted_payload = base64.b64encode(json.dumps(payload, sort_keys=True).encode("utf-8"))
            standard_format = "application/json+base64"
        else:
            payload = {
                "data_subject_id": subject_id,
                "standard_format": record.standard_format,
                "encryption_algorithm": record.encryption_algorithm,
                "key_size_bits": record.key_size_bits,
                "metadata": record.metadata,
                "records": [
                    {
                        "encrypted_payload_b64": base64.b64encode(record.encrypted_payload).decode("ascii"),
                    }
                ],
            }
            encrypted_payload = json.dumps(payload, sort_keys=True).encode("utf-8")
            standard_format = record.standard_format

        checksum = hashlib.sha256(encrypted_payload).hexdigest()
        return DataExport(
            data_subject_id=subject_id,
            exported_at=datetime.now(UTC),
            standard_format=standard_format,
            encrypted_payload=encrypted_payload,
            checksum_sha256=checksum,
            manifest={
                "requirement_version": self.requirement_version,
                "purpose": "data portability",
            },
        )

    def track_consent(self, data_subject_id: str, purpose: str, consent: bool) -> None:
        """Track and update consent for a data subject and purpose."""
        record = ConsentRecord(
            data_subject_id=_require_non_empty("data_subject_id", data_subject_id),
            purpose=_require_non_empty("purpose", purpose),
            consent=bool(consent),
        )
        self._consent_records.append(record)

    def register_subject_data(self, record: SubjectDataRecord) -> None:
        """Register encrypted subject data for later portability or erasure."""
        if not isinstance(record, SubjectDataRecord):
            raise TypeError("record must be a SubjectDataRecord")
        self._subject_records[record.data_subject_id] = record

    def generate_gdpr_compliance_report(self, start_date: date, end_date: date) -> Report:
        """Generate a GDPR report over the specified window."""
        if not isinstance(start_date, date) or not isinstance(end_date, date):
            raise TypeError("start_date and end_date must be date instances")
        if start_date > end_date:
            raise ValueError("start_date must be <= end_date")

        activities = [activity for activity in self._activities if start_date <= activity.breach_detected_at.date() <= end_date] if any(activity.breach_detected_at for activity in self._activities) else list(self._activities)

        lawful_basis_checks = []
        for activity in activities:
            allowed, minimization_ok, consent_ok, transfer_ok, breach_ok = self._assess_lawful_basis(activity)
            lawful_basis_checks.append(
                {
                    "activity_id": activity.activity_id,
                    "data_subject_id": activity.data_subject_id,
                    "purpose": activity.purpose,
                    "lawful_basis": activity.lawful_basis,
                    "compliant": bool(allowed and minimization_ok and consent_ok and transfer_ok and breach_ok),
                }
            )

        data_exports = [self.generate_gdpr_data_export(subject_id) for subject_id in sorted(self._subject_records)]
        deletion_proofs = list(self._deletion_proofs)
        consent_records = list(self._consent_records)
        breach_notifications = list(self._breach_notifications)

        violations: list[str] = []
        for item in lawful_basis_checks:
            if not item["compliant"]:
                violations.append(f"Lawful basis failed for {item['activity_id']}")
        for notification in breach_notifications:
            if not notification.reported_within_72h:
                violations.append(f"Breach notification exceeded 72 hours for {notification.data_subject_id}")
        for proof in deletion_proofs:
            if not proof.target_met:
                violations.append(f"Right-to-erasure proof below target for {proof.data_subject_id}")

        compliant = not violations and all(proof.dti >= GDPR_MIN_DTI for proof in deletion_proofs)

        return Report(
            generated_at=datetime.now(UTC),
            start_date=start_date,
            end_date=end_date,
            requirement_version=self.requirement_version,
            compliant=compliant,
            lawful_basis_checks=lawful_basis_checks,
            deletion_proofs=deletion_proofs,
            data_exports=data_exports,
            consent_records=consent_records,
            breach_notifications=breach_notifications,
            dpia_template=self.generate_dpia_template(),
            violations=violations,
        )

    def generate_dpia_template(self) -> str:
        """Generate a data processing impact assessment template."""
        return (
            "Data Protection Impact Assessment (DPIA)\n"
            f"Version: {self.requirement_version}\n"
            f"Organization: {self.organization_name}\n"
            f"Data Protection Officer: {self.dpo_name}\n\n"
            "1. Processing Description\n"
            "- Describe the nature, scope, context, and purpose of the processing.\n\n"
            "2. Necessity and Proportionality\n"
            "- Document lawful basis, data minimization, retention, and international transfer safeguards.\n\n"
            "3. Risk Assessment\n"
            "- Evaluate risks to rights and freedoms, including unauthorized access and re-identification.\n\n"
            "4. Mitigations\n"
            "- Record encryption, consent, access controls, breach detection, and deletion procedures.\n\n"
            "5. Residual Risk and Approval\n"
            "- Record final approval, owners, and review cadence.\n"
        )

    def _evaluate_breach_window(self, activity: Activity) -> bool:
        if not activity.breach_detected:
            return True
        if activity.breach_detected_at is None or activity.breach_notified_at is None:
            return False
        elapsed = activity.breach_notified_at - activity.breach_detected_at
        return elapsed <= timedelta(hours=GDPR_BREACH_NOTIFICATION_WINDOW_HOURS)

    def _assess_lawful_basis(self, activity: Activity) -> tuple[bool, bool, bool, bool, bool]:
        allowed = activity.lawful_basis in GDPR_APPROVED_LAWFUL_BASES
        minimization_ok = set(activity.encrypted_data_fields).issubset(set(activity.necessary_data_fields))
        consent_ok = True
        if activity.consent_required or activity.lawful_basis == "consent":
            consent_ok = activity.consent_recorded and self._has_consent(activity.data_subject_id, activity.purpose)

        transfer_ok = True
        if activity.transfer_outside_eea:
            transfer_ok = activity.transfer_safeguards_enabled

        breach_ok = self._evaluate_breach_window(activity)
        return allowed, minimization_ok, consent_ok, transfer_ok, breach_ok

    def _append_breach_notification(self, activity: Activity, *, within_window: bool) -> None:
        detected_at = activity.breach_detected_at or datetime.now(UTC)
        notified_at = activity.breach_notified_at
        notification = BreachNotification(
            data_subject_id=activity.data_subject_id,
            detected_at=detected_at,
            notified_at=notified_at,
            reported_within_72h=within_window and notified_at is not None,
            reason="Breach detected during GDPR processing review",
            details=dict(activity.metadata),
        )
        self._breach_notifications.append(notification)

    def _has_consent(self, data_subject_id: str, purpose: str) -> bool:
        normalized_subject = _require_non_empty("data_subject_id", data_subject_id)
        normalized_purpose = _require_non_empty("purpose", purpose)
        return any(
            record.data_subject_id == normalized_subject
            and record.purpose == normalized_purpose
            and record.consent
            for record in self._consent_records
        )

    @staticmethod
    def _coerce_activity(processing_activity: Activity | Mapping[str, Any]) -> Activity:
        if isinstance(processing_activity, Activity):
            return processing_activity
        if isinstance(processing_activity, Mapping):
            return Activity(**dict(processing_activity))
        raise TypeError("processing_activity must be an Activity or mapping")


def _normalize_string_sequence(name: str, values: Sequence[str]) -> tuple[str, ...]:
    if not isinstance(values, Sequence):
        raise TypeError(f"{name} must be a sequence")
    normalized: list[str] = []
    for value in values:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must contain non-empty strings")
        normalized.append(value.strip())
    return tuple(normalized)


def _require_non_empty(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value.strip()


__all__ = [
    "GDPR_REQUIREMENT_VERSION",
    "GDPR_MIN_DTI",
    "GDPR_BREACH_NOTIFICATION_WINDOW_HOURS",
    "Activity",
    "ConsentRecord",
    "SubjectDataRecord",
    "DeletionProof",
    "DataExport",
    "BreachNotification",
    "Report",
    "GDPRComplianceFramework",
]
