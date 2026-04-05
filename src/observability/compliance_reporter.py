"""Regulatory compliance report generation with signed PDF exports.

This module preserves the compliance reporting layer while extending it with
multi-standard report generation and automated evidence collection from audit
logs.

Supported reports:
- HIPAA
- GDPR
- SOC2
- PCI-DSS

Each report includes:
- Type-safe Pydantic schema
- Evidence derived from audit events
- Embedded signed PDF artifact with detached digital signature metadata
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import threading
import uuid
from datetime import UTC, date, datetime
from typing import Any, Iterable, List, Literal, Mapping

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from src.observability.audit_event_schema import (
    AccessEvent,
    AuditEvent,
    ConfigChangeEvent,
    EncryptionEvent,
    KeyRotationEvent,
)
from src.observability.audit_storage import AuditFilter, AuditStorage
from src.observability.audit_ledger import ImmutableAuditLedger
from src.utils.logging import get_logger, log_security_event


logger = get_logger("src.observability.compliance_reporter")


class SignedPDFArtifact(BaseModel):
    """Signed PDF export artifact."""

    model_config = ConfigDict(extra="forbid")

    filename: str = Field(min_length=1)
    pdf_bytes: bytes
    digest_sha256: str = Field(min_length=64, max_length=64)
    signature_algorithm: Literal["ed25519"] = "ed25519"
    signature_b64: str = Field(min_length=1)
    signer_id: str = Field(min_length=1)
    public_key_b64: str = Field(min_length=1)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("filename", "digest_sha256", "signature_b64", "signer_id", "public_key_b64")
    @classmethod
    def _validate_non_empty_text(cls, value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("field must be a non-empty string")
        return value.strip()

    def verify_signature(self) -> bool:
        """Verify detached Ed25519 signature against embedded PDF bytes."""
        try:
            signature = base64.b64decode(self.signature_b64)
            public_key_bytes = base64.b64decode(self.public_key_b64)
            public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
            public_key.verify(signature, self.pdf_bytes)

            digest = hashlib.sha256(self.pdf_bytes).hexdigest()
            return digest == self.digest_sha256
        except Exception:
            return False


class ComplianceReportBase(BaseModel):
    """Base schema for compliance report outputs."""

    model_config = ConfigDict(extra="forbid")

    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    standard: str = Field(min_length=1)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    evidence_records: list[dict[str, Any]] = Field(default_factory=list)
    pdf_artifact: SignedPDFArtifact


class HIPAAReport(ComplianceReportBase):
    """HIPAA compliance report."""

    standard: Literal["HIPAA"] = "HIPAA"
    start_date: date
    end_date: date
    encryption_usage: dict[str, Any]
    key_rotation_compliance: dict[str, Any]
    access_logs: list[dict[str, Any]]
    breach_notifications: list[dict[str, Any]]

    @model_validator(mode="after")
    def _validate_range(self) -> "HIPAAReport":
        if self.start_date > self.end_date:
            raise ValueError("start_date must be <= end_date")
        return self


class GDPRReport(ComplianceReportBase):
    """GDPR compliance report for a data subject."""

    standard: Literal["GDPR"] = "GDPR"
    data_subject_id: str = Field(min_length=1)
    data_inventory: list[str]
    processing_purposes: list[str]
    deletion_proofs: list[dict[str, Any]]
    consent_records: list[dict[str, Any]]


class SOC2Report(ComplianceReportBase):
    """SOC2 control evidence report."""

    standard: Literal["SOC2"] = "SOC2"
    controls: list[str]
    control_implementation_evidence: dict[str, list[dict[str, Any]]]
    test_results: dict[str, dict[str, Any]]
    exceptions: list[dict[str, Any]]


class PCIDSSReport(ComplianceReportBase):
    """PCI-DSS cardholder security report."""

    standard: Literal["PCI-DSS"] = "PCI-DSS"
    cardholder_data_inventory: list[str]
    encryption_validation: dict[str, Any]
    access_controls: dict[str, Any]


class ComplianceReporter:
    """Compliance report generator with audit-evidence harvesting."""

    def __init__(
        self,
        *,
        audit_storage: AuditStorage | None = None,
        immutable_ledger: ImmutableAuditLedger | None = None,
        seed_events: Iterable[AuditEvent] | None = None,
        signer_id: str = "keycrypt-compliance-reporter",
        report_signing_key: str | bytes | None = None,
        default_evidence_limit: int = 5000,
    ) -> None:
        self._audit_storage = audit_storage
        self._immutable_ledger = immutable_ledger
        self._seed_events = list(seed_events or [])
        self._signer_id = self._require_non_empty("signer_id", signer_id)

        if default_evidence_limit <= 0:
            raise ValueError("default_evidence_limit must be > 0")
        self._default_evidence_limit = int(default_evidence_limit)

        self._private_key = self._load_or_generate_signing_key(report_signing_key)
        self._public_key_raw = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def generate_hipaa_report(self, start_date: date, end_date: date) -> HIPAAReport:
        """Generate HIPAA report with encryption/rotation/access/breach evidence."""
        if not isinstance(start_date, date) or not isinstance(end_date, date):
            raise TypeError("start_date and end_date must be date instances")
        if start_date > end_date:
            raise ValueError("start_date must be <= end_date")

        events = self._events_in_date_range(self._collect_evidence_events(), start_date, end_date)

        encryption_events = [event for event in events if event.event_type == "encryption"]
        rotation_events = [event for event in events if event.event_type == "key_rotation"]
        access_events = [
            event
            for event in events
            if event.event_type in {"access", "authorization", "permission_check"}
        ]
        breach_events = [
            event
            for event in events
            if "breach" in event.event_type.lower() or "breach" in event.outcome.lower()
        ]

        algorithms: dict[str, int] = {}
        encrypted_bytes = 0
        for event in encryption_events:
            payload = event.to_payload()
            algorithm = str(payload.get("algorithm", "unknown")).strip() or "unknown"
            algorithms[algorithm] = algorithms.get(algorithm, 0) + 1
            size = payload.get("data_size")
            if isinstance(size, int) and size >= 0:
                encrypted_bytes += size

        key_rotation_compliance = {
            "total_rotations": len(rotation_events),
            "compliant": len(rotation_events) > 0,
            "rotation_reasons": sorted(
                {
                    str(event.to_payload().get("rotation_reason", "unspecified"))
                    for event in rotation_events
                }
            ),
        }

        access_logs = [self._event_summary(event) for event in access_events]
        breach_notifications = [self._event_summary(event) for event in breach_events]
        evidence = [self._event_summary(event) for event in events]

        report = HIPAAReport(
            start_date=start_date,
            end_date=end_date,
            encryption_usage={
                "total_encryption_events": len(encryption_events),
                "algorithms": algorithms,
                "encrypted_data_bytes": encrypted_bytes,
            },
            key_rotation_compliance=key_rotation_compliance,
            access_logs=access_logs,
            breach_notifications=breach_notifications,
            evidence_records=evidence,
            pdf_artifact=self._signed_pdf_placeholder(),
        )

        return report.model_copy(update={"pdf_artifact": self._render_and_sign_pdf("hipaa", report)})

    def generate_gdpr_report(self, data_subject_id: str) -> GDPRReport:
        """Generate GDPR report for data subject evidence and rights operations."""
        subject = self._require_non_empty("data_subject_id", data_subject_id)
        subject_lc = subject.lower()

        events = self._collect_evidence_events()
        subject_events = [event for event in events if self._event_mentions_subject(event, subject_lc)]

        data_inventory = sorted({event.resource for event in subject_events})
        processing_purposes = sorted(
            {
                self._processing_purpose_from_event(event)
                for event in subject_events
            }
        )
        processing_purposes = [purpose for purpose in processing_purposes if purpose]

        deletion_proofs = [
            self._event_summary(event)
            for event in subject_events
            if self._is_deletion_event(event)
        ]
        consent_records = [
            self._event_summary(event)
            for event in subject_events
            if "consent" in event.event_type.lower() or "consent" in event.action.lower()
        ]

        evidence = [self._event_summary(event) for event in subject_events]

        report = GDPRReport(
            data_subject_id=subject,
            data_inventory=data_inventory,
            processing_purposes=processing_purposes,
            deletion_proofs=deletion_proofs,
            consent_records=consent_records,
            evidence_records=evidence,
            pdf_artifact=self._signed_pdf_placeholder(),
        )

        return report.model_copy(update={"pdf_artifact": self._render_and_sign_pdf("gdpr", report)})

    def generate_soc2_report(self, controls: List[str]) -> SOC2Report:
        """Generate SOC2 control evidence and testing report."""
        if not isinstance(controls, list):
            raise TypeError("controls must be a list of strings")

        normalized_controls = [self._require_non_empty("control", control) for control in controls]
        if not normalized_controls:
            raise ValueError("controls must contain at least one control")

        events = self._collect_evidence_events()
        evidence_by_control: dict[str, list[dict[str, Any]]] = {}
        test_results: dict[str, dict[str, Any]] = {}
        exceptions: list[dict[str, Any]] = []

        for control in normalized_controls:
            control_lc = control.lower()
            matched_events = [
                event
                for event in events
                if self._event_matches_control(event, control_lc)
            ]

            evidence_entries = [self._event_summary(event) for event in matched_events]
            evidence_by_control[control] = evidence_entries

            status = "pass" if evidence_entries else "fail"
            test_results[control] = {
                "status": status,
                "evidence_count": len(evidence_entries),
            }

            if not evidence_entries:
                exceptions.append(
                    {
                        "control": control,
                        "severity": "medium",
                        "reason": "No implementation evidence found in audit logs",
                    }
                )

        report = SOC2Report(
            controls=normalized_controls,
            control_implementation_evidence=evidence_by_control,
            test_results=test_results,
            exceptions=exceptions,
            evidence_records=[self._event_summary(event) for event in events],
            pdf_artifact=self._signed_pdf_placeholder(),
        )

        return report.model_copy(update={"pdf_artifact": self._render_and_sign_pdf("soc2", report)})

    def generate_pci_dss_report(self) -> PCIDSSReport:
        """Generate PCI-DSS report for cardholder data controls and encryption."""
        events = self._collect_evidence_events()

        cardholder_resources = sorted(
            {
                event.resource
                for event in events
                if self._is_cardholder_related_resource(event.resource)
            }
        )

        encryption_events = [
            event
            for event in events
            if event.event_type == "encryption" and self._is_cardholder_related_resource(event.resource)
        ]

        approved_algorithms = {
            "aes-256-gcm",
            "aes-gcm",
            "chacha20-poly1305",
            "xchacha20-poly1305",
        }
        algorithm_usage: dict[str, int] = {}
        non_compliant_algorithms: set[str] = set()

        for event in encryption_events:
            payload = event.to_payload()
            algorithm = str(payload.get("algorithm", "unknown")).strip()
            algorithm_usage[algorithm] = algorithm_usage.get(algorithm, 0) + 1
            if algorithm.lower() not in approved_algorithms:
                non_compliant_algorithms.add(algorithm)

        access_events = [
            event
            for event in events
            if event.event_type in {"access", "authorization", "permission_check"}
            and self._is_cardholder_related_resource(event.resource)
        ]

        granted = 0
        denied = 0
        for event in access_events:
            if isinstance(event, AccessEvent):
                if event.access_granted:
                    granted += 1
                else:
                    denied += 1
            else:
                if event.outcome.lower() in {"allow", "granted", "success"}:
                    granted += 1
                else:
                    denied += 1

        report = PCIDSSReport(
            cardholder_data_inventory=cardholder_resources,
            encryption_validation={
                "events_evaluated": len(encryption_events),
                "algorithm_usage": algorithm_usage,
                "approved_algorithms": sorted(approved_algorithms),
                "non_compliant_algorithms": sorted(non_compliant_algorithms),
                "compliant": len(non_compliant_algorithms) == 0,
            },
            access_controls={
                "access_events_evaluated": len(access_events),
                "granted": granted,
                "denied": denied,
            },
            evidence_records=[self._event_summary(event) for event in events],
            pdf_artifact=self._signed_pdf_placeholder(),
        )

        return report.model_copy(update={"pdf_artifact": self._render_and_sign_pdf("pci_dss", report)})

    def _collect_evidence_events(self) -> list[AuditEvent]:
        """Collect evidence events from configured audit sources."""
        collected: dict[str, AuditEvent] = {}

        if self._audit_storage is not None:
            storage_events = self._run_async(self._audit_storage.query_events(AuditFilter(), self._default_evidence_limit))
            for event in storage_events:
                collected[event.event_id] = event

        if self._immutable_ledger is not None:
            entries = self._immutable_ledger.query({})
            for entry in entries:
                maybe_event = self._event_from_ledger_entry(entry)
                if maybe_event is not None:
                    collected[maybe_event.event_id] = maybe_event

        for event in self._seed_events:
            collected[event.event_id] = event

        events = list(collected.values())
        events.sort(key=lambda item: item.timestamp)
        return events

    def _event_from_ledger_entry(self, entry: Mapping[str, Any]) -> AuditEvent | None:
        event_payload_raw = entry.get("event")
        if not isinstance(event_payload_raw, Mapping):
            return None

        event_payload = dict(event_payload_raw)
        details = event_payload.get("details")
        if not isinstance(details, Mapping):
            details = {}
        metadata = event_payload.get("metadata")
        if not isinstance(metadata, Mapping):
            metadata = {}

        event_id = str(event_payload.get("event_id") or entry.get("event_hash") or f"ledger-{entry.get('index', '0')}")
        event_type = str(event_payload.get("event_type") or "audit")
        actor = str(event_payload.get("actor") or event_payload.get("actor_id") or "unknown")
        action = str(event_payload.get("action") or details.get("action") or "unknown")
        resource = str(
            event_payload.get("resource")
            or details.get("resource")
            or metadata.get("resource")
            or "unknown"
        )
        outcome = str(
            event_payload.get("outcome")
            or details.get("outcome")
            or details.get("result")
            or "unknown"
        )

        timestamp = self._coerce_timestamp(event_payload.get("timestamp"))

        base_payload = {
            "timestamp": timestamp,
            "event_id": event_id,
            "event_type": event_type,
            "actor": actor,
            "resource": resource,
            "action": action,
            "outcome": outcome,
        }

        if event_type == "encryption":
            candidate = {
                **base_payload,
                "algorithm": str(details.get("algorithm") or metadata.get("algorithm") or "unknown"),
                "key_id": str(details.get("key_id") or metadata.get("key_id") or "unknown"),
                "data_size": int(details.get("data_size") or metadata.get("data_size") or 0),
                "duration": float(details.get("duration") or metadata.get("duration") or 0.0),
            }
            try:
                return EncryptionEvent.model_validate(candidate)
            except ValidationError:
                return AuditEvent.model_validate(base_payload)

        if event_type == "key_rotation":
            candidate = {
                **base_payload,
                "old_key_id": str(details.get("old_key_id") or "unknown"),
                "new_key_id": str(details.get("new_key_id") or "unknown-new"),
                "rotation_reason": str(details.get("rotation_reason") or details.get("reason") or "unspecified"),
            }
            try:
                return KeyRotationEvent.model_validate(candidate)
            except ValidationError:
                return AuditEvent.model_validate(base_payload)

        if event_type in {"access", "authorization", "permission_check"}:
            access_granted = str(outcome).lower() in {"allow", "allowed", "granted", "success", "ok", "true"}
            candidate = {
                **base_payload,
                "event_type": "access",
                "resource_accessed": str(details.get("resource_accessed") or resource),
                "access_granted": access_granted,
                "denial_reason": None if access_granted else str(details.get("denial_reason") or "not specified"),
            }
            try:
                return AccessEvent.model_validate(candidate)
            except ValidationError:
                return AuditEvent.model_validate(base_payload)

        return AuditEvent.model_validate(base_payload)

    @staticmethod
    def _coerce_timestamp(value: Any) -> datetime:
        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=UTC)
            return value.astimezone(UTC)
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(float(value), tz=UTC)
        if isinstance(value, str) and value.strip():
            parsed = datetime.fromisoformat(value)
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=UTC)
            return parsed.astimezone(UTC)
        return datetime.now(UTC)

    @staticmethod
    def _events_in_date_range(events: list[AuditEvent], start_date: date, end_date: date) -> list[AuditEvent]:
        return [
            event
            for event in events
            if start_date <= event.timestamp.date() <= end_date
        ]

    @staticmethod
    def _event_mentions_subject(event: AuditEvent, subject_lc: str) -> bool:
        payload_text = _json_lower(event.to_payload())
        return subject_lc in payload_text

    @staticmethod
    def _processing_purpose_from_event(event: AuditEvent) -> str:
        payload = event.to_payload()
        if "processing_purpose" in payload:
            return str(payload.get("processing_purpose", "")).strip()
        if isinstance(payload.get("metadata"), Mapping):
            metadata = payload.get("metadata", {})
            purpose = metadata.get("processing_purpose")
            if isinstance(purpose, str):
                return purpose.strip()
        return event.action

    @staticmethod
    def _is_deletion_event(event: AuditEvent) -> bool:
        text = f"{event.event_type} {event.action} {event.resource} {event.outcome}".lower()
        return "delete" in text or "erasure" in text or "deletion" in text

    @staticmethod
    def _event_matches_control(event: AuditEvent, control_lc: str) -> bool:
        compact = _json_lower(event.to_payload())
        tokens = {control_lc, control_lc.replace(" ", ""), control_lc.replace(" ", "-")}
        return any(token and token in compact for token in tokens)

    @staticmethod
    def _is_cardholder_related_resource(resource: str) -> bool:
        normalized = resource.lower()
        keywords = ("cardholder", "payment", "pan", "card", "pci")
        return any(keyword in normalized for keyword in keywords)

    @staticmethod
    def _event_summary(event: AuditEvent) -> dict[str, Any]:
        payload = event.to_payload()
        return {
            "event_id": event.event_id,
            "timestamp": event.timestamp.astimezone(UTC).isoformat(),
            "event_type": event.event_type,
            "actor": event.actor,
            "resource": event.resource,
            "action": event.action,
            "outcome": event.outcome,
            "payload": payload,
        }

    def _render_and_sign_pdf(self, prefix: str, report: ComplianceReportBase) -> SignedPDFArtifact:
        summary = {
            "report_id": report.report_id,
            "standard": report.standard,
            "generated_at": report.generated_at.astimezone(UTC).isoformat(),
            "evidence_count": len(report.evidence_records),
        }
        report_payload = report.model_dump(mode="json")
        lines: list[str] = [
            f"{report.standard} Compliance Report",
            f"Report ID: {report.report_id}",
            f"Generated: {report.generated_at.astimezone(UTC).isoformat()}",
            f"Evidence Records: {len(report.evidence_records)}",
            "",
            "Summary:",
        ]

        for key, value in summary.items():
            lines.append(f"- {key}: {value}")

        lines.append("")
        lines.append("Sections:")

        for key, value in report_payload.items():
            if key in {"pdf_artifact", "evidence_records"}:
                continue
            lines.append(f"- {key}: {self._compact_for_pdf(value)}")

        # Include deterministic digest of full report payload as evidence anchor.
        payload_digest = hashlib.sha256(
            json.dumps(report_payload, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()
        lines.append("")
        lines.append(f"Payload Digest (SHA-256): {payload_digest}")

        pdf_bytes = _build_simple_pdf(lines)
        digest = hashlib.sha256(pdf_bytes).hexdigest()

        signature = self._private_key.sign(pdf_bytes)
        signature_b64 = base64.b64encode(signature).decode("ascii")

        artifact = SignedPDFArtifact(
            filename=f"{prefix}-{report.report_id}.pdf",
            pdf_bytes=pdf_bytes,
            digest_sha256=digest,
            signature_algorithm="ed25519",
            signature_b64=signature_b64,
            signer_id=self._signer_id,
            public_key_b64=base64.b64encode(self._public_key_raw).decode("ascii"),
            generated_at=datetime.now(UTC),
        )

        log_security_event(
            "compliance_report_generated",
            severity="INFO",
            actor=self._signer_id,
            target=report.report_id,
            details={
                "standard": report.standard,
                "filename": artifact.filename,
                "digest_sha256": artifact.digest_sha256,
                "evidence_count": len(report.evidence_records),
            },
        )

        return artifact

    @staticmethod
    def _compact_for_pdf(value: Any) -> str:
        text = json.dumps(value, ensure_ascii=True, sort_keys=True, default=str)
        if len(text) <= 220:
            return text
        return text[:220] + "..."

    @staticmethod
    def _load_or_generate_signing_key(value: str | bytes | None) -> Ed25519PrivateKey:
        if value is None:
            return Ed25519PrivateKey.generate()

        if isinstance(value, str):
            normalized = value.strip()
            if not normalized:
                raise ValueError("report_signing_key cannot be empty")

            if normalized.startswith("-----BEGIN"):
                loaded = serialization.load_pem_private_key(normalized.encode("utf-8"), password=None)
                if not isinstance(loaded, Ed25519PrivateKey):
                    raise ValueError("report_signing_key PEM must contain Ed25519 private key")
                return loaded

            key_bytes = base64.b64decode(normalized)
            return Ed25519PrivateKey.from_private_bytes(key_bytes)

        if isinstance(value, bytes):
            if not value:
                raise ValueError("report_signing_key cannot be empty")

            if value.startswith(b"-----BEGIN"):
                loaded = serialization.load_pem_private_key(value, password=None)
                if not isinstance(loaded, Ed25519PrivateKey):
                    raise ValueError("report_signing_key PEM must contain Ed25519 private key")
                return loaded

            return Ed25519PrivateKey.from_private_bytes(value)

        raise TypeError("report_signing_key must be str, bytes, or None")

    @staticmethod
    def _signed_pdf_placeholder() -> SignedPDFArtifact:
        return SignedPDFArtifact(
            filename="placeholder.pdf",
            pdf_bytes=b"%PDF-1.4\n%placeholder\n",
            digest_sha256=hashlib.sha256(b"%PDF-1.4\n%placeholder\n").hexdigest(),
            signature_algorithm="ed25519",
            signature_b64=base64.b64encode(b"placeholder").decode("ascii"),
            signer_id="placeholder",
            public_key_b64=base64.b64encode(b"placeholder").decode("ascii"),
            generated_at=datetime.now(UTC),
        )

    @staticmethod
    def _require_non_empty(name: str, value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must be a non-empty string")
        return value.strip()

    @staticmethod
    def _run_async(coro: Any) -> Any:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(coro)

        result: dict[str, Any] = {}
        error: dict[str, Exception] = {}

        def _runner() -> None:
            try:
                result["value"] = asyncio.run(coro)
            except Exception as exc:  # pragma: no cover - threaded fallback boundary
                error["value"] = exc

        worker = threading.Thread(target=_runner, daemon=True)
        worker.start()
        worker.join()

        if "value" in error:
            raise error["value"]
        return result.get("value")


def _json_lower(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str).lower()


def _build_simple_pdf(lines: list[str]) -> bytes:
    """Build a minimal one-page text PDF without external dependencies."""

    def _escape(text: str) -> str:
        return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    text_lines = [line for line in lines if isinstance(line, str)]
    if not text_lines:
        text_lines = ["Compliance Report"]

    max_lines = 46
    clipped = text_lines[:max_lines]

    stream_parts: list[str] = ["BT", "/F1 11 Tf", "72 780 Td"]
    for index, line in enumerate(clipped):
        escaped = _escape(line)
        if index == 0:
            stream_parts.append(f"({escaped}) Tj")
        else:
            stream_parts.append("0 -16 Td")
            stream_parts.append(f"({escaped}) Tj")
    stream_parts.append("ET")

    content_stream = "\n".join(stream_parts).encode("latin-1", errors="replace")

    objects: list[bytes] = []
    objects.append(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
    objects.append(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")
    objects.append(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\nendobj\n"
    )
    objects.append(b"4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n")
    objects.append(
        b"5 0 obj\n<< /Length "
        + str(len(content_stream)).encode("ascii")
        + b" >>\nstream\n"
        + content_stream
        + b"\nendstream\nendobj\n"
    )

    header = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
    output = bytearray(header)

    offsets = [0]
    for obj in objects:
        offsets.append(len(output))
        output.extend(obj)

    xref_start = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")

    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))

    trailer = (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref_start}\n%%EOF\n"
    ).encode("ascii")
    output.extend(trailer)
    return bytes(output)


__all__ = [
    "ValidationError",
    "SignedPDFArtifact",
    "ComplianceReportBase",
    "HIPAAReport",
    "GDPRReport",
    "SOC2Report",
    "PCIDSSReport",
    "ComplianceReporter",
]
