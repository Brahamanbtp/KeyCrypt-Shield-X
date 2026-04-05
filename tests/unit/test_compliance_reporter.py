"""Unit tests for src.observability.compliance_reporter."""

from __future__ import annotations

import asyncio
import sys
from datetime import UTC, date, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.observability.audit_event_schema import AccessEvent, AuditEvent, EncryptionEvent, KeyRotationEvent
from src.observability.audit_storage import AuditStorage, BlockchainAuditBackend
from src.observability.compliance_reporter import ComplianceReporter


def _run(coro):
    return asyncio.run(coro)


def _seed_events(now: datetime) -> list[AuditEvent]:
    return [
        EncryptionEvent(
            timestamp=now,
            actor="svc-crypto",
            resource="/cardholder-data/pan/txn-1",
            action="encrypt",
            outcome="success",
            algorithm="AES-256-GCM",
            key_id="key-1",
            data_size=2048,
            duration=0.02,
        ),
        KeyRotationEvent(
            timestamp=now,
            actor="key-manager",
            resource="/keys/prod",
            action="rotate",
            outcome="success",
            old_key_id="key-1",
            new_key_id="key-2",
            rotation_reason="scheduled",
        ),
        AccessEvent(
            timestamp=now,
            actor="user-42",
            resource="/patients/user-42/record",
            action="read",
            outcome="allow",
            resource_accessed="/patients/user-42/record",
            access_granted=True,
        ),
        AuditEvent(
            timestamp=now,
            event_type="breach_notification",
            actor="soc-team",
            resource="/incidents/ir-1",
            action="notify",
            outcome="breach_reported",
        ),
        AuditEvent(
            timestamp=now,
            event_type="consent_record",
            actor="user-42",
            resource="/consent/user-42",
            action="consent_granted",
            outcome="success",
        ),
        AuditEvent(
            timestamp=now,
            event_type="deletion_proof",
            actor="dpo-service",
            resource="/patients/user-42/archive",
            action="delete",
            outcome="success",
        ),
    ]


def test_generate_hipaa_report_contains_required_sections_and_signed_pdf() -> None:
    now = datetime.now(UTC)
    reporter = ComplianceReporter(seed_events=_seed_events(now))

    report = reporter.generate_hipaa_report(start_date=now.date(), end_date=now.date())

    assert report.standard == "HIPAA"
    assert report.encryption_usage["total_encryption_events"] >= 1
    assert report.key_rotation_compliance["total_rotations"] >= 1
    assert len(report.access_logs) >= 1
    assert len(report.breach_notifications) >= 1
    assert report.pdf_artifact.filename.endswith(".pdf")
    assert report.pdf_artifact.verify_signature() is True


def test_generate_gdpr_report_contains_subject_evidence() -> None:
    now = datetime.now(UTC)
    reporter = ComplianceReporter(seed_events=_seed_events(now))

    report = reporter.generate_gdpr_report("user-42")

    assert report.standard == "GDPR"
    assert report.data_subject_id == "user-42"
    assert any("user-42" in item for item in report.data_inventory)
    assert len(report.deletion_proofs) >= 1
    assert len(report.consent_records) >= 1
    assert report.pdf_artifact.verify_signature() is True


def test_generate_soc2_report_includes_control_evidence_and_exceptions() -> None:
    now = datetime.now(UTC)
    reporter = ComplianceReporter(seed_events=_seed_events(now))

    report = reporter.generate_soc2_report(["encryption", "access", "incident-response"])

    assert report.standard == "SOC2"
    assert report.test_results["encryption"]["evidence_count"] >= 1
    assert report.test_results["access"]["evidence_count"] >= 1
    assert report.test_results["incident-response"]["status"] == "fail"
    assert any(item["control"] == "incident-response" for item in report.exceptions)
    assert report.pdf_artifact.verify_signature() is True


def test_generate_pci_dss_report_contains_cardholder_sections() -> None:
    now = datetime.now(UTC)
    reporter = ComplianceReporter(seed_events=_seed_events(now))

    report = reporter.generate_pci_dss_report()

    assert report.standard == "PCI-DSS"
    assert len(report.cardholder_data_inventory) >= 1
    assert report.encryption_validation["events_evaluated"] >= 1
    assert "granted" in report.access_controls
    assert report.pdf_artifact.verify_signature() is True


def test_reporter_collects_evidence_from_audit_storage() -> None:
    storage = AuditStorage(backend=BlockchainAuditBackend())
    now = datetime.now(UTC)

    event = EncryptionEvent(
        timestamp=now,
        actor="svc-crypto",
        resource="/cardholder-data/pan/txn-999",
        action="encrypt",
        outcome="success",
        algorithm="CHACHA20-POLY1305",
        key_id="key-99",
        data_size=512,
        duration=0.01,
    )
    _run(storage.append_event(event))

    reporter = ComplianceReporter(audit_storage=storage)
    report = reporter.generate_pci_dss_report()

    # Evidence records are serialized dict payloads.
    assert any(str(entry.get("resource")) == event.resource for entry in report.evidence_records)
