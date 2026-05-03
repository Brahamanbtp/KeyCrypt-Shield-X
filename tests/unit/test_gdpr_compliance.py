"""Unit tests for src/compliance/gdpr_compliance.py."""

from __future__ import annotations

import importlib.util
import sys
from datetime import UTC, date, datetime, timedelta
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


def _load_module():
    module_path = PROJECT_ROOT / "src/compliance/gdpr_compliance.py"
    spec = importlib.util.spec_from_file_location("gdpr_compliance_module", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load gdpr_compliance module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_validate_gdpr_lawful_basis_requires_minimization_and_consent_tracking() -> None:
    module = _load_module()
    framework = module.GDPRComplianceFramework()

    framework.track_consent("subject-1", "research", True)
    activity = module.Activity(
        activity_id="act-1",
        data_subject_id="subject-1",
        purpose="research",
        lawful_basis="consent",
        necessary_data_fields=("email", "age"),
        encrypted_data_fields=("email",),
        consent_required=True,
        consent_recorded=True,
    )

    assert framework.validate_gdpr_lawful_basis(activity) is True


def test_validate_gdpr_lawful_basis_rejects_unnecessary_encryption_or_missing_consent() -> None:
    module = _load_module()
    framework = module.GDPRComplianceFramework()

    activity = module.Activity(
        activity_id="act-2",
        data_subject_id="subject-2",
        purpose="marketing",
        lawful_basis="consent",
        necessary_data_fields=("email",),
        encrypted_data_fields=("email", "ssn"),
        consent_required=True,
        consent_recorded=False,
    )

    assert framework.validate_gdpr_lawful_basis(activity) is False


def test_right_to_erasure_returns_dti_backed_proof() -> None:
    module = _load_module()
    framework = module.GDPRComplianceFramework()
    framework.register_subject_data(
        module.SubjectDataRecord(
            data_subject_id="subject-3",
            encrypted_payload=b"encrypted-payload",
            metadata={"purpose": "archive"},
        )
    )

    proof = framework.implement_right_to_erasure("subject-3")

    assert proof.dti >= module.GDPR_MIN_DTI
    assert proof.target_met is True
    assert proof.proof_details["summary"]["key_erasure_ok"] is True


def test_generate_gdpr_data_export_returns_portable_encrypted_payload() -> None:
    module = _load_module()
    framework = module.GDPRComplianceFramework()
    framework.register_subject_data(
        module.SubjectDataRecord(
            data_subject_id="subject-4",
            encrypted_payload=b"payload-bytes",
            standard_format="application/json",
            metadata={"purpose": "portability"},
        )
    )

    export = framework.generate_gdpr_data_export("subject-4")

    assert export.data_subject_id == "subject-4"
    assert export.standard_format == "application/json"
    assert export.checksum_sha256
    assert export.encrypted_payload


def test_report_includes_dpia_and_breach_window_assessment() -> None:
    module = _load_module()
    framework = module.GDPRComplianceFramework(organization_name="Acme EU", dpo_name="DPO")

    now = datetime.now(UTC)
    activity = module.Activity(
        activity_id="act-5",
        data_subject_id="subject-5",
        purpose="analytics",
        lawful_basis="legitimate_interests",
        necessary_data_fields=("country",),
        encrypted_data_fields=("country",),
        breach_detected=True,
        breach_detected_at=now,
        breach_notified_at=now + timedelta(hours=24),
    )
    framework.validate_gdpr_lawful_basis(activity)
    framework.track_consent("subject-5", "analytics", True)

    report = framework.generate_gdpr_compliance_report(date.today() - timedelta(days=1), date.today())

    assert report.requirement_version == module.GDPR_REQUIREMENT_VERSION
    assert report.compliant is True
    assert "Data Protection Impact Assessment" in report.dpia_template
    assert len(report.breach_notifications) == 1
    assert report.breach_notifications[0].reported_within_72h is True