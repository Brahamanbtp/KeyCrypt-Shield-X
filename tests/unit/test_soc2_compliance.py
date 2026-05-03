"""Unit tests for src/compliance/soc2_compliance.py."""

from __future__ import annotations

import importlib.util
import sys
from datetime import UTC, date, datetime
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


def _load_module():
    module_path = PROJECT_ROOT / "src/compliance/soc2_compliance.py"
    spec = importlib.util.spec_from_file_location("soc2_compliance_module", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load soc2_compliance module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _FakeAuditEvent:
    def __init__(self, event_id: str, timestamp: datetime, event_type: str, resource: str, action: str, outcome: str, details: dict | None = None) -> None:
        self.event_id = event_id
        self.timestamp = timestamp
        self.event_type = event_type
        self.resource = resource
        self.action = action
        self.outcome = outcome
        self._details = details or {}

    def to_payload(self):
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "resource": self.resource,
            "action": self.action,
            "outcome": self.outcome,
            **self._details,
        }


class _FakeAuditStorage:
    def __init__(self, events: list[_FakeAuditEvent]) -> None:
        self._events = events

    async def query_events(self, filters, limit: int):
        return self._events[:limit]


def test_validate_soc2_security_controls_uses_control_mapping() -> None:
    module = _load_module()
    framework = module.SOC2ComplianceFramework(system_controls={"encryption_at_rest": True, "access_controls": True, "monitoring": True})

    validation = framework.validate_soc2_security_controls()

    assert validation.criterion == "Security"
    assert validation.compliant is True
    assert "Encryption at rest" in validation.mapped_controls


def test_validate_soc2_availability_requires_999_and_disaster_recovery() -> None:
    module = _load_module()
    framework = module.SOC2ComplianceFramework(system_controls={"disaster_recovery": True})

    assert framework.validate_soc2_availability(99.95) is True
    assert framework.validate_soc2_availability(99.5) is False


def test_validate_soc2_processing_integrity_uses_hash_baseline() -> None:
    module = _load_module()
    framework = module.SOC2ComplianceFramework(expected_data_hash="a" * 64)

    assert framework.validate_soc2_processing_integrity("a" * 64) is True
    assert framework.validate_soc2_processing_integrity("b" * 64) is False


def test_generate_soc2_type2_report_includes_audit_evidence_and_control_mapping() -> None:
    module = _load_module()
    now = datetime.now(UTC)
    storage = _FakeAuditStorage(
        [
            _FakeAuditEvent("evt-1", now, "encryption", "/secure/data", "encrypt", "success", {"uptime_percentage": 99.97}),
            _FakeAuditEvent("evt-2", now, "access", "/secure/data", "read", "allow", {}),
        ]
    )
    framework = module.SOC2ComplianceFramework(
        system_controls={
            "encryption_at_rest": True,
            "encryption_in_transit": True,
            "access_controls": True,
            "monitoring": True,
            "disaster_recovery": True,
            "privacy_policy_aligned": True,
        },
        audit_storage=storage,
    )

    report = framework.generate_soc2_type2_report(module.Period(start_date=now.date(), end_date=now.date()))

    assert report.requirement_version == module.SOC2_REQUIREMENT_VERSION
    assert report.compliant is True
    assert "Security" in report.control_mapping
    assert len(report.evidence) >= 2
    assert report.summary["controls_tested"] == 5
    assert report.summary["evidence_items"] >= 2