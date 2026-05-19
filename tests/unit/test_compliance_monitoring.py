import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.governance.compliance_monitoring import ComplianceBaseline, ComplianceMonitoringSystem, ComplianceViolation, CronSchedule


def test_monitor_posture_and_dashboard_and_schedule():
    system = ComplianceMonitoringSystem()

    posture = system.monitor_compliance_posture(["HIPAA", "GDPR", "SOC2"])
    assert posture.score == 100
    assert posture.compliant is True
    assert posture.category_scores["encryption"] == 100

    system.schedule_compliance_assessments(CronSchedule(expression="0 6 * * 1", description="weekly compliance scan"))
    dashboard = system.generate_compliance_dashboard()
    assert dashboard.overall_score == 100
    assert dashboard.scheduled_assessments


def test_detect_drift_and_auto_remediate():
    snapshot = {
        "configuration": {"policy_enforcement": False},
        "access_controls": {"rbac": False},
        "encryption": {"algorithm": "AES-128-GCM", "key_length": 128},
        "audit_logging": {"all_events_logged": False},
        "retention": {"deletion_schedules_enabled": False},
    }
    system = ComplianceMonitoringSystem(snapshot_provider=lambda: snapshot)

    baseline = ComplianceBaseline(
        standards=["HIPAA", "GDPR"],
        configuration_policies={"policy_enforcement": True},
        access_controls={"rbac": True},
        encryption_controls={"algorithm": "AES-256-GCM", "key_length": 256},
        audit_logging_controls={"all_events_logged": True},
        retention_controls={"deletion_schedules_enabled": True},
    )

    deviations = system.detect_compliance_drift(baseline)
    assert len(deviations) == 6

    violation = ComplianceViolation(
        standard="HIPAA",
        standard_version="continuous",
        requirement_id="audit_logging.hipaa",
        requirement_version="continuous",
        severity="high",
        message="HIPAA requires audit logging to be enabled.",
        remediation="Enable immutable audit logging for this operation path.",
        evidence={"control": "audit_logging"},
    )

    remediation = system.auto_remediate_violations(violation)
    assert remediation.fixed is True
    assert remediation.status == "remediated"