import json
from datetime import datetime, timedelta

from src.audit.audit_framework import AuditFramework, Operation, TimeRange
from src.audit.compliance_reporting import ComplianceReporter


def test_generate_quarterly_report_and_verify_signature():
    af = AuditFramework()
    # create events in Q1 (Jan-Mar)
    op1 = Operation(name="op1", resource="r1", actor="u1", outcome="success", details={})
    af.create_audit_trail(op1)
    af._entries[0].timestamp = datetime(2026, 1, 15)
    reporter = ComplianceReporter(af, signing_key=b"k")
    rep = reporter.generate_quarterly_compliance_report(1, 2026)
    payload_data = dict(rep.__dict__)
    payload_data['signature'] = None
    payload_data['signed_by'] = None
    payload = reporter._serialize(payload_data)
    assert reporter.verify_report_signature(payload, rep.signature)


def test_generate_annual_security_report_and_breach_report_and_evidence_package():
    af = AuditFramework()
    now = datetime(2026, 5, 4)
    op1 = Operation(name="login", resource="srv", actor="alice", outcome="success", details={"incident_id": "INC-10", "personal_data": True})
    e1 = af.create_audit_trail(op1)
    af._entries[0].timestamp = now
    reporter = ComplianceReporter(af, signing_key=b"k2")
    sec = reporter.generate_annual_security_report(2026)
    payload_data = dict(sec.__dict__)
    payload_data['signature'] = None
    payload_data['signed_by'] = None
    payload = reporter._serialize(payload_data)
    assert reporter.verify_report_signature(payload, sec.signature)

    br = reporter.generate_breach_notification_report("INC-10")
    assert "GDPR" in br.recommended_notifications

    pkg = reporter.generate_auditor_evidence_package(e1.id)
    assert pkg.signature is not None
