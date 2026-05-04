from datetime import timedelta, datetime

from src.audit.audit_framework import AuditFramework, Operation
from src.audit.forensic_analysis import ForensicAnalyzer


def test_reconstruct_timeline_and_root_cause_and_report():
    af = AuditFramework()
    # create events for incident 'INC-1'
    op1 = Operation(name="login", resource="srv1", actor="u1", outcome="success", details={"incident_id": "INC-1", "handled_by": "sec1"})
    e1 = af.create_audit_trail(op1)
    op2 = Operation(name="upload", resource="srv1", actor="u1", outcome="success", details={"incident_id": "INC-1", "initial_compromise": True, "handled_by": "sec2"})
    e2 = af.create_audit_trail(op2)
    # ensure timestamps are ordered: e1 before e2
    af._entries[0].timestamp = datetime.utcnow()
    af._entries[1].timestamp = datetime.utcnow() + timedelta(seconds=2)

    fa = ForensicAnalyzer(af)
    timeline = fa.reconstruct_event_timeline("INC-1")
    assert timeline.incident_id == "INC-1"
    assert len(timeline.events) == 2

    root = fa.identify_root_cause("INC-1")
    assert root.probable_root_cause is not None
    assert root.probable_root_cause.details.get("initial_compromise") is True

    report = fa.generate_forensic_report("INC-1")
    assert report.incident_id == "INC-1"
    assert len(report.chain_of_custody) == 2


def test_find_related_events():
    af = AuditFramework()
    op1 = Operation(name="a", resource="r", actor="x", outcome="ok", details={"incident_id": "I1"})
    e1 = af.create_audit_trail(op1)
    op2 = Operation(name="b", resource="r", actor="y", outcome="ok", details={"incident_id": "I1"})
    e2 = af.create_audit_trail(op2)
    # set timestamps close together
    now = datetime.utcnow()
    af._entries[0].timestamp = now
    af._entries[1].timestamp = now + timedelta(seconds=30)

    fa = ForensicAnalyzer(af)
    related = fa.find_related_events(e1.id, timedelta(minutes=1))
    assert len(related) >= 2
