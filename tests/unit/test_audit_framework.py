import json
from datetime import datetime, timedelta

from src.audit.audit_framework import AuditFramework, Operation, TimeRange


def test_create_and_query_and_verify_chain():
    af = AuditFramework()
    op1 = Operation(name="create", resource="db/1", actor="alice", outcome="success", details={"size": 123})
    op2 = Operation(name="delete", resource="db/1", actor="bob", outcome="failure", details={"reason": "locked"})
    e1 = af.create_audit_trail(op1)
    e2 = af.create_audit_trail(op2)
    assert len(af.query_audit_trail()) == 2
    assert af.verify_chain_integrity() is True


def test_search_by_user_and_resource_and_time_range():
    af = AuditFramework()
    now = datetime.utcnow()
    af.create_audit_trail(Operation(name="op", resource="r1", actor="u1", outcome="ok"))
    af.create_audit_trail(Operation(name="op2", resource="r2", actor="u2", outcome="ok"))
    results = af.search_audit_by_user("u1", time_range=TimeRange(start=now - timedelta(minutes=1), end=now + timedelta(minutes=1)))
    assert len(results) >= 1
    r = af.search_audit_by_resource("r2")
    assert any(e.resource == "r2" for e in r)


def test_export_formats():
    af = AuditFramework()
    af.create_audit_trail(Operation(name="op", resource="r", actor="u", outcome="ok"))
    j = af.export_audit_trail("json")
    data = json.loads(j)
    assert isinstance(data, list)
    csv_out = af.export_audit_trail("csv")
    assert "id" in csv_out
    syslog = af.export_audit_trail("syslog")
    assert "u" in syslog
    cef = af.export_audit_trail("cef")
    assert "CEF:0" in cef


def test_tamper_detection():
    af = AuditFramework()
    af.create_audit_trail(Operation(name="x", resource="r", actor="a", outcome="ok"))
    af.create_audit_trail(Operation(name="y", resource="r", actor="b", outcome="ok"))
    assert af.verify_chain_integrity() is True
    # tamper with an entry
    af._entries[0].actor = "mallory"
    assert af.verify_chain_integrity() is False
