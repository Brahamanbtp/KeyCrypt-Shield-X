from datetime import timedelta, datetime

from src.governance.retention_policy import RetentionManager


def test_define_and_apply_policy_and_enforce():
    m = RetentionManager()
    policy = m.define_retention_policy("logs", timedelta(days=-1), description="test immediate expiry")
    m.apply_retention_policy("d-1", policy, now=datetime.utcnow())
    result = m.enforce_retention_policy(now=datetime.utcnow())
    assert "d-1" in result.deleted


def test_legal_hold_prevents_deletion():
    m = RetentionManager()
    policy = m.define_retention_policy("records", timedelta(days=-1))
    m.apply_retention_policy("case-1", policy, now=datetime.utcnow())
    m.legal_hold("case-1", "CASE-123")
    result = m.enforce_retention_policy(now=datetime.utcnow())
    assert "case-1" in result.skipped_due_to_hold


def test_release_legal_hold_allows_deletion():
    m = RetentionManager()
    policy = m.define_retention_policy("records", timedelta(days=-1))
    m.apply_retention_policy("case-2", policy, now=datetime.utcnow())
    m.legal_hold("case-2", "CASE-456")
    m.release_legal_hold("case-2", "CASE-456")
    result = m.enforce_retention_policy(now=datetime.utcnow())
    assert "case-2" in result.deleted


def test_validate_policy_compliance():
    m = RetentionManager()
    policy = m.define_retention_policy("financial", timedelta(days=365 * 5))
    regs = {"financial": timedelta(days=365 * 7)}
    assert m.validate_policy_compliance(policy, regulations=regs) is False
