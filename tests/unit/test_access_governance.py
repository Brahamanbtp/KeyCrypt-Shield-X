from datetime import datetime, timedelta

from src.governance.access_governance import AccessManager, AccessEvent


class DummyUser:
    def __init__(self, name: str, permissions=None):
        self.name = name
        self.permissions = permissions or {}


def test_define_policy_and_enforce_least_privilege():
    m = AccessManager()
    m.define_access_policy("db", ["alice"], ["read", "write", "admin"])  # admin should be kept if assigned
    alice = DummyUser("alice", permissions={"db": ["read", "write", "admin", "danger"]})
    m.enforce_least_privilege(alice)
    assert "db" in alice.permissions
    assert set(alice.permissions["db"]) == set(["read", "write", "admin"]) or set(alice.permissions["db"]) == set(["read", "write"])


def test_periodic_access_review_detects_issues():
    m = AccessManager()
    m.define_access_policy("payments", ["bob"], ["create_payments", "approve_payments"])  # conflicting pair
    report = m.periodic_access_review(timedelta(days=30))
    assert report.policies_count == 1
    assert report.issues, "Expected separation-of-duties issue"


def test_detect_access_anomalies():
    m = AccessManager()
    user = DummyUser("eve")
    # create 6 rapid events within a minute
    now = datetime.utcnow()
    events = [AccessEvent(user="eve", resource="db", permission="read", timestamp=now) for _ in range(6)]
    anomalies = m.detect_access_anomalies(user, events)
    assert any(a.reason.startswith("burst") for a in anomalies)


def test_revoke_access_on_termination():
    m = AccessManager()
    m.define_access_policy("service", ["carol", "dave"], ["read"]) 
    carol = DummyUser("carol")
    m.revoke_access_on_termination(carol)
    policy = m.policies.get("service")
    assert "carol" not in policy.principals
