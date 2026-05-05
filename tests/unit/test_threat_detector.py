from datetime import datetime, timedelta

from src.security.threat_detector import ThreatDetector, AuthEvent, TransferEvent, AccessEvent, UserBehavior, ThreatAlert


class DummyDetector:
    def __init__(self, risk=0.95, anomaly=True):
        self._risk = risk
        self._anomaly = anomaly

    def score_realtime(self, features):
        return {"risk_score": self._risk, "is_anomaly": self._anomaly}


def test_detect_brute_force():
    now = datetime.utcnow()
    events = [AuthEvent(user="u1", timestamp=now - timedelta(seconds=10 * i), success=False) for i in range(7)]
    td = ThreatDetector()
    alert = td.detect_brute_force_attack(events, window=timedelta(minutes=5))
    assert alert is not None
    assert alert.severity in ("medium", "high", "critical")


def test_detect_data_exfiltration():
    now = datetime.utcnow()
    # generate a large transfer to exceed baseline*2 threshold
    transfers = [TransferEvent(user="u", timestamp=now - timedelta(minutes=10), bytes_transferred=25 * 1024 * 1024)]
    td = ThreatDetector()
    alert = td.detect_data_exfiltration(transfers, window=timedelta(hours=1), baseline_bytes=10 * 1024 * 1024)
    assert alert is not None
    assert alert.severity in ("medium", "high", "critical")


def test_detect_privilege_escalation():
    ev = AccessEvent(user="bob", timestamp=datetime.utcnow(), action="grant_role", details={"granted": "admin"})
    td = ThreatDetector()
    alert = td.detect_privilege_escalation([ev])
    assert alert is not None
    assert alert.name == "privilege_escalation"


def test_detect_insider_threat_with_detector():
    dummy = DummyDetector(risk=0.8, anomaly=True)
    td = ThreatDetector(detector=dummy)
    ub = UserBehavior(user="alice", features=None)
    alert = td.detect_insider_threat(ub)
    assert alert is not None
    assert alert.severity in ("medium", "high", "critical")


def test_aggregate_alerts():
    a1 = ThreatAlert(name="a", severity="low", score=0.2, details={})
    a2 = ThreatAlert(name="b", severity="high", score=0.9, details={})
    td = ThreatDetector()
    agg = td.aggregate_alerts([a1, a2])
    assert agg is not None
    assert agg.severity == "high"
