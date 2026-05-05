from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import List, Optional, Any

try:
    from src.ai.anomaly_detection import AnomalyDetector
except Exception:  # pragma: no cover - optional dependency in tests
    AnomalyDetector = None  # type: ignore


@dataclass
class AuthEvent:
    user: str
    timestamp: datetime
    success: bool
    source_ip: Optional[str] = None


@dataclass
class TransferEvent:
    user: str
    timestamp: datetime
    bytes_transferred: int
    resource: Optional[str] = None


@dataclass
class AccessEvent:
    user: str
    timestamp: datetime
    action: str
    resource: Optional[str] = None
    details: dict = None


@dataclass
class UserBehavior:
    user: str
    features: Any  # feature vector suitable for AnomalyDetector.score_realtime


@dataclass
class ThreatAlert:
    name: str
    severity: str  # low, medium, high, critical
    score: float
    details: dict


class ThreatDetector:
    """Real-time threat detection utilities.

    Where possible this class accepts an `AnomalyDetector` instance for ML-based
    scoring. For unit tests a lightweight stub can be provided.
    """

    def __init__(self, detector: Optional[AnomalyDetector] = None):
        self.detector = detector

    def detect_brute_force_attack(self, auth_events: List[AuthEvent], window: timedelta = timedelta(minutes=5)) -> Optional[ThreatAlert]:
        if not auth_events:
            return None
        # Group by user and look for many failures in window
        now = max(e.timestamp for e in auth_events)
        failures_by_user = {}
        for e in auth_events:
            if not e.success and now - e.timestamp <= window:
                failures_by_user.setdefault(e.user, 0)
                failures_by_user[e.user] += 1
        for user, failures in failures_by_user.items():
            if failures >= 20:
                return ThreatAlert(name="brute_force", severity="critical", score=min(1.0, failures / 100.0), details={"user": user, "failures": failures})
            if failures >= 10:
                return ThreatAlert(name="brute_force", severity="high", score=min(1.0, failures / 100.0), details={"user": user, "failures": failures})
            if failures >= 5:
                return ThreatAlert(name="brute_force", severity="medium", score=min(1.0, failures / 100.0), details={"user": user, "failures": failures})
        return None

    def detect_data_exfiltration(self, transfer_events: List[TransferEvent], window: timedelta = timedelta(minutes=60), baseline_bytes: int = 10 * 1024 * 1024) -> Optional[ThreatAlert]:
        if not transfer_events:
            return None
        now = max(e.timestamp for e in transfer_events)
        total = sum(e.bytes_transferred for e in transfer_events if now - e.timestamp <= window)
        # severity by multiplier over baseline
        if total >= baseline_bytes * 10:
            severity = "critical"
        elif total >= baseline_bytes * 5:
            severity = "high"
        elif total >= baseline_bytes * 2:
            severity = "medium"
        else:
            return None
        score = min(1.0, total / (baseline_bytes * 10))
        return ThreatAlert(name="data_exfiltration", severity=severity, score=float(score), details={"bytes": total})

    def detect_privilege_escalation(self, access_events: List[AccessEvent]) -> Optional[ThreatAlert]:
        # look for permission change events where the action indicates grant/modify
        for e in access_events:
            if e.action in ("grant_role", "add_permission", "modify_permission"):
                details = e.details or {}
                # simple heuristic: if the granted permission contains 'admin' or 'root'
                granted = details.get("granted")
                if isinstance(granted, str) and ("admin" in granted or "root" in granted):
                    return ThreatAlert(name="privilege_escalation", severity="high", score=0.9, details={"user": e.user, "granted": granted})
        return None

    def detect_insider_threat(self, user_behavior: UserBehavior) -> Optional[ThreatAlert]:
        if not self.detector:
            # without ML detector, fall back to no alert
            return None
        # detector.score_realtime expects a Tensor; tests should provide a stub that returns a dict
        try:
            score = self.detector.score_realtime(user_behavior.features)
        except Exception:
            return None
        # score expected to contain 'risk_score' and 'is_anomaly'
        risk = float(score.get("risk_score", 0.0))
        is_anomaly = bool(score.get("is_anomaly", False))
        if not is_anomaly:
            if risk < 0.5:
                return None
            severity = "low"
        else:
            if risk > 0.9:
                severity = "critical"
            elif risk > 0.7:
                severity = "high"
            else:
                severity = "medium"
        return ThreatAlert(name="insider_threat", severity=severity, score=risk, details={"user": user_behavior.user})

    def aggregate_alerts(self, alerts: List[ThreatAlert]) -> Optional[ThreatAlert]:
        if not alerts:
            return None
        # take max severity
        severity_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        top = max(alerts, key=lambda a: severity_order.get(a.severity, 0))
        # aggregate score
        avg_score = sum(a.score for a in alerts) / len(alerts)
        return ThreatAlert(name="aggregate", severity=top.severity, score=avg_score, details={"count": len(alerts)})
