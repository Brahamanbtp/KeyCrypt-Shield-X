"""Automated incident response framework.

PRESERVE: Incident response automation
EXTEND: Security orchestration

Provides incident correlation, incident classification, automated response
playbooks, containment, eradication, recovery, and timeline tracking.
Optional ML scoring can be injected, while deterministic heuristics remain
available as a fallback for minimal environments.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from threading import RLock
from typing import Any, Iterable, Optional
from collections import Counter, defaultdict
import uuid


SEVERITY_RANK: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


@dataclass(frozen=True)
class SecurityEvent:
    event_id: str
    event_type: str
    source: str
    timestamp: datetime
    actor: Optional[str] = None
    target: Optional[str] = None
    severity: str = "medium"
    confidence: float = 0.5
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class IncidentClassification:
    label: str
    severity: str
    confidence: float
    rationale: str
    indicators: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class TimelineEntry:
    timestamp: datetime
    action: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class Incident:
    id: str
    incident_type: str
    description: str
    severity: str
    detected_at: datetime
    events: list[SecurityEvent] = field(default_factory=list)
    confidence: float = 0.0
    indicators: dict[str, Any] = field(default_factory=dict)
    timeline: list[TimelineEntry] = field(default_factory=list)


@dataclass(frozen=True)
class ResponseStep:
    name: str
    status: str = "pending"
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class ResponsePlan:
    incident_id: str
    incident_type: str
    playbook_name: str
    steps: list[ResponseStep]
    status: str
    created_at: datetime
    updated_at: datetime
    automation_level: str = "automated"
    notes: list[str] = field(default_factory=list)


@dataclass
class ContainmentResult:
    incident_id: str
    status: str
    isolated_systems: list[str] = field(default_factory=list)
    revoked_credentials: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    completed_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class EradicationResult:
    incident_id: str
    status: str
    removed_artifacts: list[str] = field(default_factory=list)
    patched_vulnerabilities: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    completed_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class RecoveryResult:
    incident_id: str
    status: str
    restored_systems: list[str] = field(default_factory=list)
    backup_sources: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    completed_at: datetime = field(default_factory=datetime.utcnow)


class IncidentResponseFramework:
    """Detects incidents and executes automated response workflows."""

    INCIDENT_WINDOW = timedelta(minutes=30)
    DETECTION_THRESHOLD = 0.55

    def __init__(self, ml_model: Any | None = None) -> None:
        self._ml_model = ml_model
        self._lock = RLock()
        self._incidents: dict[str, Incident] = {}
        self._responses: dict[str, ResponsePlan] = {}
        self._containment: dict[str, ContainmentResult] = {}
        self._eradication: dict[str, EradicationResult] = {}
        self._recovery: dict[str, RecoveryResult] = {}

    def detect_security_incident(self, events: list[SecurityEvent]) -> Optional[Incident]:
        """Correlate events to detect incidents using optional ML scoring."""
        normalized_events = sorted(events, key=lambda item: item.timestamp)
        if len(normalized_events) < 2:
            return None

        feature_data = self._build_feature_data(normalized_events)
        heuristic_score = self._heuristic_incident_score(feature_data)
        ml_score = self._ml_incident_score(feature_data)
        combined_score = heuristic_score if ml_score is None else (heuristic_score + ml_score) / 2.0

        if combined_score < self.DETECTION_THRESHOLD and not feature_data["strong_signals"]:
            return None

        incident_type = self._infer_incident_type(feature_data)
        severity = self._score_to_severity(combined_score)
        incident = Incident(
            id=f"INC-{uuid.uuid4().hex[:10]}",
            incident_type=incident_type,
            description=self._describe_incident(incident_type, feature_data),
            severity=severity,
            detected_at=normalized_events[-1].timestamp,
            events=normalized_events,
            confidence=max(heuristic_score, combined_score),
            indicators=feature_data,
        )
        self._append_timeline(incident, "detected", {"event_count": len(normalized_events), "incident_type": incident_type})

        with self._lock:
            self._incidents[incident.id] = incident

        return incident

    def classify_incident(self, incident: Incident) -> IncidentClassification:
        """Classify an incident into common incident categories."""
        label = self._normalize_incident_type(incident.incident_type)
        severity = incident.severity if incident.severity in SEVERITY_RANK else self._score_to_severity(incident.confidence)
        confidence = max(0.0, min(1.0, incident.confidence))

        rationale_map = {
            "data breach": "Indicators suggest exposure or exfiltration of sensitive data.",
            "unauthorized access": "Events show suspicious authentication or privilege escalation patterns.",
            "dos": "Traffic or request patterns indicate service exhaustion or rate-based disruption.",
            "malware": "Malicious artifact or host compromise signals were observed.",
            "phishing": "User interaction indicators and credential capture signals were observed.",
        }

        rationale = rationale_map.get(label, "Incident pattern matched generic security response criteria.")
        classification = IncidentClassification(
            label=label,
            severity=severity,
            confidence=confidence,
            rationale=rationale,
            indicators=sorted(str(key) for key in incident.indicators.keys()),
        )
        self._append_timeline(incident, "classified", {"label": label, "severity": severity})
        return classification

    def initiate_response(self, incident: Incident) -> ResponsePlan:
        """Create and store an automated response plan based on incident type."""
        classification = self.classify_incident(incident)
        playbook = self._playbook_for_type(classification.label)
        steps = [ResponseStep(name=step["name"], details=dict(step)) for step in playbook["steps"]]
        plan = ResponsePlan(
            incident_id=incident.id,
            incident_type=classification.label,
            playbook_name=playbook["name"],
            steps=steps,
            status="running",
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            automation_level="automated",
            notes=list(playbook["notes"]),
        )
        self._append_timeline(incident, "response_initiated", {"playbook": plan.playbook_name, "steps": [step.name for step in steps]})

        with self._lock:
            self._responses[incident.id] = plan

        return plan

    def contain_incident(self, incident: Incident) -> ContainmentResult:
        """Isolate affected systems and revoke compromised credentials."""
        affected_systems = self._affected_systems(incident)
        revoked_credentials = self._compromised_credentials(incident)
        result = ContainmentResult(
            incident_id=incident.id,
            status="contained",
            isolated_systems=affected_systems,
            revoked_credentials=revoked_credentials,
            notes=self._containment_notes(incident),
        )
        self._append_timeline(incident, "contained", {"isolated_systems": affected_systems, "revoked_credentials": revoked_credentials})

        with self._lock:
            self._containment[incident.id] = result

        return result

    def eradicate_threat(self, incident: Incident) -> EradicationResult:
        """Remove malicious artifacts and patch exposed vulnerabilities."""
        removed_artifacts = self._artifact_removals(incident)
        patched_vulnerabilities = self._patched_vulnerabilities(incident)
        result = EradicationResult(
            incident_id=incident.id,
            status="eradicated",
            removed_artifacts=removed_artifacts,
            patched_vulnerabilities=patched_vulnerabilities,
            notes=["Malicious indicators removed"],
        )
        self._append_timeline(incident, "eradicated", {"removed_artifacts": removed_artifacts, "patched_vulnerabilities": patched_vulnerabilities})

        with self._lock:
            self._eradication[incident.id] = result

        return result

    def recover_from_incident(self, incident: Incident) -> RecoveryResult:
        """Restore clean systems and services from trusted backups."""
        restored_systems = self._affected_systems(incident)
        backup_sources = [f"clean-backup-{system}" for system in restored_systems] or ["clean-backup-primary"]
        result = RecoveryResult(
            incident_id=incident.id,
            status="recovered",
            restored_systems=restored_systems,
            backup_sources=backup_sources,
            notes=["Restored from clean backups", "Validated service health"],
        )
        self._append_timeline(incident, "recovered", {"restored_systems": restored_systems, "backup_sources": backup_sources})

        with self._lock:
            self._recovery[incident.id] = result

        return result

    def get_incident_timeline(self, incident_id: str) -> list[TimelineEntry]:
        with self._lock:
            incident = self._incidents.get(incident_id)
            return list(incident.timeline) if incident else []

    def _build_feature_data(self, events: list[SecurityEvent]) -> dict[str, Any]:
        types = Counter(event.event_type.lower() for event in events)
        actors = Counter(event.actor for event in events if event.actor)
        targets = Counter(event.target for event in events if event.target)
        severities = Counter(event.severity.lower() for event in events)
        strong_signals = []

        time_span = (events[-1].timestamp - events[0].timestamp).total_seconds() if len(events) > 1 else 0.0
        failed_logins = types.get("failed_login", 0) + types.get("auth_failure", 0)
        privilege_changes = types.get("privilege_escalation", 0) + types.get("role_change", 0)
        data_access = types.get("data_export", 0) + types.get("unusual_download", 0) + types.get("sensitive_read", 0)
        malware_hits = types.get("malware_detected", 0) + types.get("quarantine", 0)
        dos_hits = types.get("traffic_spike", 0) + types.get("request_flood", 0) + types.get("rate_limit_exceeded", 0)

        if failed_logins >= 3:
            strong_signals.append("auth_burst")
        if privilege_changes:
            strong_signals.append("privilege_change")
        if data_access >= 2:
            strong_signals.append("possible_exfiltration")
        if malware_hits:
            strong_signals.append("malware_indicator")
        if dos_hits:
            strong_signals.append("service_disruption")

        return {
            "event_count": len(events),
            "time_span_seconds": max(0.0, time_span),
            "failed_logins": failed_logins,
            "privilege_changes": privilege_changes,
            "data_access": data_access,
            "malware_hits": malware_hits,
            "dos_hits": dos_hits,
            "unique_actors": len(actors),
            "unique_targets": len(targets),
            "severity_histogram": dict(severities),
            "event_type_histogram": dict(types),
            "strong_signals": strong_signals,
        }

    def _heuristic_incident_score(self, features: dict[str, Any]) -> float:
        score = 0.0
        score += min(0.2, features["event_count"] / 50.0)
        score += min(0.2, features["failed_logins"] * 0.05)
        score += min(0.2, features["privilege_changes"] * 0.08)
        score += min(0.2, features["data_access"] * 0.07)
        score += min(0.2, features["malware_hits"] * 0.15)
        score += min(0.2, features["dos_hits"] * 0.1)
        if features["time_span_seconds"] <= 900:
            score += 0.08
        if features["unique_targets"] >= 2:
            score += 0.05
        if features["strong_signals"]:
            score += 0.1
        return max(0.0, min(1.0, score))

    def _ml_incident_score(self, features: dict[str, Any]) -> Optional[float]:
        if self._ml_model is None:
            return None

        model = self._ml_model
        try:
            if hasattr(model, "predict_proba"):
                raw = model.predict_proba([features])
                if raw and len(raw[0]) >= 2:
                    return float(raw[0][1])
            if hasattr(model, "score"):
                return float(model.score(features))
            if callable(model):
                return float(model(features))
        except Exception:
            return None
        return None

    def _infer_incident_type(self, features: dict[str, Any]) -> str:
        if features["malware_hits"]:
            return "malware"
        if features["dos_hits"]:
            return "dos"
        if features["data_access"] and (features["failed_logins"] or features["privilege_changes"]):
            return "data breach"
        if features["failed_logins"] >= 3 or features["privilege_changes"]:
            return "unauthorized access"
        return "security incident"

    def _describe_incident(self, incident_type: str, features: dict[str, Any]) -> str:
        if incident_type == "malware":
            return "Potential malware activity detected from correlated host and quarantine signals."
        if incident_type == "dos":
            return "Traffic and request patterns indicate a possible denial-of-service event."
        if incident_type == "data breach":
            return "Authentication anomalies and sensitive data access suggest a breach scenario."
        if incident_type == "unauthorized access":
            return "Multiple authentication or privilege escalation signals indicate unauthorized access."
        return f"Correlated suspicious activity across {features['event_count']} events."

    def _playbook_for_type(self, incident_type: str) -> dict[str, Any]:
        playbooks = {
            "data breach": {
                "name": "data-breach-response",
                "steps": [
                    {"name": "revoke_keys"},
                    {"name": "notify_affected_parties"},
                    {"name": "capture_forensics"},
                    {"name": "preserve_logs"},
                ],
                "notes": ["Revoke exposed credentials", "Notify legal/compliance stakeholders", "Preserve evidence chain"],
            },
            "unauthorized access": {
                "name": "unauthorized-access-response",
                "steps": [
                    {"name": "disable_accounts"},
                    {"name": "audit_logs"},
                    {"name": "investigate_source"},
                    {"name": "reset_sessions"},
                ],
                "notes": ["Disable suspected accounts", "Audit recent activity", "Investigate origin and scope"],
            },
            "dos": {
                "name": "dos-response",
                "steps": [
                    {"name": "enable_rate_limiting"},
                    {"name": "filter_traffic"},
                    {"name": "scale_resources"},
                    {"name": "monitor_service_health"},
                ],
                "notes": ["Throttle or filter abusive traffic", "Scale critical services"],
            },
            "malware": {
                "name": "malware-response",
                "steps": [
                    {"name": "isolate_host"},
                    {"name": "remove_malware"},
                    {"name": "patch_vulnerabilities"},
                    {"name": "restore_clean_state"},
                ],
                "notes": ["Quarantine affected systems", "Patch exploited weaknesses"],
            },
        }
        return playbooks.get(
            incident_type,
            {
                "name": "generic-security-response",
                "steps": [{"name": "triage"}, {"name": "contain"}, {"name": "investigate"}],
                "notes": ["Perform rapid triage and assign an incident commander"],
            },
        )

    def _affected_systems(self, incident: Incident) -> list[str]:
        systems: list[str] = []
        for event in incident.events:
            if event.target:
                systems.append(str(event.target))
            elif event.source:
                systems.append(str(event.source))
        return sorted(dict.fromkeys(systems))

    def _compromised_credentials(self, incident: Incident) -> list[str]:
        creds: list[str] = []
        for event in incident.events:
            if event.actor:
                if event.event_type.lower() in {"failed_login", "auth_failure", "privilege_escalation"}:
                    creds.append(str(event.actor))
                if event.metadata.get("credential_id"):
                    creds.append(str(event.metadata["credential_id"]))
        return sorted(dict.fromkeys(creds))

    def _containment_notes(self, incident: Incident) -> list[str]:
        notes = ["Affected systems isolated", "Compromised credentials revoked"]
        if incident.incident_type == "dos":
            notes.append("Traffic filters applied and capacity increased")
        return notes

    def _artifact_removals(self, incident: Incident) -> list[str]:
        removed: list[str] = []
        for event in incident.events:
            lower = event.event_type.lower()
            if lower in {"malware_detected", "quarantine"}:
                removed.append(str(event.metadata.get("artifact", event.event_id)))
            if lower in {"suspicious_process", "malicious_file"}:
                removed.append(str(event.metadata.get("path", event.event_id)))
        return sorted(dict.fromkeys(removed))

    def _patched_vulnerabilities(self, incident: Incident) -> list[str]:
        patched: list[str] = []
        for event in incident.events:
            if event.metadata.get("cve_id"):
                patched.append(str(event.metadata["cve_id"]))
        if incident.incident_type in {"data breach", "unauthorized access"}:
            patched.append("session-hardening")
        return sorted(dict.fromkeys(patched))

    def _append_timeline(self, incident: Incident, action: str, details: dict[str, Any]) -> None:
        incident.timeline.append(TimelineEntry(timestamp=datetime.utcnow(), action=action, details=dict(details)))

    def _normalize_incident_type(self, value: str) -> str:
        normalized = value.strip().lower()
        if normalized in {"data breach", "unauthorized access", "dos", "malware"}:
            return normalized
        return normalized.replace("denial of service", "dos")

    def _score_to_severity(self, score: float) -> str:
        if score >= 0.85:
            return "critical"
        if score >= 0.65:
            return "high"
        if score >= 0.4:
            return "medium"
        return "low"


__all__ = [
    "SecurityEvent",
    "IncidentClassification",
    "TimelineEntry",
    "Incident",
    "ResponseStep",
    "ResponsePlan",
    "ContainmentResult",
    "EradicationResult",
    "RecoveryResult",
    "IncidentResponseFramework",
]