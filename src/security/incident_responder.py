from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import List, Dict, Any
import uuid


@dataclass
class Incident:
    id: str
    incident_type: str
    description: str
    severity: str
    detected_at: datetime
    indicators: Dict[str, Any] = None


@dataclass
class PlaybookExecution:
    playbook_name: str
    steps: List[Dict[str, Any]]
    status: str
    started_at: datetime
    finished_at: datetime | None = None


class IncidentResponder:
    """Automated incident response manager (simulation).

    This implementation is intentionally self-contained and simulates actions such
    as isolation and key rotation. In production these should call real orchestration
    systems (cloud APIs, IAM, KMS, etc.).
    """

    def __init__(self):
        self.quarantined_resources: List[str] = []
        self.rotated_keys: Dict[str, str] = {}  # indicator -> new_key_id
        self.notifications: List[Dict[str, Any]] = []
        self.executed_playbooks: List[PlaybookExecution] = []

    def isolate_compromised_resource(self, resource_id: str) -> None:
        if resource_id not in self.quarantined_resources:
            # simulate revoking access and quarantining
            self.quarantined_resources.append(resource_id)

    def rotate_potentially_compromised_keys(self, threat_indicator: str, candidates: List[str] | None = None) -> List[str]:
        # Simulate rotating keys: for each candidate key id return a new UUID
        if not candidates:
            candidates = [f"key-{i}" for i in range(1, 4)]
        new_keys = []
        for k in candidates:
            new_id = str(uuid.uuid4())
            self.rotated_keys[k] = new_id
            new_keys.append(new_id)
        return new_keys

    def notify_security_team(self, incident: Incident, channels: List[str] | None = None) -> None:
        channels = channels or ["email"]
        note = {
            "incident_id": incident.id,
            "type": incident.incident_type,
            "severity": incident.severity,
            "channels": channels,
            "sent_at": datetime.utcnow(),
        }
        self.notifications.append(note)

    def trigger_incident_playbook(self, incident_type: str) -> PlaybookExecution:
        # Simulate selecting and executing a playbook based on type
        now = datetime.utcnow()
        steps = [
            {"name": "collect_evidence", "status": "completed"},
            {"name": "isolate_resource", "status": "completed"},
            {"name": "rotate_keys", "status": "in_progress"},
        ]
        exec_rec = PlaybookExecution(playbook_name=f"playbook:{incident_type}", steps=steps, status="running", started_at=now)
        self.executed_playbooks.append(exec_rec)
        return exec_rec

    def classify_incident_severity(self, impact: int, likelihood: int) -> str:
        """Classify severity using a simple NIST-inspired matrix.

        impact and likelihood are integers from 1 (low) to 5 (critical).
        Return severity: low, medium, high, critical.
        """
        score = impact * likelihood
        if score >= 16:
            return "critical"
        if score >= 9:
            return "high"
        if score >= 4:
            return "medium"
        return "low"


__all__ = ["IncidentResponder", "Incident", "PlaybookExecution"]
