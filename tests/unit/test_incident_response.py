import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.governance.incident_response import IncidentResponseFramework, SecurityEvent


def build_events() -> list[SecurityEvent]:
    now = datetime.utcnow()
    return [
        SecurityEvent(event_id="e1", event_type="failed_login", source="auth", timestamp=now - timedelta(minutes=4), actor="alice", target="vpn", severity="medium"),
        SecurityEvent(event_id="e2", event_type="failed_login", source="auth", timestamp=now - timedelta(minutes=3), actor="alice", target="vpn", severity="medium"),
        SecurityEvent(event_id="e3", event_type="privilege_escalation", source="iam", timestamp=now - timedelta(minutes=2), actor="alice", target="admin", severity="high", metadata={"credential_id": "cred-1"}),
        SecurityEvent(event_id="e4", event_type="data_export", source="db", timestamp=now - timedelta(minutes=1), actor="alice", target="warehouse", severity="high"),
    ]


def test_detect_and_classify_incident():
    framework = IncidentResponseFramework()
    incident = framework.detect_security_incident(build_events())

    assert incident is not None
    classification = framework.classify_incident(incident)
    assert classification.label in {"data breach", "unauthorized access", "malware", "dos", "security incident"}
    assert incident.timeline


def test_response_flow_tracks_timeline_and_actions():
    framework = IncidentResponseFramework()
    incident = framework.detect_security_incident(build_events())
    assert incident is not None

    plan = framework.initiate_response(incident)
    containment = framework.contain_incident(incident)
    eradication = framework.eradicate_threat(incident)
    recovery = framework.recover_from_incident(incident)

    assert plan.playbook_name
    assert containment.status == "contained"
    assert eradication.status == "eradicated"
    assert recovery.status == "recovered"
    assert len(framework.get_incident_timeline(incident.id)) >= 4


def test_dos_playbook_has_traffic_controls():
    framework = IncidentResponseFramework()
    now = datetime.utcnow()
    incident = framework.detect_security_incident(
        [
            SecurityEvent(event_id="d1", event_type="traffic_spike", source="edge", timestamp=now - timedelta(minutes=1), target="api", severity="high"),
            SecurityEvent(event_id="d2", event_type="rate_limit_exceeded", source="edge", timestamp=now, target="api", severity="high"),
        ]
    )
    assert incident is not None
    plan = framework.initiate_response(incident)
    assert any(step.name == "enable_rate_limiting" for step in plan.steps)