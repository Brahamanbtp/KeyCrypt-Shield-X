from datetime import datetime

from src.security.incident_responder import IncidentResponder, Incident


def test_isolate_and_rotate_and_notify_and_playbook_and_classify():
    ir = IncidentResponder()
    ir.isolate_compromised_resource("res-1")
    assert "res-1" in ir.quarantined_resources

    new_keys = ir.rotate_potentially_compromised_keys("indicator-1", candidates=["k1", "k2"])
    assert len(new_keys) == 2
    assert all(k in ir.rotated_keys.values() for k in new_keys)

    inc = Incident(id="INC-1", incident_type="malware", description="test", severity="high", detected_at=datetime.utcnow())
    ir.notify_security_team(inc, channels=["email", "slack"])
    assert any(n["incident_id"] == "INC-1" for n in ir.notifications)

    exec_rec = ir.trigger_incident_playbook("malware")
    assert exec_rec.playbook_name.startswith("playbook:")

    sev = ir.classify_incident_severity(impact=4, likelihood=4)
    assert sev in ("low", "medium", "high", "critical")
