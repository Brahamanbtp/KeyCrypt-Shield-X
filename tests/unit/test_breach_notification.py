import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.governance.breach_notification import BreachNotificationFramework
from src.governance.incident_response import Incident


def build_incident() -> Incident:
    return Incident(
        id="INC-BC-1",
        incident_type="data breach",
        description="Sensitive records were exfiltrated",
        severity="high",
        detected_at=datetime.utcnow() - timedelta(hours=1),
        indicators={
            "affected_count": 120,
            "personal_data": True,
            "affected_states": ["CA", "NY"],
            "individual_recipients": ["person1@example.com", "person2@example.com"],
        },
    )


def test_assess_and_generate_notifications():
    framework = BreachNotificationFramework()
    incident = build_incident()

    requirement = framework.assess_breach_notification_requirements(incident)
    assert requirement.required is True
    assert "GDPR" in requirement.frameworks
    assert requirement.deadline is not None

    notification = framework.generate_breach_notification(incident, ["dpa@regulator.example"])
    assert notification.incident_id == incident.id
    assert "Breach notification" in notification.subject


def test_notify_regulators_and_individuals_and_timeline():
    framework = BreachNotificationFramework()
    incident = build_incident()

    regulator_result = framework.notify_regulators(incident)
    individual_result = framework.notify_affected_individuals(incident)
    timeline = framework.track_notification_timeline(incident.id)

    assert regulator_result.status == "sent"
    assert individual_result.status == "sent"
    assert timeline.incident_id == incident.id
    assert timeline.entries
    assert "earliest" in timeline.deadlines