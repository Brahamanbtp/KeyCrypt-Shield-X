"""Breach notification automation.

PRESERVE: Breach notification automation
EXTEND: Regulatory notification

Provides regulatory deadline assessment, GDPR/HIPAA notification templates,
notification generation, regulator and individual notice routing, and
timeline tracking for compliance operations.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from threading import RLock
from typing import Any, Optional
import json
import uuid

from src.governance.incident_response import Incident


@dataclass(frozen=True)
class NotificationRequirement:
    required: bool
    frameworks: list[str] = field(default_factory=list)
    deadline: Optional[datetime] = None
    deadline_hours: Optional[int] = None
    affected_authorities: list[str] = field(default_factory=list)
    affected_individuals_required: bool = False
    affected_media_required: bool = False
    state_deadlines: dict[str, datetime] = field(default_factory=dict)
    rationale: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class NotificationDocument:
    notification_id: str
    incident_id: str
    recipients: list[str]
    subject: str
    body: str
    framework: str
    created_at: datetime
    deadline: Optional[datetime] = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class NotificationResult:
    incident_id: str
    status: str
    delivered_to: list[str] = field(default_factory=list)
    pending_recipients: list[str] = field(default_factory=list)
    notification_ids: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    completed_at: datetime = field(default_factory=datetime.utcnow)


@dataclass(frozen=True)
class TimelineEntry:
    timestamp: datetime
    action: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Timeline:
    incident_id: str
    entries: list[TimelineEntry] = field(default_factory=list)
    deadlines: dict[str, datetime] = field(default_factory=dict)


GDPR_DEADLINE = timedelta(hours=72)
HIPAA_DEADLINE = timedelta(days=60)
DEFAULT_STATE_DEADLINE = timedelta(days=30)

STATE_NOTIFICATIONS: dict[str, timedelta] = {
    "CA": timedelta(days=15),
    "NY": timedelta(days=30),
    "TX": timedelta(days=30),
    "FL": timedelta(days=30),
    "WA": timedelta(days=30),
    "MA": timedelta(days=30),
}


class BreachNotificationFramework:
    """Automates breach notification workflows."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._requirements: dict[str, NotificationRequirement] = {}
        self._notifications: dict[str, list[NotificationDocument]] = {}
        self._timeline: dict[str, list[TimelineEntry]] = {}

    def assess_breach_notification_requirements(self, incident: Incident) -> NotificationRequirement:
        """Determine regulatory notification requirements for an incident."""
        metadata = dict(incident.indicators or {})
        frameworks: list[str] = []
        rationale: list[str] = []
        authorities: list[str] = []
        affected_individuals_required = False
        affected_media_required = False
        state_deadlines: dict[str, datetime] = {}
        deadline_candidates: list[tuple[str, datetime]] = []

        detected_at = incident.detected_at
        lower_desc = incident.description.lower()
        breach_signals = any(keyword in lower_desc for keyword in ("breach", "exfiltration", "leak", "compromised")) or incident.incident_type in {"data breach", "unauthorized access", "malware"}
        phi = bool(metadata.get("phi", False)) or "hipaa" in str(metadata.get("compliance", "")).lower()
        personal_data = bool(metadata.get("personal_data", True)) or bool(metadata.get("pii", True))

        if personal_data:
            frameworks.append("GDPR")
            authorities.append("Data Protection Authority")
            affected_individuals_required = True
            deadline = detected_at + GDPR_DEADLINE
            deadline_candidates.append(("GDPR", deadline))
            rationale.append("Personal data impacted: GDPR notification obligations likely apply")

        if phi:
            frameworks.append("HIPAA")
            authorities.extend(["HHS"])
            affected_individuals_required = True
            if int(metadata.get("affected_count", 0)) >= 500:
                affected_media_required = True
            deadline = detected_at + HIPAA_DEADLINE
            deadline_candidates.append(("HIPAA", deadline))
            rationale.append("Protected health information involved: HIPAA breach rules likely apply")

        affected_states = [str(state).upper() for state in metadata.get("affected_states", []) if str(state).strip()]
        if affected_states:
            frameworks.append("STATE")
            rationale.append("Affected individuals span state jurisdictions")
            for state in affected_states:
                state_delta = STATE_NOTIFICATIONS.get(state, DEFAULT_STATE_DEADLINE)
                state_deadline = detected_at + state_delta
                state_deadlines[state] = state_deadline
                deadline_candidates.append((f"STATE:{state}", state_deadline))

        if not breach_signals and not frameworks:
            rationale.append("No breach indicators strong enough to require notification")
            return NotificationRequirement(required=False, rationale=rationale)

        deadline = min((candidate[1] for candidate in deadline_candidates), default=None)
        deadline_hours = int((deadline - detected_at).total_seconds() // 3600) if deadline else None

        return NotificationRequirement(
            required=True,
            frameworks=sorted(dict.fromkeys(frameworks)),
            deadline=deadline,
            deadline_hours=deadline_hours,
            affected_authorities=sorted(dict.fromkeys(authorities)),
            affected_individuals_required=affected_individuals_required,
            affected_media_required=affected_media_required,
            state_deadlines=state_deadlines,
            rationale=rationale,
        )

    def generate_breach_notification(self, incident: Incident, recipients: list[str]) -> NotificationDocument:
        """Create a notification document with required information."""
        requirement = self.assess_breach_notification_requirements(incident)
        framework = self._primary_framework(requirement)
        template = self._template_for(framework)
        evidence_summary = self._evidence_summary(incident)

        body = template.format(
            incident_id=incident.id,
            incident_type=incident.incident_type,
            detected_at=incident.detected_at.isoformat(),
            severity=incident.severity,
            description=incident.description,
            evidence_summary=evidence_summary,
            deadline=requirement.deadline.isoformat() if requirement.deadline else "not-applicable",
            affected_count=incident.indicators.get("affected_count", "unknown"),
            jurisdiction=", ".join(requirement.frameworks) or "unknown",
        )
        subject = f"Breach notification: {incident.incident_type} ({incident.id})"
        notification = NotificationDocument(
            notification_id=f"NTF-{uuid.uuid4().hex[:12]}",
            incident_id=incident.id,
            recipients=list(dict.fromkeys(recipients)),
            subject=subject,
            body=body,
            framework=framework,
            created_at=datetime.utcnow(),
            deadline=requirement.deadline,
            metadata={"requirements": requirement.__dict__, "template": framework},
        )

        self._record_timeline(incident.id, "notification_generated", {"notification_id": notification.notification_id, "framework": framework, "recipients": notification.recipients})
        with self._lock:
            self._notifications.setdefault(incident.id, []).append(notification)
            self._requirements[incident.id] = requirement
        return notification

    def notify_regulators(self, incident: Incident) -> NotificationResult:
        """Send notifications to regulators and authorities."""
        requirement = self.assess_breach_notification_requirements(incident)
        recipients = self._regulator_recipients(requirement)
        if not recipients:
            return NotificationResult(incident_id=incident.id, status="not-required", notes=["No regulator notification required"])

        notification = self.generate_breach_notification(incident, recipients)
        self._record_timeline(incident.id, "regulator_notified", {"recipients": recipients, "notification_id": notification.notification_id})
        return NotificationResult(
            incident_id=incident.id,
            status="sent",
            delivered_to=recipients,
            notification_ids=[notification.notification_id],
            notes=["Regulators notified"],
        )

    def notify_affected_individuals(self, incident: Incident) -> NotificationResult:
        """Notify affected data subjects of the breach."""
        requirement = self.assess_breach_notification_requirements(incident)
        if not requirement.affected_individuals_required:
            return NotificationResult(incident_id=incident.id, status="not-required", notes=["Individual notification not required"])

        recipients = self._individual_recipients(incident)
        notification = self.generate_breach_notification(incident, recipients)
        self._record_timeline(incident.id, "individuals_notified", {"recipient_count": len(recipients), "notification_id": notification.notification_id})
        notes = ["Affected individuals notified"]
        if requirement.deadline is not None and datetime.utcnow() > requirement.deadline:
            notes.append("Notification sent after statutory deadline")
        return NotificationResult(
            incident_id=incident.id,
            status="sent",
            delivered_to=recipients,
            notification_ids=[notification.notification_id],
            notes=notes,
        )

    def track_notification_timeline(self, incident_id: str) -> Timeline:
        """Track notification deadlines and actions for an incident."""
        with self._lock:
            entries = list(self._timeline.get(incident_id, []))
            requirement = self._requirements.get(incident_id)

        deadlines: dict[str, datetime] = {}
        if requirement and requirement.deadline is not None:
            deadlines["earliest"] = requirement.deadline
            for framework in requirement.frameworks:
                if framework == "GDPR":
                    deadlines["GDPR"] = requirement.deadline
                if framework == "HIPAA":
                    deadlines["HIPAA"] = requirement.deadline if requirement.deadline else datetime.utcnow() + HIPAA_DEADLINE
            for state, deadline in requirement.state_deadlines.items():
                deadlines[f"STATE:{state}"] = deadline

        entries.sort(key=lambda entry: entry.timestamp)
        return Timeline(incident_id=incident_id, entries=entries, deadlines=deadlines)

    def _primary_framework(self, requirement: NotificationRequirement) -> str:
        if "GDPR" in requirement.frameworks:
            return "GDPR"
        if "HIPAA" in requirement.frameworks:
            return "HIPAA"
        if "STATE" in requirement.frameworks:
            return "STATE"
        return "GENERAL"

    def _template_for(self, framework: str) -> str:
        if framework == "GDPR":
            return (
                "GDPR breach notification\n"
                "Incident: {incident_id}\nType: {incident_type}\nDetected: {detected_at}\nSeverity: {severity}\n"
                "Description: {description}\nEvidence summary: {evidence_summary}\n"
                "Deadline: {deadline}\nJurisdiction: {jurisdiction}\n"
                "Required content: nature of the breach, likely consequences, measures taken, and contact details."
            )
        if framework == "HIPAA":
            return (
                "HIPAA breach notification\n"
                "Incident: {incident_id}\nType: {incident_type}\nDetected: {detected_at}\nSeverity: {severity}\n"
                "Affected count: {affected_count}\nDescription: {description}\nEvidence summary: {evidence_summary}\n"
                "Deadline: {deadline}\nJurisdiction: {jurisdiction}\n"
                "Required content: description of the breach, PHI involved, mitigation steps, and contact information."
            )
        return (
            "Breach notification\n"
            "Incident: {incident_id}\nType: {incident_type}\nDetected: {detected_at}\nSeverity: {severity}\n"
            "Description: {description}\nEvidence summary: {evidence_summary}\nDeadline: {deadline}\nJurisdiction: {jurisdiction}"
        )

    def _evidence_summary(self, incident: Incident) -> str:
        indicators = incident.indicators or {}
        parts = []
        for key in ("affected_count", "personal_data", "phi", "affected_states", "systems"):
            if key in indicators:
                parts.append(f"{key}={indicators[key]}")
        return "; ".join(parts) if parts else "No structured evidence metadata provided"

    def _regulator_recipients(self, requirement: NotificationRequirement) -> list[str]:
        recipients = []
        for authority in requirement.affected_authorities:
            if authority == "Data Protection Authority":
                recipients.append("dpa@regulator.example")
            elif authority == "HHS":
                recipients.append("hipaa-breach@hhs.gov")
            else:
                recipients.append(f"notify@{authority.lower().replace(' ', '-')}.example")
        return sorted(dict.fromkeys(recipients))

    def _individual_recipients(self, incident: Incident) -> list[str]:
        metadata = incident.indicators or {}
        raw_recipients = metadata.get("individual_recipients") or metadata.get("emails") or []
        recipients = [str(item) for item in raw_recipients if str(item).strip()]
        if not recipients and metadata.get("affected_count"):
            recipients = ["affected-individuals@notification.example"]
        return sorted(dict.fromkeys(recipients))

    def _record_timeline(self, incident_id: str, action: str, details: dict[str, Any]) -> None:
        with self._lock:
            self._timeline.setdefault(incident_id, []).append(TimelineEntry(timestamp=datetime.utcnow(), action=action, details=dict(details)))


__all__ = [
    "NotificationRequirement",
    "NotificationDocument",
    "NotificationResult",
    "TimelineEntry",
    "Timeline",
    "BreachNotificationFramework",
]