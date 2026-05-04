from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any

from src.audit.audit_framework import AuditFramework, AuditEntry


@dataclass
class TimelineEvent:
    id: str
    timestamp: datetime
    actor: str
    resource: Optional[str]
    operation: str
    details: Dict[str, Any]


@dataclass
class Timeline:
    incident_id: str
    events: List[TimelineEvent]


@dataclass
class RootCauseAnalysis:
    incident_id: str
    probable_root_cause: Optional[TimelineEvent]
    rationale: str


@dataclass
class ForensicReport:
    incident_id: str
    timeline: Timeline
    root_cause: RootCauseAnalysis
    chain_of_custody: List[Dict[str, Any]]


class ForensicAnalyzer:
    """Forensic analysis tools using the in-memory `AuditFramework` as source of truth.

    This is a research-grade, testable implementation. For production, connect
    to durable audit storage and evidence stores, and sign chain-of-custody
    records with KMS/HSM-backed keys.
    """

    def __init__(self, audit: AuditFramework):
        self.audit = audit

    def reconstruct_event_timeline(self, incident_id: str) -> Timeline:
        # Find audit entries that reference this incident id in details
        entries = [e for e in self.audit.query_audit_trail() if e.details.get("incident_id") == incident_id]
        # sort chronologically
        entries.sort(key=lambda e: e.timestamp)
        events = [TimelineEvent(id=e.id, timestamp=e.timestamp, actor=e.actor, resource=e.resource, operation=e.operation, details=e.details) for e in entries]
        return Timeline(incident_id=incident_id, events=events)

    def identify_root_cause(self, incident_id: str) -> RootCauseAnalysis:
        timeline = self.reconstruct_event_timeline(incident_id)
        if not timeline.events:
            return RootCauseAnalysis(incident_id=incident_id, probable_root_cause=None, rationale="no events found")
        # Prefer events explicitly marked as initial_compromise in details
        for ev in timeline.events:
            if ev.details.get("initial_compromise"):
                return RootCauseAnalysis(incident_id=incident_id, probable_root_cause=ev, rationale="marked as initial_compromise")
        # Fallback: earliest event
        return RootCauseAnalysis(incident_id=incident_id, probable_root_cause=timeline.events[0], rationale="earliest event in timeline")

    def find_related_events(self, event_id: str, correlation_window: timedelta) -> List[TimelineEvent]:
        # locate the event
        base = next((e for e in self.audit.query_audit_trail() if e.id == event_id), None)
        if not base:
            return []
        start = base.timestamp - correlation_window
        end = base.timestamp + correlation_window
        entries = [e for e in self.audit.query_audit_trail() if start <= e.timestamp <= end and (e.resource == base.resource or e.actor == base.actor or e.details.get("incident_id") == base.details.get("incident_id"))]
        entries.sort(key=lambda e: e.timestamp)
        return [TimelineEvent(id=e.id, timestamp=e.timestamp, actor=e.actor, resource=e.resource, operation=e.operation, details=e.details) for e in entries]

    def generate_forensic_report(self, incident_id: str) -> ForensicReport:
        timeline = self.reconstruct_event_timeline(incident_id)
        root = self.identify_root_cause(incident_id)
        # chain of custody: list of evidence items (id, hash, timestamp, handler)
        chain = []
        for e in timeline.events:
            chain.append({
                "id": e.id,
                "timestamp": e.timestamp.isoformat(),
                "actor": e.actor,
                "resource": e.resource,
                "hash": self._entry_hash(e.id),
                "handled_by": e.details.get("handled_by"),
            })
        return ForensicReport(incident_id=incident_id, timeline=timeline, root_cause=root, chain_of_custody=chain)

    def _entry_hash(self, entry_id: str) -> Optional[str]:
        e = next((x for x in self.audit.query_audit_trail() if x.id == entry_id), None)
        if not e:
            return None
        return e.hash


__all__ = ["ForensicAnalyzer", "Timeline", "TimelineEvent", "ForensicReport", "RootCauseAnalysis"]
