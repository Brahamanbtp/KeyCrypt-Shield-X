from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
import hmac
import hashlib
import json

from src.audit.audit_framework import AuditFramework, TimeRange


@dataclass
class ComplianceReport:
    quarter: int
    year: int
    total_operations: int
    success_rate: float
    incidents_reported: int
    generated_at: datetime = field(default_factory=datetime.utcnow)
    signed_by: Optional[str] = None
    signature: Optional[str] = None


@dataclass
class SecurityReport:
    year: int
    total_incidents: int
    major_incidents: int
    summary: Dict[str, Any]
    generated_at: datetime = field(default_factory=datetime.utcnow)
    signed_by: Optional[str] = None
    signature: Optional[str] = None


@dataclass
class BreachReport:
    incident_id: str
    entries: List[Dict[str, Any]]
    recommended_notifications: List[str]
    generated_at: datetime = field(default_factory=datetime.utcnow)
    signed_by: Optional[str] = None
    signature: Optional[str] = None


@dataclass
class EvidencePackage:
    audit_id: str
    exported: str
    signature: Optional[str] = None


class ComplianceReporter:
    """Automated compliance reporting using the `AuditFramework` as the event source.

    Reports are signed using HMAC-SHA256 with a provided key to provide simple
    non-repudiation for tests and local usage. For production use a KMS/HSM-backed
    asymmetric signature should be used instead.
    """

    def __init__(self, audit: AuditFramework, signing_key: bytes = b"test-key"):
        self.audit = audit
        self.signing_key = signing_key

    def _sign(self, payload: str) -> str:
        mac = hmac.new(self.signing_key, payload.encode("utf-8"), digestmod=hashlib.sha256)
        return mac.hexdigest()

    def _serialize(self, obj: Any) -> str:
        return json.dumps(obj, default=str, sort_keys=True)

    def generate_quarterly_compliance_report(self, quarter: int, year: int, signer: Optional[str] = "compliance-service") -> ComplianceReport:
        # compute quarter range
        q_start_month = (quarter - 1) * 3 + 1
        start = datetime(year, q_start_month, 1)
        if q_start_month + 3 > 12:
            end = datetime(year + 1, 1, 1) - timedelta(seconds=1)
        else:
            end = datetime(year, q_start_month + 3, 1) - timedelta(seconds=1)
        tr = TimeRange(start=start, end=end)
        entries = self.audit.query_audit_trail(time_range=tr)
        total = len(entries)
        successes = sum(1 for e in entries if e.outcome == "success")
        incidents = len({e.details.get("incident_id") for e in entries if e.details.get("incident_id")})
        success_rate = (successes / total) if total else 0.0
        report = ComplianceReport(quarter=quarter, year=year, total_operations=total, success_rate=success_rate, incidents_reported=incidents)
        payload = self._serialize(report.__dict__)
        sig = self._sign(payload)
        report.signed_by = signer
        report.signature = sig
        return report

    def generate_annual_security_report(self, year: int, signer: Optional[str] = "security-service") -> SecurityReport:
        start = datetime(year, 1, 1)
        end = datetime(year + 1, 1, 1) - timedelta(seconds=1)
        entries = self.audit.query_audit_trail(time_range=TimeRange(start=start, end=end))
        incidents = [e for e in entries if e.details.get("incident_id")]
        major = [e for e in incidents if e.details.get("severity") == "high"]
        summary = {
            "total_events": len(entries),
            "total_incidents": len(incidents),
            "major_incidents": len(major),
        }
        report = SecurityReport(year=year, total_incidents=len(incidents), major_incidents=len(major), summary=summary)
        payload = self._serialize(report.__dict__)
        report.signature = self._sign(payload)
        report.signed_by = signer
        return report

    def generate_breach_notification_report(self, incident_id: str, signer: Optional[str] = "compliance-service") -> BreachReport:
        entries = [self._entry_to_dict(e) for e in self.audit.query_audit_trail() if e.details.get("incident_id") == incident_id]
        # basic GDPR/HIPAA decision logic
        notifications = []
        # GDPR: notify if personal data involved -> assume details.personal_data == True
        if any(e.get("details", {}).get("personal_data") for e in entries):
            notifications.append("GDPR")
        # HIPAA: notify if hipaa_scope true
        if any(e.get("details", {}).get("hipaa_scope") for e in entries):
            notifications.append("HIPAA")
        rep = BreachReport(incident_id=incident_id, entries=entries, recommended_notifications=notifications)
        payload = self._serialize(rep.__dict__)
        rep.signature = self._sign(payload)
        rep.signed_by = signer
        return rep

    def generate_auditor_evidence_package(self, audit_id: str, signer: Optional[str] = "evidence-service") -> EvidencePackage:
        # collect entries that have audit_id in details or match id
        entries = [e for e in self.audit.query_audit_trail() if e.details.get("audit_id") == audit_id or e.id == audit_id]
        exported = self.audit.export_audit_trail(format="json") if not entries else json.dumps([self._entry_to_dict(e) for e in entries], default=str)
        sig = self._sign(exported)
        return EvidencePackage(audit_id=audit_id, exported=exported, signature=sig)

    def verify_report_signature(self, serialized_payload: str, signature: str) -> bool:
        return hmac.compare_digest(self._sign(serialized_payload), signature)

    def _entry_to_dict(self, e) -> Dict[str, Any]:
        return {
            "id": e.id,
            "operation": e.operation,
            "resource": e.resource,
            "actor": e.actor,
            "outcome": e.outcome,
            "timestamp": e.timestamp.isoformat(),
            "details": e.details,
            "hash": e.hash,
        }


__all__ = ["ComplianceReporter", "ComplianceReport", "SecurityReport", "BreachReport", "EvidencePackage"]
