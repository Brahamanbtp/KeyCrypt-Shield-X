from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any
import hashlib
import json
import csv
import io
import uuid


@dataclass
class TimeRange:
    start: Optional[datetime]
    end: Optional[datetime]


@dataclass
class Operation:
    name: str
    resource: Optional[str]
    actor: str
    outcome: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditEntry:
    id: str
    operation: str
    resource: Optional[str]
    actor: str
    outcome: str
    timestamp: datetime
    details: Dict[str, Any]
    prev_hash: Optional[str]
    hash: str


@dataclass
class AuditFilter:
    actor: Optional[str] = None
    resource: Optional[str] = None
    outcome: Optional[str] = None
    operation_name: Optional[str] = None


class AuditFramework:
    """In-memory audit trail with export and integrity verification.

    This is a compact, testable framework. In production the storage
    backend should be append-only and backed by immutable storage and
    cryptographic signing (HSM / KMS).
    """

    def __init__(self):
        self._entries: List[AuditEntry] = []

    def _compute_hash(self, payload: Dict[str, Any], prev_hash: Optional[str]) -> str:
        m = hashlib.sha256()
        # deterministic serialization
        m.update(json.dumps(payload, sort_keys=True, default=str).encode("utf-8"))
        if prev_hash:
            m.update(prev_hash.encode("utf-8"))
        return m.hexdigest()

    def create_audit_trail(self, operation: Operation) -> AuditEntry:
        prev_hash = self._entries[-1].hash if self._entries else None
        timestamp = datetime.utcnow()
        payload = {
            "id": str(uuid.uuid4()),
            "operation": operation.name,
            "resource": operation.resource,
            "actor": operation.actor,
            "outcome": operation.outcome,
            "timestamp": timestamp.isoformat(),
            "details": operation.details,
        }
        h = self._compute_hash(payload, prev_hash)
        entry = AuditEntry(
            id=payload["id"],
            operation=operation.name,
            resource=operation.resource,
            actor=operation.actor,
            outcome=operation.outcome,
            timestamp=timestamp,
            details=operation.details,
            prev_hash=prev_hash,
            hash=h,
        )
        self._entries.append(entry)
        return entry

    def query_audit_trail(self, filters: Optional[AuditFilter] = None, time_range: Optional[TimeRange] = None) -> List[AuditEntry]:
        res = list(self._entries)
        if time_range:
            if time_range.start:
                res = [e for e in res if e.timestamp >= time_range.start]
            if time_range.end:
                res = [e for e in res if e.timestamp <= time_range.end]
        if filters:
            if filters.actor:
                res = [e for e in res if e.actor == filters.actor]
            if filters.resource:
                res = [e for e in res if e.resource == filters.resource]
            if filters.outcome:
                res = [e for e in res if e.outcome == filters.outcome]
            if filters.operation_name:
                res = [e for e in res if e.operation == filters.operation_name]
        return res

    def search_audit_by_user(self, user_id: str, time_range: Optional[TimeRange] = None) -> List[AuditEntry]:
        f = AuditFilter(actor=user_id)
        return self.query_audit_trail(filters=f, time_range=time_range)

    def search_audit_by_resource(self, resource_id: str) -> List[AuditEntry]:
        f = AuditFilter(resource=resource_id)
        return self.query_audit_trail(filters=f)

    def export_audit_trail(self, format: str = "json", time_range: Optional[TimeRange] = None) -> str:
        entries = self.query_audit_trail(time_range=time_range)
        if format.lower() == "json":
            out = [self._entry_to_dict(e) for e in entries]
            return json.dumps(out, default=str, sort_keys=True)
        if format.lower() == "csv":
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(["id", "timestamp", "actor", "resource", "operation", "outcome", "hash"])
            for e in entries:
                writer.writerow([e.id, e.timestamp.isoformat(), e.actor, e.resource, e.operation, e.outcome, e.hash])
            return buf.getvalue()
        if format.lower() == "syslog":
            lines = []
            for e in entries:
                lines.append(f"{e.timestamp.isoformat()} {e.actor} {e.operation} {e.resource} {e.outcome}")
            return "\n".join(lines)
        if format.lower() == "cef":
            # Minimal CEF-like representation
            lines = []
            for e in entries:
                # header: CEF:Version|DeviceVendor|DeviceProduct|DeviceVersion|SignatureID|Name|Severity|Extension
                ext = f"actor={e.actor} resource={e.resource} outcome={e.outcome} id={e.id} hash={e.hash}"
                lines.append(f"CEF:0|KeyCrypt|Audit|1.0|{e.operation}|{e.operation}|0|{ext}")
            return "\n".join(lines)
        raise ValueError(f"unsupported export format: {format}")

    def _entry_to_dict(self, e: AuditEntry) -> Dict[str, Any]:
        return {
            "id": e.id,
            "operation": e.operation,
            "resource": e.resource,
            "actor": e.actor,
            "outcome": e.outcome,
            "timestamp": e.timestamp.isoformat(),
            "details": e.details,
            "prev_hash": e.prev_hash,
            "hash": e.hash,
        }

    def verify_chain_integrity(self) -> bool:
        prev_hash = None
        for e in self._entries:
            payload = {
                "id": e.id,
                "operation": e.operation,
                "resource": e.resource,
                "actor": e.actor,
                "outcome": e.outcome,
                "timestamp": e.timestamp.isoformat(),
                "details": e.details,
            }
            expected = self._compute_hash(payload, prev_hash)
            if expected != e.hash:
                return False
            if e.prev_hash != prev_hash:
                return False
            prev_hash = e.hash
        return True


__all__ = ["AuditFramework", "Operation", "AuditFilter", "TimeRange", "AuditEntry"]
