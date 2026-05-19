"""Data retention policy enforcement helpers.

PRESERVE: Retention governance
EXTEND: Data lifecycle management

Provides retention policy definition, enforcement, legal hold management,
audit reporting, and a lightweight scheduled deletion worker.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
import logging
import threading
import time
from typing import Dict, List, Optional

LOG = logging.getLogger(__name__)

DEFAULT_RETENTION_PERIODS: Dict[str, Optional[timedelta]] = {
    "audit_logs": timedelta(days=365 * 7),
    "encryption_metadata": None,
    "temporary_data": timedelta(days=30),
    "backups": timedelta(days=90),
}


@dataclass
class RetentionPolicy:
    data_type: str
    retention_period: Optional[timedelta]
    description: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)

    @property
    def is_indefinite(self) -> bool:
        return self.retention_period is None


# Backward-compatible alias for older call sites.
Policy = RetentionPolicy


@dataclass
class RetentionRecord:
    data_id: str
    data_type: str
    policy: RetentionPolicy
    created_at: datetime
    expiration: Optional[datetime]
    deleted: bool = False
    deleted_at: Optional[datetime] = None
    legal_holds: List[str] = field(default_factory=list)


@dataclass
class EnforcementResult:
    deleted: List[str]
    skipped_due_to_hold: List[str]
    errors: List[str]


@dataclass
class RetentionAuditReport:
    generated_at: datetime
    total_policies: int
    total_records: int
    expired_records: int
    held_records: int
    deleted_records: int
    non_compliant_records: List[str]
    compliant: bool
    notes: List[str] = field(default_factory=list)


class RetentionManager:
    """In-memory retention policy manager with scheduled enforcement support."""

    def __init__(self) -> None:
        self.policies: Dict[str, RetentionPolicy] = {}
        self._records: Dict[str, RetentionRecord] = {}
        self._lock = threading.RLock()

    def define_retention_policy(
        self,
        data_type: str,
        retention_period: Optional[timedelta],
        description: Optional[str] = None,
    ) -> RetentionPolicy:
        policy = RetentionPolicy(
            data_type=data_type,
            retention_period=retention_period,
            description=description,
        )
        with self._lock:
            self.policies[data_type] = policy
        return policy

    def get_retention_policy(self, data_type: str) -> Optional[RetentionPolicy]:
        with self._lock:
            return self.policies.get(data_type)

    def register_data(self, data_id: str, data_type: str, now: Optional[datetime] = None) -> RetentionRecord:
        now = now or datetime.utcnow()
        policy = self._resolve_policy(data_type)
        expiration = None if policy.is_indefinite else now + policy.retention_period  # type: ignore[operator]
        record = RetentionRecord(
            data_id=data_id,
            data_type=data_type,
            policy=policy,
            created_at=now,
            expiration=expiration,
        )
        with self._lock:
            self._records[data_id] = record
        return record

    def enforce_retention_policy(self, data_id: str) -> EnforcementResult:
        """Delete a single record if it exceeds its retention period."""
        now = datetime.utcnow()
        with self._lock:
            record = self._records.get(data_id)
            if record is None:
                return EnforcementResult(deleted=[], skipped_due_to_hold=[], errors=[f"{data_id}: not found"])

            if record.deleted:
                return EnforcementResult(deleted=[], skipped_due_to_hold=[], errors=[])

            if record.legal_holds:
                return EnforcementResult(deleted=[], skipped_due_to_hold=[data_id], errors=[])

            if record.expiration is None:
                return EnforcementResult(deleted=[], skipped_due_to_hold=[], errors=[])

            if record.expiration > now:
                return EnforcementResult(deleted=[], skipped_due_to_hold=[], errors=[])

            try:
                record.deleted = True
                record.deleted_at = now
                return EnforcementResult(deleted=[data_id], skipped_due_to_hold=[], errors=[])
            except Exception as exc:  # pragma: no cover - defensive guard
                LOG.exception("Retention deletion failed for %s", data_id)
                return EnforcementResult(deleted=[], skipped_due_to_hold=[], errors=[f"{data_id}: {exc}"])

    def apply_legal_hold(self, data_id: str, case_id: str) -> None:
        with self._lock:
            record = self._records.get(data_id)
            if record is None:
                raise KeyError(f"Unknown data_id: {data_id}")
            if case_id not in record.legal_holds:
                record.legal_holds.append(case_id)

    def release_legal_hold(self, data_id: str, case_id: str) -> None:
        with self._lock:
            record = self._records.get(data_id)
            if record is None:
                raise KeyError(f"Unknown data_id: {data_id}")
            try:
                record.legal_holds.remove(case_id)
            except ValueError:
                pass

    def audit_retention_compliance(self) -> RetentionAuditReport:
        now = datetime.utcnow()
        expired_records = 0
        held_records = 0
        deleted_records = 0
        non_compliant_records: List[str] = []
        notes: List[str] = []

        with self._lock:
            records = list(self._records.values())
            policies = len(self.policies)

        for record in records:
            if record.deleted:
                deleted_records += 1
                continue
            if record.legal_holds:
                held_records += 1
                continue
            if record.expiration is not None and record.expiration <= now:
                expired_records += 1
                non_compliant_records.append(record.data_id)

        compliant = len(non_compliant_records) == 0
        if not compliant:
            notes.append("Expired records remain undeleted without legal hold")

        return RetentionAuditReport(
            generated_at=now,
            total_policies=policies,
            total_records=len(records),
            expired_records=expired_records,
            held_records=held_records,
            deleted_records=deleted_records,
            non_compliant_records=non_compliant_records,
            compliant=compliant,
            notes=notes,
        )

    def enforce_all_retention_policies(self) -> EnforcementResult:
        deleted: List[str] = []
        skipped: List[str] = []
        errors: List[str] = []

        with self._lock:
            data_ids = list(self._records.keys())

        for data_id in data_ids:
            result = self.enforce_retention_policy(data_id)
            deleted.extend(result.deleted)
            skipped.extend(result.skipped_due_to_hold)
            errors.extend(result.errors)

        return EnforcementResult(deleted=deleted, skipped_due_to_hold=skipped, errors=errors)

    def start_scheduled_deletion_jobs(self, interval_seconds: int = 24 * 60 * 60) -> threading.Event:
        """Start a daemon worker that periodically enforces retention policies."""
        stop_event = threading.Event()

        def _worker() -> None:
            LOG.info("Starting retention deletion worker with interval=%ss", interval_seconds)
            while not stop_event.is_set():
                try:
                    self.enforce_all_retention_policies()
                    self.audit_retention_compliance()
                except Exception:  # pragma: no cover - defensive guard
                    LOG.exception("Scheduled retention enforcement failed")
                stop_event.wait(interval_seconds)

        thread = threading.Thread(target=_worker, name="retention-deletion-worker", daemon=True)
        thread.start()
        return stop_event

    def _resolve_policy(self, data_type: str) -> RetentionPolicy:
        with self._lock:
            policy = self.policies.get(data_type)
        if policy is not None:
            return policy

        default_period = DEFAULT_RETENTION_PERIODS.get(data_type)
        if default_period is None and data_type not in DEFAULT_RETENTION_PERIODS:
            default_period = timedelta(days=30)
            description = "Default retention policy"
        elif default_period is None:
            description = "Indefinite retention policy"
        else:
            description = f"Default retention policy for {data_type}"
        return self.define_retention_policy(data_type=data_type, retention_period=default_period, description=description)


_DEFAULT_MANAGER = RetentionManager()


def define_retention_policy(data_type: str, retention_period: Optional[timedelta]) -> RetentionPolicy:
    return _DEFAULT_MANAGER.define_retention_policy(data_type, retention_period)


def enforce_retention_policy(data_id: str) -> EnforcementResult:
    return _DEFAULT_MANAGER.enforce_retention_policy(data_id)


def apply_legal_hold(data_id: str, case_id: str) -> None:
    _DEFAULT_MANAGER.apply_legal_hold(data_id, case_id)


def release_legal_hold(data_id: str, case_id: str) -> None:
    _DEFAULT_MANAGER.release_legal_hold(data_id, case_id)


def audit_retention_compliance() -> RetentionAuditReport:
    return _DEFAULT_MANAGER.audit_retention_compliance()


def register_data(data_id: str, data_type: str, now: Optional[datetime] = None) -> RetentionRecord:
    return _DEFAULT_MANAGER.register_data(data_id, data_type, now=now)


def schedule_retention_deletion_jobs(interval_seconds: int = 24 * 60 * 60) -> threading.Event:
    return _DEFAULT_MANAGER.start_scheduled_deletion_jobs(interval_seconds)


def seed_default_retention_policies() -> None:
    for data_type, period in DEFAULT_RETENTION_PERIODS.items():
        _DEFAULT_MANAGER.define_retention_policy(data_type, period)


__all__ = [
    "RetentionPolicy",
    "Policy",
    "RetentionRecord",
    "EnforcementResult",
    "RetentionAuditReport",
    "RetentionManager",
    "DEFAULT_RETENTION_PERIODS",
    "define_retention_policy",
    "enforce_retention_policy",
    "apply_legal_hold",
    "release_legal_hold",
    "audit_retention_compliance",
    "register_data",
    "schedule_retention_deletion_jobs",
    "seed_default_retention_policies",
]
