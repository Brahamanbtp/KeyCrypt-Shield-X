from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, Optional, List


@dataclass
class Policy:
    data_type: str
    retention_period: timedelta
    description: Optional[str] = None


@dataclass
class RetentionRecord:
    data_id: str
    policy: Policy
    expiration: datetime
    deleted: bool = False
    legal_holds: List[str] = field(default_factory=list)


@dataclass
class EnforcementResult:
    deleted: List[str]
    skipped_due_to_hold: List[str]
    errors: List[str]


class RetentionManager:
    """Simple in-memory retention policy manager.

    This provides the core behaviors requested:
    - define_retention_policy
    - apply_retention_policy
    - enforce_retention_policy
    - legal_hold / release_legal_hold

    It is intentionally lightweight and intended to be wired to the
    project's canonical metadata and storage backends in later work.
    """

    def __init__(self):
        self.policies: Dict[str, Policy] = {}
        self._records: Dict[str, RetentionRecord] = {}

    def define_retention_policy(self, data_type: str, retention_period: timedelta, description: Optional[str] = None) -> Policy:
        policy = Policy(data_type=data_type, retention_period=retention_period, description=description)
        self.policies[data_type] = policy
        return policy

    def apply_retention_policy(self, data_id: str, policy: Policy, now: Optional[datetime] = None) -> None:
        """Associate `data_id` with `policy` and set an expiration date.

        The `now` parameter is provided for easier testing.
        """
        now = now or datetime.utcnow()
        expiration = now + policy.retention_period
        record = RetentionRecord(data_id=data_id, policy=policy, expiration=expiration)
        self._records[data_id] = record

    def legal_hold(self, data_id: str, case_id: str) -> None:
        r = self._records.get(data_id)
        if r:
            if case_id not in r.legal_holds:
                r.legal_holds.append(case_id)

    def release_legal_hold(self, data_id: str, case_id: str) -> None:
        r = self._records.get(data_id)
        if r:
            try:
                r.legal_holds.remove(case_id)
            except ValueError:
                pass

    def enforce_retention_policy(self, now: Optional[datetime] = None) -> EnforcementResult:
        """Enforce all retention policies: delete records past expiration unless under legal hold.

        Deletion here is simulated by marking `deleted = True` on the record. In a
        real system this should trigger secure deletion flows and evidence logging.
        """
        now = now or datetime.utcnow()
        deleted = []
        skipped = []
        errors = []
        for data_id, record in list(self._records.items()):
            if record.deleted:
                continue
            if record.expiration <= now:
                if record.legal_holds:
                    skipped.append(data_id)
                    continue
                try:
                    # Simulate deletion
                    record.deleted = True
                    deleted.append(data_id)
                except Exception as e:
                    errors.append(f"{data_id}: {e}")
        return EnforcementResult(deleted=deleted, skipped_due_to_hold=skipped, errors=errors)

    def validate_policy_compliance(self, policy: Policy, regulations: Optional[Dict[str, timedelta]] = None) -> bool:
        """Validate a policy against a simple regulations mapping.

        `regulations` should map data_type -> minimum retention timedelta.
        If no regulations provided, the method returns True.
        """
        if not regulations:
            return True
        min_required = regulations.get(policy.data_type)
        if min_required is None:
            return True
        return policy.retention_period >= min_required


__all__ = ["Policy", "RetentionManager", "EnforcementResult"]
