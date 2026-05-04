from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional


@dataclass
class Policy:
    resource: str
    principals: List[str]
    permissions: List[str]
    description: Optional[str] = None


@dataclass
class AccessEvent:
    user: str
    resource: str
    permission: str
    timestamp: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Anomaly:
    user: str
    reason: str
    events: List[AccessEvent]


@dataclass
class ReviewReport:
    timestamp: datetime
    policies_count: int
    principals_count: int
    issues: List[str]


class AccessManager:
    """In-memory access governance manager.

    - define_access_policy
    - enforce_least_privilege
    - periodic_access_review
    - detect_access_anomalies
    - revoke_access_on_termination

    Note: This is a lightweight framework intended to be connected to the
    project's identity and IAM systems later.
    """

    # simple conflicting permission pairs to demonstrate separation of duties
    CONFLICTING_PERMISSIONS = [
        ("approve_payments", "create_payments"),
        ("admin", "auditor"),
    ]

    def __init__(self):
        self.policies: Dict[str, Policy] = {}

    def define_access_policy(self, resource: str, principals: List[str], permissions: List[str], description: Optional[str] = None) -> Policy:
        # Note: do not auto-remove conflicting permissions here — keep the policy
        # as-declared and surface separation-of-duties issues during review.
        policy = Policy(resource=resource, principals=list(principals), permissions=list(permissions), description=description)
        self.policies[resource] = policy
        return policy

    def enforce_least_privilege(self, user: Any) -> None:
        """Ensure `user.permissions` matches what policies assign to them.

        `user` is expected to have attributes: `name` and `permissions` (dict resource->List[str]).
        This method will remove permissions that are not assigned by any policy for that user.
        """
        try:
            user_name = user.name
        except Exception:
            return
        current = getattr(user, "permissions", {}) or {}
        effective: Dict[str, List[str]] = {}
        for resource, policy in self.policies.items():
            if user_name in policy.principals:
                effective[resource] = list(policy.permissions)

        # apply effective permissions, removing excessive ones
        # users may have other resources not covered by policies; keep only if in effective
        new_permissions = {}
        for resource, perms in effective.items():
            new_permissions[resource] = perms
        user.permissions = new_permissions

    def periodic_access_review(self, review_period: timedelta) -> ReviewReport:
        now = datetime.utcnow()
        principals = set()
        issues: List[str] = []
        for policy in self.policies.values():
            principals.update(policy.principals)
            # separation of duties check
            for p in policy.principals:
                for a, b in self.CONFLICTING_PERMISSIONS:
                    if a in policy.permissions and b in policy.permissions:
                        issues.append(f"{p}: conflicting permissions {a} & {b} on {policy.resource}")
        return ReviewReport(timestamp=now, policies_count=len(self.policies), principals_count=len(principals), issues=issues)

    def detect_access_anomalies(self, user: Any, access_log: List[AccessEvent]) -> List[Anomaly]:
        """Detect simple anomalies: bursts of activity or access outside normal hours.

        This is a placeholder ML-like detector: projects should replace with a
        trained model for production use.
        """
        if not access_log:
            return []
        anomalies: List[Anomaly] = []
        # burst detection: >5 events within 1 minute
        events_by_minute: Dict[int, List[AccessEvent]] = {}
        for ev in access_log:
            minute = int(ev.timestamp.timestamp() // 60)
            events_by_minute.setdefault(minute, []).append(ev)

        for minute, evs in events_by_minute.items():
            if len(evs) > 5:
                anomalies.append(Anomaly(user=user.name if hasattr(user, 'name') else 'unknown', reason=f"burst:{len(evs)} in 1min", events=evs))

        # outside-hours access: define normal hours 06:00-20:00 UTC
        outside = [ev for ev in access_log if not (6 <= ev.timestamp.hour < 20)]
        if outside:
            anomalies.append(Anomaly(user=user.name if hasattr(user, 'name') else 'unknown', reason="outside-hours", events=outside))

        return anomalies

    def revoke_access_on_termination(self, user: Any) -> None:
        name = getattr(user, 'name', None)
        if not name:
            return
        for policy in self.policies.values():
            if name in policy.principals:
                try:
                    policy.principals.remove(name)
                except ValueError:
                    pass


__all__ = ["Policy", "AccessManager", "AccessEvent", "Anomaly", "ReviewReport"]
