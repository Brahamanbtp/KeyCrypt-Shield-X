from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any, Callable
from enum import Enum
from datetime import datetime, date
import uuid
import time


class AlgorithmStatus(Enum):
    EXPERIMENTAL = "experimental"
    APPROVED = "approved"
    DEPRECATED = "deprecated"
    FORBIDDEN = "forbidden"


@dataclass
class Operation:
    operation_id: str
    algorithm: str
    use_case: str
    user_id: Optional[str] = None
    timestamp: float = field(default_factory=time.time)


@dataclass
class AlgorithmLifecycleInfo:
    algorithm_name: str
    status: AlgorithmStatus
    use_cases: Set[str] = field(default_factory=set)  # e.g., "encryption", "signing", "hashing"
    approved_date: Optional[date] = None
    deprecation_scheduled_date: Optional[date] = None
    forbidden_reason: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Notification:
    notification_id: str
    recipient: str  # email or user_id
    subject: str
    message: str
    sent_at: Optional[float] = None
    notification_type: str = "email"


class AlgorithmLifecycleManager:
    """Manages algorithm lifecycle: experimental → approved → deprecated → forbidden.

    Features:
    - Track algorithm status and lifecycle
    - Filter approved algorithms by use case
    - Schedule deprecations
    - Enforce algorithm policies
    - Generate notifications for status changes
    - Block operations using forbidden algorithms

    For production: integrate with real email/notification systems, add audit logging,
    and implement approval workflows.
    """

    def __init__(self, notification_handler: Optional[Callable] = None):
        self._algorithms: Dict[str, AlgorithmLifecycleInfo] = {}
        self._operations_log: List[Operation] = []
        self._notifications: List[Notification] = []
        self._notification_handler = notification_handler or self._default_notification_handler
        self._deprecation_schedule: Dict[str, date] = {}

    def set_algorithm_status(self, algorithm: str, status: AlgorithmStatus, reason: Optional[str] = None) -> None:
        """Set the lifecycle status of an algorithm."""
        info = self._algorithms.get(algorithm)
        if info is None:
            info = AlgorithmLifecycleInfo(algorithm_name=algorithm, status=status)
            self._algorithms[algorithm] = info
        else:
            old_status = info.status
            info.status = status

            # emit notification on status change
            if old_status != status:
                self._notify_status_change(algorithm, old_status, status, reason)

        if status == AlgorithmStatus.APPROVED and info.approved_date is None:
            info.approved_date = date.today()

        if status == AlgorithmStatus.FORBIDDEN:
            info.forbidden_reason = reason or "Security policy violation"

    def register_algorithm_use_case(self, algorithm: str, use_case: str, status: AlgorithmStatus = AlgorithmStatus.EXPERIMENTAL) -> None:
        """Register an algorithm for a specific use case."""
        if algorithm not in self._algorithms:
            self._algorithms[algorithm] = AlgorithmLifecycleInfo(algorithm_name=algorithm, status=status)
        self._algorithms[algorithm].use_cases.add(use_case)

    def get_approved_algorithms(self, use_case: str) -> List[str]:
        """Get all approved algorithms for a given use case."""
        approved = []
        for algo_name, info in self._algorithms.items():
            if info.status == AlgorithmStatus.APPROVED and use_case in info.use_cases:
                approved.append(algo_name)
        return approved

    def schedule_algorithm_deprecation(self, algorithm: str, deprecation_date: date) -> None:
        """Schedule an algorithm to be deprecated on a specific date."""
        if algorithm not in self._algorithms:
            self._algorithms[algorithm] = AlgorithmLifecycleInfo(algorithm_name=algorithm, status=AlgorithmStatus.APPROVED)

        info = self._algorithms[algorithm]
        info.deprecation_scheduled_date = deprecation_date
        self._deprecation_schedule[algorithm] = deprecation_date

        # emit notification
        days_until = (deprecation_date - date.today()).days
        msg = f"Algorithm '{algorithm}' will be deprecated in {days_until} days ({deprecation_date})."
        self._send_notification(
            recipient="admins",
            subject=f"Deprecation scheduled: {algorithm}",
            message=msg,
            notification_type="admin_alert",
        )

    def enforce_algorithm_policy(self, operation: Operation) -> bool:
        """Enforce algorithm policy: block forbidden algorithms and log operation.

        Returns True if operation is allowed, False if blocked.
        """
        self._operations_log.append(operation)

        info = self._algorithms.get(operation.algorithm)
        if info is None:
            # unknown algorithm: allow but warn
            return True

        # block forbidden algorithms
        if info.status == AlgorithmStatus.FORBIDDEN:
            msg = f"Operation blocked: algorithm '{operation.algorithm}' is forbidden. Reason: {info.forbidden_reason}"
            self._send_notification(
                recipient=operation.user_id or "security_team",
                subject="Blocked operation",
                message=msg,
                notification_type="security_alert",
            )
            return False

        # warn about experimental algorithms
        if info.status == AlgorithmStatus.EXPERIMENTAL:
            msg = f"Warning: using experimental algorithm '{operation.algorithm}' in {operation.use_case}."
            self._send_notification(
                recipient=operation.user_id or "ops_team",
                subject="Experimental algorithm in use",
                message=msg,
                notification_type="warning",
            )

        # warn about deprecated algorithms
        if info.status == AlgorithmStatus.DEPRECATED:
            msg = f"Algorithm '{operation.algorithm}' is deprecated. Plan migration to approved alternative."
            self._send_notification(
                recipient=operation.user_id or "ops_team",
                subject="Deprecated algorithm in use",
                message=msg,
                notification_type="warning",
            )

        return True

    def check_algorithm_deprecation_date(self, algorithm: str) -> Optional[date]:
        """Check if an algorithm has a scheduled deprecation date and return it."""
        info = self._algorithms.get(algorithm)
        return info.deprecation_scheduled_date if info else None

    def apply_scheduled_deprecations(self) -> List[str]:
        """Apply scheduled deprecations that are due today or past.

        Returns list of algorithms that were deprecated.
        """
        today = date.today()
        deprecated_list = []

        for algo_name, scheduled_date in list(self._deprecation_schedule.items()):
            if scheduled_date <= today:
                info = self._algorithms.get(algo_name)
                if info and info.status != AlgorithmStatus.DEPRECATED:
                    old_status = info.status
                    info.status = AlgorithmStatus.DEPRECATED
                    deprecated_list.append(algo_name)
                    self._notify_status_change(algo_name, old_status, AlgorithmStatus.DEPRECATED, "Scheduled deprecation date reached")

        return deprecated_list

    def get_algorithm_lifecycle_info(self, algorithm: str) -> Optional[Dict[str, Any]]:
        """Get detailed lifecycle information for an algorithm."""
        info = self._algorithms.get(algorithm)
        if not info:
            return None
        return {
            "algorithm_name": info.algorithm_name,
            "status": info.status.value,
            "use_cases": list(info.use_cases),
            "approved_date": info.approved_date.isoformat() if info.approved_date else None,
            "deprecation_scheduled_date": info.deprecation_scheduled_date.isoformat() if info.deprecation_scheduled_date else None,
            "forbidden_reason": info.forbidden_reason,
        }

    def get_operations_log(self, algorithm: Optional[str] = None, user_id: Optional[str] = None) -> List[Operation]:
        """Get operations log, optionally filtered by algorithm or user."""
        ops = self._operations_log
        if algorithm:
            ops = [op for op in ops if op.algorithm == algorithm]
        if user_id:
            ops = [op for op in ops if op.user_id == user_id]
        return ops

    def get_pending_notifications(self) -> List[Notification]:
        """Get unsent notifications."""
        return [n for n in self._notifications if n.sent_at is None]

    def mark_notification_sent(self, notification_id: str) -> bool:
        """Mark a notification as sent."""
        for notif in self._notifications:
            if notif.notification_id == notification_id:
                notif.sent_at = time.time()
                return True
        return False

    def _send_notification(
        self, recipient: str, subject: str, message: str, notification_type: str = "email"
    ) -> Notification:
        """Create and send a notification."""
        notification = Notification(
            notification_id=str(uuid.uuid4()),
            recipient=recipient,
            subject=subject,
            message=message,
            notification_type=notification_type,
        )
        self._notifications.append(notification)
        # call notification handler (can be overridden)
        self._notification_handler(notification)
        return notification

    def _notify_status_change(self, algorithm: str, old_status: AlgorithmStatus, new_status: AlgorithmStatus, reason: Optional[str]) -> None:
        """Notify about algorithm status change."""
        reason_text = f" Reason: {reason}" if reason else ""
        msg = f"Algorithm '{algorithm}' status changed from {old_status.value} to {new_status.value}.{reason_text}"
        self._send_notification(
            recipient="admins",
            subject=f"Algorithm status change: {algorithm}",
            message=msg,
            notification_type="admin_alert",
        )

    def _default_notification_handler(self, notification: Notification) -> None:
        """Default notification handler (simulated)."""
        # in production: send actual email or use notification service
        pass


__all__ = [
    "AlgorithmLifecycleManager",
    "AlgorithmStatus",
    "AlgorithmLifecycleInfo",
    "Operation",
    "Notification",
]
