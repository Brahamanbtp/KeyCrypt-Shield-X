"""Telemetry collection system for security events.

Provides:
- Access pattern telemetry
- Authentication event telemetry
- Entropy measurements
- Failed operation/error telemetry

Storage:
- InfluxDB line protocol format (append-only local sink)
- Prometheus export through prometheus_client

Analytics:
- Sliding-window aggregations for 1 minute, 5 minutes, and 1 hour windows
"""

from __future__ import annotations

import math
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from prometheus_client import Counter as PromCounter
from prometheus_client import Gauge, Histogram, generate_latest


WINDOWS_SECONDS = {
    "1min": 60,
    "5min": 300,
    "1hour": 3600,
}


telemetry_access_total = PromCounter(
    "telemetry_access_total",
    "Total access pattern events collected.",
)

telemetry_auth_total = PromCounter(
    "telemetry_auth_total",
    "Total authentication events collected.",
    labelnames=("result",),
)

telemetry_failed_operations_total = PromCounter(
    "telemetry_failed_operations_total",
    "Total failed operations collected.",
    labelnames=("security_violation",),
)

telemetry_entropy_histogram = Histogram(
    "telemetry_entropy_values",
    "Observed entropy measurements.",
    buckets=(0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 7.5, 8.0),
)

telemetry_active_users_gauge = Gauge(
    "telemetry_active_users_window_5m",
    "Unique active users in the last 5 minutes.",
)

telemetry_auth_failure_ratio = Gauge(
    "telemetry_auth_failure_ratio_window_5m",
    "Authentication failure ratio in the last 5 minutes.",
)


@dataclass(frozen=True)
class AccessEvent:
    timestamp: float
    user_id: str
    resource: str


@dataclass(frozen=True)
class AuthenticationEvent:
    timestamp: float
    user_id: str
    success: bool
    method: str
    geolocation: str


@dataclass(frozen=True)
class EntropyEvent:
    timestamp: float
    value: float
    source: str


@dataclass(frozen=True)
class FailedOperationEvent:
    timestamp: float
    operation: str
    error: str
    exception_type: str
    security_violation: bool
    user_id: str | None


class TelemetryCollector:
    """Collects security telemetry and produces analytics/exports."""

    def __init__(
        self,
        *,
        influx_sink_path: str | Path = "telemetry_influx.lp",
        retention_seconds: int = WINDOWS_SECONDS["1hour"] * 2,
    ) -> None:
        self.influx_sink_path = Path(influx_sink_path)
        self.retention_seconds = max(retention_seconds, WINDOWS_SECONDS["1hour"])
        self._lock = threading.RLock()

        self._access_events: deque[AccessEvent] = deque()
        self._auth_events: deque[AuthenticationEvent] = deque()
        self._entropy_events: deque[EntropyEvent] = deque()
        self._failed_events: deque[FailedOperationEvent] = deque()

        self.influx_sink_path.parent.mkdir(parents=True, exist_ok=True)

    def record_access(self, user_id: str, resource: str, timestamp: float | None = None) -> None:
        """Track access pattern event (timestamp, user, resource)."""
        ts = float(timestamp if timestamp is not None else time.time())
        event = AccessEvent(timestamp=ts, user_id=user_id, resource=resource)

        with self._lock:
            self._access_events.append(event)
            self._append_influx_line(self._to_influx_access(event))
            self._prune_old_events_locked()

        telemetry_access_total.inc()
        self._refresh_prometheus_window_metrics()

    def record_authentication(
        self,
        user_id: str,
        success: bool,
        method: str,
        geolocation: str,
        timestamp: float | None = None,
    ) -> None:
        """Track authentication event (success/failure, method, geolocation)."""
        ts = float(timestamp if timestamp is not None else time.time())
        event = AuthenticationEvent(
            timestamp=ts,
            user_id=user_id,
            success=bool(success),
            method=method,
            geolocation=geolocation,
        )

        with self._lock:
            self._auth_events.append(event)
            self._append_influx_line(self._to_influx_auth(event))
            self._prune_old_events_locked()

        telemetry_auth_total.labels(result="success" if success else "failure").inc()
        self._refresh_prometheus_window_metrics()

    def record_entropy_measurement(self, value: float, source: str = "access", timestamp: float | None = None) -> None:
        """Track entropy/randomness measurement event."""
        if not isinstance(value, (int, float)):
            raise TypeError("value must be numeric")

        ts = float(timestamp if timestamp is not None else time.time())
        event = EntropyEvent(timestamp=ts, value=float(value), source=source)

        with self._lock:
            self._entropy_events.append(event)
            self._append_influx_line(self._to_influx_entropy(event))
            self._prune_old_events_locked()

        telemetry_entropy_histogram.observe(float(value))

    def record_failed_operation(
        self,
        operation: str,
        error: str,
        *,
        exception_type: str = "Exception",
        security_violation: bool = False,
        user_id: str | None = None,
        timestamp: float | None = None,
    ) -> None:
        """Track failed operation and exception/security violation context."""
        ts = float(timestamp if timestamp is not None else time.time())
        event = FailedOperationEvent(
            timestamp=ts,
            operation=operation,
            error=error,
            exception_type=exception_type,
            security_violation=bool(security_violation),
            user_id=user_id,
        )

        with self._lock:
            self._failed_events.append(event)
            self._append_influx_line(self._to_influx_failed(event))
            self._prune_old_events_locked()

        telemetry_failed_operations_total.labels(
            security_violation="true" if security_violation else "false"
        ).inc()

    def get_sliding_window_aggregations(self) -> dict[str, dict[str, Any]]:
        """Return 1min/5min/1hour aggregation snapshots."""
        with self._lock:
            now = time.time()
            self._prune_old_events_locked(now)

            result: dict[str, dict[str, Any]] = {}
            for label, seconds in WINDOWS_SECONDS.items():
                result[label] = self._window_aggregate_locked(now=now, window_seconds=seconds)
            return result

    def export_influx_lines(self, last_n: int | None = None) -> list[str]:
        """Export stored InfluxDB line protocol entries from sink file."""
        if not self.influx_sink_path.exists():
            return []

        lines = self.influx_sink_path.read_text(encoding="utf-8").splitlines()
        if last_n is not None and last_n > 0:
            return lines[-last_n:]
        return lines

    def export_prometheus(self) -> bytes:
        """Export Prometheus metrics payload."""
        self._refresh_prometheus_window_metrics()
        return generate_latest()

    def _window_aggregate_locked(self, *, now: float, window_seconds: int) -> dict[str, Any]:
        window_start = now - window_seconds

        access = [e for e in self._access_events if e.timestamp >= window_start]
        auth = [e for e in self._auth_events if e.timestamp >= window_start]
        entropy_events = [e for e in self._entropy_events if e.timestamp >= window_start]
        failed = [e for e in self._failed_events if e.timestamp >= window_start]

        unique_users = len({e.user_id for e in access} | {e.user_id for e in auth})
        top_resources = Counter(e.resource for e in access).most_common(5)

        auth_total = len(auth)
        auth_failures = sum(1 for e in auth if not e.success)
        auth_failure_ratio = auth_failures / auth_total if auth_total else 0.0

        entropy_values = [e.value for e in entropy_events]
        avg_entropy = sum(entropy_values) / len(entropy_values) if entropy_values else None

        access_randomness_entropy = self._resource_distribution_entropy(access)

        security_violations = sum(1 for e in failed if e.security_violation)

        return {
            "window_seconds": window_seconds,
            "access_events": len(access),
            "unique_users": unique_users,
            "top_resources": top_resources,
            "authentication_events": auth_total,
            "authentication_failures": auth_failures,
            "authentication_failure_ratio": auth_failure_ratio,
            "entropy_measurements": len(entropy_values),
            "average_entropy": avg_entropy,
            "access_randomness_entropy": access_randomness_entropy,
            "failed_operations": len(failed),
            "security_violations": security_violations,
            "exceptions_by_type": Counter(e.exception_type for e in failed),
        }

    def _resource_distribution_entropy(self, access_events: list[AccessEvent]) -> float | None:
        if not access_events:
            return None

        counts = Counter(e.resource for e in access_events)
        total = sum(counts.values())
        entropy = 0.0
        for count in counts.values():
            p = count / total
            entropy -= p * math.log2(p)
        return entropy

    def _refresh_prometheus_window_metrics(self) -> None:
        with self._lock:
            now = time.time()
            snapshot = self._window_aggregate_locked(now=now, window_seconds=WINDOWS_SECONDS["5min"])

        telemetry_active_users_gauge.set(float(snapshot["unique_users"]))
        telemetry_auth_failure_ratio.set(float(snapshot["authentication_failure_ratio"]))

    def _prune_old_events_locked(self, now: float | None = None) -> None:
        now_ts = float(now if now is not None else time.time())
        cutoff = now_ts - self.retention_seconds

        self._prune_deque(self._access_events, cutoff)
        self._prune_deque(self._auth_events, cutoff)
        self._prune_deque(self._entropy_events, cutoff)
        self._prune_deque(self._failed_events, cutoff)

    @staticmethod
    def _prune_deque(queue: deque[Any], cutoff: float) -> None:
        while queue and queue[0].timestamp < cutoff:
            queue.popleft()

    def _append_influx_line(self, line: str) -> None:
        with self.influx_sink_path.open("a", encoding="utf-8") as handle:
            handle.write(line)
            handle.write("\n")

    def _to_influx_access(self, event: AccessEvent) -> str:
        ts_ns = int(event.timestamp * 1_000_000_000)
        user = self._escape_tag(event.user_id)
        resource = self._escape_tag(event.resource)
        return f"access_patterns,user_id={user},resource={resource} count=1i {ts_ns}"

    def _to_influx_auth(self, event: AuthenticationEvent) -> str:
        ts_ns = int(event.timestamp * 1_000_000_000)
        user = self._escape_tag(event.user_id)
        method = self._escape_tag(event.method)
        geo = self._escape_tag(event.geolocation)
        success = "true" if event.success else "false"
        return (
            f"authentication_events,user_id={user},method={method},geolocation={geo},success={success} "
            f"count=1i {ts_ns}"
        )

    def _to_influx_entropy(self, event: EntropyEvent) -> str:
        ts_ns = int(event.timestamp * 1_000_000_000)
        source = self._escape_tag(event.source)
        return f"entropy_measurements,source={source} value={event.value} {ts_ns}"

    def _to_influx_failed(self, event: FailedOperationEvent) -> str:
        ts_ns = int(event.timestamp * 1_000_000_000)
        operation = self._escape_tag(event.operation)
        exc_type = self._escape_tag(event.exception_type)
        sec = "true" if event.security_violation else "false"

        error_field = self._escape_field_string(event.error)
        user_tag = f",user_id={self._escape_tag(event.user_id)}" if event.user_id else ""

        return (
            f"failed_operations,operation={operation},exception_type={exc_type},security_violation={sec}{user_tag} "
            f"count=1i,error=\"{error_field}\" {ts_ns}"
        )

    @staticmethod
    def _escape_tag(value: str) -> str:
        return (
            str(value)
            .replace("\\", "\\\\")
            .replace(" ", "\\ ")
            .replace(",", "\\,")
            .replace("=", "\\=")
        )

    @staticmethod
    def _escape_field_string(value: str) -> str:
        return str(value).replace("\\", "\\\\").replace('"', '\\"')


__all__ = [
    "TelemetryCollector",
    "AccessEvent",
    "AuthenticationEvent",
    "EntropyEvent",
    "FailedOperationEvent",
]
