"""Comprehensive Prometheus metrics collector for observability.

This module extends existing monitoring metrics with additional categories,
custom decorators, and in-process aggregation snapshots.
"""

from __future__ import annotations

import asyncio
import functools
import resource
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, ParamSpec, TypeVar

from prometheus_client import REGISTRY, CollectorRegistry, Counter, Gauge, Histogram, generate_latest

try:  # pragma: no cover - optional dependency boundary
    import psutil
except Exception:  # pragma: no cover - optional dependency boundary
    psutil = None  # type: ignore[assignment]

try:  # pragma: no cover - optional extension bridge
    from src.monitoring.metrics import observe_encryption_throughput as _legacy_observe_encryption_throughput
except Exception:  # pragma: no cover - optional extension bridge
    _legacy_observe_encryption_throughput = None


P = ParamSpec("P")
R = TypeVar("R")


@dataclass
class _AggregationState:
    """Rolling aggregation state with bounded samples for percentiles."""

    total: float = 0.0
    count: int = 0
    min_value: float = float("inf")
    max_value: float = float("-inf")
    samples: deque[float] = field(default_factory=deque)

    def observe(self, value: float, *, max_samples: int) -> None:
        self.total += value
        self.count += 1
        if value < self.min_value:
            self.min_value = value
        if value > self.max_value:
            self.max_value = value

        self.samples.append(value)
        while len(self.samples) > max_samples:
            self.samples.popleft()

    def snapshot(self) -> dict[str, float]:
        if self.count == 0:
            return {
                "sum": 0.0,
                "avg": 0.0,
                "min": 0.0,
                "max": 0.0,
                "p50": 0.0,
                "p90": 0.0,
                "p95": 0.0,
                "p99": 0.0,
            }

        sorted_values = sorted(self.samples)
        return {
            "sum": float(self.total),
            "avg": float(self.total / self.count),
            "min": float(self.min_value),
            "max": float(self.max_value),
            "p50": _percentile(sorted_values, 50.0),
            "p90": _percentile(sorted_values, 90.0),
            "p95": _percentile(sorted_values, 95.0),
            "p99": _percentile(sorted_values, 99.0),
        }


def _percentile(sorted_values: list[float], percentile: float) -> float:
    if not sorted_values:
        return 0.0

    if percentile <= 0.0:
        return float(sorted_values[0])
    if percentile >= 100.0:
        return float(sorted_values[-1])

    rank = (percentile / 100.0) * (len(sorted_values) - 1)
    lower = int(rank)
    upper = min(lower + 1, len(sorted_values) - 1)
    if lower == upper:
        return float(sorted_values[lower])

    fraction = rank - lower
    return float(
        sorted_values[lower] + (sorted_values[upper] - sorted_values[lower]) * fraction
    )


class MetricsCollector:
    """Collects throughput, latency, resource, and business metrics."""

    def __init__(
        self,
        *,
        registry: CollectorRegistry | None = None,
        rate_window_seconds: float = 5.0,
        aggregation_max_samples: int = 4096,
    ) -> None:
        if rate_window_seconds <= 0:
            raise ValueError("rate_window_seconds must be > 0")
        if aggregation_max_samples <= 0:
            raise ValueError("aggregation_max_samples must be > 0")

        self._registry = registry or REGISTRY
        self._rate_window_seconds = float(rate_window_seconds)
        self._aggregation_max_samples = int(aggregation_max_samples)

        self._lock = threading.RLock()
        self._aggregations: dict[str, _AggregationState] = {}
        self._recent_encryption_events: deque[tuple[float, int]] = deque()
        self._unique_users: set[str] = set()

        # Throughput metrics
        self.bytes_encrypted_total = self._get_or_create_metric(
            Counter,
            "bytes_encrypted_total",
            "Total bytes encrypted across all operations.",
        )
        self.operations_total = self._get_or_create_metric(
            Counter,
            "operations_total",
            "Total encryption operations executed.",
        )
        self.bytes_encrypted_per_second = self._get_or_create_metric(
            Gauge,
            "bytes_encrypted_per_second",
            "Recent average encrypted throughput in bytes/second.",
        )
        self.operations_per_second = self._get_or_create_metric(
            Gauge,
            "operations_per_second",
            "Recent average operation throughput in operations/second.",
        )

        # Latency metrics
        self.encryption_duration_ms = self._get_or_create_metric(
            Histogram,
            "encryption_duration_ms",
            "Encryption operation duration in milliseconds.",
            buckets=(
                0.1,
                0.25,
                0.5,
                1.0,
                2.0,
                5.0,
                10.0,
                25.0,
                50.0,
                100.0,
                250.0,
                500.0,
                1_000.0,
                float("inf"),
            ),
        )
        self.key_derivation_duration_ms = self._get_or_create_metric(
            Histogram,
            "key_derivation_duration_ms",
            "Key derivation duration in milliseconds.",
            buckets=(
                0.05,
                0.1,
                0.25,
                0.5,
                1.0,
                2.0,
                5.0,
                10.0,
                25.0,
                50.0,
                100.0,
                250.0,
                500.0,
                float("inf"),
            ),
        )

        # Resource metrics
        self.cpu_percent = self._get_or_create_metric(
            Gauge,
            "cpu_percent",
            "CPU usage percentage.",
        )
        self.memory_bytes = self._get_or_create_metric(
            Gauge,
            "memory_bytes",
            "Process or host memory usage in bytes.",
        )
        self.disk_io_bytes = self._get_or_create_metric(
            Gauge,
            "disk_io_bytes",
            "Disk I/O bytes read+written.",
        )

        # Business metrics
        self.files_encrypted_count = self._get_or_create_metric(
            Counter,
            "files_encrypted_count",
            "Total number of files encrypted.",
        )
        self.unique_users_count = self._get_or_create_metric(
            Gauge,
            "unique_users_count",
            "Unique users observed by this collector instance.",
        )
        self.active_keys_count = self._get_or_create_metric(
            Gauge,
            "active_keys_count",
            "Current number of active keys.",
        )

        # Decorator-support metrics
        self.custom_duration_ms = self._get_or_create_metric(
            Histogram,
            "custom_duration_ms",
            "Duration of custom tracked operations in milliseconds.",
            labelnames=("metric_name",),
            buckets=(
                0.05,
                0.1,
                0.25,
                0.5,
                1.0,
                2.0,
                5.0,
                10.0,
                25.0,
                50.0,
                100.0,
                250.0,
                500.0,
                1_000.0,
                float("inf"),
            ),
        )
        self.custom_invocations_total = self._get_or_create_metric(
            Counter,
            "custom_invocations_total",
            "Total invocation count for custom tracked operations.",
            labelnames=("metric_name",),
        )

        # Aggregation export metric
        self.metric_aggregation_value = self._get_or_create_metric(
            Gauge,
            "metric_aggregation_value",
            "Aggregated metric values by metric name and statistic.",
            labelnames=("metric_name", "stat"),
        )

    def record_encryption_event(
        self,
        *,
        bytes_processed: int,
        duration_ms: float,
        user_id: str | None = None,
    ) -> None:
        """Record one encryption event across throughput, latency, and business views."""
        if bytes_processed < 0:
            raise ValueError("bytes_processed must be non-negative")
        if duration_ms < 0:
            raise ValueError("duration_ms must be non-negative")

        now = time.time()

        with self._lock:
            self.bytes_encrypted_total.inc(float(bytes_processed))
            self.operations_total.inc()
            self.files_encrypted_count.inc()
            self.encryption_duration_ms.observe(float(duration_ms))

            self._recent_encryption_events.append((now, int(bytes_processed)))
            self._trim_events_locked(now)
            self._update_rate_gauges_locked(now)

            if isinstance(user_id, str) and user_id.strip():
                self._unique_users.add(user_id.strip())
                self.unique_users_count.set(float(len(self._unique_users)))

            self._observe_aggregation_locked("bytes_encrypted_per_second", self._gauge_value(self.bytes_encrypted_per_second))
            self._observe_aggregation_locked("operations_per_second", self._gauge_value(self.operations_per_second))
            self._observe_aggregation_locked("encryption_duration_ms", float(duration_ms))
            self._observe_aggregation_locked("files_encrypted_count", self.files_encrypted_count._value.get())  # noqa: SLF001

        if callable(_legacy_observe_encryption_throughput):
            try:
                _legacy_observe_encryption_throughput(int(bytes_processed))
            except Exception:
                pass

    def record_key_derivation(self, duration_ms: float) -> None:
        """Record key-derivation latency."""
        if duration_ms < 0:
            raise ValueError("duration_ms must be non-negative")

        with self._lock:
            self.key_derivation_duration_ms.observe(float(duration_ms))
            self._observe_aggregation_locked("key_derivation_duration_ms", float(duration_ms))

    def observe_resource_usage(self, *, cpu_percent: float, memory_bytes: int, disk_io_bytes: int) -> None:
        """Record resource-usage gauges and aggregation state."""
        if memory_bytes < 0:
            raise ValueError("memory_bytes must be non-negative")
        if disk_io_bytes < 0:
            raise ValueError("disk_io_bytes must be non-negative")

        with self._lock:
            self.cpu_percent.set(float(cpu_percent))
            self.memory_bytes.set(float(memory_bytes))
            self.disk_io_bytes.set(float(disk_io_bytes))

            self._observe_aggregation_locked("cpu_percent", float(cpu_percent))
            self._observe_aggregation_locked("memory_bytes", float(memory_bytes))
            self._observe_aggregation_locked("disk_io_bytes", float(disk_io_bytes))

    def collect_resource_usage(self) -> dict[str, float]:
        """Collect a best-effort resource snapshot and observe it."""
        cpu_value = 0.0
        memory_value = 0
        disk_value = 0

        if psutil is not None:
            try:
                cpu_value = float(psutil.cpu_percent(interval=None))
            except Exception:
                cpu_value = 0.0

            try:
                memory_value = int(psutil.virtual_memory().used)
            except Exception:
                memory_value = 0

            try:
                io = psutil.disk_io_counters()
                if io is not None:
                    disk_value = int(io.read_bytes + io.write_bytes)
            except Exception:
                disk_value = 0
        else:
            try:
                memory_value = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024)
            except Exception:
                memory_value = 0

        self.observe_resource_usage(
            cpu_percent=cpu_value,
            memory_bytes=memory_value,
            disk_io_bytes=disk_value,
        )
        return {
            "cpu_percent": cpu_value,
            "memory_bytes": float(memory_value),
            "disk_io_bytes": float(disk_value),
        }

    def set_active_keys_count(self, count: int) -> None:
        """Set current active key count business metric."""
        if count < 0:
            raise ValueError("count must be non-negative")

        with self._lock:
            self.active_keys_count.set(float(count))
            self._observe_aggregation_locked("active_keys_count", float(count))

    def increment_invocation(self, metric_name: str) -> None:
        """Increment custom invocation counter for decorator and manual use."""
        normalized = self._normalize_metric_name(metric_name)

        with self._lock:
            self.custom_invocations_total.labels(metric_name=normalized).inc()
            self._observe_aggregation_locked(
                f"invocations:{normalized}",
                self.custom_invocations_total.labels(metric_name=normalized)._value.get(),  # noqa: SLF001
            )

    def observe_duration(self, metric_name: str, duration_ms: float) -> None:
        """Observe custom duration metric value."""
        if duration_ms < 0:
            raise ValueError("duration_ms must be non-negative")

        normalized = self._normalize_metric_name(metric_name)
        with self._lock:
            self.custom_duration_ms.labels(metric_name=normalized).observe(float(duration_ms))
            self._observe_aggregation_locked(f"duration:{normalized}", float(duration_ms))

    def get_aggregation(self, metric_name: str) -> dict[str, float]:
        """Return sum/avg/min/max/percentiles for one metric."""
        normalized = self._normalize_metric_name(metric_name)
        with self._lock:
            state = self._aggregations.get(normalized)
            if state is None:
                return _AggregationState().snapshot()
            snapshot = state.snapshot()
            self._publish_aggregation_locked(normalized, snapshot)
            return snapshot

    def get_all_aggregations(self) -> dict[str, dict[str, float]]:
        """Return all current aggregation snapshots."""
        with self._lock:
            output: dict[str, dict[str, float]] = {}
            for metric_name, state in self._aggregations.items():
                snapshot = state.snapshot()
                self._publish_aggregation_locked(metric_name, snapshot)
                output[metric_name] = snapshot
            return output

    def export_metrics(self) -> bytes:
        """Export Prometheus payload for this collector registry."""
        return generate_latest(self._registry)

    def _observe_aggregation_locked(self, metric_name: str, value: float) -> None:
        normalized = self._normalize_metric_name(metric_name)
        state = self._aggregations.get(normalized)
        if state is None:
            state = _AggregationState(samples=deque())
            self._aggregations[normalized] = state

        state.observe(float(value), max_samples=self._aggregation_max_samples)
        self._publish_aggregation_locked(normalized, state.snapshot())

    def _publish_aggregation_locked(self, metric_name: str, snapshot: dict[str, float]) -> None:
        for stat, value in snapshot.items():
            self.metric_aggregation_value.labels(metric_name=metric_name, stat=stat).set(float(value))

    def _trim_events_locked(self, now: float) -> None:
        cutoff = now - self._rate_window_seconds
        while self._recent_encryption_events and self._recent_encryption_events[0][0] < cutoff:
            self._recent_encryption_events.popleft()

    def _update_rate_gauges_locked(self, now: float) -> None:
        if not self._recent_encryption_events:
            self.bytes_encrypted_per_second.set(0.0)
            self.operations_per_second.set(0.0)
            return

        first_ts = self._recent_encryption_events[0][0]
        window = max(1e-6, min(self._rate_window_seconds, now - first_ts if now > first_ts else self._rate_window_seconds))

        total_bytes = float(sum(item[1] for item in self._recent_encryption_events))
        total_ops = float(len(self._recent_encryption_events))

        self.bytes_encrypted_per_second.set(total_bytes / window)
        self.operations_per_second.set(total_ops / window)

    def _get_or_create_metric(self, metric_cls: Any, name: str, documentation: str, **kwargs: Any) -> Any:
        try:
            return metric_cls(name, documentation, registry=self._registry, **kwargs)
        except ValueError:
            existing = getattr(self._registry, "_names_to_collectors", {}).get(name)  # type: ignore[attr-defined]
            if existing is None:
                raise
            return existing

    @staticmethod
    def _normalize_metric_name(metric_name: str) -> str:
        if not isinstance(metric_name, str) or not metric_name.strip():
            raise ValueError("metric_name must be a non-empty string")
        return metric_name.strip().lower()

    @staticmethod
    def _gauge_value(gauge: Gauge) -> float:
        try:
            return float(gauge._value.get())  # noqa: SLF001
        except Exception:
            return 0.0


_DEFAULT_COLLECTOR: MetricsCollector | None = None
_DEFAULT_LOCK = threading.RLock()


def get_default_metrics_collector() -> MetricsCollector:
    """Return process-wide default metrics collector singleton."""
    global _DEFAULT_COLLECTOR
    with _DEFAULT_LOCK:
        if _DEFAULT_COLLECTOR is None:
            _DEFAULT_COLLECTOR = MetricsCollector()
        return _DEFAULT_COLLECTOR


def track_duration(metric_name: str) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Decorator to measure function duration in milliseconds."""

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        if asyncio.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> Any:
                start = time.perf_counter()
                try:
                    return await func(*args, **kwargs)
                finally:
                    elapsed_ms = (time.perf_counter() - start) * 1000.0
                    get_default_metrics_collector().observe_duration(metric_name, elapsed_ms)

            return async_wrapper  # type: ignore[return-value]

        @functools.wraps(func)
        def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            start = time.perf_counter()
            try:
                return func(*args, **kwargs)
            finally:
                elapsed_ms = (time.perf_counter() - start) * 1000.0
                get_default_metrics_collector().observe_duration(metric_name, elapsed_ms)

        return sync_wrapper

    return decorator


def count_invocations(metric_name: str) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Decorator to count function invocations."""

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        if asyncio.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> Any:
                get_default_metrics_collector().increment_invocation(metric_name)
                return await func(*args, **kwargs)

            return async_wrapper  # type: ignore[return-value]

        @functools.wraps(func)
        def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            get_default_metrics_collector().increment_invocation(metric_name)
            return func(*args, **kwargs)

        return sync_wrapper

    return decorator


__all__ = [
    "MetricsCollector",
    "get_default_metrics_collector",
    "track_duration",
    "count_invocations",
]
