"""Prometheus metrics and decorators for KeyCrypt Shield X."""

from __future__ import annotations

import functools
import time
from typing import Any, Callable, ParamSpec, TypeVar

from prometheus_client import Counter, Enum, Gauge, Histogram, Summary


P = ParamSpec("P")
R = TypeVar("R")


# NOTE: Python's prometheus_client Summary exports count/sum; quantiles are
# typically computed from histogram data in Prometheus queries. This Summary is
# included to satisfy latency tracking requirements.
encryption_throughput_bytes = Histogram(
    "encryption_throughput_bytes",
    "Distribution of encrypted bytes per operation.",
    buckets=(
        1_024,
        4_096,
        16_384,
        65_536,
        262_144,
        1_048_576,
        4_194_304,
        16_777_216,
        67_108_864,
        float("inf"),
    ),
)

decryption_latency_seconds = Summary(
    "decryption_latency_seconds",
    "Latency distribution for decryption operations in seconds.",
)

key_rotation_total = Counter(
    "key_rotation_total",
    "Total number of completed key rotation events.",
)

active_encryption_operations = Gauge(
    "active_encryption_operations",
    "Number of encryption operations currently in progress.",
)

security_state = Enum(
    "security_state",
    "Current security state of the platform.",
    states=["LOW", "NORMAL", "ELEVATED", "CRITICAL"],
)


function_calls_total = Counter(
    "function_calls_total",
    "Total number of instrumented function calls.",
    labelnames=("function",),
)

function_errors_total = Counter(
    "function_errors_total",
    "Total number of errors raised by instrumented functions.",
    labelnames=("function",),
)


def set_security_state(level: str) -> None:
    """Update global security state metric."""
    normalized = level.strip().upper()
    if normalized not in {"LOW", "NORMAL", "ELEVATED", "CRITICAL"}:
        raise ValueError("security level must be one of LOW, NORMAL, ELEVATED, CRITICAL")
    security_state.state(normalized)


def measure_time(
    metric: Summary | Histogram = decryption_latency_seconds,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Decorator to measure execution time in seconds and observe to metric."""

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            start = time.perf_counter()
            try:
                return func(*args, **kwargs)
            finally:
                elapsed = time.perf_counter() - start
                metric.observe(elapsed)

        return wrapper

    return decorator


def count_calls(
    counter: Counter | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Decorator to increment a call counter for each invocation."""

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            if counter is not None:
                counter.inc()
            else:
                function_calls_total.labels(function=func.__name__).inc()
            return func(*args, **kwargs)

        return wrapper

    return decorator


def track_errors(
    counter: Counter | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Decorator to count exceptions and re-raise them unchanged."""

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            try:
                return func(*args, **kwargs)
            except Exception:
                if counter is not None:
                    counter.inc()
                else:
                    function_errors_total.labels(function=func.__name__).inc()
                raise

        return wrapper

    return decorator


def track_active_encryption(
    func: Callable[P, R],
) -> Callable[P, R]:
    """Decorator to track active encryption operations via Gauge."""

    @functools.wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        active_encryption_operations.inc()
        try:
            return func(*args, **kwargs)
        finally:
            active_encryption_operations.dec()

    return wrapper


def observe_encryption_throughput(bytes_processed: int) -> None:
    """Record encrypted bytes into throughput histogram."""
    if bytes_processed < 0:
        raise ValueError("bytes_processed must be non-negative")
    encryption_throughput_bytes.observe(float(bytes_processed))


def increment_key_rotation_total(amount: int = 1) -> None:
    """Increment key rotation counter."""
    if amount <= 0:
        raise ValueError("amount must be positive")
    key_rotation_total.inc(amount)


__all__ = [
    "encryption_throughput_bytes",
    "decryption_latency_seconds",
    "key_rotation_total",
    "active_encryption_operations",
    "security_state",
    "set_security_state",
    "measure_time",
    "count_calls",
    "track_errors",
    "track_active_encryption",
    "observe_encryption_throughput",
    "increment_key_rotation_total",
]
