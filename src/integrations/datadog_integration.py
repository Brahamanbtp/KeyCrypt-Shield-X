"""Datadog integration for KeyCrypt metrics and APM.

This module preserves cloud monitoring integration and extends support for:
- Datadog metric submission with automatic environment/service/version tags
- Datadog event publishing
- APM tracing context manager and decorator via ddtrace
- custom metric aggregation strategies (gauge/count/rate)
"""

from __future__ import annotations

import functools
import inspect
import os
import time
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
from typing import Any, Callable, ContextManager, Mapping


try:  # pragma: no cover - optional dependency boundary
    from datadog import api as datadog_api
    from datadog import initialize as datadog_initialize
    from datadog import statsd as datadog_statsd
except Exception as exc:  # pragma: no cover - optional dependency boundary
    datadog_api = None  # type: ignore[assignment]
    datadog_initialize = None  # type: ignore[assignment]
    datadog_statsd = None  # type: ignore[assignment]
    _DATADOG_IMPORT_ERROR = exc
else:
    _DATADOG_IMPORT_ERROR = None

try:  # pragma: no cover - optional dependency boundary
    from ddtrace import tracer as ddtrace_tracer
except Exception as exc:  # pragma: no cover - optional dependency boundary
    ddtrace_tracer = None  # type: ignore[assignment]
    _DDTRACE_IMPORT_ERROR = exc
else:
    _DDTRACE_IMPORT_ERROR = None


_ALLOWED_AGGREGATIONS = {"gauge", "count", "rate"}
_ALLOWED_ALERT_TYPES = {"info", "success", "warning", "error"}


class DatadogIntegrationError(RuntimeError):
    """Raised when Datadog integration operations fail."""


@dataclass
class _DatadogConfig:
    api_key: str | None = None
    app_key: str | None = None
    initialized: bool = False

    environment: str = "development"
    service: str = "keycrypt"
    version: str = "0.0.0"

    initialize_func: Callable[..., Any] | None = None
    statsd_client: Any | None = None
    event_creator: Callable[..., Any] | None = None
    tracer: Any | None = None


_CONFIG = _DatadogConfig(
    environment=(os.getenv("KEYCRYPT_ENVIRONMENT") or os.getenv("DD_ENV") or "development"),
    service=(os.getenv("KEYCRYPT_SERVICE") or os.getenv("DD_SERVICE") or "keycrypt"),
    version=(os.getenv("KEYCRYPT_VERSION") or os.getenv("DD_VERSION") or "0.0.0"),
)

_METRIC_AGGREGATIONS: dict[str, str] = {}
_RATE_STATE: dict[str, tuple[float, float]] = {}


def configure_datadog_integration(
    *,
    environment: str | None = None,
    service: str | None = None,
    version: str | None = None,
    initialize_func: Callable[..., Any] | None = None,
    statsd_client: Any | None = None,
    event_creator: Callable[..., Any] | None = None,
    tracer: Any | None = None,
) -> None:
    """Configure Datadog integration runtime dependencies and default tags."""
    _CONFIG.environment = _validate_non_empty("environment", environment or _CONFIG.environment)
    _CONFIG.service = _validate_non_empty("service", service or _CONFIG.service)
    _CONFIG.version = _validate_non_empty("version", version or _CONFIG.version)

    if initialize_func is not None:
        _CONFIG.initialize_func = initialize_func
    if statsd_client is not None:
        _CONFIG.statsd_client = statsd_client
    if event_creator is not None:
        _CONFIG.event_creator = event_creator
    if tracer is not None:
        _CONFIG.tracer = tracer


def initialize_datadog(api_key: str, app_key: str) -> None:
    """Initialize Datadog client state for metrics/events/APM integration."""
    _CONFIG.api_key = _validate_non_empty("api_key", api_key)
    _CONFIG.app_key = _validate_non_empty("app_key", app_key)

    initializer = _resolve_initializer()
    constant_tags = _automatic_tags()

    try:
        initializer(api_key=_CONFIG.api_key, app_key=_CONFIG.app_key, statsd_constant_tags=constant_tags)
    except Exception as exc:
        raise DatadogIntegrationError(f"failed to initialize Datadog: {exc}") from exc

    _CONFIG.initialized = True


def register_metric_aggregation(metric_name: str, aggregation: str) -> None:
    """Configure aggregation strategy for a metric name.

    Supported aggregations:
    - gauge: send raw gauge values
    - count: send count increments
    - rate: derive rate from value delta/time and send as gauge
    """
    name = _normalize_metric_name(metric_name)
    normalized_aggregation = _normalize_aggregation(aggregation)
    _METRIC_AGGREGATIONS[name] = normalized_aggregation


def send_metric(metric_name: str, value: float, tags: list[str]) -> None:
    """Send a Datadog metric with configured aggregation strategy."""
    _ensure_initialized()

    name = _normalize_metric_name(metric_name)
    metric_value = float(value)
    submitted_tags = _merge_tags(tags)

    aggregation = _METRIC_AGGREGATIONS.get(name, "gauge")
    statsd = _resolve_statsd_client()

    if aggregation == "gauge":
        _statsd_gauge(statsd, name, metric_value, submitted_tags)
        return

    if aggregation == "count":
        _statsd_increment(statsd, name, metric_value, submitted_tags)
        return

    if aggregation == "rate":
        rate_value = _compute_rate(name, metric_value)
        _statsd_gauge(statsd, name, rate_value, submitted_tags)
        return

    raise DatadogIntegrationError(f"unsupported metric aggregation: {aggregation}")


def send_event(title: str, text: str, alert_type: str) -> None:
    """Send Datadog event with automatic integration tags."""
    _ensure_initialized()

    normalized_title = _validate_non_empty("title", title)
    normalized_text = _validate_non_empty("text", text)
    normalized_alert_type = _validate_non_empty("alert_type", alert_type).lower()

    if normalized_alert_type not in _ALLOWED_ALERT_TYPES:
        allowed = ", ".join(sorted(_ALLOWED_ALERT_TYPES))
        raise ValueError(f"alert_type must be one of: {allowed}")

    event_create = _resolve_event_creator()

    try:
        event_create(
            title=normalized_title,
            text=normalized_text,
            alert_type=normalized_alert_type,
            tags=_automatic_tags(),
            source_type_name="keycrypt",
        )
    except Exception as exc:
        raise DatadogIntegrationError(f"failed to send Datadog event: {exc}") from exc


def trace_operation(operation_name: str) -> ContextManager[Any]:
    """Return ddtrace context manager for tracing one operation."""
    _ensure_initialized()

    normalized_operation = _validate_non_empty("operation_name", operation_name)
    tracer = _resolve_tracer()

    trace_callable = getattr(tracer, "trace", None)
    if not callable(trace_callable):
        return nullcontext()

    @contextmanager
    def _trace_context() -> Any:
        with trace_callable(normalized_operation, service=_CONFIG.service, resource=normalized_operation) as span:
            _set_span_tag(span, "env", _CONFIG.environment)
            _set_span_tag(span, "service", _CONFIG.service)
            _set_span_tag(span, "version", _CONFIG.version)
            yield span

    return _trace_context()


def apm_trace(operation_name: str | None = None) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator for tracing sync and async functions with ddtrace."""

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        name = _validate_non_empty("operation_name", operation_name or func.__name__)

        if inspect.iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                with trace_operation(name):
                    return await func(*args, **kwargs)

            return async_wrapper

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            with trace_operation(name):
                return func(*args, **kwargs)

        return sync_wrapper

    return decorator


def _compute_rate(metric_name: str, value: float) -> float:
    now = time.time()

    state = _RATE_STATE.get(metric_name)
    if state is None:
        _RATE_STATE[metric_name] = (value, now)
        return 0.0

    prev_value, prev_ts = state
    elapsed = max(1e-6, now - prev_ts)
    rate = (value - prev_value) / elapsed

    _RATE_STATE[metric_name] = (value, now)
    return rate


def _statsd_gauge(statsd_client: Any, metric_name: str, value: float, tags: list[str]) -> None:
    gauge = getattr(statsd_client, "gauge", None)
    if not callable(gauge):
        raise DatadogIntegrationError("statsd client does not support gauge")
    gauge(metric_name, value, tags=tags)


def _statsd_increment(statsd_client: Any, metric_name: str, value: float, tags: list[str]) -> None:
    increment = getattr(statsd_client, "increment", None)
    if callable(increment):
        increment(metric_name, value=value, tags=tags)
        return

    count = getattr(statsd_client, "count", None)
    if callable(count):
        count(metric_name, value=value, tags=tags)
        return

    raise DatadogIntegrationError("statsd client does not support increment/count")


def _resolve_initializer() -> Callable[..., Any]:
    if _CONFIG.initialize_func is not None:
        return _CONFIG.initialize_func

    if callable(datadog_initialize):
        return datadog_initialize

    raise DatadogIntegrationError(
        "datadog.initialize is unavailable"
        + ("" if _DATADOG_IMPORT_ERROR is None else f" (import error: {_DATADOG_IMPORT_ERROR})")
    )


def _resolve_statsd_client() -> Any:
    if _CONFIG.statsd_client is not None:
        return _CONFIG.statsd_client

    if datadog_statsd is not None:
        return datadog_statsd

    raise DatadogIntegrationError(
        "datadog statsd client is unavailable"
        + ("" if _DATADOG_IMPORT_ERROR is None else f" (import error: {_DATADOG_IMPORT_ERROR})")
    )


def _resolve_event_creator() -> Callable[..., Any]:
    if _CONFIG.event_creator is not None:
        return _CONFIG.event_creator

    event_cls = getattr(datadog_api, "Event", None)
    create = getattr(event_cls, "create", None)
    if callable(create):
        return create

    raise DatadogIntegrationError(
        "datadog event API is unavailable"
        + ("" if _DATADOG_IMPORT_ERROR is None else f" (import error: {_DATADOG_IMPORT_ERROR})")
    )


def _resolve_tracer() -> Any:
    if _CONFIG.tracer is not None:
        return _CONFIG.tracer

    if ddtrace_tracer is not None:
        return ddtrace_tracer

    raise DatadogIntegrationError(
        "ddtrace tracer is unavailable"
        + ("" if _DDTRACE_IMPORT_ERROR is None else f" (import error: {_DDTRACE_IMPORT_ERROR})")
    )


def _automatic_tags() -> list[str]:
    return [
        f"env:{_CONFIG.environment}",
        f"service:{_CONFIG.service}",
        f"version:{_CONFIG.version}",
    ]


def _merge_tags(tags: list[str]) -> list[str]:
    if tags is None:
        tags = []
    if not isinstance(tags, list):
        raise TypeError("tags must be List[str]")

    merged: list[str] = []
    for entry in list(tags) + _automatic_tags():
        text = _validate_non_empty("tag", str(entry))
        if text not in merged:
            merged.append(text)
    return merged


def _set_span_tag(span: Any, key: str, value: str) -> None:
    setter = getattr(span, "set_tag", None)
    if callable(setter):
        setter(key, value)


def _ensure_initialized() -> None:
    if not _CONFIG.initialized:
        raise DatadogIntegrationError("Datadog integration is not initialized; call initialize_datadog first")


def _normalize_metric_name(metric_name: str) -> str:
    return _validate_non_empty("metric_name", metric_name).lower()


def _normalize_aggregation(aggregation: str) -> str:
    normalized = _validate_non_empty("aggregation", aggregation).lower()
    if normalized not in _ALLOWED_AGGREGATIONS:
        allowed = ", ".join(sorted(_ALLOWED_AGGREGATIONS))
        raise ValueError(f"aggregation must be one of: {allowed}")
    return normalized


def _validate_non_empty(field_name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value.strip()


__all__ = [
    "DatadogIntegrationError",
    "apm_trace",
    "configure_datadog_integration",
    "initialize_datadog",
    "register_metric_aggregation",
    "send_event",
    "send_metric",
    "trace_operation",
]
