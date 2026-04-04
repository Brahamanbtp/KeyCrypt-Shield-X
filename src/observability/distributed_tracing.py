"""Distributed tracing setup and non-invasive span instrumentation.

This module integrates OpenTelemetry when available and degrades gracefully to
no-op tracing when optional dependencies are missing.
"""

from __future__ import annotations

import asyncio
import os
import threading
import time
from functools import wraps
from typing import Any, Callable, Mapping, ParamSpec, TypeVar, cast

P = ParamSpec("P")
R = TypeVar("R")

try:  # pragma: no cover - optional dependency boundary
    from opentelemetry import trace as otel_trace
    from opentelemetry.trace import Status, StatusCode
except Exception:  # pragma: no cover - optional dependency boundary
    otel_trace = None  # type: ignore[assignment]
    Status = None  # type: ignore[assignment]
    StatusCode = None  # type: ignore[assignment]

try:  # pragma: no cover - optional dependency boundary
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
except Exception:  # pragma: no cover - optional dependency boundary
    Resource = None  # type: ignore[assignment]
    TracerProvider = None  # type: ignore[assignment]
    BatchSpanProcessor = None  # type: ignore[assignment]

try:  # pragma: no cover - optional dependency boundary
    from opentelemetry.exporter.jaeger.thrift import JaegerExporter
except Exception:  # pragma: no cover - optional dependency boundary
    JaegerExporter = None  # type: ignore[assignment]

try:  # pragma: no cover - optional dependency boundary
    from opentelemetry.exporter.zipkin.json import ZipkinExporter
except Exception:  # pragma: no cover - optional dependency boundary
    ZipkinExporter = None  # type: ignore[assignment]

try:  # pragma: no cover - optional dependency boundary
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
except Exception:  # pragma: no cover - optional dependency boundary
    OTLPSpanExporter = None  # type: ignore[assignment]


_setup_lock = threading.RLock()
_setup_complete = False
_last_setup_metadata: dict[str, Any] = {
    "enabled": False,
    "exporters": [],
}


class _NoopSpan:
    def __enter__(self) -> "_NoopSpan":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        _ = (exc_type, exc, tb)
        return False

    def set_attribute(self, key: str, value: Any) -> None:
        _ = (key, value)

    def record_exception(self, exc: BaseException) -> None:
        _ = exc

    def set_status(self, status: Any) -> None:
        _ = status


class _NoopTracer:
    def start_as_current_span(self, name: str, **kwargs: Any) -> _NoopSpan:
        _ = (name, kwargs)
        return _NoopSpan()


_NOOP_TRACER = _NoopTracer()


def setup_tracing(
    *,
    service_name: str = "keycrypt-shield-x",
    service_version: str | None = None,
    instrumentation_name: str = "src.observability.distributed_tracing",
    jaeger_endpoint: str | None = None,
    zipkin_endpoint: str | None = None,
    otlp_endpoint: str | None = None,
    otlp_headers: Mapping[str, str] | None = None,
) -> Any:
    """Initialize OpenTelemetry tracing and return tracer instance.

    Exporters are configured when their endpoint is provided directly or via
    environment variables:
    - Jaeger: KEYCRYPT_TRACE_JAEGER_ENDPOINT or JAEGER_ENDPOINT
    - Zipkin: KEYCRYPT_TRACE_ZIPKIN_ENDPOINT or ZIPKIN_ENDPOINT
    - OTLP: KEYCRYPT_TRACE_OTLP_ENDPOINT or OTEL_EXPORTER_OTLP_ENDPOINT

    The function is idempotent and does not raise when OpenTelemetry packages
    are unavailable.
    """
    if otel_trace is None:
        _last_setup_metadata.update({"enabled": False, "reason": "opentelemetry-api-unavailable"})
        return _NOOP_TRACER

    if Resource is None or TracerProvider is None or BatchSpanProcessor is None:
        _last_setup_metadata.update({"enabled": False, "reason": "opentelemetry-sdk-unavailable"})
        return otel_trace.get_tracer(instrumentation_name, service_version)

    resolved_jaeger = _normalize_endpoint(
        jaeger_endpoint,
        env_keys=("KEYCRYPT_TRACE_JAEGER_ENDPOINT", "JAEGER_ENDPOINT"),
    )
    resolved_zipkin = _normalize_endpoint(
        zipkin_endpoint,
        env_keys=("KEYCRYPT_TRACE_ZIPKIN_ENDPOINT", "ZIPKIN_ENDPOINT"),
    )
    resolved_otlp = _normalize_endpoint(
        otlp_endpoint,
        env_keys=("KEYCRYPT_TRACE_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_ENDPOINT"),
    )

    with _setup_lock:
        global _setup_complete
        if not _setup_complete:
            resource = Resource.create(
                {
                    "service.name": service_name,
                    "service.version": service_version or os.getenv("KEYCRYPT_VERSION", "0.1.0"),
                    "deployment.environment": os.getenv("KEYCRYPT_ENV", "development"),
                }
            )

            provider = TracerProvider(resource=resource)
            configured_exporters = _configure_exporters(
                provider=provider,
                jaeger_endpoint=resolved_jaeger,
                zipkin_endpoint=resolved_zipkin,
                otlp_endpoint=resolved_otlp,
                otlp_headers=otlp_headers,
            )

            otel_trace.set_tracer_provider(provider)
            _setup_complete = True
            _last_setup_metadata.update(
                {
                    "enabled": True,
                    "configured_at": time.time(),
                    "exporters": configured_exporters,
                }
            )

    return otel_trace.get_tracer(instrumentation_name, service_version)


def trace_operation(
    span_name: str | None = None,
    *,
    attributes: Mapping[str, Any] | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Decorator that creates a span around sync and async operations."""

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        resolved_span_name = span_name or f"{func.__module__}.{func.__qualname__}"

        if asyncio.iscoroutinefunction(func):

            @wraps(func)
            async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> Any:
                tracer = _get_tracer(func.__module__)
                with _safe_start_span(tracer, resolved_span_name) as span:
                    _set_span_defaults(span, func, attributes)
                    try:
                        return await cast(Callable[..., Any], func)(*args, **kwargs)
                    except Exception as exc:
                        _record_exception(span, exc)
                        raise

            return cast(Callable[P, R], async_wrapper)

        @wraps(func)
        def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> Any:
            tracer = _get_tracer(func.__module__)
            with _safe_start_span(tracer, resolved_span_name) as span:
                _set_span_defaults(span, func, attributes)
                try:
                    return cast(Callable[..., Any], func)(*args, **kwargs)
                except Exception as exc:
                    _record_exception(span, exc)
                    raise

        return cast(Callable[P, R], sync_wrapper)

    return decorator


def get_tracing_setup_metadata() -> dict[str, Any]:
    """Return last setup metadata for diagnostics/debugging."""
    return dict(_last_setup_metadata)


def _configure_exporters(
    *,
    provider: Any,
    jaeger_endpoint: str | None,
    zipkin_endpoint: str | None,
    otlp_endpoint: str | None,
    otlp_headers: Mapping[str, str] | None,
) -> list[str]:
    configured: list[str] = []

    if jaeger_endpoint and JaegerExporter is not None:
        jaeger = JaegerExporter(collector_endpoint=jaeger_endpoint)
        provider.add_span_processor(BatchSpanProcessor(jaeger))
        configured.append("jaeger")

    if zipkin_endpoint and ZipkinExporter is not None:
        zipkin = ZipkinExporter(endpoint=zipkin_endpoint)
        provider.add_span_processor(BatchSpanProcessor(zipkin))
        configured.append("zipkin")

    if otlp_endpoint and OTLPSpanExporter is not None:
        headers = dict(otlp_headers or {})
        otlp = OTLPSpanExporter(endpoint=otlp_endpoint, headers=headers)
        provider.add_span_processor(BatchSpanProcessor(otlp))
        configured.append("otlp")

    return configured


def _normalize_endpoint(value: str | None, *, env_keys: tuple[str, ...]) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()

    for key in env_keys:
        env_value = os.getenv(key)
        if isinstance(env_value, str) and env_value.strip():
            return env_value.strip()

    return None


def _get_tracer(module_name: str) -> Any:
    if otel_trace is None:
        return _NOOP_TRACER
    try:
        return otel_trace.get_tracer(module_name)
    except Exception:
        return _NOOP_TRACER


def _safe_start_span(tracer: Any, span_name: str) -> Any:
    try:
        return tracer.start_as_current_span(span_name)
    except Exception:
        return _NOOP_TRACER.start_as_current_span(span_name)


def _set_span_defaults(span: Any, func: Callable[..., Any], attributes: Mapping[str, Any] | None) -> None:
    _safe_set_attribute(span, "code.function", func.__qualname__)
    _safe_set_attribute(span, "code.module", func.__module__)

    if not attributes:
        return

    for key, value in attributes.items():
        if not isinstance(key, str) or not key:
            continue
        _safe_set_attribute(span, key, _coerce_attribute_value(value))


def _record_exception(span: Any, exc: Exception) -> None:
    try:
        span.record_exception(exc)
    except Exception:
        pass

    _safe_set_attribute(span, "error", True)
    _safe_set_attribute(span, "error.type", exc.__class__.__name__)
    _safe_set_attribute(span, "error.message", str(exc))

    if Status is None or StatusCode is None:
        return

    try:
        span.set_status(Status(StatusCode.ERROR, str(exc)))
    except Exception:
        pass


def _safe_set_attribute(span: Any, key: str, value: Any) -> None:
    try:
        span.set_attribute(key, value)
    except Exception:
        return


def _coerce_attribute_value(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value

    if isinstance(value, (list, tuple)):
        coerced = [item for item in value if isinstance(item, (bool, int, float, str))]
        if coerced:
            return coerced

    return repr(value)


__all__ = [
    "setup_tracing",
    "trace_operation",
    "get_tracing_setup_metadata",
]
