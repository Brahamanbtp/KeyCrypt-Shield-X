"""OpenTelemetry-compatible span processor with enrichment and export.

The processor enriches spans with system, security, and performance metadata,
supports deterministic sampling for high-volume systems, and exports batches to
 multiple backends.
"""

from __future__ import annotations

import contextvars
import hashlib
import json
import os
import platform
import threading
import time
from typing import Any, Mapping, Sequence

try:  # pragma: no cover - optional dependency boundary
    from opentelemetry.sdk.trace import Span as OTelSpan
    from opentelemetry.sdk.trace import SpanProcessor as OTelBaseSpanProcessor
    from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SpanExportResult
    from opentelemetry.trace import Span, format_span_id, format_trace_id
except Exception:  # pragma: no cover - optional dependency boundary
    OTelSpan = Any  # type: ignore[assignment]

    class OTelBaseSpanProcessor:  # type: ignore[no-redef]
        """Fallback OpenTelemetry base when SDK is unavailable."""

    class SpanExportResult:  # type: ignore[no-redef]
        SUCCESS = "success"
        FAILURE = "failure"

    Span = Any  # type: ignore[assignment]
    ConsoleSpanExporter = None  # type: ignore[assignment]
    format_trace_id = None  # type: ignore[assignment]
    format_span_id = None  # type: ignore[assignment]

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

try:  # pragma: no cover - optional dependency boundary
    import psutil
except Exception:  # pragma: no cover - optional dependency boundary
    psutil = None  # type: ignore[assignment]


_SECURITY_CONTEXT: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar(
    "keycrypt_span_security_context",
    default=None,
)


def set_security_context(
    *,
    user_id: str | None = None,
    security_state: str | None = None,
    encryption_algorithm: str | None = None,
    extra: Mapping[str, Any] | None = None,
) -> contextvars.Token[dict[str, Any] | None]:
    """Bind security metadata for span enrichment in current async context."""
    payload: dict[str, Any] = {}
    if user_id is not None:
        payload["user_id"] = str(user_id)
    if security_state is not None:
        payload["security_state"] = str(security_state)
    if encryption_algorithm is not None:
        payload["encryption_algorithm"] = str(encryption_algorithm)
    if extra:
        payload.update({str(k): v for k, v in extra.items()})

    if not payload:
        payload = {}
    return _SECURITY_CONTEXT.set(payload)


def reset_security_context(token: contextvars.Token[dict[str, Any] | None]) -> None:
    """Reset previously bound security context token."""
    _SECURITY_CONTEXT.reset(token)


class SpanProcessor(OTelBaseSpanProcessor):
    """Enriching span processor with sampling and multi-export support."""

    def __init__(
        self,
        *,
        exporters: Sequence[str] | None = None,
        jaeger_endpoint: str | None = None,
        zipkin_endpoint: str | None = None,
        otlp_endpoint: str | None = None,
        otlp_headers: Mapping[str, str] | None = None,
        sample_rate: float = 0.01,
        sample_errors_always: bool = True,
        batch_size: int = 128,
    ) -> None:
        if not 0.0 < float(sample_rate) <= 1.0:
            raise ValueError("sample_rate must be within (0, 1]")
        if int(batch_size) <= 0:
            raise ValueError("batch_size must be > 0")

        self._sample_rate = float(sample_rate)
        self._sample_errors_always = bool(sample_errors_always)
        self._batch_size = int(batch_size)

        self._hostname = platform.node() or os.getenv("HOSTNAME", "unknown-host")
        self._process_id = os.getpid()
        self._python_version = platform.python_version()

        self._lock = threading.RLock()
        self._exporters: list[Any] = []
        self._pending_batch: list[Span] = []
        self._span_start_perf: dict[tuple[str, str], tuple[float, int]] = {}
        self._span_end_perf: dict[tuple[str, str], tuple[float, int]] = {}

        self._initialize_exporters(
            exporters=tuple(exporters or ("console",)),
            jaeger_endpoint=jaeger_endpoint,
            zipkin_endpoint=zipkin_endpoint,
            otlp_endpoint=otlp_endpoint,
            otlp_headers=otlp_headers,
        )

    def on_start(self, span: Span, parent_context: Any | None = None) -> None:  # type: ignore[override]
        """Enrich a span at start with system + security metadata."""
        _ = parent_context

        self._safe_set_attribute(span, "system.hostname", self._hostname)
        self._safe_set_attribute(span, "system.process_id", self._process_id)
        self._safe_set_attribute(span, "system.python_version", self._python_version)

        security = _SECURITY_CONTEXT.get() or {}
        self._safe_set_attribute(span, "security.user_id", security.get("user_id", "unknown"))
        self._safe_set_attribute(span, "security.security_state", security.get("security_state", "unknown"))
        self._safe_set_attribute(
            span,
            "security.encryption_algorithm",
            security.get("encryption_algorithm", "unknown"),
        )

        # Include additional security labels without overriding canonical fields.
        for key, value in security.items():
            normalized = str(key).strip().lower()
            if normalized in {"user_id", "security_state", "encryption_algorithm"}:
                continue
            self._safe_set_attribute(span, f"security.{normalized}", value)

        identity = self._span_identity(span)
        if identity is None:
            return

        with self._lock:
            self._span_start_perf[identity] = (
                time.process_time(),
                self._current_memory_bytes(),
            )

    def on_end(self, span: Span) -> None:  # type: ignore[override]
        """Capture end performance data and enqueue sampled spans for export."""
        identity = self._span_identity(span)
        if identity is None:
            return

        end_cpu = time.process_time()
        end_mem = self._current_memory_bytes()

        with self._lock:
            start_perf = self._span_start_perf.pop(identity, None)

        cpu_delta = 0.0
        mem_delta = 0
        if start_perf is not None:
            cpu_delta = max(0.0, end_cpu - start_perf[0])
            mem_delta = max(0, end_mem - start_perf[1])

        self._safe_set_attribute(span, "performance.cpu_time", cpu_delta)
        self._safe_set_attribute(span, "performance.memory_allocated", mem_delta)

        with self._lock:
            self._span_end_perf[identity] = (cpu_delta, mem_delta)

            if not self._should_sample(span):
                return

            self._pending_batch.append(span)
            if len(self._pending_batch) >= self._batch_size:
                batch = list(self._pending_batch)
                self._pending_batch.clear()
                self.export_spans(batch)

    def export_spans(self, spans: list[Span]) -> None:
        """Batch export spans to configured backends."""
        if not spans:
            return

        # Console structured export guarantees enriched visibility even if spans
        # are immutable at end-of-life in the SDK.
        if self._has_console_exporter_fallback():
            for span in spans:
                self._export_console_fallback(span)

        for exporter in self._exporters:
            if exporter is None:
                continue
            if self._is_console_fallback_marker(exporter):
                continue

            export = getattr(exporter, "export", None)
            if not callable(export):
                continue

            try:
                result = export(spans)
            except Exception:
                continue

            if result not in {getattr(SpanExportResult, "SUCCESS", None), None}:
                continue

    def force_flush(self, timeout_millis: int = 30_000) -> bool:  # type: ignore[override]
        """Flush buffered spans and invoke exporter-specific flush hooks."""
        _ = timeout_millis

        with self._lock:
            pending = list(self._pending_batch)
            self._pending_batch.clear()

        if pending:
            self.export_spans(pending)

        success = True
        for exporter in self._exporters:
            flush = getattr(exporter, "force_flush", None)
            if callable(flush):
                try:
                    flush()
                except Exception:
                    success = False
        return success

    def shutdown(self) -> None:  # type: ignore[override]
        """Flush and shutdown configured exporters."""
        self.force_flush()

        for exporter in self._exporters:
            shutdown = getattr(exporter, "shutdown", None)
            if callable(shutdown):
                try:
                    shutdown()
                except Exception:
                    continue

    def _initialize_exporters(
        self,
        *,
        exporters: Sequence[str],
        jaeger_endpoint: str | None,
        zipkin_endpoint: str | None,
        otlp_endpoint: str | None,
        otlp_headers: Mapping[str, str] | None,
    ) -> None:
        normalized = [str(item).strip().lower() for item in exporters if str(item).strip()]
        if not normalized:
            normalized = ["console"]

        for name in normalized:
            if name == "console":
                if ConsoleSpanExporter is not None:
                    try:
                        self._exporters.append(ConsoleSpanExporter())
                    except Exception:
                        self._exporters.append("console-fallback")
                else:
                    self._exporters.append("console-fallback")
                continue

            if name == "jaeger" and JaegerExporter is not None:
                endpoint = (
                    jaeger_endpoint
                    or os.getenv("KEYCRYPT_TRACE_JAEGER_ENDPOINT")
                    or os.getenv("JAEGER_ENDPOINT")
                )
                if endpoint:
                    try:
                        self._exporters.append(JaegerExporter(collector_endpoint=endpoint))
                    except Exception:
                        continue
                continue

            if name == "zipkin" and ZipkinExporter is not None:
                endpoint = (
                    zipkin_endpoint
                    or os.getenv("KEYCRYPT_TRACE_ZIPKIN_ENDPOINT")
                    or os.getenv("ZIPKIN_ENDPOINT")
                )
                if endpoint:
                    try:
                        self._exporters.append(ZipkinExporter(endpoint=endpoint))
                    except Exception:
                        continue
                continue

            if name == "otlp" and OTLPSpanExporter is not None:
                endpoint = (
                    otlp_endpoint
                    or os.getenv("KEYCRYPT_TRACE_OTLP_ENDPOINT")
                    or os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
                )
                if endpoint:
                    try:
                        self._exporters.append(
                            OTLPSpanExporter(endpoint=endpoint, headers=dict(otlp_headers or {}))
                        )
                    except Exception:
                        continue

    def _should_sample(self, span: Span) -> bool:
        if self._sample_rate >= 1.0:
            return True

        if self._sample_errors_always and self._span_has_error(span):
            return True

        identity = self._span_identity(span)
        if identity is None:
            return False

        trace_id_hex, span_id_hex = identity
        digest = hashlib.sha256(f"{trace_id_hex}:{span_id_hex}".encode("utf-8")).digest()
        value = int.from_bytes(digest[:8], "big") / float(2**64 - 1)
        return value <= self._sample_rate

    def _span_identity(self, span: Span) -> tuple[str, str] | None:
        span_context = None
        get_context = getattr(span, "get_span_context", None)
        if callable(get_context):
            try:
                span_context = get_context()
            except Exception:
                span_context = None

        if span_context is None:
            return None

        trace_id = self._format_trace_id(getattr(span_context, "trace_id", 0))
        span_id = self._format_span_id(getattr(span_context, "span_id", 0))

        if trace_id is None or span_id is None:
            return None
        return trace_id, span_id

    def _span_has_error(self, span: Span) -> bool:
        status = getattr(span, "status", None)
        status_code = getattr(status, "status_code", None)
        if status_code is None:
            return False
        text = str(status_code).upper()
        return "ERROR" in text

    @staticmethod
    def _safe_set_attribute(span: Span, key: str, value: Any) -> None:
        setter = getattr(span, "set_attribute", None)
        if not callable(setter):
            return
        try:
            setter(key, value)
        except Exception:
            return

    def _current_memory_bytes(self) -> int:
        if psutil is not None:
            try:
                return int(psutil.Process(self._process_id).memory_info().rss)
            except Exception:
                return 0
        return 0

    @staticmethod
    def _format_trace_id(value: Any) -> str | None:
        try:
            as_int = int(value)
        except Exception:
            return None
        if as_int == 0:
            return None

        if callable(format_trace_id):
            try:
                return str(format_trace_id(as_int)).lower()
            except Exception:
                pass

        return f"{as_int:032x}"

    @staticmethod
    def _format_span_id(value: Any) -> str | None:
        try:
            as_int = int(value)
        except Exception:
            return None
        if as_int == 0:
            return None

        if callable(format_span_id):
            try:
                return str(format_span_id(as_int)).lower()
            except Exception:
                pass

        return f"{as_int:016x}"

    def _export_console_fallback(self, span: Span) -> None:
        identity = self._span_identity(span)
        trace_id, span_id = identity if identity is not None else ("unknown", "unknown")

        name = str(getattr(span, "name", "unnamed-span"))
        attributes = dict(getattr(span, "attributes", {}) or {})

        perf = self._span_end_perf.get(identity, (0.0, 0)) if identity is not None else (0.0, 0)
        payload = {
            "trace_id": trace_id,
            "span_id": span_id,
            "name": name,
            "attributes": attributes,
            "performance": {
                "cpu_time": float(perf[0]),
                "memory_allocated": int(perf[1]),
            },
        }
        print(json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True))

    def _has_console_exporter_fallback(self) -> bool:
        return any(self._is_console_fallback_marker(item) for item in self._exporters)

    @staticmethod
    def _is_console_fallback_marker(value: Any) -> bool:
        return isinstance(value, str) and value == "console-fallback"


__all__ = [
    "SpanProcessor",
    "set_security_context",
    "reset_security_context",
]
