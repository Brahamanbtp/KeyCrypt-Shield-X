"""W3C trace context propagation helpers for cross-component observability.

This module provides a lightweight OpenTelemetry-compatible trace context model
and propagation utilities for inter-service carriers.
"""

from __future__ import annotations

import contextvars
import re
import secrets
from dataclasses import dataclass, field
from typing import Any, Mapping
from urllib.parse import quote, unquote

try:  # pragma: no cover - optional dependency boundary
    from opentelemetry import baggage as otel_baggage
    from opentelemetry import trace as otel_trace
    from opentelemetry.trace import format_span_id, format_trace_id
except Exception:  # pragma: no cover - optional dependency boundary
    otel_baggage = None  # type: ignore[assignment]
    otel_trace = None  # type: ignore[assignment]
    format_span_id = None  # type: ignore[assignment]
    format_trace_id = None  # type: ignore[assignment]


_TRACEPARENT_RE = re.compile(
    r"^(?P<version>[0-9a-f]{2})-(?P<trace_id>[0-9a-f]{32})-(?P<span_id>[0-9a-f]{16})-(?P<flags>[0-9a-f]{2})$"
)
_HEX_TRACE_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_HEX_SPAN_ID_RE = re.compile(r"^[0-9a-f]{16}$")

_CURRENT_TRACE_CONTEXT: contextvars.ContextVar[TraceContext | None] = contextvars.ContextVar(
    "keycrypt_trace_context",
    default=None,
)


@dataclass(frozen=True)
class TraceContext:
    """W3C trace context envelope used across component boundaries."""

    trace_id: str
    span_id: str
    parent_span_id: str | None = None
    baggage: dict[str, str] = field(default_factory=dict)
    trace_flags: str = "01"

    def __post_init__(self) -> None:
        trace_id = self.trace_id.strip().lower()
        span_id = self.span_id.strip().lower()
        trace_flags = self.trace_flags.strip().lower()

        if not _HEX_TRACE_ID_RE.fullmatch(trace_id) or _is_all_zeros(trace_id):
            raise ValueError("trace_id must be a 32-char lowercase hex value and not all zeros")
        if not _HEX_SPAN_ID_RE.fullmatch(span_id) or _is_all_zeros(span_id):
            raise ValueError("span_id must be a 16-char lowercase hex value and not all zeros")
        if not re.fullmatch(r"[0-9a-f]{2}", trace_flags):
            raise ValueError("trace_flags must be a 2-char lowercase hex value")

        parent = self.parent_span_id
        if parent is not None:
            parent = parent.strip().lower()
            if not _HEX_SPAN_ID_RE.fullmatch(parent) or _is_all_zeros(parent):
                raise ValueError(
                    "parent_span_id must be a 16-char lowercase hex value and not all zeros"
                )

        normalized_baggage = _normalize_baggage(self.baggage)

        object.__setattr__(self, "trace_id", trace_id)
        object.__setattr__(self, "span_id", span_id)
        object.__setattr__(self, "trace_flags", trace_flags)
        object.__setattr__(self, "parent_span_id", parent)
        object.__setattr__(self, "baggage", normalized_baggage)

    def traceparent(self) -> str:
        """Render W3C traceparent header value."""
        return f"00-{self.trace_id}-{self.span_id}-{self.trace_flags}"


def create_trace_context(operation_name: str) -> TraceContext:
    """Create and bind a new trace context for the operation.

    If a current context exists, the new span continues the same trace and sets
    the current span id as parent_span_id.
    """
    if not isinstance(operation_name, str) or not operation_name.strip():
        raise ValueError("operation_name must be a non-empty string")

    parent = get_current_trace_context() or _trace_context_from_current_otel_span()

    if parent is not None:
        trace_id = parent.trace_id
        parent_span_id = parent.span_id
        baggage = dict(parent.baggage)
        trace_flags = parent.trace_flags
    else:
        trace_id = _new_trace_id()
        parent_span_id = None
        baggage = _current_otel_baggage()
        trace_flags = "01"

    context = TraceContext(
        trace_id=trace_id,
        span_id=_new_span_id(),
        parent_span_id=parent_span_id,
        baggage=baggage,
        trace_flags=trace_flags,
    )
    _CURRENT_TRACE_CONTEXT.set(context)
    return context


def inject_trace_context(context: TraceContext, carrier: dict[str, Any]) -> None:
    """Inject trace context into a mutable carrier using W3C headers."""
    if not isinstance(context, TraceContext):
        raise TypeError("context must be a TraceContext instance")
    if not isinstance(carrier, dict):
        raise TypeError("carrier must be a dictionary")

    carrier["traceparent"] = context.traceparent()

    if context.baggage:
        carrier["baggage"] = _encode_baggage(context.baggage)
    elif "baggage" in carrier:
        carrier.pop("baggage", None)

    if context.parent_span_id is not None:
        carrier["x-parent-span-id"] = context.parent_span_id

    _CURRENT_TRACE_CONTEXT.set(context)


def extract_trace_context(carrier: dict[str, Any]) -> TraceContext:
    """Extract and bind a trace context from a W3C-compliant carrier."""
    if not isinstance(carrier, Mapping):
        raise TypeError("carrier must be a mapping")

    header_lookup = {
        str(key).strip().lower(): value
        for key, value in carrier.items()
        if isinstance(key, str) and key.strip()
    }

    traceparent = _as_header_text(header_lookup.get("traceparent"))
    if not traceparent:
        raise ValueError("carrier missing required traceparent header")

    match = _TRACEPARENT_RE.fullmatch(traceparent.strip().lower())
    if match is None:
        raise ValueError("invalid traceparent header format")

    trace_id = match.group("trace_id")
    span_id = match.group("span_id")
    trace_flags = match.group("flags")

    if _is_all_zeros(trace_id) or _is_all_zeros(span_id):
        raise ValueError("traceparent contains invalid all-zero trace/span identifiers")

    parent_span_id = _as_header_text(header_lookup.get("x-parent-span-id"))
    if parent_span_id is not None:
        candidate_parent = parent_span_id.strip().lower()
        if not _HEX_SPAN_ID_RE.fullmatch(candidate_parent) or _is_all_zeros(candidate_parent):
            raise ValueError("x-parent-span-id must be a 16-char hex value and not all zeros")
        parent_span_id = candidate_parent

    baggage = _decode_baggage(_as_header_text(header_lookup.get("baggage")))

    context = TraceContext(
        trace_id=trace_id,
        span_id=span_id,
        parent_span_id=parent_span_id,
        baggage=baggage,
        trace_flags=trace_flags,
    )
    _CURRENT_TRACE_CONTEXT.set(context)
    return context


def get_current_trace_context() -> TraceContext | None:
    """Return currently bound context (propagates across async boundaries)."""
    return _CURRENT_TRACE_CONTEXT.get()


def clear_current_trace_context() -> None:
    """Clear the currently bound trace context."""
    _CURRENT_TRACE_CONTEXT.set(None)


def _trace_context_from_current_otel_span() -> TraceContext | None:
    if otel_trace is None or format_trace_id is None or format_span_id is None:
        return None

    try:
        span = otel_trace.get_current_span()
        span_context = span.get_span_context()
    except Exception:
        return None

    if span_context is None:
        return None
    if not bool(getattr(span_context, "is_valid", False)):
        return None

    try:
        trace_id = str(format_trace_id(span_context.trace_id)).lower()
        span_id = str(format_span_id(span_context.span_id)).lower()
        trace_flags_int = int(getattr(span_context, "trace_flags", 1)) & 0xFF
        trace_flags = f"{trace_flags_int:02x}"
    except Exception:
        return None

    try:
        return TraceContext(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=None,
            baggage=_current_otel_baggage(),
            trace_flags=trace_flags,
        )
    except Exception:
        return None


def _current_otel_baggage() -> dict[str, str]:
    if otel_baggage is None:
        return {}

    try:
        raw = otel_baggage.get_all()
    except Exception:
        return {}

    if not isinstance(raw, Mapping):
        return {}

    baggage: dict[str, str] = {}
    for key, value in raw.items():
        if key is None or value is None:
            continue
        baggage[str(key)] = str(value)
    return _normalize_baggage(baggage)


def _new_trace_id() -> str:
    while True:
        candidate = secrets.token_hex(16)
        if not _is_all_zeros(candidate):
            return candidate


def _new_span_id() -> str:
    while True:
        candidate = secrets.token_hex(8)
        if not _is_all_zeros(candidate):
            return candidate


def _encode_baggage(values: Mapping[str, str]) -> str:
    parts: list[str] = []
    for key, value in values.items():
        safe_key = str(key).strip()
        safe_value = str(value)
        if not safe_key:
            continue
        # W3C baggage values are URL-encoded for safe transport.
        parts.append(f"{quote(safe_key, safe='!#$%&\'*+-.^_`|~')}={quote(safe_value, safe='!#$%&\'*+-.^_`|~')}")
    return ",".join(parts)


def _decode_baggage(raw: str | None) -> dict[str, str]:
    if not raw:
        return {}

    output: dict[str, str] = {}
    for segment in raw.split(","):
        chunk = segment.strip()
        if not chunk:
            continue

        kv = chunk.split(";", 1)[0]
        if "=" not in kv:
            continue

        key_text, value_text = kv.split("=", 1)
        key = unquote(key_text).strip()
        value = unquote(value_text).strip()

        if not key:
            continue
        output[key] = value

    return _normalize_baggage(output)


def _normalize_baggage(values: Mapping[str, Any]) -> dict[str, str]:
    output: dict[str, str] = {}
    for key, value in values.items():
        key_text = str(key).strip()
        if not key_text:
            continue
        output[key_text] = str(value)
    return output


def _as_header_text(value: Any) -> str | None:
    if isinstance(value, str):
        text = value.strip()
        return text if text else None
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="ignore").strip()
        return text if text else None
    return None


def _is_all_zeros(value: str) -> bool:
    return all(ch == "0" for ch in value)


__all__ = [
    "TraceContext",
    "create_trace_context",
    "inject_trace_context",
    "extract_trace_context",
    "get_current_trace_context",
    "clear_current_trace_context",
]
