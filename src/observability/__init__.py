"""Observability namespace exports for tracing, logging, and audit ledger.

This package intentionally keeps integration non-invasive while exposing a
single import surface for newer observability components.
"""

from __future__ import annotations

from .audit_ledger import ImmutableAuditLedger
from .audit_event_schema import (
    AccessEvent,
    AuditEvent,
    ConfigChangeEvent,
    EncryptionEvent,
    KeyRotationEvent,
)
from .distributed_tracing import setup_tracing
from .structured_logging import StructuredLogger
from .audit_storage import (
    AuditFilter,
    AuditStorage,
    AuditStorageBackend,
    BlockchainAuditBackend,
    PostgreSQLAuditBackend,
    S3AuditBackend,
)

# Optional compatibility bridge so callers can continue using monitoring
# modules while importing from the observability namespace.
try:  # pragma: no cover - optional compatibility bridge
    from ..monitoring import *  # type: ignore[F403]
except Exception:
    pass

try:  # pragma: no cover - optional compatibility bridge
    from ..monitoring import metrics as monitoring_metrics
except Exception:
    monitoring_metrics = None  # type: ignore[assignment]

try:  # pragma: no cover - optional compatibility bridge
    from ..monitoring import security_events as monitoring_security_events
except Exception:
    monitoring_security_events = None  # type: ignore[assignment]

try:  # pragma: no cover - optional compatibility bridge
    from ..monitoring import telemetry as monitoring_telemetry
except Exception:
    monitoring_telemetry = None  # type: ignore[assignment]


__all__ = [
    "setup_tracing",
    "StructuredLogger",
    "ImmutableAuditLedger",
    "AuditEvent",
    "EncryptionEvent",
    "KeyRotationEvent",
    "AccessEvent",
    "ConfigChangeEvent",
    "AuditFilter",
    "AuditStorage",
    "AuditStorageBackend",
    "PostgreSQLAuditBackend",
    "S3AuditBackend",
    "BlockchainAuditBackend",
    "monitoring_metrics",
    "monitoring_security_events",
    "monitoring_telemetry",
]
