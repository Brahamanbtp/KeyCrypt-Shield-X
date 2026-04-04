"""Structured event logging for observability and gradual migration.

This module introduces a structlog-based logger for domain events while
remaining non-invasive when structlog is unavailable in minimal runtimes.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
from datetime import UTC, datetime
from typing import Any

try:  # pragma: no cover - optional dependency boundary
    import structlog
except Exception:  # pragma: no cover - optional dependency boundary
    structlog = None  # type: ignore[assignment]


_configure_lock = threading.RLock()
_configured = False


class StructuredLogger:
    """Structured JSON logger for encryption and key-management events."""

    def __init__(
        self,
        *,
        logger_name: str = "keycrypt.structured",
        level: str | None = None,
    ) -> None:
        if not isinstance(logger_name, str) or not logger_name.strip():
            raise ValueError("logger_name must be a non-empty string")

        resolved_level = (level or os.getenv("KEYCRYPT_LOG_LEVEL", "INFO")).upper().strip()
        self._level_name = resolved_level
        self._logger_name = logger_name.strip()

        self._configure_logging_once(level_name=resolved_level)

        if structlog is not None:
            self._logger: Any = structlog.get_logger(self._logger_name)
        else:
            self._logger = logging.getLogger(self._logger_name)

    def log_encryption_event(
        self,
        algorithm: str,
        size: int,
        duration: float,
        user_id: str,
        trace_id: str,
    ) -> None:
        """Log an encryption event in structured JSON format."""
        self._require_non_empty("algorithm", algorithm)
        self._require_non_empty("user_id", user_id)
        self._require_non_empty("trace_id", trace_id)

        details = {
            "algorithm": algorithm.strip(),
            "size_bytes": int(size),
            "duration_seconds": float(duration),
            "user_id": user_id.strip(),
        }

        self._emit_event(
            level="info",
            event_type="encryption",
            trace_id=trace_id,
            details=details,
        )

    def log_key_rotation(
        self,
        old_key_id: str,
        new_key_id: str,
        reason: str,
        trace_id: str,
    ) -> None:
        """Log a key-rotation lifecycle event in structured JSON format."""
        self._require_non_empty("old_key_id", old_key_id)
        self._require_non_empty("new_key_id", new_key_id)
        self._require_non_empty("reason", reason)
        self._require_non_empty("trace_id", trace_id)

        details = {
            "old_key_id": old_key_id.strip(),
            "new_key_id": new_key_id.strip(),
            "reason": reason.strip(),
        }

        self._emit_event(
            level="warning",
            event_type="key_rotation",
            trace_id=trace_id,
            details=details,
        )

    @classmethod
    def _configure_logging_once(cls, *, level_name: str) -> None:
        global _configured
        with _configure_lock:
            if _configured:
                return

            level_value = cls._level_to_value(level_name)

            logging.basicConfig(
                level=level_value,
                stream=sys.stdout,
                format="%(message)s",
            )

            if structlog is not None:
                structlog.configure(
                    processors=[
                        structlog.contextvars.merge_contextvars,
                        structlog.processors.TimeStamper(fmt="iso", utc=True, key="timestamp"),
                        structlog.stdlib.add_log_level,
                        structlog.processors.JSONRenderer(sort_keys=True),
                    ],
                    logger_factory=structlog.stdlib.LoggerFactory(),
                    wrapper_class=structlog.stdlib.BoundLogger,
                    context_class=dict,
                    cache_logger_on_first_use=True,
                )

            _configured = True

    def _emit_event(
        self,
        *,
        level: str,
        event_type: str,
        trace_id: str,
        details: dict[str, Any],
    ) -> None:
        payload = {
            "event_type": event_type,
            "trace_id": trace_id,
            "details": details,
        }

        if structlog is not None:
            log_fn = getattr(self._logger, level, None)
            if callable(log_fn):
                log_fn("structured_event", **payload)
                return

        fallback_payload = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": level,
            "event_type": event_type,
            "trace_id": trace_id,
            "details": details,
        }
        self._logger.log(
            self._level_to_value(level),
            json.dumps(fallback_payload, separators=(",", ":"), sort_keys=True),
        )

    @staticmethod
    def _require_non_empty(name: str, value: str) -> None:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must be a non-empty string")

    @staticmethod
    def _level_to_value(level_name: str) -> int:
        normalized = level_name.upper().strip()
        return getattr(logging, normalized, logging.INFO)


__all__ = ["StructuredLogger"]
