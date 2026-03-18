"""Structured security event logging aligned with OWASP recommendations.

Key properties:
- JSON event format
- Correlation IDs for traceability
- Sensitive data sanitization
- Optional forwarding to SIEM endpoints
"""

from __future__ import annotations

import json
import re
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib import request

from src.utils.logging import get_logger


logger = get_logger("src.monitoring.security_events")


SENSITIVE_KEYS = {
    "password",
    "passphrase",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "private_key",
    "key_material",
    "session_key",
    "authorization",
    "api_key",
    "credential",
}


EMAIL_RE = re.compile(r"([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*(@[A-Za-z0-9.-]+\.[A-Za-z]{2,})")


@dataclass(frozen=True)
class SIEMForwardTarget:
    """SIEM forwarding target using JSON-over-HTTP."""

    url: str
    api_key: str | None = None
    timeout_seconds: float = 3.0


class SecurityEventLogger:
    """JSON security event logger with optional SIEM forwarding."""

    def __init__(
        self,
        *,
        service_name: str = "keycrypt-shield-x",
        environment: str = "production",
        default_actor_type: str = "user",
        local_jsonl_path: str | Path | None = None,
        forward_targets: list[SIEMForwardTarget] | None = None,
    ) -> None:
        self.service_name = service_name
        self.environment = environment
        self.default_actor_type = default_actor_type
        self.local_jsonl_path = Path(local_jsonl_path) if local_jsonl_path else None
        self.forward_targets = forward_targets or []

        if self.local_jsonl_path is not None:
            self.local_jsonl_path.parent.mkdir(parents=True, exist_ok=True)

    def log_authentication(
        self,
        user: str,
        method: str,
        result: str,
        metadata: dict[str, Any] | None = None,
        *,
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        """Log authentication event with outcome and metadata."""
        event = self._build_event(
            event_type="authentication",
            action="authenticate",
            result=result,
            actor={"id": user, "type": self.default_actor_type},
            target={"auth_method": method},
            metadata=metadata,
            correlation_id=correlation_id,
            severity="INFO" if result.lower() in {"success", "allow"} else "WARNING",
        )
        self._emit(event)
        return event

    def log_authorization(
        self,
        user: str,
        resource: str,
        action: str,
        decision: str,
        *,
        correlation_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Log authorization event and access decision."""
        event = self._build_event(
            event_type="authorization",
            action=action,
            result=decision,
            actor={"id": user, "type": self.default_actor_type},
            target={"resource": resource},
            metadata=metadata,
            correlation_id=correlation_id,
            severity="INFO" if decision.lower() in {"allow", "granted", "success"} else "WARNING",
        )
        self._emit(event)
        return event

    def log_encryption(
        self,
        file: str,
        algorithm: str,
        key_id: str,
        duration: float,
        *,
        correlation_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Log encryption operation telemetry as a security event."""
        event = self._build_event(
            event_type="encryption",
            action="encrypt",
            result="success",
            actor={"id": "system", "type": "service"},
            target={"file": file, "algorithm": algorithm, "key_id": key_id},
            metadata={"duration_seconds": duration, **(metadata or {})},
            correlation_id=correlation_id,
            severity="INFO",
        )
        self._emit(event)
        return event

    def log_key_rotation(
        self,
        old_key_id: str,
        new_key_id: str,
        reason: str,
        *,
        correlation_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Log key rotation lifecycle event."""
        event = self._build_event(
            event_type="key_management",
            action="rotate_key",
            result="success",
            actor={"id": "key_manager", "type": "service"},
            target={"old_key_id": old_key_id, "new_key_id": new_key_id},
            metadata={"reason": reason, **(metadata or {})},
            correlation_id=correlation_id,
            severity="WARNING",
        )
        self._emit(event)
        return event

    def log_security_state_change(
        self,
        old_state: str,
        new_state: str,
        trigger: str,
        *,
        correlation_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Log transition between security posture states."""
        severity = "INFO"
        if new_state.upper() in {"ELEVATED", "CRITICAL"}:
            severity = "WARNING"
        if new_state.upper() == "CRITICAL":
            severity = "ERROR"

        event = self._build_event(
            event_type="security_state",
            action="state_change",
            result="success",
            actor={"id": "security_controller", "type": "service"},
            target={"old_state": old_state, "new_state": new_state},
            metadata={"trigger": trigger, **(metadata or {})},
            correlation_id=correlation_id,
            severity=severity,
        )
        self._emit(event)
        return event

    def _build_event(
        self,
        *,
        event_type: str,
        action: str,
        result: str,
        actor: dict[str, Any],
        target: dict[str, Any],
        metadata: dict[str, Any] | None,
        correlation_id: str | None,
        severity: str,
    ) -> dict[str, Any]:
        event = {
            "event_id": str(uuid.uuid4()),
            "correlation_id": correlation_id or str(uuid.uuid4()),
            "timestamp": time.time(),
            "service": self.service_name,
            "environment": self.environment,
            "event_type": event_type,
            "action": action,
            "result": result,
            "severity": severity,
            "actor": actor,
            "target": target,
            "metadata": metadata or {},
        }
        return self._sanitize(event)

    def _sanitize(self, payload: Any) -> Any:
        if isinstance(payload, dict):
            sanitized: dict[str, Any] = {}
            for key, value in payload.items():
                key_lower = str(key).lower()
                if key_lower in SENSITIVE_KEYS:
                    sanitized[key] = "[REDACTED]"
                else:
                    sanitized[key] = self._sanitize(value)
            return sanitized

        if isinstance(payload, list):
            return [self._sanitize(item) for item in payload]

        if isinstance(payload, str):
            masked = EMAIL_RE.sub(r"\1***\2", payload)
            if len(masked) > 2048:
                return masked[:2048] + "...[TRUNCATED]"
            return masked

        return payload

    def _emit(self, event: dict[str, Any]) -> None:
        line = json.dumps(event, separators=(",", ":"), sort_keys=True)
        logger.info("security_event={line}", line=line)

        if self.local_jsonl_path is not None:
            with self.local_jsonl_path.open("a", encoding="utf-8") as handle:
                handle.write(line)
                handle.write("\n")

        if self.forward_targets:
            self._forward_to_siem(event)

    def _forward_to_siem(self, event: dict[str, Any]) -> None:
        payload = json.dumps(event, separators=(",", ":"), sort_keys=True).encode("utf-8")

        for target in self.forward_targets:
            headers = {"Content-Type": "application/json"}
            if target.api_key:
                headers["Authorization"] = f"Bearer {target.api_key}"

            req = request.Request(
                url=target.url,
                data=payload,
                headers=headers,
                method="POST",
            )

            try:
                with request.urlopen(req, timeout=target.timeout_seconds) as resp:
                    _ = resp.read(16)
            except Exception as exc:
                logger.warning(
                    "siem_forward_failed url={url} error={error}",
                    url=target.url,
                    error=str(exc),
                )


__all__ = ["SecurityEventLogger", "SIEMForwardTarget"]
