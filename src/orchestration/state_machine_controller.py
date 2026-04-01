"""Security state transition controller with hysteresis and event emission.

This module manages state transitions for system security posture using
threshold-based rules, consecutive-evaluation hysteresis, and monitoring events
for every applied state change.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.monitoring.security_events import SecurityEventLogger

try:
    from src.core.security_states import SecurityStates as SecurityState
except Exception:
    # Fallback keeps this controller import-safe until core enum is available.
    from enum import Enum

    class SecurityState(Enum):
        LOW = "LOW"
        NORMAL = "NORMAL"
        ELEVATED = "ELEVATED"
        CRITICAL = "CRITICAL"
        LOCKDOWN = "LOCKDOWN"


@dataclass(frozen=True)
class SecurityMetrics:
    """Operational metrics used for transition evaluation.

    Attributes:
        risk_score: Normalized risk score in [0.0, 1.0].
        failed_auth: Recent failed authentication count.
        active_attack: Indicates active attack detection.
        imminent_breach: Indicates immediate breach likelihood.
        manual_trigger: Indicates operator-triggered lockdown intent.
    """

    risk_score: float
    failed_auth: int = 0
    active_attack: bool = False
    imminent_breach: bool = False
    manual_trigger: bool = False


class StateMachineController:
    """Manages security posture state transitions with hysteresis.

    Transition rules:
    - LOW -> NORMAL: risk_score > 0.3
    - NORMAL -> ELEVATED: risk_score > 0.6 or failed_auth > 10
    - ELEVATED -> CRITICAL: risk_score > 0.8 or active_attack
    - CRITICAL -> LOCKDOWN: imminent_breach or manual_trigger

    Hysteresis:
    - A transition is applied only after three consecutive evaluations produce
      the same next-state candidate.
    """

    def __init__(
        self,
        *,
        initial_state: SecurityState | None = None,
        event_logger: SecurityEventLogger | None = None,
        hysteresis_count: int = 3,
    ) -> None:
        self._state_low = self._state_value("LOW")
        self._state_normal = self._state_value("NORMAL")
        self._state_elevated = self._state_value("ELEVATED")
        self._state_critical = self._state_value("CRITICAL")
        self._state_lockdown = self._state_value("LOCKDOWN")

        self._current_state: SecurityState = initial_state or self._state_normal
        self._event_logger = event_logger or SecurityEventLogger(default_actor_type="service")

        self._hysteresis_count = max(1, int(hysteresis_count))
        self._pending_state: SecurityState | None = None
        self._pending_evaluations = 0

    def evaluate_state_transition(self, current_state: SecurityState, metrics: SecurityMetrics) -> SecurityState:
        """Evaluate and apply transition rules from the current state.

        Args:
            current_state: Current security state.
            metrics: Latest security telemetry metrics.

        Returns:
            Effective state after evaluation and hysteresis checks.
        """
        self._validate_metrics(metrics)

        if current_state != self._current_state:
            self._current_state = current_state
            self._reset_hysteresis()

        candidate = self._compute_candidate_state(current_state, metrics)

        if candidate == current_state:
            self._reset_hysteresis()
            return current_state

        if candidate == self._pending_state:
            self._pending_evaluations += 1
        else:
            self._pending_state = candidate
            self._pending_evaluations = 1

        if self._pending_evaluations < self._hysteresis_count:
            return current_state

        reason = self._build_reason(current_state=current_state, next_state=candidate, metrics=metrics)
        self.trigger_state_change(candidate, reason)
        self._reset_hysteresis()
        return self._current_state

    def trigger_state_change(self, new_state: SecurityState, reason: str) -> None:
        """Apply state change and emit monitoring event.

        Args:
            new_state: Target security state.
            reason: Human-readable trigger reason for auditing.
        """
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("reason must be a non-empty string")

        old_state = self._current_state
        if new_state == old_state:
            return

        self._current_state = new_state

        self._event_logger.log_security_state_change(
            old_state=self._state_name(old_state),
            new_state=self._state_name(new_state),
            trigger=reason.strip(),
            metadata={
                "controller": self.__class__.__name__,
                "hysteresis_required": self._hysteresis_count,
            },
        )

    def get_current_state(self) -> SecurityState:
        """Return currently active security state."""
        return self._current_state

    def _compute_candidate_state(self, current_state: SecurityState, metrics: SecurityMetrics) -> SecurityState:
        if current_state == self._state_low:
            if metrics.risk_score > 0.3:
                return self._state_normal
            return current_state

        if current_state == self._state_normal:
            if metrics.risk_score > 0.6 or metrics.failed_auth > 10:
                return self._state_elevated
            return current_state

        if current_state == self._state_elevated:
            if metrics.risk_score > 0.8 or metrics.active_attack:
                return self._state_critical
            return current_state

        if current_state == self._state_critical:
            if metrics.imminent_breach or metrics.manual_trigger:
                return self._state_lockdown
            return current_state

        return current_state

    def _build_reason(
        self,
        *,
        current_state: SecurityState,
        next_state: SecurityState,
        metrics: SecurityMetrics,
    ) -> str:
        if current_state == self._state_low and next_state == self._state_normal:
            return f"risk_score={metrics.risk_score:.3f} exceeded LOW->NORMAL threshold 0.3"

        if current_state == self._state_normal and next_state == self._state_elevated:
            if metrics.failed_auth > 10:
                return f"failed_auth={metrics.failed_auth} exceeded NORMAL->ELEVATED threshold 10"
            return f"risk_score={metrics.risk_score:.3f} exceeded NORMAL->ELEVATED threshold 0.6"

        if current_state == self._state_elevated and next_state == self._state_critical:
            if metrics.active_attack:
                return "active_attack detected during ELEVATED state"
            return f"risk_score={metrics.risk_score:.3f} exceeded ELEVATED->CRITICAL threshold 0.8"

        if current_state == self._state_critical and next_state == self._state_lockdown:
            if metrics.manual_trigger:
                return "manual lockdown trigger requested"
            return "imminent_breach detected"

        return "security state transition conditions met"

    def _reset_hysteresis(self) -> None:
        self._pending_state = None
        self._pending_evaluations = 0

    @staticmethod
    def _validate_metrics(metrics: SecurityMetrics) -> None:
        if not 0.0 <= float(metrics.risk_score) <= 1.0:
            raise ValueError("risk_score must be in range [0.0, 1.0]")
        if int(metrics.failed_auth) < 0:
            raise ValueError("failed_auth must be >= 0")

    @staticmethod
    def _state_name(value: Any) -> str:
        return str(getattr(value, "name", value))

    @staticmethod
    def _state_value(name: str) -> SecurityState:
        state = getattr(SecurityState, name, None)
        if state is None:
            raise ValueError(f"SecurityState enum does not define required state: {name}")
        return state


__all__ = [
    "SecurityState",
    "SecurityMetrics",
    "StateMachineController",
]
