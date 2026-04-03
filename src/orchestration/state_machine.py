"""Security state transition controller built on top of SecurityStates.

This module provides a small, deterministic state machine wrapper that
evaluates transitions against risk score and event triggers, while applying
hysteresis to avoid state flapping.
"""

from __future__ import annotations

from collections.abc import Iterable

from ..core.security_states import SecurityStates


class StateMachineController:
    """Evaluate and apply security-state transitions with hysteresis.

    Graph:
        LOW -> NORMAL -> ELEVATED -> CRITICAL -> LOCKDOWN

    Hysteresis:
        A proposed transition is applied only after it is triggered in
        `required_consecutive_triggers` consecutive evaluations.
    """

    _ORDER: tuple[SecurityStates, ...] = SecurityStates.ordered()
    _INDEX: dict[SecurityStates, int] = {state: idx for idx, state in enumerate(_ORDER)}

    _EVENT_TARGETS: dict[str, SecurityStates] = {
        "policy_violation": SecurityStates.ELEVATED,
        "auth_fail_spike": SecurityStates.ELEVATED,
        "suspicious_activity": SecurityStates.ELEVATED,
        "active_attack": SecurityStates.CRITICAL,
        "credential_compromise": SecurityStates.CRITICAL,
        "data_exfiltration": SecurityStates.CRITICAL,
        "manual_lockdown": SecurityStates.LOCKDOWN,
        "key_compromise": SecurityStates.LOCKDOWN,
        "imminent_breach": SecurityStates.LOCKDOWN,
    }

    def __init__(
        self,
        *,
        initial_state: SecurityStates = SecurityStates.NORMAL,
        required_consecutive_triggers: int = 3,
    ) -> None:
        if required_consecutive_triggers <= 0:
            raise ValueError("required_consecutive_triggers must be positive")

        self._current_state = self._coerce_state(initial_state)
        self._required_consecutive_triggers = int(required_consecutive_triggers)
        self._pending_transition: tuple[SecurityStates, SecurityStates] | None = None
        self._pending_count = 0

    def evaluate_transition(
        self,
        current_state: SecurityStates,
        risk_score: float,
        events: Iterable[str] | None,
    ) -> SecurityStates:
        """Evaluate transition from current state using risk and events.

        Args:
            current_state: Current security state.
            risk_score: Normalized risk score in [0.0, 1.0].
            events: Iterable of event names influencing escalation.

        Returns:
            New state when hysteresis threshold is met; otherwise current state.
        """
        state = self._coerce_state(current_state)
        score = self._coerce_risk_score(risk_score)
        event_set = self._normalize_events(events)

        if state != self._current_state:
            self._current_state = state
            self._reset_pending()

        target_state = self._target_state(score, event_set)
        candidate_state = self._step_toward_target(state, target_state)

        if candidate_state == state:
            self._reset_pending()
            return state

        transition = (state, candidate_state)
        if self._pending_transition == transition:
            self._pending_count += 1
        else:
            self._pending_transition = transition
            self._pending_count = 1

        if self._pending_count < self._required_consecutive_triggers:
            return state

        self._current_state = candidate_state
        self._reset_pending()
        return candidate_state

    def get_current_state(self) -> SecurityStates:
        """Return the internally tracked current state."""
        return self._current_state

    @classmethod
    def _target_state(cls, risk_score: float, events: set[str]) -> SecurityStates:
        if risk_score >= 0.90:
            risk_target = SecurityStates.LOCKDOWN
        elif risk_score >= 0.75:
            risk_target = SecurityStates.CRITICAL
        elif risk_score >= 0.55:
            risk_target = SecurityStates.ELEVATED
        elif risk_score >= 0.25:
            risk_target = SecurityStates.NORMAL
        else:
            risk_target = SecurityStates.LOW

        event_target = SecurityStates.LOW
        for event in events:
            mapped = cls._EVENT_TARGETS.get(event)
            if mapped is None:
                continue
            if cls._INDEX[mapped] > cls._INDEX[event_target]:
                event_target = mapped

        return risk_target if cls._INDEX[risk_target] >= cls._INDEX[event_target] else event_target

    @classmethod
    def _step_toward_target(cls, current_state: SecurityStates, target_state: SecurityStates) -> SecurityStates:
        current_idx = cls._INDEX[current_state]
        target_idx = cls._INDEX[target_state]

        if target_idx > current_idx:
            return cls._ORDER[current_idx + 1]
        if target_idx < current_idx:
            return cls._ORDER[current_idx - 1]
        return current_state

    @staticmethod
    def _coerce_state(value: SecurityStates) -> SecurityStates:
        if isinstance(value, SecurityStates):
            return value
        raise TypeError("current_state must be a SecurityStates value")

    @staticmethod
    def _coerce_risk_score(value: float) -> float:
        score = float(value)
        if not 0.0 <= score <= 1.0:
            raise ValueError("risk_score must be in range [0.0, 1.0]")
        return score

    @staticmethod
    def _normalize_events(events: Iterable[str] | None) -> set[str]:
        if events is None:
            return set()

        normalized: set[str] = set()
        for event in events:
            if not isinstance(event, str):
                continue
            name = event.strip().lower()
            if name:
                normalized.add(name)
        return normalized

    def _reset_pending(self) -> None:
        self._pending_transition = None
        self._pending_count = 0


__all__ = ["StateMachineController", "SecurityStates"]
