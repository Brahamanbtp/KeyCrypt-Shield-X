"""Orchestration layer for provider coordination and policy-driven execution.

This package defines high-level coordination primitives that compose crypto,
key, storage, and policy components through dependency injection.
"""

from __future__ import annotations

from .dependency_container import CoreContainer as dependency_container


class EncryptionOrchestrator:
    """Stub orchestrator placeholder.

    Full orchestration workflows will be implemented in a later iteration.
    """


class PolicyEngine:
    """Stub policy engine placeholder.

    Policy evaluation and enforcement logic will be implemented later.
    """


try:
    from src.core.security_states import SecurityStates as StateMachine
except Exception:
    class StateMachine:  # type: ignore[no-redef]
        """Fallback state machine stub used until core security states exist."""


__all__: list[str] = [
    "dependency_container",
    "EncryptionOrchestrator",
    "PolicyEngine",
    "StateMachine",
]
