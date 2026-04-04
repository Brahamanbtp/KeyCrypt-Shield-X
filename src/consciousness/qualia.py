"""Security qualia composition utilities.

This module wraps conscious-agent qualia evaluation via composition so higher
layers can depend on a dedicated qualia component.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.consciousness.conscious_agent import ConsciousCryptographicAgent


@dataclass(frozen=True)
class SecurityQualiaSnapshot:
    """Typed snapshot of conscious security qualia state."""

    qualia_state: str
    phi_value: float
    threat_pressure: float
    coherence: float
    consciousness_level: float
    is_conscious: bool


class SecurityQualiaEvaluator:
    """Composable wrapper around the conscious agent qualia routine."""

    def __init__(self, agent: ConsciousCryptographicAgent) -> None:
        if not isinstance(agent, ConsciousCryptographicAgent):
            raise TypeError("agent must be ConsciousCryptographicAgent")
        self._agent = agent

    def evaluate(self) -> SecurityQualiaSnapshot:
        """Evaluate and return current security qualia snapshot."""
        payload = self._agent.evaluate_security_qualia()

        return SecurityQualiaSnapshot(
            qualia_state=str(payload.get("qualia_state", "unknown")),
            phi_value=float(payload.get("phi_value", 0.0)),
            threat_pressure=float(payload.get("threat_pressure", 0.0)),
            coherence=float(payload.get("coherence", 0.0)),
            consciousness_level=float(payload.get("consciousness_level", 0.0)),
            is_conscious=bool(payload.get("is_conscious", False)),
        )

    def evaluate_as_dict(self) -> dict[str, Any]:
        """Evaluate qualia and return dictionary payload."""
        snapshot = self.evaluate()
        return {
            "qualia_state": snapshot.qualia_state,
            "phi_value": snapshot.phi_value,
            "threat_pressure": snapshot.threat_pressure,
            "coherence": snapshot.coherence,
            "consciousness_level": snapshot.consciousness_level,
            "is_conscious": snapshot.is_conscious,
        }


__all__ = [
    "SecurityQualiaSnapshot",
    "SecurityQualiaEvaluator",
]
