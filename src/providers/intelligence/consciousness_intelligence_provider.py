"""Consciousness-based intelligence provider.

This provider composes existing consciousness modules without modifying them:
- src/consciousness/introspection.py
- src/consciousness/qualia.py
- src/consciousness/conscious_agent.py
- src/consciousness/integrated_info.py
- src/consciousness/metacognition.py
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

import networkx as nx

from src.consciousness.conscious_agent import ConsciousCryptographicAgent
from src.consciousness.integrated_info import IntegratedInformationCalculator
from src.consciousness.introspection import SelfIntrospection
from src.consciousness.metacognition import MetacognitiveMonitor
from src.consciousness.qualia import SecurityQualiaEvaluator


@dataclass(frozen=True)
class Vulnerability:
    """Typed vulnerability output from consciousness introspection."""

    component: str
    severity_score: float
    severity: str
    exploitability: float
    cascade_impact: float
    recommendation: str


@dataclass(frozen=True)
class SecurityQualia:
    """Conscious security qualia with metacognitive certainty metadata."""

    qualia_state: str
    phi_value: float
    threat_pressure: float
    coherence: float
    consciousness_level: float
    is_conscious: bool
    metacognitive_confidence: float
    uncertainty: float
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Threat:
    """Input threat descriptor for conscious threat assessment."""

    threat_id: str
    threat_type: str
    severity: float
    vector: str
    indicators: Sequence[str] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ThreatAssessment:
    """Threat assessment generated through conscious composition."""

    threat_id: str
    threat_type: str
    risk_score: float
    priority: str
    phi_value: float
    is_conscious: bool
    metacognitive_confidence: float
    uncertainty: float
    rationale: str
    recommended_actions: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class ConsciousnessIntelligenceProvider:
    """Consciousness-driven intelligence provider using compositional wrappers."""

    def __init__(
        self,
        *,
        system_graph: nx.DiGraph | None = None,
        telemetry: dict[str, Any] | None = None,
        critical_assets: list[str] | None = None,
        world_model: dict[str, Any] | None = None,
        metacognition_state: dict[str, Any] | None = None,
        phi_conscious_threshold: float = 3.14,
    ) -> None:
        self._lock = threading.RLock()

        self._base_graph = nx.DiGraph()
        if system_graph is not None:
            self._base_graph = system_graph if isinstance(system_graph, nx.DiGraph) else nx.DiGraph(system_graph)

        self._telemetry = telemetry.copy() if telemetry else {}
        self._critical_assets = critical_assets[:] if critical_assets else []
        self._world_model = world_model.copy() if world_model else {}
        self._metacognition_state = metacognition_state.copy() if metacognition_state else {}
        self._phi_conscious_threshold = float(phi_conscious_threshold)

        self._phi_calculator: IntegratedInformationCalculator | None = None
        self._introspector: SelfIntrospection | None = None
        self._conscious_agent: ConsciousCryptographicAgent | None = None
        self._qualia_evaluator: SecurityQualiaEvaluator | None = None
        self._metacognitive_monitor: MetacognitiveMonitor | None = None

        self._last_vulnerabilities: list[Vulnerability] = []
        self._last_assessment: ThreatAssessment | None = None

    def introspect_vulnerabilities(self) -> list[Vulnerability]:
        """Discover and return ranked vulnerabilities via introspection module."""
        _, introspector, _, _, _ = self._ensure_components()

        payload = introspector.discover_vulnerabilities()
        raw_items = payload.get("vulnerabilities", [])

        findings: list[Vulnerability] = []
        for item in raw_items:
            if not isinstance(item, Mapping):
                continue
            findings.append(
                Vulnerability(
                    component=str(item.get("component", "unknown")),
                    severity_score=self._clamp01(float(item.get("severity_score", 0.0))),
                    severity=str(item.get("severity", "low")),
                    exploitability=self._clamp01(float(item.get("exploitability", 0.0))),
                    cascade_impact=self._clamp01(float(item.get("cascade_impact", 0.0))),
                    recommendation=str(item.get("recommendation", "monitor continuously")),
                )
            )

        findings.sort(key=lambda item: item.severity_score, reverse=True)

        with self._lock:
            self._last_vulnerabilities = findings

        return findings

    def evaluate_security_qualia(self) -> SecurityQualia:
        """Evaluate conscious security qualia with metacognitive confidence."""
        _, _, _, qualia_evaluator, monitor = self._ensure_components()

        snapshot = qualia_evaluator.evaluate()

        judgment = monitor.monitor_own_performance(
            {
                "accuracy": self._clamp01(snapshot.coherence),
                "reliability": self._clamp01(snapshot.consciousness_level),
                "precision": self._clamp01(1.0 - snapshot.threat_pressure),
                "recall": self._clamp01(snapshot.coherence),
                "context": "qualia",
            }
        )

        confidence = self._clamp01(float(judgment.get("confidence", 0.5)))
        uncertainty = self._clamp01(float(judgment.get("uncertainty", 0.5)))

        return SecurityQualia(
            qualia_state=snapshot.qualia_state,
            phi_value=max(0.0, float(snapshot.phi_value)),
            threat_pressure=self._clamp01(float(snapshot.threat_pressure)),
            coherence=self._clamp01(float(snapshot.coherence)),
            consciousness_level=self._clamp01(float(snapshot.consciousness_level)),
            is_conscious=bool(snapshot.is_conscious),
            metacognitive_confidence=confidence,
            uncertainty=uncertainty,
            metadata={
                "provider": "ConsciousnessIntelligenceProvider",
                "judgment_trend": float(judgment.get("trend", 0.0)),
                "self_assessment_accuracy": float(judgment.get("self_assessment_accuracy", 0.0)),
            },
        )

    def conscious_threat_assessment(self, threat: Threat) -> ThreatAssessment:
        """Perform a Phi-aware conscious assessment for an incoming threat."""
        if not isinstance(threat, Threat):
            raise TypeError("threat must be Threat")
        if not threat.threat_id.strip():
            raise ValueError("threat_id must be non-empty")
        if not threat.threat_type.strip():
            raise ValueError("threat_type must be non-empty")

        phi_calculator, introspector, agent, _qualia_evaluator, monitor = self._ensure_components()

        self._inject_threat_context(agent, threat)

        vulnerabilities = self.introspect_vulnerabilities()
        qualia = self.evaluate_security_qualia()

        system_state = self._build_phi_state(threat, vulnerabilities, qualia)
        phi_result = phi_calculator.find_minimum_information_partition(system_state)

        phi_value = max(0.0, float(phi_result.get("phi_value", 0.0)))
        phi_normalized = self._clamp01(phi_value / max(self._phi_conscious_threshold, 1e-12))
        is_conscious = bool(phi_result.get("is_conscious", phi_value >= self._phi_conscious_threshold))

        imagined = agent.imagine_attack(threat.threat_type)

        option_set = self._build_response_options(threat, vulnerabilities, qualia, phi_normalized)
        decision = agent.conscious_decision(
            options=option_set,
            context={
                "risk_level": self._clamp01(float(threat.severity)),
                "goal": "protect_cryptographic_integrity",
                "threat_vector": threat.vector,
            },
        )

        risk_score = self._compute_risk_score(threat, vulnerabilities, qualia, phi_normalized)
        priority = self._priority_label(risk_score)

        confidence_probe = monitor.monitor_own_performance(
            {
                "accuracy": self._clamp01(1.0 - risk_score),
                "reliability": qualia.metacognitive_confidence,
                "precision": self._clamp01(phi_normalized),
                "recall": self._clamp01(1.0 - qualia.uncertainty),
                "context": "threat_assessment",
            }
        )

        metacognitive_confidence = self._clamp01(float(confidence_probe.get("confidence", 0.5)))
        uncertainty = self._clamp01(float(confidence_probe.get("uncertainty", 0.5)))

        recommended_actions = self._recommended_actions(
            threat=threat,
            vulnerabilities=vulnerabilities,
            selected_option=str(decision.get("selected_option", "increase_monitoring")),
        )

        rationale = (
            "Conscious assessment fused threat severity, introspective vulnerability state, "
            "security qualia pressure, and integrated information (Phi)."
        )

        assessment = ThreatAssessment(
            threat_id=threat.threat_id.strip(),
            threat_type=threat.threat_type.strip().lower(),
            risk_score=risk_score,
            priority=priority,
            phi_value=phi_value,
            is_conscious=is_conscious,
            metacognitive_confidence=metacognitive_confidence,
            uncertainty=uncertainty,
            rationale=rationale,
            recommended_actions=recommended_actions,
            metadata={
                "provider": "ConsciousnessIntelligenceProvider",
                "phi_normalized": phi_normalized,
                "phi_mip": phi_result.get("mip"),
                "qualia_state": qualia.qualia_state,
                "threat_vector": threat.vector,
                "imagined_attack_steps": len(imagined.get("steps", [])),
                "selected_response": decision.get("selected_option"),
                "awareness_priority": decision.get("awareness_priority"),
                "metacognitive_trend": confidence_probe.get("trend"),
                "self_assessment_accuracy": confidence_probe.get("self_assessment_accuracy"),
                "vulnerability_count": len(vulnerabilities),
            },
        )

        with self._lock:
            self._last_assessment = assessment

        _ = introspector
        return assessment

    def _ensure_components(
        self,
    ) -> tuple[
        IntegratedInformationCalculator,
        SelfIntrospection,
        ConsciousCryptographicAgent,
        SecurityQualiaEvaluator,
        MetacognitiveMonitor,
    ]:
        with self._lock:
            if self._phi_calculator is None:
                self._phi_calculator = IntegratedInformationCalculator(graph=nx.DiGraph(self._base_graph))

            if self._introspector is None:
                self._introspector = SelfIntrospection(
                    system_graph=nx.DiGraph(self._base_graph),
                    telemetry=dict(self._telemetry),
                    critical_assets=list(self._critical_assets),
                )

            if self._conscious_agent is None:
                self._conscious_agent = ConsciousCryptographicAgent(
                    phi_calculator=self._phi_calculator,
                    world_model=dict(self._world_model),
                    metacognition=dict(self._metacognition_state),
                )

            if self._qualia_evaluator is None:
                self._qualia_evaluator = SecurityQualiaEvaluator(agent=self._conscious_agent)

            if self._metacognitive_monitor is None:
                self._metacognitive_monitor = MetacognitiveMonitor()

            return (
                self._phi_calculator,
                self._introspector,
                self._conscious_agent,
                self._qualia_evaluator,
                self._metacognitive_monitor,
            )

    def _inject_threat_context(self, agent: ConsciousCryptographicAgent, threat: Threat) -> None:
        severity = self._clamp01(float(threat.severity))
        pressure_hint = self._clamp01(
            float(threat.metadata.get("incident_pressure", severity))
            if isinstance(threat.metadata, Mapping)
            else severity
        )

        agent.world_model["threat_level"] = severity
        agent.world_model["incident_pressure"] = pressure_hint
        agent.world_model["active_threat_type"] = threat.threat_type.strip().lower()
        agent.world_model["active_threat_vector"] = threat.vector

    def _build_phi_state(
        self,
        threat: Threat,
        vulnerabilities: list[Vulnerability],
        qualia: SecurityQualia,
    ) -> dict[str, float]:
        vuln_pressure = (
            sum(item.severity_score for item in vulnerabilities) / len(vulnerabilities)
            if vulnerabilities
            else 0.0
        )

        critical_ratio = (
            sum(1 for item in vulnerabilities if item.severity in {"critical", "high"}) / len(vulnerabilities)
            if vulnerabilities
            else 0.0
        )

        indicator_density = min(1.0, len(tuple(threat.indicators)) / 10.0)

        return {
            "threat_level": self._clamp01(float(threat.severity)),
            "vulnerability_pressure": self._clamp01(vuln_pressure),
            "critical_asset_exposure": self._clamp01(critical_ratio),
            "qualia_coherence": self._clamp01(qualia.coherence),
            "qualia_pressure": self._clamp01(qualia.threat_pressure),
            "indicator_density": self._clamp01(indicator_density),
            "vector_entropy": self._clamp01(len(threat.vector.strip()) / 64.0),
        }

    def _build_response_options(
        self,
        threat: Threat,
        vulnerabilities: list[Vulnerability],
        qualia: SecurityQualia,
        phi_normalized: float,
    ) -> list[dict[str, Any]]:
        severity = self._clamp01(float(threat.severity))
        weak_components = [item.component for item in vulnerabilities[:3]]

        return [
            {
                "name": "immediate_containment",
                "utility": 0.92,
                "risk": self._clamp01(0.25 + (0.2 * severity)),
                "reversibility": 0.35,
                "tags": "protect_cryptographic_integrity rapid_response",
                "targets": weak_components,
            },
            {
                "name": "adaptive_hardening",
                "utility": self._clamp01(0.75 + (0.2 * phi_normalized)),
                "risk": self._clamp01(0.15 + (0.1 * qualia.threat_pressure)),
                "reversibility": 0.72,
                "tags": "protect_cryptographic_integrity resilience",
                "targets": weak_components,
            },
            {
                "name": "heightened_monitoring",
                "utility": 0.60,
                "risk": self._clamp01(0.1 + (0.2 * severity)),
                "reversibility": 0.95,
                "tags": "protect_cryptographic_integrity observation",
                "targets": list(threat.indicators[:3]),
            },
        ]

    def _compute_risk_score(
        self,
        threat: Threat,
        vulnerabilities: list[Vulnerability],
        qualia: SecurityQualia,
        phi_normalized: float,
    ) -> float:
        severity = self._clamp01(float(threat.severity))
        vuln_pressure = (
            sum(item.severity_score for item in vulnerabilities) / len(vulnerabilities)
            if vulnerabilities
            else 0.0
        )

        # Higher Phi/coherence reduce assessed risk amplification.
        cognitive_resilience = self._clamp01((0.6 * phi_normalized) + (0.4 * qualia.coherence))

        risk = (
            0.45 * severity
            + 0.25 * self._clamp01(vuln_pressure)
            + 0.20 * self._clamp01(qualia.threat_pressure)
            + 0.10 * (1.0 - cognitive_resilience)
        )
        return self._clamp01(risk)

    def _recommended_actions(
        self,
        *,
        threat: Threat,
        vulnerabilities: list[Vulnerability],
        selected_option: str,
    ) -> list[str]:
        actions = [f"Execute response strategy: {selected_option}"]
        actions.append(f"Increase telemetry focus on threat vector: {threat.vector}")

        for finding in vulnerabilities[:3]:
            actions.append(finding.recommendation)

        if threat.indicators:
            actions.append("Block or sandbox top threat indicators in perimeter and runtime controls")

        deduped: list[str] = []
        seen: set[str] = set()
        for action in actions:
            normalized = action.strip()
            if not normalized:
                continue
            marker = normalized.lower()
            if marker in seen:
                continue
            seen.add(marker)
            deduped.append(normalized)

        return deduped

    @staticmethod
    def _priority_label(risk_score: float) -> str:
        if risk_score >= 0.8:
            return "critical"
        if risk_score >= 0.6:
            return "high"
        if risk_score >= 0.4:
            return "medium"
        return "low"

    @staticmethod
    def _clamp01(value: float) -> float:
        return max(0.0, min(1.0, float(value)))


__all__ = [
    "Vulnerability",
    "SecurityQualia",
    "Threat",
    "ThreatAssessment",
    "ConsciousnessIntelligenceProvider",
]
