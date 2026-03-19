"""Self-introspective vulnerability discovery for conscious security systems."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any

import networkx as nx

from src.utils.logging import get_logger


logger = get_logger("src.consciousness.introspection")


@dataclass(frozen=True)
class VulnerabilityRecord:
    """Ranked vulnerability discovered via introspection."""

    component: str
    severity_score: float
    severity: str
    exploitability: float
    cascade_impact: float
    recommendation: str


class SelfIntrospection:
    """Builds self-models and discovers vulnerabilities via causal introspection."""

    def __init__(
        self,
        system_graph: nx.DiGraph | None = None,
        telemetry: dict[str, Any] | None = None,
        critical_assets: list[str] | None = None,
    ) -> None:
        self.system_graph: nx.DiGraph = nx.DiGraph()
        if system_graph is not None:
            self.system_graph = system_graph if isinstance(system_graph, nx.DiGraph) else nx.DiGraph(system_graph)

        self.telemetry: dict[str, Any] = telemetry.copy() if telemetry else {}
        self.critical_assets: list[str] = critical_assets[:] if critical_assets else []

        self.self_model: dict[str, Any] = {}
        self.discovery_history: list[dict[str, Any]] = []

    def build_self_model(self) -> dict[str, Any]:
        """Create an internal representation of components, dependencies, and risk signals."""
        model_nodes: dict[str, dict[str, Any]] = {}

        for node in self.system_graph.nodes:
            node_id = str(node)
            attrs = self.system_graph.nodes[node]
            node_telemetry = self.telemetry.get(node_id, {}) if isinstance(self.telemetry.get(node_id, {}), dict) else {}

            base_exposure = float(attrs.get("external_exposure", node_telemetry.get("external_exposure", 0.3)))
            auth_strength = float(attrs.get("auth_strength", node_telemetry.get("auth_strength", 0.6)))
            patch_lag_days = float(attrs.get("patch_lag_days", node_telemetry.get("patch_lag_days", 7.0)))
            hardening = float(attrs.get("hardening", node_telemetry.get("hardening", 0.5)))
            criticality = float(attrs.get("criticality", node_telemetry.get("criticality", 0.5)))

            exploitability = self._clamp01((0.45 * base_exposure) + (0.35 * (1.0 - auth_strength)) + (0.2 * (1.0 - hardening)))
            patch_lag_factor = self._clamp01(min(patch_lag_days / 30.0, 1.0))

            model_nodes[node_id] = {
                "external_exposure": self._clamp01(base_exposure),
                "auth_strength": self._clamp01(auth_strength),
                "patch_lag_days": max(0.0, patch_lag_days),
                "hardening": self._clamp01(hardening),
                "criticality": self._clamp01(criticality),
                "exploitability": self._clamp01(exploitability + (0.2 * patch_lag_factor)),
            }

        if not model_nodes and self.telemetry:
            for node_id, payload in self.telemetry.items():
                if not isinstance(payload, dict):
                    continue
                model_nodes[str(node_id)] = {
                    "external_exposure": self._clamp01(float(payload.get("external_exposure", 0.3))),
                    "auth_strength": self._clamp01(float(payload.get("auth_strength", 0.6))),
                    "patch_lag_days": max(0.0, float(payload.get("patch_lag_days", 7.0))),
                    "hardening": self._clamp01(float(payload.get("hardening", 0.5))),
                    "criticality": self._clamp01(float(payload.get("criticality", 0.5))),
                    "exploitability": self._clamp01(float(payload.get("exploitability", 0.4))),
                }
                self.system_graph.add_node(str(node_id))

        dependencies = {str(node): [str(n) for n in self.system_graph.successors(node)] for node in self.system_graph.nodes}
        entry_points = [
            node_id
            for node_id, data in model_nodes.items()
            if data["external_exposure"] >= 0.6 or data["exploitability"] >= 0.65
        ]

        crown_jewels = self._resolve_critical_assets(model_nodes)

        self.self_model = {
            "nodes": model_nodes,
            "dependencies": dependencies,
            "entry_points": sorted(entry_points),
            "critical_assets": crown_jewels,
        }

        logger.info(
            "self model built node_count={nodes} edge_count={edges} entry_points={entry_points}",
            nodes=len(model_nodes),
            edges=self.system_graph.number_of_edges(),
            entry_points=len(entry_points),
        )
        return self.self_model

    def perspective_taking(self, role: str = "adversary") -> dict[str, Any]:
        """Simulate alternate viewpoints, defaulting to attacker perspective."""
        if not self.self_model:
            self.build_self_model()

        normalized_role = role.strip().lower()
        nodes = self.self_model.get("nodes", {})

        if normalized_role == "adversary":
            ranked_surface = sorted(
                (
                    {
                        "component": node,
                        "attack_score": self._clamp01(
                            (0.55 * data["exploitability"]) + (0.45 * data["criticality"])
                        ),
                    }
                    for node, data in nodes.items()
                ),
                key=lambda item: item["attack_score"],
                reverse=True,
            )

            likely_paths = self._enumerate_attack_paths(
                sources=self.self_model.get("entry_points", []),
                targets=self.self_model.get("critical_assets", []),
            )

            result = {
                "role": "adversary",
                "high_value_targets": ranked_surface[:7],
                "likely_attack_paths": likely_paths[:10],
                "attacker_goal": "maximize cascade impact while minimizing detection",
            }
            logger.info("perspective taking generated adversary view targets={targets}", targets=len(ranked_surface))
            return result

        if normalized_role == "defender":
            weakest_controls = sorted(
                (
                    {
                        "component": node,
                        "control_weakness": self._clamp01(1.0 - data["hardening"]),
                    }
                    for node, data in nodes.items()
                ),
                key=lambda item: item["control_weakness"],
                reverse=True,
            )

            result = {
                "role": "defender",
                "weakest_controls": weakest_controls[:7],
                "defender_goal": "minimize exploitability and blast radius",
            }
            logger.info("perspective taking generated defender view components={components}", components=len(weakest_controls))
            return result

        result = {
            "role": normalized_role,
            "summary": "unsupported role; fallback to neutral system view",
            "node_count": len(nodes),
        }
        logger.info("perspective taking used neutral fallback role={role}", role=normalized_role)
        return result

    def counterfactual_reasoning(self, intervention: dict[str, Any]) -> dict[str, Any]:
        """Run do-style what-if analysis and estimate causal impact on system risk."""
        if not self.self_model:
            self.build_self_model()

        target = str(intervention.get("target", ""))
        if not target:
            raise ValueError("intervention.target is required")

        baseline_model = deepcopy(self.self_model)
        intervened_model = deepcopy(self.self_model)
        intervened_graph = self._do_intervention(self.system_graph, intervened_model, intervention)

        baseline_risk = self._system_risk_score(self.system_graph, baseline_model)
        intervened_risk = self._system_risk_score(intervened_graph, intervened_model)

        # Approximate average causal effect under do(X=x): delta risk after forced intervention.
        average_causal_effect = baseline_risk - intervened_risk

        cascading = self._simulate_failure_cascade(intervened_graph, intervened_model, target)

        result = {
            "intervention": intervention,
            "baseline_risk": baseline_risk,
            "intervened_risk": intervened_risk,
            "average_causal_effect": average_causal_effect,
            "cascade_after_intervention": cascading,
            "recommendation": (
                "adopt intervention"
                if average_causal_effect > 0.05
                else "insufficient impact; prioritize alternate control"
            ),
        }

        logger.info(
            "counterfactual computed target={target} ace={ace} baseline={baseline} intervened={intervened}",
            target=target,
            ace=average_causal_effect,
            baseline=baseline_risk,
            intervened=intervened_risk,
        )
        return result

    def discover_vulnerabilities(self) -> dict[str, Any]:
        """Find weaknesses by introspection, causal stress, and cascade simulation."""
        model = self.build_self_model()
        adversary_view = self.perspective_taking(role="adversary")

        nodes = model.get("nodes", {})
        vulnerabilities: list[VulnerabilityRecord] = []

        for node, data in nodes.items():
            cascade = self._simulate_failure_cascade(self.system_graph, model, node)
            exploitability = float(data["exploitability"])
            criticality = float(data["criticality"])
            cascade_impact = float(cascade["aggregate_impact"])

            severity_score = self._clamp01((0.45 * exploitability) + (0.35 * cascade_impact) + (0.20 * criticality))
            severity = self._severity_label(severity_score)

            vulnerabilities.append(
                VulnerabilityRecord(
                    component=node,
                    severity_score=severity_score,
                    severity=severity,
                    exploitability=exploitability,
                    cascade_impact=cascade_impact,
                    recommendation=self._patching_recommendation(node, data, cascade_impact),
                )
            )

        ranked = sorted(vulnerabilities, key=lambda item: item.severity_score, reverse=True)
        top_recommendations = [item.recommendation for item in ranked[:8]]

        result = {
            "vulnerabilities": [self._record_to_dict(item) for item in ranked],
            "adversary_view": adversary_view,
            "patching_recommendations": top_recommendations,
            "summary": {
                "critical_count": sum(1 for item in ranked if item.severity == "critical"),
                "high_count": sum(1 for item in ranked if item.severity == "high"),
                "node_count": len(nodes),
            },
        }

        self.discovery_history.append(result)
        if len(self.discovery_history) > 128:
            self.discovery_history = self.discovery_history[-128:]

        logger.info(
            "vulnerability discovery complete nodes={nodes} findings={findings}",
            nodes=len(nodes),
            findings=len(ranked),
        )
        return result

    def _do_intervention(
        self,
        graph: nx.DiGraph,
        model: dict[str, Any],
        intervention: dict[str, Any],
    ) -> nx.DiGraph:
        target = str(intervention["target"])
        do_value = intervention.get("set_exploitability")

        adjusted = nx.DiGraph(graph)
        if target not in adjusted:
            adjusted.add_node(target)

        # do(X=x): cut incoming causes and force target state to x.
        incoming = list(adjusted.in_edges(target))
        if incoming:
            adjusted.remove_edges_from(incoming)

        if do_value is not None:
            node_data = model.setdefault("nodes", {}).setdefault(
                target,
                {
                    "external_exposure": 0.3,
                    "auth_strength": 0.6,
                    "patch_lag_days": 7.0,
                    "hardening": 0.5,
                    "criticality": 0.5,
                    "exploitability": 0.4,
                },
            )
            node_data["exploitability"] = self._clamp01(float(do_value))

        for edge in intervention.get("remove_edges", []):
            if isinstance(edge, (list, tuple)) and len(edge) == 2:
                source = str(edge[0])
                target_node = str(edge[1])
                if adjusted.has_edge(source, target_node):
                    adjusted.remove_edge(source, target_node)

        for edge in intervention.get("add_edges", []):
            if isinstance(edge, (list, tuple)) and len(edge) >= 2:
                source = str(edge[0])
                target_node = str(edge[1])
                weight = float(edge[2]) if len(edge) > 2 else 1.0
                adjusted.add_edge(source, target_node, weight=weight)

        return adjusted

    def _simulate_failure_cascade(
        self,
        graph: nx.DiGraph,
        model: dict[str, Any],
        start_node: str,
    ) -> dict[str, Any]:
        node_data = model.get("nodes", {}).get(start_node)
        if node_data is None:
            return {"failed_nodes": [], "aggregate_impact": 0.0}

        failed_probability: dict[str, float] = {start_node: float(node_data["exploitability"])}
        frontier: list[str] = [start_node]

        while frontier:
            current = frontier.pop(0)
            current_prob = failed_probability[current]

            for _, neighbor, edge_data in graph.out_edges(current, data=True):
                neighbor_id = str(neighbor)
                if neighbor_id not in model.get("nodes", {}):
                    continue

                edge_weight = self._clamp01(float(edge_data.get("weight", 0.6)))
                neighbor_base = float(model["nodes"][neighbor_id]["exploitability"])
                propagated = self._clamp01(current_prob * edge_weight * (0.6 + 0.4 * neighbor_base))

                if propagated > failed_probability.get(neighbor_id, 0.0) + 0.03:
                    failed_probability[neighbor_id] = propagated
                    frontier.append(neighbor_id)

        impacted = sorted(failed_probability.items(), key=lambda item: item[1], reverse=True)
        aggregate_impact = self._clamp01(
            sum(mean_prob for _, mean_prob in impacted) / max(len(impacted), 1)
        )

        return {
            "failed_nodes": [{"component": node, "failure_probability": prob} for node, prob in impacted],
            "aggregate_impact": aggregate_impact,
        }

    def _system_risk_score(self, graph: nx.DiGraph, model: dict[str, Any]) -> float:
        nodes = model.get("nodes", {})
        if not nodes:
            return 0.0

        base_risk = 0.0
        for node, data in nodes.items():
            cascade = self._simulate_failure_cascade(graph, model, node)
            base_risk += (0.6 * float(data["exploitability"])) + (0.4 * float(cascade["aggregate_impact"]))

        return self._clamp01(base_risk / max(len(nodes), 1))

    def _enumerate_attack_paths(self, sources: list[str], targets: list[str]) -> list[list[str]]:
        paths: list[list[str]] = []
        if not sources or not targets:
            return paths

        for source in sources:
            for target in targets:
                if source == target:
                    continue
                if source not in self.system_graph or target not in self.system_graph:
                    continue
                try:
                    for path in nx.all_simple_paths(self.system_graph, source=source, target=target, cutoff=5):
                        paths.append([str(step) for step in path])
                except nx.NetworkXNoPath:
                    continue

        return paths

    def _resolve_critical_assets(self, nodes: dict[str, dict[str, Any]]) -> list[str]:
        explicit = [asset for asset in self.critical_assets if asset in nodes]
        if explicit:
            return explicit

        ranked = sorted(nodes.items(), key=lambda item: item[1]["criticality"], reverse=True)
        return [node for node, _ in ranked[:3]]

    def _patching_recommendation(self, node: str, data: dict[str, Any], cascade_impact: float) -> str:
        if float(data["patch_lag_days"]) > 14:
            return f"Prioritize emergency patch rollout for {node}; reduce patch lag below 7 days."
        if float(data["auth_strength"]) < 0.5:
            return f"Strengthen authentication and access controls on {node} (MFA + least privilege)."
        if float(data["hardening"]) < 0.6:
            return f"Increase hardening baseline on {node}; disable weak ciphers and tighten service sandboxing."
        if cascade_impact > 0.55:
            return f"Segment {node} to reduce downstream blast radius and add circuit-breaker policies."
        return f"Continuously monitor {node} and enforce integrity attestation for rapid anomaly response."

    def _severity_label(self, score: float) -> str:
        if score >= 0.8:
            return "critical"
        if score >= 0.65:
            return "high"
        if score >= 0.45:
            return "medium"
        return "low"

    def _record_to_dict(self, record: VulnerabilityRecord) -> dict[str, Any]:
        return {
            "component": record.component,
            "severity_score": record.severity_score,
            "severity": record.severity,
            "exploitability": record.exploitability,
            "cascade_impact": record.cascade_impact,
            "recommendation": record.recommendation,
        }

    def _clamp01(self, value: float) -> float:
        return max(0.0, min(1.0, float(value)))


__all__ = ["SelfIntrospection", "VulnerabilityRecord"]
