"""Automated threat modeling helpers.

PRESERVE: Threat analysis framework
EXTEND: Automated threat modeling

Provides STRIDE-based threat generation, attack surface discovery, attack tree
construction, control effectiveness assessment, and report generation.
Integrates with ``src.ai.threat_intelligence`` when available.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence
import asyncio
import logging
import re

LOG = logging.getLogger(__name__)

try:
    from src.ai.threat_intelligence import ThreatIntelligenceAggregator
except Exception:  # pragma: no cover - optional integration
    ThreatIntelligenceAggregator = None  # type: ignore[assignment]


STRIDE_CATEGORIES = [
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
]


@dataclass
class Control:
    name: str
    effectiveness: float
    description: Optional[str] = None


@dataclass
class AttackSurface:
    name: str
    surface_type: str
    description: str
    exposure: str
    controls: List[Control] = field(default_factory=list)


@dataclass
class Threat:
    threat_id: str
    category: str
    title: str
    description: str
    likelihood: int
    impact: int
    attack_vectors: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    surfaces: List[str] = field(default_factory=list)
    threat_intel_score: float = 0.0

    @property
    def score(self) -> int:
        return self.likelihood * self.impact


@dataclass
class ThreatModel:
    generated_at: datetime
    system_architecture: Dict[str, Any]
    attack_surfaces: List[AttackSurface]
    threats: List[Threat]
    notes: List[str] = field(default_factory=list)


@dataclass
class AttackTreeNode:
    name: str
    description: str
    children: List["AttackTreeNode"] = field(default_factory=list)


@dataclass
class AttackTree:
    target: str
    root: AttackTreeNode
    paths: List[List[str]] = field(default_factory=list)


@dataclass
class Effectiveness:
    threat_id: str
    control_names: List[str]
    effective: bool
    score: float
    notes: List[str] = field(default_factory=list)


@dataclass
class ThreatReport:
    generated_at: datetime
    threats: List[Threat]
    attack_surfaces: List[AttackSurface]
    attack_trees: List[AttackTree]
    control_effectiveness: List[Effectiveness]
    summary: Dict[str, Any]
    mitigations: Dict[str, List[str]] = field(default_factory=dict)


class ThreatModelManager:
    """STRIDE-oriented threat modeling and reporting manager."""

    def __init__(self, threat_intel_db_path: str = "threat_intel.db") -> None:
        self.threat_intel_db_path = threat_intel_db_path
        self._last_system_architecture: Dict[str, Any] = {}
        self._last_attack_surfaces: List[AttackSurface] = []
        self._last_threats: List[Threat] = []
        self._last_attack_trees: List[AttackTree] = []
        self._last_effectiveness: List[Effectiveness] = []

    def identify_attack_surfaces(self, architecture: Dict[str, Any]) -> List[AttackSurface]:
        surfaces: List[AttackSurface] = []

        def add(name: str, surface_type: str, description: str, exposure: str, controls: Optional[List[Control]] = None) -> None:
            surfaces.append(
                AttackSurface(
                    name=name,
                    surface_type=surface_type,
                    description=description,
                    exposure=exposure,
                    controls=list(controls or []),
                )
            )

        for key in ("entry_points", "endpoints", "apis", "services", "datastores", "queues", "buckets", "users"):
            value = architecture.get(key)
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        name = str(item.get("name") or item.get("id") or item.get("path") or key)
                        exposure = str(item.get("exposure") or item.get("access") or "unknown")
                        surface_type = str(item.get("type") or key.rstrip("s"))
                        description = str(item.get("description") or f"{surface_type} exposed via {key}")
                        add(name, surface_type, description, exposure)
                    else:
                        add(str(item), key.rstrip("s"), f"{key.rstrip('s')} surface", "unknown")

        network = architecture.get("network", {}) if isinstance(architecture.get("network"), dict) else {}
        if network:
            for name, exposure in (
                ("public_ingress", network.get("public_ingress")),
                ("vpn", network.get("vpn")),
                ("admin_interface", network.get("admin_interface")),
            ):
                if exposure is not None:
                    add(name, "network", f"Network surface for {name}", str(exposure))

        auth = architecture.get("authentication", {}) if isinstance(architecture.get("authentication"), dict) else {}
        if auth:
            add("auth_service", "identity", "Authentication and session management surface", str(auth.get("exposure", "internal")))

        storage = architecture.get("storage", {}) if isinstance(architecture.get("storage"), dict) else {}
        if storage:
            add("storage_backend", "storage", "Data persistence surface", str(storage.get("exposure", "internal")))

        return surfaces

    def _stride_threats_for_surface(self, surface: AttackSurface) -> List[Threat]:
        base = surface.name.lower()
        exposure = surface.exposure.lower()
        if exposure in {"public", "internet", "external"}:
            likelihood = 4
        elif exposure in {"dmz", "partner"}:
            likelihood = 3
        else:
            likelihood = 2

        impact = 4 if surface.surface_type in {"identity", "storage", "api", "network"} else 3
        if any(control.effectiveness >= 0.8 for control in surface.controls):
            likelihood = max(1, likelihood - 1)

        threats = [
            Threat(
                threat_id=f"{base}-spoofing",
                category="Spoofing",
                title=f"Spoofing against {surface.name}",
                description=f"An attacker may impersonate a trusted actor at {surface.name}.",
                likelihood=likelihood,
                impact=impact,
                attack_vectors=["credential theft", "session hijacking", "token replay"],
                mitigations=["strong authentication", "mTLS", "short-lived credentials"],
                surfaces=[surface.name],
            ),
            Threat(
                threat_id=f"{base}-tampering",
                category="Tampering",
                title=f"Tampering with {surface.name}",
                description=f"Data or requests may be altered in transit or at rest around {surface.name}.",
                likelihood=max(1, likelihood - 1),
                impact=impact,
                attack_vectors=["payload manipulation", "configuration drift", "message injection"],
                mitigations=["integrity checks", "signed artifacts", "configuration management"],
                surfaces=[surface.name],
            ),
            Threat(
                threat_id=f"{base}-repudiation",
                category="Repudiation",
                title=f"Repudiation on {surface.name}",
                description=f"Actions at {surface.name} may not be attributable without robust logging.",
                likelihood=likelihood,
                impact=max(2, impact - 1),
                attack_vectors=["log suppression", "shared credentials", "insufficient audit trails"],
                mitigations=["immutable logs", "time sync", "request IDs"],
                surfaces=[surface.name],
            ),
            Threat(
                threat_id=f"{base}-info-disclosure",
                category="Information Disclosure",
                title=f"Information disclosure from {surface.name}",
                description=f"Sensitive data may be exposed through {surface.name}.",
                likelihood=likelihood,
                impact=impact,
                attack_vectors=["misconfiguration", "overbroad permissions", "debug endpoints"],
                mitigations=["encryption", "least privilege", "secret scanning"],
                surfaces=[surface.name],
            ),
            Threat(
                threat_id=f"{base}-dos",
                category="Denial of Service",
                title=f"DoS against {surface.name}",
                description=f"{surface.name} may be exhausted or rate-limited by adversarial traffic.",
                likelihood=likelihood,
                impact=max(2, impact),
                attack_vectors=["request flooding", "resource exhaustion", "queue saturation"],
                mitigations=["rate limiting", "autoscaling", "circuit breakers"],
                surfaces=[surface.name],
            ),
            Threat(
                threat_id=f"{base}-elevation",
                category="Elevation of Privilege",
                title=f"Privilege escalation via {surface.name}",
                description=f"Weak authorization or insecure defaults may allow privilege escalation at {surface.name}.",
                likelihood=max(1, likelihood - 1),
                impact=impact,
                attack_vectors=["authz bypass", "unsafe deserialization", "policy abuse"],
                mitigations=["authorization checks", "sandboxing", "secure defaults"],
                surfaces=[surface.name],
            ),
        ]
        return threats

    def _lookup_threat_intel(self, target: str) -> float:
        if ThreatIntelligenceAggregator is None:
            return 0.0

        try:
            aggregator = ThreatIntelligenceAggregator(db_path=self.threat_intel_db_path)
            return asyncio.run(self._async_lookup_threat_intel(aggregator, target))
        except RuntimeError:
            try:
                return asyncio.get_event_loop().run_until_complete(self._async_lookup_threat_intel(aggregator, target))  # pragma: no cover - fallback path
            except Exception:
                LOG.exception("Threat intelligence lookup failed")
                return 0.0
        except Exception:
            LOG.exception("Threat intelligence integration unavailable")
            return 0.0

    async def _async_lookup_threat_intel(self, aggregator: Any, target: str) -> float:
        score = 0.0
        text = target.lower()
        if await aggregator.is_malicious(text):
            score = 0.9
        else:
            top = await aggregator.top_threats(limit=10)
            for item in top:
                entity = str(item.get("entity", "")).lower()
                if entity and entity in text:
                    score = max(score, min(1.0, float(item.get("score", 0.0))))
        return score

    def generate_threat_model(self, system_architecture: Dict[str, Any]) -> ThreatModel:
        attack_surfaces = self.identify_attack_surfaces(system_architecture)
        threats: List[Threat] = []
        notes: List[str] = []

        for surface in attack_surfaces:
            threats.extend(self._stride_threats_for_surface(surface))

        # Enrich threats with external intelligence where the target name overlaps
        # with known malicious entities or observed IOCs.
        for threat in threats:
            intel_score = self._lookup_threat_intel(threat.title + " " + " ".join(threat.attack_vectors))
            threat.threat_intel_score = intel_score
            if intel_score >= 0.8:
                threat.likelihood = min(5, threat.likelihood + 1)
                threat.mitigations.append("prioritized threat-intel response")
                notes.append(f"Threat intel elevated concern for {threat.threat_id}")

        self._last_system_architecture = dict(system_architecture)
        self._last_attack_surfaces = attack_surfaces
        self._last_threats = threats

        return ThreatModel(
            generated_at=datetime.utcnow(),
            system_architecture=system_architecture,
            attack_surfaces=attack_surfaces,
            threats=threats,
            notes=notes,
        )

    def analyze_attack_trees(self, target: str) -> AttackTree:
        normalized = target.strip() or "target"
        root = AttackTreeNode(
            name=normalized,
            description=f"Attack tree for compromising {normalized}",
        )

        paths: List[List[str]] = []
        indicators = [
            ("reconnaissance", ["enumerate surface", "identify versions", "map trust boundaries"]),
            ("initial_access", ["phish credentials", "exploit exposed endpoint", "abuse weak auth"]),
            ("execution", ["execute payload", "pivot inside network", "persist access"]),
            ("impact", ["exfiltrate data", "tamper records", "disable services"]),
        ]

        for label, steps in indicators:
            node = AttackTreeNode(name=label, description=f"{label.replace('_', ' ').title()} phase")
            current = node
            for step in steps:
                child = AttackTreeNode(name=step, description=f"Step toward compromising {normalized}")
                current.children.append(child)
                current = child
            root.children.append(node)
            paths.append([normalized, label, *steps])

        tree = AttackTree(target=normalized, root=root, paths=paths)
        self._last_attack_trees.append(tree)
        return tree

    def assess_control_effectiveness(self, threat: Threat, controls: List[Control]) -> Effectiveness:
        if not controls:
            return Effectiveness(
                threat_id=threat.threat_id,
                control_names=[],
                effective=False,
                score=0.0,
                notes=["No controls provided"],
            )

        score = 0.0
        for control in controls:
            score += max(0.0, min(1.0, control.effectiveness))
        score = min(1.0, score / len(controls))

        required = min(1.0, max(0.2, threat.score / 25.0))
        effective = score >= required
        notes = []
        if effective:
            notes.append("Controls appear adequate for this threat")
        else:
            notes.append("Controls do not fully address threat")
            notes.append(f"Required effectiveness >= {required:.2f}")

        result = Effectiveness(
            threat_id=threat.threat_id,
            control_names=[control.name for control in controls],
            effective=effective,
            score=score,
            notes=notes,
        )
        self._last_effectiveness.append(result)
        return result

    def generate_threat_report(self) -> ThreatReport:
        if not self._last_system_architecture:
            self.generate_threat_model({"entry_points": []})

        attack_trees = list(self._last_attack_trees)
        if not attack_trees and self._last_threats:
            for threat in self._last_threats[:3]:
                attack_trees.append(self.analyze_attack_trees(threat.title))

        mitigation_map: Dict[str, List[str]] = {}
        for threat in self._last_threats:
            mitigation_map[threat.threat_id] = list(threat.mitigations)

        summary = {
            "threat_count": len(self._last_threats),
            "attack_surface_count": len(self._last_attack_surfaces),
            "high_risk_threats": len([t for t in self._last_threats if t.score >= 16]),
            "stride_categories": list(STRIDE_CATEGORIES),
        }

        return ThreatReport(
            generated_at=datetime.utcnow(),
            threats=list(self._last_threats),
            attack_surfaces=list(self._last_attack_surfaces),
            attack_trees=attack_trees,
            control_effectiveness=list(self._last_effectiveness),
            summary=summary,
            mitigations=mitigation_map,
        )

    def render_attack_tree(self, tree: AttackTree) -> str:
        lines: List[str] = []

        def walk(node: AttackTreeNode, depth: int = 0) -> None:
            lines.append(f"{'  ' * depth}- {node.name}: {node.description}")
            for child in node.children:
                walk(child, depth + 1)

        walk(tree.root)
        return "\n".join(lines)


_DEFAULT_MANAGER = ThreatModelManager()


def identify_attack_surfaces(architecture: Dict[str, Any]) -> List[AttackSurface]:
    return _DEFAULT_MANAGER.identify_attack_surfaces(architecture)


def generate_threat_model(system_architecture: Dict[str, Any]) -> ThreatModel:
    return _DEFAULT_MANAGER.generate_threat_model(system_architecture)


def analyze_attack_trees(target: str) -> AttackTree:
    return _DEFAULT_MANAGER.analyze_attack_trees(target)


def assess_control_effectiveness(threat: Threat, controls: List[Control]) -> Effectiveness:
    return _DEFAULT_MANAGER.assess_control_effectiveness(threat, controls)


def generate_threat_report() -> ThreatReport:
    return _DEFAULT_MANAGER.generate_threat_report()


def render_attack_tree(tree: AttackTree) -> str:
    return _DEFAULT_MANAGER.render_attack_tree(tree)


__all__ = [
    "Control",
    "AttackSurface",
    "Threat",
    "ThreatModel",
    "AttackTreeNode",
    "AttackTree",
    "Effectiveness",
    "ThreatReport",
    "ThreatModelManager",
    "generate_threat_model",
    "identify_attack_surfaces",
    "analyze_attack_trees",
    "assess_control_effectiveness",
    "generate_threat_report",
    "render_attack_tree",
]
