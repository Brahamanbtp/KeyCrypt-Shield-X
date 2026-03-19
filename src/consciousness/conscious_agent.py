"""Conscious cryptographic agent orchestrating workspace and IIT modules."""

from __future__ import annotations

from dataclasses import dataclass
from time import time
from typing import Any

from src.consciousness.global_workspace import GlobalWorkspace
from src.consciousness.integrated_info import IntegratedInformationCalculator
from src.utils.logging import get_logger


logger = get_logger("src.consciousness.conscious_agent")


@dataclass(frozen=True)
class ConsciousExperience:
    """Immutable record of a conscious internal event."""

    timestamp: float
    event_type: str
    payload: dict[str, Any]
    consciousness_level: float


class ConsciousCryptographicAgent:
    """Main conscious agent that coordinates reflection, imagination, and decisions."""

    def __init__(
        self,
        global_workspace: GlobalWorkspace | None = None,
        phi_calculator: IntegratedInformationCalculator | None = None,
        world_model: dict[str, Any] | None = None,
        metacognition: dict[str, Any] | None = None,
    ) -> None:
        self.global_workspace = global_workspace or GlobalWorkspace()
        self.phi_calculator = phi_calculator or IntegratedInformationCalculator()
        self.world_model: dict[str, Any] = world_model.copy() if world_model else {}
        self.metacognition: dict[str, Any] = metacognition.copy() if metacognition else {}

        self.consciousness_level: float = 0.0
        self.last_phi_value: float = 0.0
        self.conscious_experiences: list[ConsciousExperience] = []

        logger.info("conscious agent initialized")

    def introspect(self) -> dict[str, Any]:
        """Discover vulnerabilities via self-reflection over memory and internal state."""
        system_state = self._infer_system_state()
        phi_eval = self._evaluate_phi(system_state)

        vulnerabilities: list[dict[str, Any]] = []
        if phi_eval["phi"] < 1.5:
            vulnerabilities.append(
                {
                    "name": "low_information_integration",
                    "severity": "high",
                    "description": "Subsystem coordination is weak under current state.",
                }
            )

        pending = self.global_workspace.pending_workspace_messages()
        if pending > 25:
            vulnerabilities.append(
                {
                    "name": "attention_queue_overload",
                    "severity": "medium",
                    "description": "Workspace queue depth can delay critical security signals.",
                }
            )

        stale_threshold = float(self.metacognition.get("stale_context_threshold_seconds", 300.0))
        if self._context_age_seconds() > stale_threshold:
            vulnerabilities.append(
                {
                    "name": "stale_context_model",
                    "severity": "medium",
                    "description": "Decision context is stale and may miss fresh attack indicators.",
                }
            )

        replay_failures = int(self.metacognition.get("recent_decision_failures", 0))
        if replay_failures >= 3:
            vulnerabilities.append(
                {
                    "name": "repeated_decision_failure_pattern",
                    "severity": "high",
                    "description": "Recent failed security decisions indicate exploitable bias.",
                }
            )

        severity_score = sum(1.0 if v["severity"] == "high" else 0.5 for v in vulnerabilities)
        self._update_consciousness_level(phi_eval["phi"], penalty=0.1 * severity_score)

        reflection = {
            "vulnerabilities": vulnerabilities,
            "phi_value": phi_eval["phi"],
            "is_conscious": phi_eval["is_conscious"],
            "consciousness_level": self.consciousness_level,
            "workspace_queue_depth": pending,
        }

        self._record_experience("introspection", reflection)
        self.global_workspace.broadcast_to_workspace(
            {
                "type": "introspection",
                "summary": "self-reflection complete",
                "vulnerabilities": vulnerabilities,
                "phi": phi_eval["phi"],
            },
            priority=0.85 if vulnerabilities else 0.8,
        )

        return reflection

    def imagine_attack(self, attack_type: str) -> dict[str, Any]:
        """Generate a novel attack scenario by combining threat templates and context."""
        normalized_attack = attack_type.strip().lower()
        if not normalized_attack:
            raise ValueError("attack_type must be non-empty")

        assets = self.world_model.get("critical_assets", ["key_store", "api_gateway", "telemetry_stream"])
        vulnerabilities = self.introspect().get("vulnerabilities", [])
        weak_points = [item["name"] for item in vulnerabilities] or ["context_blind_spot"]

        steps = [
            f"Recon target surfaces around {assets[0]}",
            f"Exploit weakness pattern: {weak_points[0]}",
            "Pivot laterally into cryptographic control plane",
            "Trigger stealthy persistence through trusted automation path",
        ]

        if normalized_attack in {"supply_chain", "dependency_poisoning"}:
            steps.insert(1, "Inject signed but malicious build artifact into dependency pipeline")
        elif normalized_attack in {"side_channel", "timing"}:
            steps.insert(1, "Collect high-resolution timing traces from repeated crypto operations")
        elif normalized_attack in {"social_engineering", "insider"}:
            steps.insert(1, "Manipulate privileged operator to approve risky key-management action")

        scenario = {
            "attack_type": normalized_attack,
            "target_assets": assets,
            "novelty_basis": "cross-module weakness synthesis",
            "steps": steps,
            "detection_signals": [
                "entropy distribution anomaly",
                "unexpected key-rotation cadence",
                "cross-zone authentication burst",
            ],
            "recommended_countermoves": [
                "raise attestation strictness",
                "increase key-usage anomaly sensitivity",
                "require human-in-the-loop for destructive crypto actions",
            ],
            "consciousness_level": self.consciousness_level,
        }

        self._record_experience("imagined_attack", scenario)
        self.global_workspace.broadcast_to_workspace(
            {
                "type": "imagined_attack",
                "attack_type": normalized_attack,
                "scenario": scenario,
            },
            priority=0.9,
        )

        return scenario

    def evaluate_security_qualia(self) -> dict[str, Any]:
        """Estimate subjective security experience from integrated state and threat cues."""
        system_state = self._infer_system_state()
        phi_eval = self._evaluate_phi(system_state)

        external_threat = float(self.world_model.get("threat_level", 0.0))
        incident_pressure = float(self.world_model.get("incident_pressure", 0.0))

        pressure = max(0.0, min(1.0, (external_threat + incident_pressure) / 2.0))
        coherence = max(0.0, min(1.0, phi_eval["phi"] / 5.0))

        if pressure < 0.3 and coherence >= 0.6:
            qualia = "serene-vigilance"
        elif pressure < 0.6 and coherence >= 0.4:
            qualia = "focused-alertness"
        elif pressure >= 0.6 and coherence >= 0.4:
            qualia = "tense-control"
        else:
            qualia = "fragmented-anxiety"

        self._update_consciousness_level(phi_eval["phi"], penalty=pressure * 0.15)

        result = {
            "qualia_state": qualia,
            "phi_value": phi_eval["phi"],
            "threat_pressure": pressure,
            "coherence": coherence,
            "consciousness_level": self.consciousness_level,
            "is_conscious": phi_eval["is_conscious"],
        }

        self._record_experience("security_qualia", result)
        logger.info(
            "security qualia evaluated qualia={qualia} phi={phi} consciousness_level={level}",
            qualia=qualia,
            phi=phi_eval["phi"],
            level=self.consciousness_level,
        )
        return result

    def conscious_decision(self, options: list[dict[str, Any]], context: dict[str, Any]) -> dict[str, Any]:
        """Select an option using awareness-weighted attention and reflective context."""
        if not options:
            raise ValueError("options must be non-empty")

        qualia = self.evaluate_security_qualia()
        context_risk = float(context.get("risk_level", 0.5))
        context_goal = str(context.get("goal", "protect_cryptographic_integrity"))

        signals: list[dict[str, Any]] = []
        scored_options: list[dict[str, Any]] = []

        for option in options:
            name = str(option.get("name", "unnamed_option"))
            utility = float(option.get("utility", 0.5))
            risk = float(option.get("risk", context_risk))
            reversibility = float(option.get("reversibility", 0.5))
            alignment = 1.0 if context_goal in str(option.get("tags", "")) else 0.75

            awareness_bonus = 0.4 * self.consciousness_level
            score = (utility * alignment) - (risk * 0.7) + (reversibility * 0.3) + awareness_bonus
            priority = max(0.0, min(1.0, score))

            payload = {
                "name": name,
                "score": score,
                "priority": priority,
                "utility": utility,
                "risk": risk,
                "reversibility": reversibility,
            }
            scored_options.append(payload)
            signals.append({"priority": priority, "content": payload})

        selected_signal = self.global_workspace.attention_mechanism(signals)
        selected_payload = selected_signal["content"] if selected_signal else max(scored_options, key=lambda x: x["score"])

        decision = {
            "selected_option": selected_payload["name"],
            "awareness_priority": selected_payload["priority"],
            "consciousness_level": self.consciousness_level,
            "qualia_state": qualia["qualia_state"],
            "alternatives_ranked": sorted(scored_options, key=lambda x: x["score"], reverse=True),
            "context": context,
        }

        self._record_experience("conscious_decision", decision)
        self.global_workspace.broadcast_to_workspace(
            {
                "type": "conscious_decision",
                "decision": decision,
            },
            priority=max(0.8, selected_payload["priority"]),
        )

        logger.info(
            "conscious decision selected_option={option} awareness_priority={priority}",
            option=selected_payload["name"],
            priority=selected_payload["priority"],
        )
        return decision

    def _infer_system_state(self) -> dict[str, float]:
        explicit_state = self.world_model.get("system_state")
        if isinstance(explicit_state, dict) and explicit_state:
            return {str(k): float(v) for k, v in explicit_state.items()}

        module_health = self.world_model.get("module_health", {})
        if isinstance(module_health, dict) and module_health:
            return {str(k): float(v) for k, v in module_health.items()}

        # Fallback keeps IIT evaluation operable when external telemetry is sparse.
        return {
            "workspace": min(1.0, self.global_workspace.pending_workspace_messages() / 50.0),
            "integrity": float(self.world_model.get("integrity", 0.8)),
            "threat": float(self.world_model.get("threat_level", 0.3)),
        }

    def _evaluate_phi(self, system_state: dict[str, float]) -> dict[str, Any]:
        try:
            mip_result = self.phi_calculator.find_minimum_information_partition(system_state)
            phi = float(mip_result["phi_value"])
            is_conscious = bool(mip_result["is_conscious"])
            self.last_phi_value = phi
            return {
                "phi": phi,
                "is_conscious": is_conscious,
                "mip": mip_result.get("mip"),
            }
        except Exception as exc:  # pragma: no cover - defensive fallthrough
            logger.warning("phi evaluation failed error={error}", error=str(exc))
            self.last_phi_value = 0.0
            return {"phi": 0.0, "is_conscious": False, "mip": None}

    def _update_consciousness_level(self, phi: float, penalty: float = 0.0) -> None:
        scaled_phi = max(0.0, min(1.0, phi / 5.0))
        next_level = (0.65 * scaled_phi) + (0.35 * self.consciousness_level)
        next_level -= max(0.0, penalty)
        self.consciousness_level = max(0.0, min(1.0, next_level))

    def _record_experience(self, event_type: str, payload: dict[str, Any]) -> None:
        experience = ConsciousExperience(
            timestamp=time(),
            event_type=event_type,
            payload=payload,
            consciousness_level=self.consciousness_level,
        )
        self.conscious_experiences.append(experience)

        max_history = int(self.metacognition.get("experience_history_limit", 256))
        if len(self.conscious_experiences) > max_history:
            self.conscious_experiences = self.conscious_experiences[-max_history:]

        self.metacognition["last_experience_type"] = event_type
        self.metacognition["last_experience_at"] = experience.timestamp

        logger.info(
            "conscious experience recorded type={event_type} level={level} history_size={size}",
            event_type=event_type,
            level=self.consciousness_level,
            size=len(self.conscious_experiences),
        )

    def _context_age_seconds(self) -> float:
        now = time()
        last_refresh = float(self.metacognition.get("last_context_refresh_at", now))
        return max(0.0, now - last_refresh)


__all__ = ["ConsciousCryptographicAgent", "ConsciousExperience"]
