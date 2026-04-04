"""Adaptive orchestration layer with multi-intelligence decisioning.

This module extends `EncryptionOrchestrator` and composes intelligence
providers to make runtime-adaptive encryption decisions while preserving
existing orchestration behavior.
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from src.abstractions.intelligence_provider import DataProfile, SecurityContext
from src.abstractions.key_provider import KeyProvider
from src.abstractions.storage_provider import StorageProvider
from src.orchestration.encryption_orchestrator import (
    AuditTrail,
    EncryptedResult,
    EncryptionContext,
    EncryptionOrchestrator,
    EncryptionPolicy,
    PolicyEngine,
)
from src.providers.intelligence.ai_intelligence_provider import AIIntelligenceProvider
from src.providers.intelligence.consciousness_intelligence_provider import (
    ConsciousnessIntelligenceProvider,
    Threat,
)
from src.providers.intelligence.evolutionary_intelligence_provider import (
    EvolutionaryIntelligenceProvider,
    OptimizationConstraints,
    ThreatLandscape,
)
from src.registry.provider_registry import ProviderRegistry


@dataclass(frozen=True)
class LearningSignal:
    """Stored adaptive learning signal used to tune future decisions."""

    timestamp: float
    risk_score: float
    selected_algorithm: str
    outcome_quality: float
    used_fallback: bool
    metadata: dict[str, Any] = field(default_factory=dict)


class AdaptiveOrchestrator(EncryptionOrchestrator):
    """Encryption orchestrator augmented with adaptive intelligence providers."""

    def __init__(
        self,
        *,
        policy_engine: PolicyEngine,
        intelligence_provider: AIIntelligenceProvider,
        consciousness_provider: ConsciousnessIntelligenceProvider,
        evolutionary_provider: EvolutionaryIntelligenceProvider,
        provider_registry: ProviderRegistry,
        key_provider: KeyProvider,
        storage_provider: StorageProvider,
        audit_trail: AuditTrail | None = None,
        observability: AuditTrail | None = None,
        pipeline_factory: Any | None = None,
        high_risk_threshold: float = 0.75,
        evolution_trigger_interval_seconds: float = 900.0,
        enable_learning_mode: bool = True,
        learning_window: int = 256,
    ) -> None:
        super().__init__(
            policy_engine=policy_engine,
            intelligence_provider=intelligence_provider,
            provider_registry=provider_registry,
            key_provider=key_provider,
            storage_provider=storage_provider,
            audit_trail=audit_trail,
            observability=observability,
            pipeline_factory=pipeline_factory,
        )

        if not isinstance(intelligence_provider, AIIntelligenceProvider):
            raise TypeError("intelligence_provider must be AIIntelligenceProvider")
        if not isinstance(consciousness_provider, ConsciousnessIntelligenceProvider):
            raise TypeError("consciousness_provider must be ConsciousnessIntelligenceProvider")
        if not isinstance(evolutionary_provider, EvolutionaryIntelligenceProvider):
            raise TypeError("evolutionary_provider must be EvolutionaryIntelligenceProvider")

        if not 0.0 <= high_risk_threshold <= 1.0:
            raise ValueError("high_risk_threshold must be in [0, 1]")
        if evolution_trigger_interval_seconds <= 0:
            raise ValueError("evolution_trigger_interval_seconds must be > 0")
        if learning_window <= 0:
            raise ValueError("learning_window must be > 0")

        self._ai_provider = intelligence_provider
        self._consciousness_provider = consciousness_provider
        self._evolutionary_provider = evolutionary_provider

        self._high_risk_threshold = float(high_risk_threshold)
        self._evolution_trigger_interval_seconds = float(evolution_trigger_interval_seconds)
        self._enable_learning_mode = bool(enable_learning_mode)
        self._learning_signals: deque[LearningSignal] = deque(maxlen=int(learning_window))

        self._last_evolution_trigger_at = 0.0
        self._pending_evolution_job_id: str | None = None
        self._algorithm_overrides: dict[str, str] = {}

    async def adaptive_encrypt(self, data: bytes, context: EncryptionContext) -> EncryptedResult:
        """Encrypt data using adaptive intelligence-driven decision workflow.

        Workflow:
        1. Query AI intelligence provider for risk assessment.
        2. If risk is high, query consciousness provider for introspection.
        3. Select algorithm based on risk + consciousness insights.
        4. Periodically trigger evolutionary protocol optimization.
        """
        self._require_bytes("data", data)
        if not isinstance(context, EncryptionContext):
            raise TypeError("context must be EncryptionContext")

        policy = await self._load_policy(context)

        risk_score, ai_metadata, used_fallback = await self._assess_risk(data, context)

        consciousness_payload: dict[str, Any] = {}
        if risk_score >= self._high_risk_threshold:
            consciousness_payload = await self._gather_consciousness_insights(risk_score, context)

        selected_algorithm = self._select_algorithm(
            context=context,
            policy=policy,
            risk_score=risk_score,
            ai_metadata=ai_metadata,
            consciousness_payload=consciousness_payload,
        )

        self._algorithm_overrides[context.tenant_id] = selected_algorithm

        adapted_context = self._inject_adaptive_context(
            context=context,
            selected_algorithm=selected_algorithm,
            risk_score=risk_score,
            ai_metadata=ai_metadata,
            consciousness_payload=consciousness_payload,
            used_fallback=used_fallback,
        )

        result = await self.orchestrate_encryption(data=data, context=adapted_context)

        await self._maybe_trigger_evolution(
            context=adapted_context,
            selected_algorithm=selected_algorithm,
            risk_score=risk_score,
            consciousness_payload=consciousness_payload,
        )

        if self._enable_learning_mode:
            self._record_learning_signal(result, selected_algorithm=selected_algorithm, used_fallback=used_fallback)

        return result

    async def _predict_risk_score(self, data: bytes, context: EncryptionContext) -> float:
        """Override base risk scoring to preserve adaptive fallback behavior."""
        adaptive_risk = context.metadata.get("adaptive_risk_score")
        if isinstance(adaptive_risk, (float, int)):
            return self._clamp01(float(adaptive_risk))

        try:
            return await super()._predict_risk_score(data, context)
        except Exception:
            security_context = SecurityContext(
                asset_id=context.tenant_id,
                actor_id=context.actor_id,
                operation="encrypt",
                telemetry_features=tuple(context.telemetry_features),
                current_threat_level=float(context.threat_level),
                sensitivity=float(context.sensitivity),
                metadata={
                    **dict(context.metadata),
                    "payload_size_bytes": len(data),
                    "policy_name": context.policy_name,
                },
            )
            return self._rule_based_risk(security_context)

    def get_learning_summary(self) -> dict[str, Any]:
        """Return aggregate metrics from adaptive learning mode."""
        if not self._learning_signals:
            return {
                "signals": 0,
                "mean_risk": 0.0,
                "mean_outcome_quality": 0.0,
                "fallback_rate": 0.0,
                "algorithm_preferences": {},
            }

        signals = list(self._learning_signals)
        mean_risk = sum(item.risk_score for item in signals) / len(signals)
        mean_outcome = sum(item.outcome_quality for item in signals) / len(signals)
        fallback_rate = sum(1 for item in signals if item.used_fallback) / len(signals)

        preferences: dict[str, int] = {}
        for item in signals:
            algo = item.selected_algorithm.lower().strip()
            preferences[algo] = preferences.get(algo, 0) + 1

        return {
            "signals": len(signals),
            "mean_risk": mean_risk,
            "mean_outcome_quality": mean_outcome,
            "fallback_rate": fallback_rate,
            "algorithm_preferences": dict(sorted(preferences.items(), key=lambda kv: kv[1], reverse=True)),
        }

    async def _assess_risk(
        self,
        data: bytes,
        context: EncryptionContext,
    ) -> tuple[float, dict[str, Any], bool]:
        security_context = SecurityContext(
            asset_id=context.tenant_id,
            actor_id=context.actor_id,
            operation="encrypt",
            telemetry_features=tuple(context.telemetry_features),
            current_threat_level=float(context.threat_level),
            sensitivity=float(context.sensitivity),
            metadata={
                **dict(context.metadata),
                "payload_size_bytes": len(data),
                "policy_name": context.policy_name,
            },
        )

        try:
            score = await asyncio.to_thread(self._ai_provider.predict_risk, security_context)
            risk_value = float(score.value)
            metadata = dict(score.metadata) if isinstance(score.metadata, Mapping) else {}
            metadata.setdefault("confidence", float(score.confidence))
            return self._clamp01(risk_value), metadata, bool(metadata.get("fallback", False))
        except Exception as exc:
            fallback_score = self._rule_based_risk(security_context)
            metadata = {
                "fallback": True,
                "reason": f"ai-risk-failure: {exc}",
            }
            return fallback_score, metadata, True

    async def _gather_consciousness_insights(
        self,
        risk_score: float,
        context: EncryptionContext,
    ) -> dict[str, Any]:
        def _collect() -> dict[str, Any]:
            vulnerabilities = self._consciousness_provider.introspect_vulnerabilities()
            qualia = self._consciousness_provider.evaluate_security_qualia()

            threat = Threat(
                threat_id=f"adaptive-{int(time.time() * 1000)}",
                threat_type="runtime-risk",
                severity=self._clamp01(risk_score),
                vector=str(context.metadata.get("threat_vector", "unknown")),
                indicators=[str(item) for item in context.metadata.get("threat_indicators", [])]
                if isinstance(context.metadata.get("threat_indicators", []), list)
                else [],
                metadata={"incident_pressure": self._clamp01(risk_score)},
            )
            assessment = self._consciousness_provider.conscious_threat_assessment(threat)

            return {
                "vulnerabilities": vulnerabilities,
                "qualia": qualia,
                "assessment": assessment,
            }

        try:
            return await asyncio.to_thread(_collect)
        except Exception as exc:
            return {
                "error": str(exc),
                "vulnerabilities": [],
            }

    def _select_algorithm(
        self,
        *,
        context: EncryptionContext,
        policy: EncryptionPolicy,
        risk_score: float,
        ai_metadata: Mapping[str, Any],
        consciousness_payload: Mapping[str, Any],
    ) -> str:
        profile = DataProfile(
            data_type=str(context.metadata.get("data_type", "file")),
            size_bytes=int(context.metadata.get("payload_size_bytes", 0)),
            latency_budget_ms=float(context.metadata.get("latency_budget_ms", 25.0)),
            confidentiality_level=self._clamp01(float(context.sensitivity)),
            integrity_level=self._clamp01(float(context.metadata.get("integrity_level", 0.8))),
            compliance_tags=self._coerce_string_list(context.metadata.get("compliance_tags", [])),
            metadata={
                "quantum_risk": context.metadata.get("quantum_risk", ""),
            },
        )

        recommended = ""
        ai_confidence = self._clamp01(float(ai_metadata.get("confidence", 0.0)))
        try:
            recommendation = self._ai_provider.suggest_algorithm(profile)
            recommended = recommendation.algorithm_name.strip().lower()
            ai_confidence = self._clamp01(float(recommendation.confidence))
        except Exception:
            recommended = ""

        if recommended:
            if risk_score >= 0.85 and "hybrid" not in recommended and "kyber" not in recommended:
                recommended = "hybrid-kem"

            if self._enable_learning_mode and ai_confidence < 0.55:
                learned = self._learned_algorithm_preference(risk_score)
                if learned:
                    return learned
            return recommended

        assessment = consciousness_payload.get("assessment")
        if assessment is not None:
            chosen = str(assessment.metadata.get("selected_response", "")).lower().strip()
            if chosen in {"immediate_containment", "adaptive_hardening"}:
                return "hybrid-kem"

            qualia_state = str(getattr(consciousness_payload.get("qualia"), "qualia_state", "")).lower()
            if "anxiety" in qualia_state or "tense" in qualia_state:
                return "aes-gcm"

        tenant_override = self._algorithm_overrides.get(context.tenant_id)
        if tenant_override:
            return tenant_override

        if self._enable_learning_mode:
            learned = self._learned_algorithm_preference(risk_score)
            if learned:
                return learned

        if risk_score >= 0.85:
            return "hybrid-kem"
        if risk_score >= 0.65:
            return "aes-gcm"
        return policy.key_algorithm.strip().lower()

    async def _maybe_trigger_evolution(
        self,
        *,
        context: EncryptionContext,
        selected_algorithm: str,
        risk_score: float,
        consciousness_payload: Mapping[str, Any],
    ) -> None:
        now = time.time()

        if self._pending_evolution_job_id:
            try:
                result = await asyncio.to_thread(
                    self._evolutionary_provider.get_async_result,
                    self._pending_evolution_job_id,
                    timeout_seconds=0.0,
                )
            except KeyError:
                self._pending_evolution_job_id = None
                result = None
            except Exception:
                result = None

            if result is not None:
                self._algorithm_overrides[context.tenant_id] = result.protocol.algorithm.strip().lower()
                self._pending_evolution_job_id = None

        if now - self._last_evolution_trigger_at < self._evolution_trigger_interval_seconds:
            return
        if self._pending_evolution_job_id is not None:
            return

        vulnerabilities = consciousness_payload.get("vulnerabilities", [])
        threat_level = max(
            self._clamp01(float(risk_score)),
            self._clamp01(float(context.threat_level)),
        )

        compliance_tags = self._coerce_string_list(context.metadata.get("compliance_tags", []))
        active_threats = [
            str(item.component)
            for item in vulnerabilities[:5]
            if hasattr(item, "component")
        ]

        landscape = ThreatLandscape(
            threat_level=threat_level,
            active_threats=active_threats,
            attack_surface_points=max(4, len(vulnerabilities) + 4),
            compliance_requirements=compliance_tags,
            performance_pressure=self._clamp01(float(context.metadata.get("performance_pressure", 0.5))),
            metadata={
                "tenant_id": context.tenant_id,
                "selected_algorithm": selected_algorithm,
            },
        )

        constraints = OptimizationConstraints(
            population_size=36,
            generations=12,
            fitness_target=0.82,
            mutation_rate=0.16 + (0.12 * threat_level),
            attack_surface_points=landscape.attack_surface_points,
        )

        try:
            job_id = await asyncio.to_thread(self._evolutionary_provider.optimize_protocol_async, constraints)
            self._pending_evolution_job_id = job_id
            self._last_evolution_trigger_at = now
        except Exception:
            # Evolution is best-effort; orchestration should not fail if optimization fails.
            return

    def _inject_adaptive_context(
        self,
        *,
        context: EncryptionContext,
        selected_algorithm: str,
        risk_score: float,
        ai_metadata: Mapping[str, Any],
        consciousness_payload: Mapping[str, Any],
        used_fallback: bool,
    ) -> EncryptionContext:
        metadata = dict(context.metadata)
        metadata["adaptive_selected_algorithm"] = selected_algorithm
        metadata["adaptive_risk_score"] = risk_score
        metadata["adaptive_ai_metadata"] = dict(ai_metadata)
        metadata["adaptive_fallback_used"] = bool(used_fallback)

        qualia = consciousness_payload.get("qualia")
        if qualia is not None:
            metadata["adaptive_qualia_state"] = getattr(qualia, "qualia_state", "unknown")
            metadata["adaptive_phi"] = float(getattr(qualia, "phi_value", 0.0))

        assessment = consciousness_payload.get("assessment")
        if assessment is not None:
            metadata["adaptive_conscious_priority"] = getattr(assessment, "priority", "unknown")
            metadata["adaptive_conscious_confidence"] = float(
                getattr(assessment, "metacognitive_confidence", 0.0)
            )

        provider_context = dict(context.provider_context)
        provider_context.setdefault("selected_algorithm", selected_algorithm)

        adaptive_provider_hint = self._provider_hint_from_algorithm(selected_algorithm)
        provider_name = context.provider_name
        if adaptive_provider_hint and not provider_name:
            provider_name = adaptive_provider_hint

        return EncryptionContext(
            tenant_id=context.tenant_id,
            actor_id=context.actor_id,
            policy_name=context.policy_name,
            provider_name=provider_name,
            key_id=context.key_id,
            associated_data=context.associated_data,
            telemetry_features=tuple(context.telemetry_features),
            threat_level=float(context.threat_level),
            sensitivity=float(context.sensitivity),
            metadata=metadata,
            provider_context=provider_context,
        )

    def _record_learning_signal(
        self,
        result: EncryptedResult,
        *,
        selected_algorithm: str,
        used_fallback: bool,
    ) -> None:
        output_size = float(result.metadata.get("output_size", 0.0))
        risk_score = self._clamp01(float(result.risk_score))

        # Lightweight proxy for outcome quality: lower risk + successful completion.
        quality = self._clamp01(1.0 - risk_score)
        if output_size > 0:
            quality = self._clamp01(min(1.0, quality + 0.05))

        self._learning_signals.append(
            LearningSignal(
                timestamp=time.time(),
                risk_score=risk_score,
                selected_algorithm=selected_algorithm,
                outcome_quality=quality,
                used_fallback=used_fallback,
                metadata={
                    "provider_name": result.provider_name,
                    "policy_name": result.policy_name,
                },
            )
        )

    def _learned_algorithm_preference(self, risk_score: float) -> str | None:
        if not self._learning_signals:
            return None

        window = [
            item
            for item in self._learning_signals
            if abs(item.risk_score - risk_score) <= 0.20 and item.outcome_quality >= 0.55
        ]
        if not window:
            return None

        weighted: dict[str, float] = {}
        for item in window:
            key = item.selected_algorithm.strip().lower()
            weighted[key] = weighted.get(key, 0.0) + item.outcome_quality

        if not weighted:
            return None

        best = sorted(weighted.items(), key=lambda kv: kv[1], reverse=True)[0][0]
        return best

    @staticmethod
    def _provider_hint_from_algorithm(algorithm: str) -> str | None:
        normalized = algorithm.strip().lower()
        if not normalized:
            return None

        if any(token in normalized for token in ("hybrid", "kyber", "dilithium", "pqc")):
            return "hybrid"
        if any(token in normalized for token in ("aes", "chacha", "classical")):
            return "classical"

        return None

    @staticmethod
    def _rule_based_risk(context: SecurityContext) -> float:
        telemetry = [float(item) for item in context.telemetry_features if isinstance(item, (int, float))]
        telemetry_factor = 0.0
        if telemetry:
            telemetry_factor = sum(abs(item) for item in telemetry) / len(telemetry)
            telemetry_factor = min(1.0, telemetry_factor)

        threat = max(0.0, min(1.0, float(context.current_threat_level)))
        sensitivity = max(0.0, min(1.0, float(context.sensitivity)))

        return max(0.0, min(1.0, (0.45 * threat) + (0.40 * sensitivity) + (0.15 * telemetry_factor)))

    @staticmethod
    def _coerce_string_list(value: Any) -> list[str]:
        if not isinstance(value, list):
            return []
        output: list[str] = []
        for item in value:
            if not isinstance(item, str):
                continue
            normalized = item.strip()
            if normalized:
                output.append(normalized)
        return output

    @staticmethod
    def _clamp01(value: float) -> float:
        if value < 0.0:
            return 0.0
        if value > 1.0:
            return 1.0
        return float(value)


__all__ = [
    "LearningSignal",
    "AdaptiveOrchestrator",
]
