"""High-level encryption workflow orchestration.

This module defines `EncryptionOrchestrator`, a coordination layer that sits
above providers and executes a full encryption workflow with policy checks,
risk-aware provider selection, storage persistence, audit logging, and rollback
on failure.
"""

from __future__ import annotations

import asyncio
import inspect
from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol, Sequence

from src.abstractions.crypto_provider import CryptoProvider
from src.abstractions.intelligence_provider import IntelligenceProvider, RiskScore, SecurityContext
from src.abstractions.key_provider import KeyGenerationParams, KeyMaterial, KeyProvider
from src.abstractions.storage_provider import StorageProvider
from src.registry.provider_registry import ProviderRegistry


@dataclass(frozen=True)
class EncryptionContext:
    """Input context for orchestration-level encryption decisions.

    Attributes:
        tenant_id: Logical tenant or boundary identifier.
        actor_id: Principal initiating encryption.
        policy_name: Optional policy identifier for policy engine lookup.
        provider_name: Optional explicit crypto provider name override.
        key_id: Optional pre-existing key identifier to use.
        associated_data: Optional additional authenticated data for providers.
        telemetry_features: Optional telemetry vector for risk models.
        threat_level: Current threat level in [0.0, 1.0].
        sensitivity: Data sensitivity in [0.0, 1.0].
        metadata: Additional orchestration metadata.
        provider_context: Provider-specific context fields.
    """

    tenant_id: str = "default"
    actor_id: str = "system"
    policy_name: str | None = None
    provider_name: str | None = None
    key_id: str | None = None
    associated_data: bytes | None = None
    telemetry_features: Sequence[float] = field(default_factory=tuple)
    threat_level: float = 0.0
    sensitivity: float = 0.5
    metadata: Mapping[str, Any] = field(default_factory=dict)
    provider_context: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class EncryptionPolicy:
    """Normalized policy inputs used by the orchestrator."""

    name: str = "default"
    preferred_provider: str | None = None
    min_security_level: int = 1
    key_algorithm: str = "AES-256-GCM"
    storage_prefix: str = "encrypted"
    require_audit: bool = True


@dataclass(frozen=True)
class EncryptedResult:
    """Result returned by successful orchestration execution."""

    object_id: str
    provider_name: str
    algorithm_name: str
    key_id: str
    policy_name: str
    risk_score: float
    metadata: Mapping[str, Any] = field(default_factory=dict)


class PolicyEngine(Protocol):
    """Policy engine contract used by EncryptionOrchestrator."""

    def load_policy(self, context: EncryptionContext) -> EncryptionPolicy | Mapping[str, Any]:
        """Resolve policy configuration for the provided context."""


class AuditTrail(Protocol):
    """Audit logging contract used by EncryptionOrchestrator."""

    def log_event(self, event_type: str, payload: Mapping[str, Any]) -> Any:
        """Log an audit event; may be sync or async."""


class _NoopAuditTrail:
    def log_event(self, event_type: str, payload: Mapping[str, Any]) -> None:
        _ = (event_type, payload)


class OrchestrationError(RuntimeError):
    """Raised when orchestration fails, including rollback failures."""


class EncryptionOrchestrator:
    """Coordinates complete encryption workflow across provider boundaries."""

    def __init__(
        self,
        *,
        policy_engine: PolicyEngine,
        intelligence_provider: IntelligenceProvider,
        provider_registry: ProviderRegistry,
        key_provider: KeyProvider,
        storage_provider: StorageProvider,
        audit_trail: AuditTrail | None = None,
    ) -> None:
        self._policy_engine = policy_engine
        self._intelligence_provider = intelligence_provider
        self._provider_registry = provider_registry
        self._key_provider = key_provider
        self._storage_provider = storage_provider
        self._audit_trail = audit_trail or _NoopAuditTrail()

    async def orchestrate_encryption(self, data: bytes, context: EncryptionContext) -> EncryptedResult:
        """Execute end-to-end encryption workflow with rollback on failure.

        Workflow:
        1. Load policy from policy engine.
        2. Query intelligence provider for risk score.
        3. Select crypto provider from registry.
        4. Obtain key material from key provider.
        5. Encrypt payload using selected crypto provider.
        6. Persist encrypted payload through storage provider.
        7. Emit audit event.
        """
        self._require_bytes("data", data)

        rollback_state: dict[str, Any] = {
            "object_id": None,
            "generated_key_id": None,
        }

        try:
            policy = await self._load_policy(context)
            risk_score = await self._predict_risk_score(data, context)

            provider_name, crypto_provider = self._select_crypto_provider(policy, context, risk_score)

            key_material, generated = await self._resolve_key_material(policy, context)
            if generated:
                rollback_state["generated_key_id"] = key_material.key_id

            provider_context = self._build_provider_context(context, key_material)
            ciphertext = await asyncio.to_thread(crypto_provider.encrypt, data, provider_context)

            storage_metadata = self._build_storage_metadata(
                context=context,
                policy=policy,
                provider_name=provider_name,
                algorithm_name=crypto_provider.get_algorithm_name(),
                key_id=key_material.key_id,
                risk_score=risk_score,
            )
            object_id = await self._storage_provider.write(ciphertext, storage_metadata)
            rollback_state["object_id"] = object_id

            result = EncryptedResult(
                object_id=object_id,
                provider_name=provider_name,
                algorithm_name=crypto_provider.get_algorithm_name(),
                key_id=key_material.key_id,
                policy_name=policy.name,
                risk_score=risk_score,
                metadata=storage_metadata,
            )

            if policy.require_audit:
                await self._log_audit_event(
                    "encryption.orchestrated",
                    {
                        "object_id": object_id,
                        "provider": provider_name,
                        "algorithm": result.algorithm_name,
                        "key_id": result.key_id,
                        "policy": result.policy_name,
                        "risk_score": result.risk_score,
                        "tenant_id": context.tenant_id,
                        "actor_id": context.actor_id,
                    },
                )

            return result

        except Exception as exc:
            rollback_errors = await self._rollback(rollback_state)
            raise OrchestrationError(self._build_failure_message(exc, rollback_errors)) from exc

    async def _load_policy(self, context: EncryptionContext) -> EncryptionPolicy:
        raw_policy = await asyncio.to_thread(self._policy_engine.load_policy, context)
        return self._normalize_policy(raw_policy, context)

    async def _predict_risk_score(self, data: bytes, context: EncryptionContext) -> float:
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

        score = await asyncio.to_thread(self._intelligence_provider.predict_risk, security_context)
        if isinstance(score, RiskScore):
            return score.value
        if isinstance(score, (float, int)):
            value = float(score)
            if 0.0 <= value <= 1.0:
                return value
        raise ValueError("intelligence provider returned invalid risk score")

    def _select_crypto_provider(
        self,
        policy: EncryptionPolicy,
        context: EncryptionContext,
        risk_score: float,
    ) -> tuple[str, CryptoProvider]:
        candidates = self._provider_registry.list_providers(CryptoProvider)
        if not candidates:
            raise OrchestrationError("no crypto providers registered for CryptoProvider interface")

        selected_name = self._choose_provider_name(candidates, policy, context, risk_score)
        provider = self._provider_registry.get_provider(CryptoProvider, selected_name)

        if provider.get_security_level() < policy.min_security_level:
            raise OrchestrationError(
                f"selected provider '{selected_name}' has insufficient security level "
                f"({provider.get_security_level()} < {policy.min_security_level})"
            )

        return selected_name, provider

    async def _resolve_key_material(
        self,
        policy: EncryptionPolicy,
        context: EncryptionContext,
    ) -> tuple[KeyMaterial, bool]:
        key_id = context.key_id
        generated = False

        if not key_id:
            key_id = await asyncio.to_thread(
                self._key_provider.generate_key,
                KeyGenerationParams(algorithm=policy.key_algorithm),
            )
            generated = True

        material = await asyncio.to_thread(self._key_provider.get_key, key_id)
        return material, generated

    def _build_provider_context(self, context: EncryptionContext, key_material: KeyMaterial) -> dict[str, Any]:
        provider_context: dict[str, Any] = dict(context.provider_context)
        provider_context.setdefault("key", key_material.material)
        provider_context.setdefault("key_id", key_material.key_id)

        if context.associated_data is not None:
            provider_context.setdefault("associated_data", context.associated_data)

        return provider_context

    def _build_storage_metadata(
        self,
        *,
        context: EncryptionContext,
        policy: EncryptionPolicy,
        provider_name: str,
        algorithm_name: str,
        key_id: str,
        risk_score: float,
    ) -> dict[str, Any]:
        metadata = {
            "storage_prefix": policy.storage_prefix,
            "policy_name": policy.name,
            "provider_name": provider_name,
            "algorithm_name": algorithm_name,
            "key_id": key_id,
            "risk_score": risk_score,
            "tenant_id": context.tenant_id,
            "actor_id": context.actor_id,
        }
        metadata.update(dict(context.metadata))
        return metadata

    async def _log_audit_event(self, event_type: str, payload: Mapping[str, Any]) -> None:
        maybe_result = self._audit_trail.log_event(event_type, payload)
        if inspect.isawaitable(maybe_result):
            await maybe_result

    async def _rollback(self, rollback_state: Mapping[str, Any]) -> list[str]:
        errors: list[str] = []

        object_id = rollback_state.get("object_id")
        if isinstance(object_id, str) and object_id:
            try:
                await self._storage_provider.delete(object_id)
            except Exception as exc:  # pragma: no cover - defensive rollback
                errors.append(f"storage rollback failed for object_id={object_id}: {exc}")

        generated_key_id = rollback_state.get("generated_key_id")
        if isinstance(generated_key_id, str) and generated_key_id:
            try:
                await asyncio.to_thread(self._key_provider.rotate_key, generated_key_id)
            except Exception as exc:  # pragma: no cover - defensive rollback
                errors.append(f"key rollback failed for key_id={generated_key_id}: {exc}")

        if errors:
            try:
                await self._log_audit_event(
                    "encryption.rollback.failed",
                    {
                        "errors": errors,
                    },
                )
            except Exception:
                pass

        return errors

    @staticmethod
    def _normalize_policy(raw: EncryptionPolicy | Mapping[str, Any], context: EncryptionContext) -> EncryptionPolicy:
        if isinstance(raw, EncryptionPolicy):
            return raw

        if not isinstance(raw, Mapping):
            raise ValueError("policy engine returned invalid policy payload")

        name = str(raw.get("name") or context.policy_name or "default")
        preferred_provider = raw.get("preferred_provider")
        min_security_level = int(raw.get("min_security_level", 1))
        key_algorithm = str(raw.get("key_algorithm", "AES-256-GCM"))
        storage_prefix = str(raw.get("storage_prefix", "encrypted"))
        require_audit = bool(raw.get("require_audit", True))

        return EncryptionPolicy(
            name=name,
            preferred_provider=str(preferred_provider) if preferred_provider else None,
            min_security_level=min_security_level,
            key_algorithm=key_algorithm,
            storage_prefix=storage_prefix,
            require_audit=require_audit,
        )

    @staticmethod
    def _choose_provider_name(
        candidates: Sequence[str],
        policy: EncryptionPolicy,
        context: EncryptionContext,
        risk_score: float,
    ) -> str:
        normalized = sorted({candidate.strip().lower() for candidate in candidates if candidate.strip()})
        if not normalized:
            raise OrchestrationError("no usable provider names available")

        preferred_chain = [
            context.provider_name,
            policy.preferred_provider,
        ]

        if risk_score >= 0.8:
            preferred_chain.extend(["hybrid", "pqc", "kyber", "dilithium"])
        else:
            preferred_chain.extend(["classical", "aes", "chacha"])

        for hint in preferred_chain:
            if not hint:
                continue
            needle = hint.strip().lower()
            for candidate in normalized:
                if needle == candidate or needle in candidate:
                    return candidate

        return normalized[0]

    @staticmethod
    def _build_failure_message(error: Exception, rollback_errors: Sequence[str]) -> str:
        if rollback_errors:
            return (
                f"encryption orchestration failed: {error}. "
                f"rollback issues: {' | '.join(rollback_errors)}"
            )
        return f"encryption orchestration failed: {error}"

    @staticmethod
    def _require_bytes(name: str, value: object) -> None:
        if not isinstance(value, bytes):
            raise TypeError(f"{name} must be bytes")


__all__ = [
    "EncryptionContext",
    "EncryptionPolicy",
    "EncryptedResult",
    "PolicyEngine",
    "AuditTrail",
    "OrchestrationError",
    "EncryptionOrchestrator",
]
