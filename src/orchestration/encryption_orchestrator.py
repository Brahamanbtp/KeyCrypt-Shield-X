"""High-level encryption workflow orchestration.

This module defines `EncryptionOrchestrator`, a coordination layer that sits
above providers and executes a full encryption workflow with policy checks,
risk-aware provider selection, storage persistence, audit logging, and rollback
on failure.
"""

from __future__ import annotations

import asyncio
import inspect
from dataclasses import asdict, dataclass, field
from typing import Any, AsyncIterator, Callable, Mapping, Protocol, Sequence, TypeAlias

from src.abstractions.crypto_provider import CryptoProvider
from src.abstractions.intelligence_provider import IntelligenceProvider, RiskScore, SecurityContext
from src.abstractions.key_provider import KeyGenerationParams, KeyMaterial, KeyProvider
from src.abstractions.storage_provider import StorageProvider
from src.registry.provider_registry import ProviderRegistry
from src.streaming.async_pipeline import AsyncEncryptionPipeline, AsyncWriter


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


Context: TypeAlias = EncryptionContext


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


@dataclass(frozen=True)
class EncryptedData:
    """High-level encrypted payload returned by `EncryptionOrchestrator.encrypt`.

    Attributes:
        ciphertext: Encrypted bytes produced by the selected provider.
        provider_name: Registered provider name selected from registry.
        algorithm_name: Provider algorithm identifier used for encryption.
        key_id: Key identifier used for encryption context.
        policy_name: Policy name resolved by policy engine.
        metadata: Additional orchestration metadata and pipeline stats.
    """

    ciphertext: bytes
    provider_name: str
    algorithm_name: str
    key_id: str
    policy_name: str
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class _PolicyDecisionHints:
    selected_algorithm: str | None = None
    key_rotation_schedule: str | None = None
    compliance_tags: list[str] = field(default_factory=list)


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


class _InMemorySink(AsyncWriter):
    """Async sink that accumulates encrypted chunks in memory."""

    def __init__(self) -> None:
        self._buffer = bytearray()

    async def write(self, data: bytes) -> None:
        if not isinstance(data, bytes):
            raise TypeError("sink expects bytes")
        self._buffer.extend(data)

    async def aclose(self) -> None:
        return

    @property
    def payload(self) -> bytes:
        return bytes(self._buffer)


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
        observability: AuditTrail | None = None,
        pipeline_factory: Callable[..., AsyncEncryptionPipeline] | None = None,
    ) -> None:
        self._policy_engine = policy_engine
        self._intelligence_provider = intelligence_provider
        self._provider_registry = provider_registry
        self._key_provider = key_provider
        self._storage_provider = storage_provider
        self._audit_trail = observability or audit_trail or _NoopAuditTrail()
        self._pipeline_factory = pipeline_factory or AsyncEncryptionPipeline

    async def encrypt(self, data: bytes, context: Context) -> EncryptedData:
        """Coordinate full high-level encryption flow.

        Steps:
        1. Evaluate policy via policy engine.
        2. Select provider from registry (`get_provider`).
        3. Execute encryption using `AsyncEncryptionPipeline`.
        4. Log observability event.

        Args:
            data: Plaintext bytes to encrypt.
            context: Orchestration context used for policy and provider routing.

        Returns:
            EncryptedData containing ciphertext and orchestration metadata.
        """
        self._require_bytes("data", data)
        if not isinstance(context, EncryptionContext):
            raise TypeError("context must be EncryptionContext")

        policy = await self._load_policy(context)
        decision = await self._evaluate_policy_decision(context, policy)

        provider_name, crypto_provider = self._select_provider_for_pipeline(
            policy=policy,
            context=context,
            decision=decision,
        )

        key_material, _generated = await self._resolve_key_material(policy, context)
        provider_context = self._build_provider_context(context, key_material)
        if decision.selected_algorithm:
            provider_context.setdefault("selected_algorithm", decision.selected_algorithm)

        queue_maxsize, transform_workers, chunk_size = self._extract_pipeline_settings(context)
        pipeline = self._pipeline_factory(
            crypto_provider=crypto_provider,
            encryption_context=provider_context,
            queue_maxsize=queue_maxsize,
            transform_workers=transform_workers,
        )

        sink = _InMemorySink()
        stats = await pipeline.process_stream(
            self._chunk_source(data, chunk_size=chunk_size),
            sink,
        )

        ciphertext = sink.payload
        metadata = {
            "policy_name": policy.name,
            "selected_algorithm": decision.selected_algorithm,
            "provider_name": provider_name,
            "algorithm_name": crypto_provider.get_algorithm_name(),
            "key_id": key_material.key_id,
            "queue_maxsize": queue_maxsize,
            "transform_workers": transform_workers,
            "chunk_size": chunk_size,
            "pipeline_stats": asdict(stats),
            "context_metadata": dict(context.metadata),
        }

        await self._log_audit_event(
            "encryption.flow.completed",
            {
                "provider": provider_name,
                "algorithm": metadata["algorithm_name"],
                "key_id": key_material.key_id,
                "policy": policy.name,
                "input_size": len(data),
                "output_size": len(ciphertext),
                "pipeline_stats": metadata["pipeline_stats"],
            },
        )

        return EncryptedData(
            ciphertext=ciphertext,
            provider_name=provider_name,
            algorithm_name=str(metadata["algorithm_name"]),
            key_id=key_material.key_id,
            policy_name=policy.name,
            metadata=metadata,
        )

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

    def _select_provider_for_pipeline(
        self,
        *,
        policy: EncryptionPolicy,
        context: EncryptionContext,
        decision: _PolicyDecisionHints,
    ) -> tuple[str, CryptoProvider]:
        candidates = self._provider_registry.list_providers(CryptoProvider)
        if not candidates:
            raise OrchestrationError("no crypto providers registered for CryptoProvider interface")

        normalized_candidates = sorted({item.strip().lower() for item in candidates if item.strip()})
        hints: list[str] = []

        if context.provider_name:
            hints.append(context.provider_name.strip().lower())
        if policy.preferred_provider:
            hints.append(policy.preferred_provider.strip().lower())
        hints.extend(self._provider_hints_from_algorithm(decision.selected_algorithm))

        selected_name = normalized_candidates[0]
        for hint in hints:
            for candidate in normalized_candidates:
                if hint == candidate or hint in candidate:
                    selected_name = candidate
                    break
            else:
                continue
            break

        provider = self._provider_registry.get_provider(CryptoProvider, selected_name)
        provider = self._apply_algorithm_override_if_supported(provider, decision.selected_algorithm)

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

    async def _evaluate_policy_decision(
        self,
        context: EncryptionContext,
        policy: EncryptionPolicy,
    ) -> _PolicyDecisionHints:
        evaluator = getattr(self._policy_engine, "evaluate_policy", None)
        if not callable(evaluator):
            return _PolicyDecisionHints()

        raw_decision: Any
        try:
            raw_decision = evaluator(context, policy)
        except TypeError:
            try:
                raw_decision = evaluator(context=context, policy=policy)
            except TypeError:
                return _PolicyDecisionHints()

        if inspect.isawaitable(raw_decision):
            raw_decision = await raw_decision

        return self._normalize_policy_decision(raw_decision)

    @staticmethod
    def _normalize_policy_decision(raw_decision: Any) -> _PolicyDecisionHints:
        if raw_decision is None:
            return _PolicyDecisionHints()

        if isinstance(raw_decision, Mapping):
            selected_algorithm = raw_decision.get("selected_algorithm", raw_decision.get("algorithm"))
            key_rotation = raw_decision.get("key_rotation_schedule", raw_decision.get("key_rotation"))
            tags = raw_decision.get("compliance_tags", [])
        else:
            selected_algorithm = getattr(raw_decision, "selected_algorithm", getattr(raw_decision, "algorithm", None))
            key_rotation = getattr(raw_decision, "key_rotation_schedule", getattr(raw_decision, "key_rotation", None))
            tags = getattr(raw_decision, "compliance_tags", [])

        normalized_tags = [
            str(tag).strip()
            for tag in tags
            if isinstance(tag, str) and str(tag).strip()
        ] if isinstance(tags, list) else []

        return _PolicyDecisionHints(
            selected_algorithm=str(selected_algorithm).strip() if isinstance(selected_algorithm, str) and selected_algorithm.strip() else None,
            key_rotation_schedule=str(key_rotation).strip() if isinstance(key_rotation, str) and key_rotation.strip() else None,
            compliance_tags=normalized_tags,
        )

    @staticmethod
    def _provider_hints_from_algorithm(algorithm: str | None) -> list[str]:
        if not algorithm:
            return []

        needle = algorithm.strip().lower()
        hints: list[str] = [needle]

        if any(token in needle for token in ("kyber", "dilithium", "pqc")):
            hints.append("pqc")
        if "hybrid" in needle:
            hints.append("hybrid")
        if any(token in needle for token in ("aes", "chacha", "classical")):
            hints.append("classical")

        return hints

    @staticmethod
    def _apply_algorithm_override_if_supported(
        provider: CryptoProvider,
        selected_algorithm: str | None,
    ) -> CryptoProvider:
        if not selected_algorithm:
            return provider

        try:
            current = provider.get_algorithm_name().strip().lower()
        except Exception:
            return provider

        target = selected_algorithm.strip().lower()
        if not target or target == current:
            return provider

        provider_cls = type(provider)
        try:
            candidate = provider_cls(target)
            if isinstance(candidate, CryptoProvider):
                return candidate
        except Exception:
            return provider

        return provider

    @staticmethod
    def _extract_pipeline_settings(context: EncryptionContext) -> tuple[int, int, int]:
        metadata = context.metadata if isinstance(context.metadata, Mapping) else {}

        queue_maxsize = EncryptionOrchestrator._coerce_positive_int(metadata.get("pipeline_queue_maxsize"), 10)
        transform_workers = EncryptionOrchestrator._coerce_positive_int(metadata.get("pipeline_transform_workers"), 1)
        chunk_size = EncryptionOrchestrator._coerce_positive_int(metadata.get("pipeline_chunk_size"), 1024 * 1024)
        return queue_maxsize, transform_workers, chunk_size

    @staticmethod
    async def _chunk_source(data: bytes, *, chunk_size: int) -> AsyncIterator[bytes]:
        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive")

        for offset in range(0, len(data), chunk_size):
            yield data[offset : offset + chunk_size]

    @staticmethod
    def _coerce_positive_int(value: Any, default: int) -> int:
        try:
            parsed = int(value)
            if parsed > 0:
                return parsed
        except Exception:
            pass
        return default

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
    "Context",
    "EncryptionContext",
    "EncryptionPolicy",
    "EncryptedData",
    "EncryptedResult",
    "PolicyEngine",
    "AuditTrail",
    "OrchestrationError",
    "EncryptionOrchestrator",
]
