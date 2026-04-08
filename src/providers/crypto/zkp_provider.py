"""Zero-knowledge proof provider wrapper.

This module wraps ZKP backends under ``src.zkp.*`` without modifying those
implementations. It exposes a stable provider-level API for generating,
verifying, and serializing zero-knowledge proofs.

Supported proof systems:
- zk-SNARKs
- zk-STARKs
- Bulletproofs
"""

from __future__ import annotations

import base64
import hashlib
import importlib
import inspect
import json
import math
import secrets
import time
import uuid
from dataclasses import dataclass, field
from types import ModuleType
from typing import Any, Mapping, Sequence

from src.utils.logging import get_logger


logger = get_logger("src.providers.crypto.zkp_provider")


_DEFAULT_PROOF_SYSTEMS: tuple[str, ...] = ("zk-snarks", "zk-starks", "bulletproofs")


_MODULE_CANDIDATES: dict[str, tuple[str, ...]] = {
    "zk-snarks": (
        "src.zkp.zk_snarks",
        "src.zkp.snarks",
        "src.zkp.zksnark",
    ),
    "zk-starks": (
        "src.zkp.zk_starks",
        "src.zkp.starks",
        "src.zkp.zkstark",
    ),
    "bulletproofs": (
        "src.zkp.bulletproofs",
        "src.zkp.bulletproof",
    ),
}


@dataclass(frozen=True)
class Statement:
    """Public statement to be proven in zero knowledge."""

    statement_id: str
    relation: str
    public_inputs: Mapping[str, Any] = field(default_factory=dict)
    proof_system: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Witness:
    """Private witness corresponding to a statement."""

    secret_inputs: Mapping[str, Any] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CompiledCircuit:
    """Arithmetic circuit representation for a statement."""

    circuit_id: str
    system: str
    relation: str
    constraints: tuple[str, ...]
    variables: tuple[str, ...]
    metadata: Mapping[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)


@dataclass(frozen=True)
class Proof:
    """Serializable proof envelope with backend payload."""

    proof_id: str
    system: str
    statement_id: str
    circuit_id: str
    payload: Any
    public_inputs: Mapping[str, Any] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)


@dataclass(frozen=True)
class ZKCPProof:
    """Zero-knowledge consciousness proof record."""

    proof: Proof
    consciousness_level: float
    threshold: float
    level_commitment: str
    metadata: Mapping[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)


@dataclass(frozen=True)
class DeletionClaim:
    """Claim that secure deletion occurred, optionally with a proof artifact."""

    claim_id: str
    resource_id: str
    deletion_timestamp: float
    algorithm: str = "crypto-erasure"
    digest: str = ""
    proof: Proof | str | bytes | None = None
    statement: Statement | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)


class ZKPProvider:
    """High-level wrapper over zero-knowledge proof system backends."""

    PERFORMANCE_WARNING = (
        "Zero-knowledge proof generation can be computationally expensive. "
        "Prefer asynchronous/offline proving paths for large circuits."
    )

    def __init__(
        self,
        *,
        proof_system_backends: Mapping[str, Any] | None = None,
        default_proof_system: str = "zk-snarks",
    ) -> None:
        self._default_proof_system = self._normalize_system(default_proof_system)

        discovered = self._load_default_backends()
        if proof_system_backends:
            for name, backend in proof_system_backends.items():
                discovered[self._normalize_system(name)] = backend

        self._backends = discovered

    def generate_proof(self, statement: Statement, witness: Witness) -> Proof:
        """Generate proof for a statement/witness pair.

        The proof system is selected from ``statement.proof_system`` when
        provided, otherwise the provider default is used.
        """
        self._validate_statement(statement)
        self._validate_witness(witness)

        system = self._normalize_system(statement.proof_system or self._default_proof_system)
        backend = self._require_backend(system)

        circuit = self.compile_circuit(statement)
        payload = self._call_backend(
            backend,
            operation_names=("generate_proof", "prove", "create_proof", "generate"),
            args=(statement, witness, circuit),
            kwargs={
                "statement": statement,
                "witness": witness,
                "circuit": circuit,
                "public_inputs": dict(statement.public_inputs),
                "secret_inputs": dict(witness.secret_inputs),
            },
            operation_label="generate_proof",
        )

        return Proof(
            proof_id=uuid.uuid4().hex,
            system=system,
            statement_id=statement.statement_id,
            circuit_id=circuit.circuit_id,
            payload=payload,
            public_inputs=dict(statement.public_inputs),
            metadata={
                "backend": self._backend_name(backend),
                "relation": statement.relation,
                "circuit_constraints": len(circuit.constraints),
            },
        )

    def verify_proof(self, statement: Statement, proof: Proof) -> bool:
        """Verify a zero-knowledge proof against its public statement."""
        self._validate_statement(statement)
        self._validate_proof(proof)

        system = self._normalize_system(proof.system)
        backend = self._require_backend(system)

        try:
            outcome = self._call_backend(
                backend,
                operation_names=("verify_proof", "verify", "verify_zkp", "validate_proof"),
                args=(statement, proof.payload),
                kwargs={
                    "statement": statement,
                    "proof": proof.payload,
                    "proof_object": proof,
                    "public_inputs": dict(statement.public_inputs),
                },
                operation_label="verify_proof",
            )
        except Exception as exc:
            logger.warning(
                "zkp verification failed statement_id={sid} system={system}: {error}",
                sid=statement.statement_id,
                system=system,
                error=str(exc),
            )
            return False

        if isinstance(outcome, Mapping):
            for key in ("valid", "is_valid", "verified", "ok", "success"):
                if key in outcome:
                    return bool(outcome[key])
        return bool(outcome)

    def generate_zkcp(self, consciousness_level: float) -> ZKCPProof:
        """Generate a zero-knowledge consciousness proof.

        This creates a proof for the statement that a consciousness level is in
        a valid range and above a public threshold without revealing witness
        internals.
        """
        level = float(consciousness_level)
        if not math.isfinite(level) or level < 0.0 or level > 1.0:
            raise ValueError("consciousness_level must be a finite float in [0.0, 1.0]")

        threshold = 0.5
        nonce = secrets.token_hex(16)
        commitment = hashlib.sha256(f"{level:.8f}|{nonce}".encode("utf-8")).hexdigest()

        statement = Statement(
            statement_id=f"zkcp-{uuid.uuid4().hex}",
            relation="consciousness_level >= threshold",
            public_inputs={
                "consciousness_level": round(level, 8),
                "threshold": threshold,
                "commitment": commitment,
            },
            proof_system=self._default_proof_system,
            metadata={"domain": "consciousness", "zero_knowledge": True},
        )
        witness = Witness(
            secret_inputs={
                "nonce": nonce,
                "scaled_level": int(level * 1_000_000),
            },
            metadata={"purpose": "zkcp"},
        )

        proof = self.generate_proof(statement, witness)
        return ZKCPProof(
            proof=proof,
            consciousness_level=level,
            threshold=threshold,
            level_commitment=commitment,
            metadata={
                "statement_id": statement.statement_id,
                "warning": self.PERFORMANCE_WARNING,
            },
        )

    def verify_deletion_proof(self, deletion_claim: DeletionClaim) -> bool:
        """Verify a deletion claim proof.

        The claim may embed a ``Proof`` object or a serialized proof payload.
        """
        if not isinstance(deletion_claim, DeletionClaim):
            raise TypeError("deletion_claim must be DeletionClaim")

        if deletion_claim.proof is None:
            return False

        proof: Proof
        if isinstance(deletion_claim.proof, Proof):
            proof = deletion_claim.proof
        elif isinstance(deletion_claim.proof, (str, bytes)):
            proof = self.deserialize_proof(deletion_claim.proof)
        else:
            raise TypeError("deletion_claim.proof must be Proof, str, bytes, or None")

        statement = deletion_claim.statement or Statement(
            statement_id=f"deletion-{deletion_claim.claim_id}",
            relation="resource_deleted(resource_id, digest, deletion_timestamp)",
            public_inputs={
                "claim_id": deletion_claim.claim_id,
                "resource_id": deletion_claim.resource_id,
                "deletion_timestamp": float(deletion_claim.deletion_timestamp),
                "digest": deletion_claim.digest,
                "algorithm": deletion_claim.algorithm,
            },
            proof_system=proof.system,
            metadata={"domain": "deletion"},
        )

        return self.verify_proof(statement, proof)

    def compile_circuit(self, statement: Statement) -> CompiledCircuit:
        """Compile a statement into an arithmetic circuit representation."""
        self._validate_statement(statement)

        system = self._normalize_system(statement.proof_system or self._default_proof_system)
        backend = self._require_backend(system)

        try:
            compiled = self._call_backend(
                backend,
                operation_names=(
                    "compile_circuit",
                    "compile",
                    "build_circuit",
                    "circuit_from_statement",
                ),
                args=(statement,),
                kwargs={
                    "statement": statement,
                    "relation": statement.relation,
                    "public_inputs": dict(statement.public_inputs),
                },
                operation_label="compile_circuit",
            )
            return self._normalize_compiled_circuit(compiled, statement=statement, system=system)
        except Exception:
            return self._fallback_compile_circuit(statement, system=system)

    def serialize_proof(self, proof: Proof) -> str:
        """Serialize proof into JSON for storage/transmission."""
        self._validate_proof(proof)

        envelope = {
            "version": 1,
            "proof": {
                "proof_id": proof.proof_id,
                "system": proof.system,
                "statement_id": proof.statement_id,
                "circuit_id": proof.circuit_id,
                "payload": self._to_json_value(proof.payload),
                "public_inputs": self._to_json_value(dict(proof.public_inputs)),
                "metadata": self._to_json_value(dict(proof.metadata)),
                "created_at": float(proof.created_at),
            },
        }
        return json.dumps(envelope, separators=(",", ":"), sort_keys=True)

    def deserialize_proof(self, serialized: str | bytes) -> Proof:
        """Deserialize proof JSON into a ``Proof`` object."""
        if isinstance(serialized, bytes):
            text = serialized.decode("utf-8")
        elif isinstance(serialized, str):
            text = serialized
        else:
            raise TypeError("serialized proof must be str or bytes")

        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError("serialized proof is not valid JSON") from exc

        if not isinstance(payload, Mapping):
            raise ValueError("serialized proof envelope must be a mapping")

        raw_proof = payload.get("proof")
        if not isinstance(raw_proof, Mapping):
            raise ValueError("serialized proof envelope missing 'proof' object")

        return Proof(
            proof_id=str(raw_proof.get("proof_id", "")),
            system=self._normalize_system(str(raw_proof.get("system", self._default_proof_system))),
            statement_id=str(raw_proof.get("statement_id", "")),
            circuit_id=str(raw_proof.get("circuit_id", "")),
            payload=self._from_json_value(raw_proof.get("payload")),
            public_inputs=self._coerce_mapping(self._from_json_value(raw_proof.get("public_inputs", {}))),
            metadata=self._coerce_mapping(self._from_json_value(raw_proof.get("metadata", {}))),
            created_at=float(raw_proof.get("created_at", time.time())),
        )

    def serialize_zkcp(self, zkcp: ZKCPProof) -> str:
        """Serialize zero-knowledge consciousness proof record."""
        if not isinstance(zkcp, ZKCPProof):
            raise TypeError("zkcp must be ZKCPProof")

        envelope = {
            "version": 1,
            "kind": "zkcp",
            "consciousness_level": zkcp.consciousness_level,
            "threshold": zkcp.threshold,
            "level_commitment": zkcp.level_commitment,
            "metadata": self._to_json_value(dict(zkcp.metadata)),
            "created_at": zkcp.created_at,
            "proof": json.loads(self.serialize_proof(zkcp.proof))["proof"],
        }
        return json.dumps(envelope, separators=(",", ":"), sort_keys=True)

    def available_proof_systems(self) -> tuple[str, ...]:
        """Return names of currently loaded proof system backends."""
        return tuple(sorted(self._backends.keys()))

    def _load_default_backends(self) -> dict[str, Any]:
        backends: dict[str, Any] = {}
        for system in _DEFAULT_PROOF_SYSTEMS:
            module = self._import_system_module(system)
            if module is not None:
                backends[system] = module
        return backends

    @staticmethod
    def _import_system_module(system: str) -> ModuleType | None:
        for path in _MODULE_CANDIDATES.get(system, ()):  # pragma: no branch
            try:
                return importlib.import_module(path)
            except Exception:
                continue
        return None

    def _require_backend(self, system: str) -> Any:
        backend = self._backends.get(system)
        if backend is None:
            raise RuntimeError(
                f"zkp backend unavailable for proof system '{system}'. "
                "Expected modules under src.zkp.*"
            )
        return backend

    def _call_backend(
        self,
        backend: Any,
        *,
        operation_names: Sequence[str],
        args: tuple[Any, ...],
        kwargs: Mapping[str, Any],
        operation_label: str,
    ) -> Any:
        for name in operation_names:
            target = getattr(backend, name, None)
            if callable(target):
                outcome, ok = self._invoke_callable(target, args=args, kwargs=kwargs)
                if ok:
                    return outcome

        for class_name in self._candidate_class_names():
            cls = getattr(backend, class_name, None)
            if not inspect.isclass(cls):
                continue

            instance = self._safe_instantiate(cls)
            if instance is None:
                continue

            for name in operation_names:
                target = getattr(instance, name, None)
                if not callable(target):
                    continue
                outcome, ok = self._invoke_callable(target, args=args, kwargs=kwargs)
                if ok:
                    return outcome

        raise RuntimeError(f"zkp backend does not expose '{operation_label}' operation")

    @staticmethod
    def _invoke_callable(
        target: Any,
        *,
        args: tuple[Any, ...],
        kwargs: Mapping[str, Any],
    ) -> tuple[Any, bool]:
        for call in (
            lambda: target(*args),
            lambda: target(**dict(kwargs)),
            lambda: target(*args, **dict(kwargs)),
        ):
            try:
                return call(), True
            except TypeError:
                continue
        return None, False

    @staticmethod
    def _candidate_class_names() -> tuple[str, ...]:
        return (
            "ZKSnark",
            "ZKStark",
            "Bulletproof",
            "ProofSystem",
            "ZKPBackend",
            "Engine",
        )

    @staticmethod
    def _safe_instantiate(cls: type[Any]) -> Any | None:
        for constructor in (lambda: cls(), lambda: cls(None)):
            try:
                return constructor()
            except Exception:
                continue
        return None

    @staticmethod
    def _backend_name(backend: Any) -> str:
        return getattr(backend, "__name__", backend.__class__.__name__)

    @staticmethod
    def _normalize_system(value: str) -> str:
        text = str(value).strip().lower()
        aliases = {
            "zk-snark": "zk-snarks",
            "zk-snarks": "zk-snarks",
            "snark": "zk-snarks",
            "snarks": "zk-snarks",
            "zksnark": "zk-snarks",
            "zk-stark": "zk-starks",
            "zk-starks": "zk-starks",
            "stark": "zk-starks",
            "starks": "zk-starks",
            "zkstark": "zk-starks",
            "bulletproof": "bulletproofs",
            "bulletproofs": "bulletproofs",
            "bp": "bulletproofs",
        }
        normalized = aliases.get(text, text)
        if normalized not in {"zk-snarks", "zk-starks", "bulletproofs"}:
            raise ValueError("proof system must be zk-snarks, zk-starks, or bulletproofs")
        return normalized

    @staticmethod
    def _validate_statement(statement: Statement) -> None:
        if not isinstance(statement, Statement):
            raise TypeError("statement must be Statement")
        if not statement.statement_id.strip():
            raise ValueError("statement.statement_id must be non-empty")
        if not statement.relation.strip():
            raise ValueError("statement.relation must be non-empty")

    @staticmethod
    def _validate_witness(witness: Witness) -> None:
        if not isinstance(witness, Witness):
            raise TypeError("witness must be Witness")

    @staticmethod
    def _validate_proof(proof: Proof) -> None:
        if not isinstance(proof, Proof):
            raise TypeError("proof must be Proof")
        if not proof.proof_id.strip():
            raise ValueError("proof.proof_id must be non-empty")
        if not proof.statement_id.strip():
            raise ValueError("proof.statement_id must be non-empty")

    def _normalize_compiled_circuit(
        self,
        compiled: Any,
        *,
        statement: Statement,
        system: str,
    ) -> CompiledCircuit:
        if isinstance(compiled, CompiledCircuit):
            return compiled

        if isinstance(compiled, Mapping):
            constraints_raw = compiled.get("constraints", ())
            variables_raw = compiled.get("variables", tuple(statement.public_inputs.keys()))
            metadata_raw = compiled.get("metadata", {})
            circuit_id = str(compiled.get("circuit_id", f"circuit-{uuid.uuid4().hex}"))

            constraints = tuple(str(item) for item in self._ensure_iterable(constraints_raw))
            variables = tuple(str(item) for item in self._ensure_iterable(variables_raw))
            metadata = self._coerce_mapping(metadata_raw)

            if constraints:
                return CompiledCircuit(
                    circuit_id=circuit_id,
                    system=system,
                    relation=statement.relation,
                    constraints=constraints,
                    variables=variables,
                    metadata=metadata,
                )

        return self._fallback_compile_circuit(statement, system=system)

    @staticmethod
    def _ensure_iterable(value: Any) -> Sequence[Any]:
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            return value
        return (value,)

    @staticmethod
    def _coerce_mapping(value: Any) -> Mapping[str, Any]:
        if isinstance(value, Mapping):
            return {str(key): item for key, item in value.items()}
        return {}

    def _fallback_compile_circuit(self, statement: Statement, *, system: str) -> CompiledCircuit:
        constraints: list[str] = [f"relation: {statement.relation}"]
        variables: list[str] = []

        for index, name in enumerate(sorted(statement.public_inputs.keys())):
            variables.append(str(name))
            constraints.append(f"public_input_{index}: {name} = pub[{index}]")

        if not variables:
            constraints.append("constant_constraint: 0 = 0")

        return CompiledCircuit(
            circuit_id=f"circuit-{uuid.uuid4().hex}",
            system=system,
            relation=statement.relation,
            constraints=tuple(constraints),
            variables=tuple(variables),
            metadata={"compiler": "fallback", "warning": "backend compile unavailable"},
        )

    def _to_json_value(self, value: Any) -> Any:
        if value is None or isinstance(value, (str, int, float, bool)):
            return value

        if isinstance(value, bytes):
            return {
                "__type__": "bytes",
                "b64": base64.b64encode(value).decode("ascii"),
            }

        if isinstance(value, Mapping):
            return {str(k): self._to_json_value(v) for k, v in value.items()}

        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            return [self._to_json_value(item) for item in value]

        if isinstance(value, Statement):
            return {
                "__type__": "Statement",
                "statement_id": value.statement_id,
                "relation": value.relation,
                "public_inputs": self._to_json_value(dict(value.public_inputs)),
                "proof_system": value.proof_system,
                "metadata": self._to_json_value(dict(value.metadata)),
            }

        if isinstance(value, Witness):
            return {
                "__type__": "Witness",
                "secret_inputs": self._to_json_value(dict(value.secret_inputs)),
                "metadata": self._to_json_value(dict(value.metadata)),
            }

        if isinstance(value, CompiledCircuit):
            return {
                "__type__": "CompiledCircuit",
                "circuit_id": value.circuit_id,
                "system": value.system,
                "relation": value.relation,
                "constraints": self._to_json_value(list(value.constraints)),
                "variables": self._to_json_value(list(value.variables)),
                "metadata": self._to_json_value(dict(value.metadata)),
                "created_at": value.created_at,
            }

        return {
            "__type__": "repr",
            "value": repr(value),
        }

    def _from_json_value(self, value: Any) -> Any:
        if isinstance(value, Mapping):
            type_name = value.get("__type__")
            if type_name == "bytes":
                return base64.b64decode(str(value.get("b64", "")).encode("ascii"))
            if type_name == "Statement":
                return Statement(
                    statement_id=str(value.get("statement_id", "")),
                    relation=str(value.get("relation", "")),
                    public_inputs=self._coerce_mapping(self._from_json_value(value.get("public_inputs", {}))),
                    proof_system=value.get("proof_system"),
                    metadata=self._coerce_mapping(self._from_json_value(value.get("metadata", {}))),
                )
            if type_name == "Witness":
                return Witness(
                    secret_inputs=self._coerce_mapping(self._from_json_value(value.get("secret_inputs", {}))),
                    metadata=self._coerce_mapping(self._from_json_value(value.get("metadata", {}))),
                )
            if type_name == "CompiledCircuit":
                constraints = self._from_json_value(value.get("constraints", []))
                variables = self._from_json_value(value.get("variables", []))
                return CompiledCircuit(
                    circuit_id=str(value.get("circuit_id", "")),
                    system=self._normalize_system(str(value.get("system", self._default_proof_system))),
                    relation=str(value.get("relation", "")),
                    constraints=tuple(str(x) for x in self._ensure_iterable(constraints)),
                    variables=tuple(str(x) for x in self._ensure_iterable(variables)),
                    metadata=self._coerce_mapping(self._from_json_value(value.get("metadata", {}))),
                    created_at=float(value.get("created_at", time.time())),
                )
            if type_name == "repr":
                return str(value.get("value", ""))
            return {str(k): self._from_json_value(v) for k, v in value.items()}

        if isinstance(value, list):
            return [self._from_json_value(item) for item in value]

        return value


__all__ = [
    "CompiledCircuit",
    "DeletionClaim",
    "Proof",
    "Statement",
    "Witness",
    "ZKCPProof",
    "ZKPProvider",
]
