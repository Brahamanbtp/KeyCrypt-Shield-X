"""Unit tests for src/providers/crypto/zkp_provider.py."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


def _load_module():
    module_path = PROJECT_ROOT / "src/providers/crypto/zkp_provider.py"
    spec = importlib.util.spec_from_file_location("zkp_provider_module", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load zkp_provider module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _FakeZKBackend:
    @staticmethod
    def compile_circuit(statement):
        return {
            "circuit_id": f"fake-{statement.statement_id}",
            "constraints": [
                f"relation: {statement.relation}",
                "witness_equation: a * b = c",
            ],
            "variables": list(statement.public_inputs.keys()),
            "metadata": {"compiler": "fake-backend"},
        }

    @staticmethod
    def generate_proof(statement, witness, circuit):
        return {
            "statement_id": statement.statement_id,
            "circuit_id": circuit.circuit_id,
            "public_inputs": dict(statement.public_inputs),
            "witness_size": len(dict(witness.secret_inputs)),
        }

    @staticmethod
    def verify_proof(statement, proof):
        return (
            isinstance(proof, dict)
            and proof.get("statement_id") == statement.statement_id
            and proof.get("public_inputs") == dict(statement.public_inputs)
        )


class _NoCompileBackend:
    @staticmethod
    def generate_proof(statement, witness, circuit):
        return {
            "statement_id": statement.statement_id,
            "circuit_id": circuit.circuit_id,
            "public_inputs": dict(statement.public_inputs),
        }

    @staticmethod
    def verify_proof(statement, proof):
        return proof.get("statement_id") == statement.statement_id


def test_generate_and_verify_proof_roundtrip() -> None:
    module = _load_module()
    provider = module.ZKPProvider(
        proof_system_backends={"zk-snarks": _FakeZKBackend},
        default_proof_system="zk-snarks",
    )

    statement = module.Statement(
        statement_id="s-1",
        relation="a * b = c",
        public_inputs={"c": 42},
        proof_system="zk-snarks",
    )
    witness = module.Witness(secret_inputs={"a": 6, "b": 7})

    proof = provider.generate_proof(statement, witness)

    assert proof.system == "zk-snarks"
    assert provider.verify_proof(statement, proof) is True


def test_proof_serialization_roundtrip() -> None:
    module = _load_module()
    provider = module.ZKPProvider(proof_system_backends={"zk-snarks": _FakeZKBackend})

    statement = module.Statement(
        statement_id="s-2",
        relation="x + y = z",
        public_inputs={"z": 10},
        proof_system="zk-snarks",
    )
    witness = module.Witness(secret_inputs={"x": 4, "y": 6})

    proof = provider.generate_proof(statement, witness)
    serialized = provider.serialize_proof(proof)
    restored = provider.deserialize_proof(serialized)

    assert restored.statement_id == proof.statement_id
    assert restored.system == proof.system
    assert provider.verify_proof(statement, restored) is True


def test_compile_circuit_fallback_when_backend_has_no_compile() -> None:
    module = _load_module()
    provider = module.ZKPProvider(
        proof_system_backends={"zk-snarks": _NoCompileBackend},
        default_proof_system="zk-snarks",
    )

    statement = module.Statement(
        statement_id="s-3",
        relation="x^2 = y",
        public_inputs={"y": 25},
        proof_system="zk-snarks",
    )

    circuit = provider.compile_circuit(statement)

    assert circuit.system == "zk-snarks"
    assert circuit.constraints
    assert "relation:" in circuit.constraints[0]


def test_generate_zkcp_creates_consciousness_proof() -> None:
    module = _load_module()
    provider = module.ZKPProvider(proof_system_backends={"zk-snarks": _FakeZKBackend})

    zkcp = provider.generate_zkcp(0.73)

    assert zkcp.proof.system == "zk-snarks"
    assert 0.0 <= zkcp.consciousness_level <= 1.0
    assert len(zkcp.level_commitment) == 64


def test_verify_deletion_proof_with_serialized_input() -> None:
    module = _load_module()
    provider = module.ZKPProvider(proof_system_backends={"zk-snarks": _FakeZKBackend})

    statement = module.Statement(
        statement_id="deletion-claim-7",
        relation="resource_deleted(resource_id, digest, deletion_timestamp)",
        public_inputs={
            "claim_id": "claim-7",
            "resource_id": "obj-123",
            "deletion_timestamp": 1712345678.0,
            "digest": "abc123",
            "algorithm": "crypto-erasure",
        },
        proof_system="zk-snarks",
    )
    witness = module.Witness(secret_inputs={"erasure_key": "k"})
    proof = provider.generate_proof(statement, witness)

    claim = module.DeletionClaim(
        claim_id="claim-7",
        resource_id="obj-123",
        deletion_timestamp=1712345678.0,
        algorithm="crypto-erasure",
        digest="abc123",
        proof=provider.serialize_proof(proof),
        statement=statement,
    )

    assert provider.verify_deletion_proof(claim) is True
