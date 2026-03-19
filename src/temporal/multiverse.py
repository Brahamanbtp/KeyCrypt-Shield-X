"""Everett many-worlds cryptographic isolation (exploratory simulation).

This module models branch-local cryptographic state under a toy many-worlds
interpretation: measurement outcomes create independent branch records whose
secrets must remain isolated.

Important caveats:
- This is a simulation framework, not physical quantum hardware.
- Branches are software abstractions and do not imply real-world universes.
- Security guarantees depend on implementation controls in this process.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from secrets import token_hex
from time import time
from typing import Any

import numpy as np
from numpy.typing import ArrayLike


@dataclass
class QuantumBranch:
    """Tracked branch-local state for many-worlds isolation simulation."""

    branch_id: str
    amplitude: complex
    probability: float
    created_at: float
    parent_branch: str | None
    state_vector: np.ndarray
    sealed: bool
    shared_channel_enabled: bool


class MultiverseCrypto:
    """Simulate Everett branch creation and cryptographic isolation controls."""

    def __init__(self, qubit_count: int = 3) -> None:
        if qubit_count <= 0:
            raise ValueError("qubit_count must be positive")

        self.qubit_count = int(qubit_count)
        self.dimension = 2**self.qubit_count

        # Start in |0...0> pure state.
        self.global_superposition = np.zeros(self.dimension, dtype=np.complex128)
        self.global_superposition[0] = 1.0 + 0.0j

        self._branch_counter = 0
        self.branches: dict[str, QuantumBranch] = {}
        self.branch_keys: dict[str, str] = {}
        self.branch_messages: dict[str, list[str]] = {}
        self.isolation_policies: dict[str, set[str]] = {}

        root_id = self._next_branch_id()
        root = QuantumBranch(
            branch_id=root_id,
            amplitude=1.0 + 0.0j,
            probability=1.0,
            created_at=time(),
            parent_branch=None,
            state_vector=self.global_superposition.copy(),
            sealed=False,
            shared_channel_enabled=False,
        )
        self.branches[root_id] = root
        self.branch_keys[root_id] = self._derive_branch_key(root_id)
        self.branch_messages[root_id] = []
        self.isolation_policies[root_id] = set()

    def create_quantum_branch(self) -> dict[str, Any]:
        """Simulate measurement branching from current superposition.

        Generates two orthogonal branch outcomes from the most probable active
        branch, splitting its probability mass into child branches. This mirrors
        an Everett-style bookkeeping expansion used for isolation studies.
        """
        parent = max(self.branches.values(), key=lambda b: b.probability)

        # Sample a random measurement basis vector and project parent state.
        random_state = self._random_normalized_state(self.dimension)
        overlap = np.vdot(parent.state_vector, random_state)
        projected_prob = float(np.clip(np.abs(overlap) ** 2, 1e-9, 1.0 - 1e-9))

        child_specs = [
            (np.sqrt(projected_prob), random_state),
            (np.sqrt(1.0 - projected_prob), self._orthogonal_state(random_state)),
        ]

        new_ids: list[str] = []
        for amp_scale, child_state in child_specs:
            branch_id = self._next_branch_id()
            amplitude = parent.amplitude * complex(amp_scale)
            probability = float(np.abs(amplitude) ** 2)

            branch = QuantumBranch(
                branch_id=branch_id,
                amplitude=amplitude,
                probability=probability,
                created_at=time(),
                parent_branch=parent.branch_id,
                state_vector=child_state,
                sealed=False,
                shared_channel_enabled=False,
            )

            self.branches[branch_id] = branch
            self.branch_keys[branch_id] = self._derive_branch_key(branch_id)
            self.branch_messages[branch_id] = []
            self.isolation_policies[branch_id] = set()
            new_ids.append(branch_id)

        parent.amplitude = 0.0 + 0.0j
        parent.probability = 0.0
        parent.sealed = True
        self._renormalize_probabilities()

        return {
            "parent_branch": parent.branch_id,
            "new_branches": new_ids,
            "branch_probabilities": {bid: self.branches[bid].probability for bid in new_ids},
            "total_branches": len(self.branches),
        }

    def isolate_branches(self, branch_ids: list[str]) -> dict[str, Any]:
        """Apply strict cryptographic isolation among selected branches."""
        self._require_branches(branch_ids)

        isolated_pairs: list[tuple[str, str]] = []
        for i, left in enumerate(branch_ids):
            self.branches[left].sealed = True
            self.branches[left].shared_channel_enabled = False

            for right in branch_ids[i + 1 :]:
                self.isolation_policies[left].add(right)
                self.isolation_policies[right].add(left)
                isolated_pairs.append((left, right))

        return {
            "isolated_branches": branch_ids,
            "isolated_pairs": isolated_pairs,
            "isolation_count": len(isolated_pairs),
        }

    def verify_no_leakage(self, branch1: str, branch2: str) -> dict[str, Any]:
        """Check that two branches cannot transfer information."""
        self._require_branches([branch1, branch2])
        b1 = self.branches[branch1]
        b2 = self.branches[branch2]

        policy_isolated = branch2 in self.isolation_policies.get(branch1, set())
        channels_closed = (not b1.shared_channel_enabled) and (not b2.shared_channel_enabled)

        key_fingerprint_1 = hashlib.sha3_256(self.branch_keys[branch1].encode("utf-8")).hexdigest()
        key_fingerprint_2 = hashlib.sha3_256(self.branch_keys[branch2].encode("utf-8")).hexdigest()
        key_distinct = key_fingerprint_1 != key_fingerprint_2

        # Orthogonality proxy: distinct branches should have low overlap.
        overlap = float(np.abs(np.vdot(b1.state_vector, b2.state_vector)))
        orthogonal_enough = overlap < 1e-6

        leakage_free = policy_isolated and channels_closed and key_distinct and orthogonal_enough

        return {
            "branch_pair": (branch1, branch2),
            "no_leakage": leakage_free,
            "policy_isolated": policy_isolated,
            "channels_closed": channels_closed,
            "keys_distinct": key_distinct,
            "state_overlap": overlap,
            "orthogonal_enough": orthogonal_enough,
        }

    def multiverse_consistency_check(self) -> dict[str, Any]:
        """Verify branch-isolation consistency across all tracked worlds."""
        branch_ids = sorted(
            branch_id for branch_id, branch in self.branches.items() if branch.probability > 1e-9
        )
        pair_results: list[dict[str, Any]] = []
        violations: list[dict[str, Any]] = []

        for i, left in enumerate(branch_ids):
            for right in branch_ids[i + 1 :]:
                result = self.verify_no_leakage(left, right)
                pair_results.append(result)
                if not result["no_leakage"]:
                    violations.append(result)

        probs = np.array([branch.probability for branch in self.branches.values()], dtype=np.float64)
        probability_normalized = bool(np.isclose(np.sum(probs), 1.0, atol=1e-6))

        return {
            "consistent": (len(violations) == 0) and probability_normalized,
            "total_branches": len(branch_ids),
            "checked_pairs": len(pair_results),
            "violations": violations,
            "probability_normalized": probability_normalized,
        }

    def _derive_branch_key(self, branch_id: str) -> str:
        salt = token_hex(16)
        digest = hashlib.sha3_256(f"{branch_id}:{salt}".encode("utf-8")).hexdigest()
        return digest

    def _next_branch_id(self) -> str:
        self._branch_counter += 1
        return f"branch-{self._branch_counter:06d}"

    def _renormalize_probabilities(self) -> None:
        probs = np.array([branch.probability for branch in self.branches.values()], dtype=np.float64)
        total = float(np.sum(probs))
        if total <= 0.0:
            raise RuntimeError("invalid branch probability total")
        for branch in self.branches.values():
            branch.probability = branch.probability / total

    def _require_branches(self, branch_ids: list[str]) -> None:
        missing = [branch_id for branch_id in branch_ids if branch_id not in self.branches]
        if missing:
            raise ValueError(f"unknown branch ids: {missing}")

    def _random_normalized_state(self, dimension: int) -> np.ndarray:
        real = np.random.normal(0.0, 1.0, size=dimension)
        imag = np.random.normal(0.0, 1.0, size=dimension)
        vec = real + 1j * imag
        norm = float(np.linalg.norm(vec))
        if norm == 0.0:
            vec[0] = 1.0 + 0.0j
            norm = 1.0
        return (vec / norm).astype(np.complex128)

    def _orthogonal_state(self, vec: np.ndarray) -> np.ndarray:
        # Gram-Schmidt against vec using deterministic basis seed for reproducibility.
        basis = np.zeros_like(vec)
        basis[0] = 1.0 + 0.0j
        projection = np.vdot(vec, basis) * vec
        orth = basis - projection
        norm = float(np.linalg.norm(orth))
        if norm < 1e-12:
            basis = np.zeros_like(vec)
            basis[1] = 1.0 + 0.0j
            projection = np.vdot(vec, basis) * vec
            orth = basis - projection
            norm = float(np.linalg.norm(orth))
        return (orth / norm).astype(np.complex128)


__all__ = ["MultiverseCrypto", "QuantumBranch"]
