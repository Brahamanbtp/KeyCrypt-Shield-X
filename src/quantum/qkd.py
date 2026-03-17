"""BB84 quantum key distribution simulator for KeyCrypt Shield X.

This module implements a protocol-level simulation of BB84 with:
- Alice qubit preparation in Z/X bases
- Bob basis-dependent measurement
- Key sifting
- QBER estimation
- Lightweight error correction and privacy amplification
"""

from __future__ import annotations

import hashlib
import random
from typing import Sequence

from qiskit import QuantumCircuit
from qiskit.quantum_info import Statevector


class BB84Protocol:
    """Simulator for BB84 quantum key distribution."""

    VALID_BITS = {"0", "1"}
    VALID_BASES = {"Z", "X"}

    def __init__(self, *, channel_error_rate: float = 0.0, seed: int | None = None) -> None:
        if not (0.0 <= channel_error_rate <= 1.0):
            raise ValueError("channel_error_rate must be within [0, 1]")

        self.channel_error_rate = channel_error_rate
        self._rng = random.Random(seed)

    def alice_prepare_qubits(self, bit_string: str, basis_string: str) -> list[QuantumCircuit]:
        """Prepare BB84 single-qubit states from Alice's bits and bases.

        Args:
            bit_string: Binary string containing Alice's raw bits.
            basis_string: Basis string using `Z` and `X` characters.

        Returns:
            List of 1-qubit circuits representing encoded BB84 states.

        Raises:
            ValueError: If input lengths mismatch or symbols are invalid.
        """
        self._validate_bit_basis_strings(bit_string, basis_string)

        states: list[QuantumCircuit] = []
        for bit, basis in zip(bit_string, basis_string):
            qc = QuantumCircuit(1)

            # Prepare computational basis bit first.
            if bit == "1":
                qc.x(0)

            # Rotate to X basis when required: |0>->|+>, |1>->|->.
            if basis == "X":
                qc.h(0)

            states.append(qc)

        return states

    def bob_measure_qubits(self, quantum_states: Sequence[QuantumCircuit], measurement_basis: str) -> str:
        """Measure BB84 states with Bob's chosen bases.

        Args:
            quantum_states: Sequence of 1-qubit circuits from Alice.
            measurement_basis: Bob basis string using `Z` and `X`.

        Returns:
            Measured bit string.

        Raises:
            ValueError: If basis length mismatches or symbols are invalid.
            TypeError: If state objects are not QuantumCircuit instances.
        """
        if len(quantum_states) != len(measurement_basis):
            raise ValueError("measurement_basis length must match number of quantum states")
        self._validate_basis_string(measurement_basis)

        measured_bits: list[str] = []

        for state, basis in zip(quantum_states, measurement_basis):
            if not isinstance(state, QuantumCircuit):
                raise TypeError("all quantum_states must be QuantumCircuit instances")

            qc = state.copy()

            # Measuring in X basis is equivalent to applying H then Z-basis measurement.
            if basis == "X":
                qc.h(0)

            measured_bit = self._sample_z_measurement(qc)

            # Simulate independent channel/detector bit flips.
            if self._rng.random() < self.channel_error_rate:
                measured_bit = "1" if measured_bit == "0" else "0"

            measured_bits.append(measured_bit)

        return "".join(measured_bits)

    def sift_key(
        self,
        alice_bits: str,
        bob_bits: str,
        alice_basis: str,
        bob_basis: str,
    ) -> tuple[str, str, list[int]]:
        """Sift raw keys by keeping positions where Alice and Bob used same basis.

        Returns:
            Tuple `(alice_sifted, bob_sifted, kept_indices)`.
        """
        self._validate_bit_basis_strings(alice_bits, alice_basis)
        self._validate_bit_basis_strings(bob_bits, bob_basis)

        if len(alice_bits) != len(bob_bits):
            raise ValueError("alice_bits and bob_bits must have equal length")

        kept_indices = [i for i, (a_b, b_b) in enumerate(zip(alice_basis, bob_basis)) if a_b == b_b]
        alice_sifted = "".join(alice_bits[i] for i in kept_indices)
        bob_sifted = "".join(bob_bits[i] for i in kept_indices)
        return alice_sifted, bob_sifted, kept_indices

    def estimate_error_rate(self, sifted_key: tuple[str, str], sample_size: int) -> float:
        """Estimate QBER from sampled sifted bits.

        Args:
            sifted_key: Tuple `(alice_sifted, bob_sifted)`.
            sample_size: Number of positions to reveal for QBER estimation.

        Returns:
            Estimated quantum bit error rate (QBER) in [0, 1].
        """
        if not isinstance(sifted_key, tuple) or len(sifted_key) != 2:
            raise ValueError("sifted_key must be a tuple: (alice_sifted, bob_sifted)")

        alice_sifted, bob_sifted = sifted_key
        self._validate_bit_string(alice_sifted)
        self._validate_bit_string(bob_sifted)

        if len(alice_sifted) != len(bob_sifted):
            raise ValueError("sifted key strings must be equal length")
        if len(alice_sifted) == 0:
            return 0.0
        if sample_size <= 0:
            raise ValueError("sample_size must be positive")

        sample_size = min(sample_size, len(alice_sifted))
        indices = self._rng.sample(range(len(alice_sifted)), k=sample_size)
        errors = sum(1 for idx in indices if alice_sifted[idx] != bob_sifted[idx])
        return errors / sample_size

    def error_correction(self, alice_sifted: str, bob_sifted: str) -> tuple[str, str]:
        """Apply a simple reconciliation step to align keys.

        This simulator uses an idealized correction channel where Bob's differing
        bits are corrected to Alice's reference bits. In practical QKD systems,
        protocols such as Cascade/LDPC are used instead.
        """
        self._validate_bit_string(alice_sifted)
        self._validate_bit_string(bob_sifted)

        if len(alice_sifted) != len(bob_sifted):
            raise ValueError("sifted keys must have equal length")

        corrected_bob = list(bob_sifted)
        for i, (a, b) in enumerate(zip(alice_sifted, bob_sifted)):
            if a != b:
                corrected_bob[i] = a

        return alice_sifted, "".join(corrected_bob)

    def privacy_amplification(self, corrected_key: str, *, output_bits: int | None = None) -> str:
        """Compress reconciled key using hash-based privacy amplification.

        Args:
            corrected_key: Reconciled key string.
            output_bits: Optional output key length; defaults to half input size.

        Returns:
            Privacy-amplified key as binary string.
        """
        self._validate_bit_string(corrected_key)
        if not corrected_key:
            return ""

        default_len = max(1, len(corrected_key) // 2)
        final_len = output_bits if output_bits is not None else default_len
        if final_len <= 0:
            raise ValueError("output_bits must be positive when provided")

        digest = hashlib.sha256(corrected_key.encode("ascii")).digest()
        digest_bits = "".join(f"{byte:08b}" for byte in digest)

        # Extend deterministically if requested output exceeds one SHA-256 block.
        counter = 1
        while len(digest_bits) < final_len:
            block = hashlib.sha256(
                corrected_key.encode("ascii") + counter.to_bytes(4, "big")
            ).digest()
            digest_bits += "".join(f"{byte:08b}" for byte in block)
            counter += 1

        return digest_bits[:final_len]

    def run_round(
        self,
        alice_bits: str,
        alice_basis: str,
        bob_basis: str,
        *,
        qber_sample_size: int,
    ) -> dict[str, object]:
        """Run one full BB84 simulation round.

        Returns:
            Dictionary containing measured bits, sifted keys, QBER, corrected key,
            and privacy-amplified final key.
        """
        states = self.alice_prepare_qubits(alice_bits, alice_basis)
        bob_bits = self.bob_measure_qubits(states, bob_basis)

        alice_sifted, bob_sifted, kept = self.sift_key(alice_bits, bob_bits, alice_basis, bob_basis)
        qber = self.estimate_error_rate((alice_sifted, bob_sifted), qber_sample_size)

        corrected_alice, corrected_bob = self.error_correction(alice_sifted, bob_sifted)
        final_key = self.privacy_amplification(corrected_bob)

        return {
            "bob_bits": bob_bits,
            "kept_indices": kept,
            "alice_sifted": corrected_alice,
            "bob_sifted": corrected_bob,
            "qber": qber,
            "final_key": final_key,
        }

    def _sample_z_measurement(self, circuit: QuantumCircuit) -> str:
        state = Statevector.from_instruction(circuit)
        probs = state.probabilities_dict()

        p0 = float(probs.get("0", 0.0))
        p1 = float(probs.get("1", 0.0))

        if p0 <= 0.0:
            return "1"
        if p1 <= 0.0:
            return "0"

        return "0" if self._rng.random() < p0 else "1"

    def _validate_bit_basis_strings(self, bit_string: str, basis_string: str) -> None:
        self._validate_bit_string(bit_string)
        self._validate_basis_string(basis_string)
        if len(bit_string) != len(basis_string):
            raise ValueError("bit_string and basis_string must have equal length")

    def _validate_bit_string(self, bit_string: str) -> None:
        if not isinstance(bit_string, str):
            raise TypeError("bit string must be str")
        if any(ch not in self.VALID_BITS for ch in bit_string):
            raise ValueError("bit string must contain only '0' and '1'")

    def _validate_basis_string(self, basis_string: str) -> None:
        if not isinstance(basis_string, str):
            raise TypeError("basis string must be str")
        if any(ch not in self.VALID_BASES for ch in basis_string):
            raise ValueError("basis string must contain only 'Z' and 'X'")


__all__ = ["BB84Protocol"]
