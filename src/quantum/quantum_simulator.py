"""Quantum circuit simulation utilities for KeyCrypt Shield X.

This module provides quantum state preparation, measurement, and entropy
analysis helpers using Qiskit.
"""

from __future__ import annotations

from typing import Any

from qiskit import QuantumCircuit
from qiskit.quantum_info import DensityMatrix, Statevector, entropy, partial_trace
from qiskit.visualization import plot_histogram


class QuantumCryptoSimulator:
    """Qiskit-based simulator for quantum cryptography primitives."""

    def create_bell_state(self, qubits: tuple[int, int] = (0, 1)) -> QuantumCircuit:
        """Create a Bell pair circuit.

        Args:
            qubits: Pair of qubit indices used for Bell state preparation.

        Returns:
            QuantumCircuit prepared in Bell state $(|00> + |11>)/sqrt(2)$ on the
            specified qubits.
        """
        if not isinstance(qubits, tuple) or len(qubits) != 2:
            raise ValueError("qubits must be a tuple of two qubit indices")

        q0, q1 = qubits
        if q0 == q1 or min(q0, q1) < 0:
            raise ValueError("qubit indices must be distinct non-negative integers")

        num_qubits = max(q0, q1) + 1
        circuit = QuantumCircuit(num_qubits)
        circuit.h(q0)
        circuit.cx(q0, q1)
        return circuit

    def create_ghz_state(self, n_qubits: int) -> QuantumCircuit:
        """Create a GHZ state preparation circuit.

        Args:
            n_qubits: Number of qubits in GHZ state.

        Returns:
            QuantumCircuit prepared in GHZ state:
            $(|0...0> + |1...1>)/sqrt(2)$.
        """
        if n_qubits < 2:
            raise ValueError("n_qubits must be at least 2 for a GHZ state")

        circuit = QuantumCircuit(n_qubits)
        circuit.h(0)
        for target in range(1, n_qubits):
            circuit.cx(0, target)
        return circuit

    def measure_quantum_state(
        self,
        quantum_circuit: QuantumCircuit,
        *,
        shots: int = 1024,
        visualize: bool = False,
    ) -> dict[str, int] | tuple[dict[str, int], Any]:
        """Measure a quantum circuit and return shot counts.

        This method uses a statevector simulation path to avoid backend-specific
        setup requirements.

        Args:
            quantum_circuit: Circuit to be measured.
            shots: Number of sampled measurement shots.
            visualize: When True, also return a Qiskit histogram figure.

        Returns:
            Either measurement counts, or `(counts, histogram_figure)`.
        """
        if not isinstance(quantum_circuit, QuantumCircuit):
            raise TypeError("quantum_circuit must be a QuantumCircuit instance")
        if shots <= 0:
            raise ValueError("shots must be a positive integer")

        base_circuit = quantum_circuit.remove_final_measurements(inplace=False)
        state = Statevector.from_instruction(base_circuit)
        counts = state.sample_counts(shots=shots)
        counts_dict = {str(k): int(v) for k, v in counts.items()}

        if visualize:
            figure = plot_histogram(counts_dict)
            return counts_dict, figure
        return counts_dict

    def compute_entanglement_entropy(self, state: QuantumCircuit | Statevector | DensityMatrix) -> float:
        """Compute bipartite von Neumann entanglement entropy.

        For an $n$-qubit state, the system is split into two halves and entropy
        is computed on the reduced state of the first half:

        $$S(\\rho_A) = -Tr(\\rho_A \\log_2 \\rho_A)$$

        Args:
            state: Quantum state as circuit, statevector, or density matrix.

        Returns:
            Entanglement entropy in bits.
        """
        rho = self._to_density_matrix(state)
        n_qubits = rho.num_qubits

        if n_qubits < 2:
            return 0.0

        split = n_qubits // 2
        subsystem_b = list(range(split, n_qubits))
        reduced_a = partial_trace(rho, subsystem_b)
        return float(entropy(reduced_a, base=2))

    @staticmethod
    def _to_density_matrix(state: QuantumCircuit | Statevector | DensityMatrix) -> DensityMatrix:
        if isinstance(state, QuantumCircuit):
            no_measure = state.remove_final_measurements(inplace=False)
            return DensityMatrix(Statevector.from_instruction(no_measure))
        if isinstance(state, Statevector):
            return DensityMatrix(state)
        if isinstance(state, DensityMatrix):
            return state
        raise TypeError("state must be QuantumCircuit, Statevector, or DensityMatrix")


__all__ = ["QuantumCryptoSimulator"]
