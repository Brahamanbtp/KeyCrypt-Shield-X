from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
import os
import secrets

try:
    import qiskit
    from qiskit import Aer, QuantumCircuit as QiskitCircuit, execute as qiskit_execute
except Exception:  # pragma: no cover - qiskit optional
    qiskit = None


@dataclass
class QuantumConnection:
    provider: str
    metadata: Dict[str, Any]
    backend: Optional[Any] = None


@dataclass
class QuantumCircuit:
    description: str
    # For simple portability, store operations as a list of tuples (op, args)
    ops: List[Any]


@dataclass
class MeasurementResult:
    counts: Dict[str, int]
    shots: int


@dataclass
class Node:
    node_id: str
    device_info: Dict[str, Any]


@dataclass
class SharedKey:
    key: bytes
    info: Dict[str, Any]


def connect_to_quantum_computer(provider: str) -> QuantumConnection:
    """Attempt to connect to a quantum provider. Returns a connection object.

    This is best-effort: if provider SDKs are not installed, returns a simulated connection.
    """
    p = provider.lower()
    if qiskit is not None:
        try:
            # try to access local Aer simulator if available
            backend = None
            try:
                backend = Aer.get_backend("aer_simulator")
            except Exception:
                backend = None
            return QuantumConnection(provider=p, metadata={"sdk": "qiskit"}, backend=backend)
        except Exception:
            pass

    # fallback simulated connection
    return QuantumConnection(provider=p, metadata={"sdk": "simulated"}, backend=None)


def generate_quantum_random_numbers(count: int, conn: Optional[QuantumConnection] = None) -> bytes:
    """Generate `count` bytes of randomness using quantum hardware if available, else fallback.

    If a real quantum connection with a simulator/backend is available, we can run
    a small circuit to sample random bits. Otherwise use `secrets.token_bytes`.
    """
    if conn and qiskit is not None and conn.backend is not None:
        try:
            # each shot produces some random bits; run circuits until we have enough bytes
            bits_needed = count * 8
            shots = max(1, bits_needed // 16)
            qc = QiskitCircuit(4, 4)
            # put qubits into superposition
            for i in range(4):
                qc.h(i)
            qc.measure(range(4), range(4))
            job = qiskit_execute(qc, backend=conn.backend, shots=shots)
            res = job.result()
            counts = res.get_counts()
            all_bits = []
            for bitstring, c in counts.items():
                all_bits.extend([bitstring] * c)
            data = "".join(all_bits)
            # convert binary string to bytes
            b = int(data, 2).to_bytes((len(data) + 7) // 8, "big")
            return b[:count].ljust(count, b"\x00")
        except Exception:
            pass

    # fallback to secure pseudo-random bytes
    return secrets.token_bytes(count)


def execute_quantum_circuit(circuit: QuantumCircuit, conn: Optional[QuantumConnection] = None, shots: int = 1024) -> MeasurementResult:
    """Execute a quantum circuit on hardware or simulate it.

    The portable `QuantumCircuit` is converted to a simple Qiskit circuit when available,
    otherwise we simulate by returning random measurement counts.
    """
    if qiskit is not None and conn and conn.backend is not None:
        try:
            # naive mapping: create a circuit with number of qubits equal to ops length if possible
            n_qubits = max(1, len(circuit.ops))
            qc = QiskitCircuit(n_qubits, n_qubits)
            # best-effort: apply H to all qubits
            for i in range(n_qubits):
                qc.h(i)
            qc.measure(range(n_qubits), range(n_qubits))
            job = qiskit_execute(qc, backend=conn.backend, shots=shots)
            res = job.result()
            counts = res.get_counts()
            return MeasurementResult(counts=counts, shots=shots)
        except Exception:
            pass

    # fallback simulation: return uniformly random bitstrings
    import random

    n_qubits = max(1, len(circuit.ops))
    counts: Dict[str, int] = {}
    for _ in range(shots):
        bits = "".join(random.choice(["0", "1"]) for _ in range(n_qubits))
        counts[bits] = counts.get(bits, 0) + 1
    return MeasurementResult(counts=counts, shots=shots)


def implement_quantum_key_distribution_hardware(alice: Node, bob: Node, conn: Optional[QuantumConnection] = None, key_length: int = 32) -> SharedKey:
    """Perform a simulated BB84-like QKD over quantum hardware if available.

    This is a proof-of-concept: on actual hardware, QKD requires low-level optical channels.
    Here we use quantum random numbers to simulate basis and bit choices and perform sifting.
    """
    # generate raw bits and bases
    raw = generate_quantum_random_numbers(key_length * 2, conn)
    bits = [(b & 1) for b in raw]
    # split bits into bit values and bases
    bit_values = bits[:key_length]
    bases = bits[key_length:key_length * 2]

    # Bob measures with his own bases
    bob_raw = generate_quantum_random_numbers(key_length * 2, conn)
    bob_bits = [(b & 1) for b in bob_raw]
    bob_bases = bob_bits[key_length:key_length * 2]
    bob_values = bob_bits[:key_length]

    # sifting: keep positions where bases match
    shared = []
    for i in range(key_length):
        if bases[i] == bob_bases[i]:
            shared.append(bit_values[i])
    # derive key from shared bits
    if not shared:
        # fallback: use random shared key
        k = secrets.token_bytes(key_length)
        return SharedKey(key=k, info={"method": "simulated_empty_sift"})

    # convert bits to bytes
    bitstr = "".join(str(b) for b in shared)
    key_bytes = int(bitstr, 2).to_bytes((len(bitstr) + 7) // 8, "big")
    return SharedKey(key=key_bytes[:key_length], info={"method": "bb84_simulated", "sifted_bits": len(shared)})
