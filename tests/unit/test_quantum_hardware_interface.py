import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.integrations.quantum.quantum_hardware_interface import (
    connect_to_quantum_computer,
    generate_quantum_random_numbers,
    QuantumCircuit,
    execute_quantum_circuit,
    Node,
    implement_quantum_key_distribution_hardware,
)


def test_quantum_rng_length() -> None:
    conn = connect_to_quantum_computer("sim")
    r = generate_quantum_random_numbers(16, conn)
    assert isinstance(r, (bytes, bytearray))
    assert len(r) == 16


def test_execute_circuit_simulation_counts() -> None:
    conn = connect_to_quantum_computer("sim")
    qc = QuantumCircuit(description="hadamard_test", ops=[("h", 0), ("measure", 0)])
    res = execute_quantum_circuit(qc, conn, shots=128)
    assert res.shots == 128
    assert isinstance(res.counts, dict)


def test_qkd_shared_key_length() -> None:
    alice = Node(node_id="alice", device_info={})
    bob = Node(node_id="bob", device_info={})
    conn = connect_to_quantum_computer("sim")
    sk = implement_quantum_key_distribution_hardware(alice, bob, conn, key_length=16)
    assert isinstance(sk.key, (bytes, bytearray))
    assert len(sk.key) >= 1
