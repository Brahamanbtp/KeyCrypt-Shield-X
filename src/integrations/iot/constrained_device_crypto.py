from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
import random
import time


@dataclass
class DeviceConstraints:
    cpu_mhz: int
    memory_kb: int
    battery_percent: float
    has_aes_hw: bool = False
    hardware_accelerator: Optional[str] = None
    require_postquantum: bool = False
    require_signatures: bool = True


@dataclass
class Algorithm:
    name: str
    estimated_cpu_cost: float
    memory_cost_kb: int
    energy_cost_per_op: float


@dataclass
class HardwareCrypto:
    device_type: str
    supports_aes: bool
    supports_curve25519: bool
    supports_chacha: bool
    notes: Optional[str] = None


@dataclass
class CryptoOperation:
    name: str
    algorithm: str
    frequency_hz: float
    payload_size_bytes: int


@dataclass
class OptimizedOperation:
    name: str
    algorithm: str
    frequency_hz: float
    estimated_energy_per_sec: float


@dataclass
class BenchmarkResult:
    latencies_ms: Dict[str, float]
    energy_estimates_j: Dict[str, float]


def select_lightweight_algorithm(device_constraints: DeviceConstraints) -> Algorithm:
    """Pick an algorithm based on device constraints and requirements.

    Heuristic rules:
    - If `require_postquantum` and device has enough CPU and memory, choose SPHINCS+.
    - If AES hardware present, prefer AES-GCM for general encryption.
    - Otherwise prefer ChaCha20 for low-power devices.
    - For key exchange, suggest Curve25519 if signatures not required or resource permits.
    """
    dc = device_constraints
    # SPHINCS+ is heavy; require at least 2000 MHz or memory > 256KB
    if dc.require_postquantum and (dc.cpu_mhz >= 2000 or dc.memory_kb >= 256 * 1024):
        return Algorithm("SPHINCS+", estimated_cpu_cost=3.0, memory_cost_kb=200 * 1024, energy_cost_per_op=5.0)

    # If AES hardware present and device has moderate resources
    if dc.has_aes_hw and dc.cpu_mhz >= 200:
        return Algorithm("AES-GCM", estimated_cpu_cost=1.0, memory_cost_kb=16 * 1024, energy_cost_per_op=1.0)

    # Curve25519 for key exchange / signatures when CPU allows
    if not dc.require_postquantum and dc.cpu_mhz >= 300 and dc.memory_kb >= 64 * 1024:
        return Algorithm("Curve25519", estimated_cpu_cost=1.5, memory_cost_kb=64 * 1024, energy_cost_per_op=1.2)

    # Fallback to ChaCha20 for small/low-power devices
    return Algorithm("ChaCha20-Poly1305", estimated_cpu_cost=0.8, memory_cost_kb=8 * 1024, energy_cost_per_op=0.6)


def implement_hardware_crypto(device_type: str) -> HardwareCrypto:
    """Simulate detection of hardware crypto accelerators on a given device type."""
    # Known device profiles
    profiles = {
        "esp32": HardwareCrypto(device_type="esp32", supports_aes=False, supports_curve25519=True, supports_chacha=True, notes="ESP32 uses software AES unless special builds"),
        "raspberry-pi": HardwareCrypto(device_type="raspberry-pi", supports_aes=True, supports_curve25519=True, supports_chacha=True, notes="Broad support; AES-NI on some models"),
        "stm32": HardwareCrypto(device_type="stm32", supports_aes=True, supports_curve25519=False, supports_chacha=False, notes="Has AES hardware engine on some variants"),
    }
    return profiles.get(device_type, HardwareCrypto(device_type=device_type, supports_aes=False, supports_curve25519=False, supports_chacha=False, notes="unknown device, assume no accelerators"))


def optimize_for_battery_life(operation: CryptoOperation, constraints: DeviceConstraints) -> OptimizedOperation:
    """Reduce operation frequency and pick a lower-energy algorithm when battery is low."""
    freq = operation.frequency_hz
    alg = operation.algorithm
    # If battery is very low, reduce frequency by 80% and prefer ChaCha20
    if constraints.battery_percent < 20.0:
        new_freq = max(0.1, freq * 0.2)
        new_alg = "ChaCha20-Poly1305"
    elif constraints.battery_percent < 50.0:
        new_freq = max(0.2, freq * 0.5)
        new_alg = "ChaCha20-Poly1305" if not constraints.has_aes_hw else alg
    else:
        new_freq = freq
        new_alg = alg

    # estimate energy: energy_per_op from selection heuristic
    sel = select_lightweight_algorithm(constraints)
    energy_per_op = sel.energy_cost_per_op if hasattr(sel, "energy_cost_per_op") else sel.energy_cost_per_op
    est_energy = energy_per_op * new_freq
    return OptimizedOperation(name=operation.name, algorithm=new_alg, frequency_hz=new_freq, estimated_energy_per_sec=est_energy)


def benchmark_on_device(device_id: str, algorithms: List[str], constraints: Optional[DeviceConstraints] = None) -> BenchmarkResult:
    """Simulate benchmarking algorithms on a device.

    If `constraints` is provided, base timing on CPU. Otherwise use a default simulation.
    For real devices, this function should run native code and measure wall-clock and energy.
    """
    # Simple simulation: base latency inversely proportional to CPU, and algorithm complexity multiplier
    cpu = constraints.cpu_mhz if constraints is not None else 500
    latencies = {}
    energies = {}
    for alg in algorithms:
        if alg.lower().startswith("aes"):
            mult = 1.0
        elif alg.lower().startswith("chacha"):
            mult = 0.8
        elif alg.lower().startswith("curve"):
            mult = 1.2
        elif alg.lower().startswith("sphincs"):
            mult = 5.0
        else:
            mult = 1.0

        # simulate
        latency_ms = max(0.1, (1000.0 / max(1, cpu)) * mult * random.uniform(0.9, 1.1))
        energy_j = latency_ms * 0.001 * mult
        latencies[alg] = latency_ms
        energies[alg] = energy_j

    return BenchmarkResult(latencies_ms=latencies, energy_estimates_j=energies)
