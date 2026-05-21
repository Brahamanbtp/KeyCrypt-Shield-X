import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.integrations.iot.constrained_device_crypto import (
    DeviceConstraints,
    select_lightweight_algorithm,
    implement_hardware_crypto,
    CryptoOperation,
    optimize_for_battery_life,
    benchmark_on_device,
)


def test_select_prefers_chacha_on_low_end():
    dc = DeviceConstraints(cpu_mhz=100, memory_kb=32 * 1024, battery_percent=80.0, has_aes_hw=False)
    alg = select_lightweight_algorithm(dc)
    assert "ChaCha20" in alg.name or "ChaCha20" in alg.name


def test_select_prefers_aes_when_has_hw():
    dc = DeviceConstraints(cpu_mhz=400, memory_kb=128 * 1024, battery_percent=80.0, has_aes_hw=True)
    alg = select_lightweight_algorithm(dc)
    assert alg.name == "AES-GCM"


def test_implement_hardware_crypto_known_profile():
    hw = implement_hardware_crypto("esp32")
    assert hw.device_type == "esp32"
    assert hw.supports_curve25519


def test_optimize_reduces_frequency_and_estimates_energy():
    dc = DeviceConstraints(cpu_mhz=200, memory_kb=64 * 1024, battery_percent=10.0, has_aes_hw=False)
    op = CryptoOperation(name="send", algorithm="AES-GCM", frequency_hz=1.0, payload_size_bytes=64)
    opt = optimize_for_battery_life(op, dc)
    assert opt.frequency_hz < op.frequency_hz
    assert opt.estimated_energy_per_sec >= 0.0


def test_benchmark_simulation_returns_values():
    dc = DeviceConstraints(cpu_mhz=500, memory_kb=128 * 1024, battery_percent=60.0, has_aes_hw=True)
    res = benchmark_on_device("dev-x", ["AES-GCM", "ChaCha20-Poly1305", "SPHINCS+"], constraints=dc)
    assert "AES-GCM" in res.latencies_ms
    assert "SPHINCS+" in res.energy_estimates_j
