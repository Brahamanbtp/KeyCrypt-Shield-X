"""Throughput benchmark tests for symmetric and post-quantum cryptography.

These benchmarks are intentionally opt-in because they are expensive.
Set KEYCRYPT_RUN_THROUGHPUT_BENCHMARKS=1 to enable this module.
"""

from __future__ import annotations

import hashlib
import importlib
import os
import sys
import time
from pathlib import Path
from typing import Any

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from src.classical.aes_gcm import AESGCM
from src.classical.chacha20_poly1305 import ChaCha20Poly1305
from src.classical.ecies import generate_keypair
from src.hardware.aes_ni_accelerator import AESNIAccelerator


MB = 1024 * 1024
ONE_GIB = 1024 * MB

AES_GCM_TARGET_MB_S = 400.0
CHACHA20_TARGET_MB_S = 500.0
KYBER_TARGET_OPS_S = 1000.0
HYBRID_PQC_TARGET_MB_S = 300.0

AES_CHUNK_BYTES = 8 * MB
AES_CHUNK_COUNT = ONE_GIB // AES_CHUNK_BYTES

CHACHA_CHUNK_BYTES = 8 * MB
CHACHA_CHUNK_COUNT = ONE_GIB // CHACHA_CHUNK_BYTES

HYBRID_CHUNK_BYTES = 8 * MB
HYBRID_CHUNK_COUNT = ONE_GIB // HYBRID_CHUNK_BYTES

KYBER_OPS_PER_RUN = 2_500


def _env_enabled(name: str) -> bool:
    value = os.getenv(name, "")
    return value.strip().lower() in {"1", "true", "yes", "on"}


@pytest.fixture(autouse=True)
def _require_performance_opt_in() -> None:
    if not _env_enabled("KEYCRYPT_RUN_THROUGHPUT_BENCHMARKS"):
        pytest.skip("Set KEYCRYPT_RUN_THROUGHPUT_BENCHMARKS=1 to run throughput benchmarks")


def _throughput_mb_s(total_bytes: int, elapsed_seconds: float) -> float:
    safe_elapsed = max(elapsed_seconds, 1e-9)
    return (total_bytes / MB) / safe_elapsed


def _load_kyber_kem_class() -> Any:
    pytest.importorskip("oqs", reason="Kyber benchmark requires liboqs/oqs-python")

    try:
        module = importlib.import_module("src.pqc.kyber")
        return getattr(module, "KyberKEM")
    except Exception as exc:
        pytest.skip(f"Kyber KEM unavailable: {exc}")


class _StaticCPUFeatures:
    def __init__(self, aes_ni: bool) -> None:
        self.aes_ni = aes_ni


class _StaticHardwareDetector:
    def __init__(self, aes_ni: bool) -> None:
        self._aes_ni = aes_ni

    def detect_cpu_features(self) -> _StaticCPUFeatures:
        return _StaticCPUFeatures(self._aes_ni)


class _UnavailableAESNIBackend:
    AESNI_AVAILABLE = False


def benchmark_aes_gcm_throughput(benchmark: Any) -> None:
    """Encrypt 1 GiB with AES-GCM and assert throughput target."""
    key = AESGCM.generate_key()
    cipher = AESGCM(key)
    payload = b"A" * AES_CHUNK_BYTES
    associated_data = b"perf-aes-gcm"

    def _run_once() -> float:
        processed = 0
        started = time.perf_counter()

        for _ in range(AES_CHUNK_COUNT):
            ciphertext, _nonce, _tag = cipher.encrypt(payload, associated_data)
            processed += len(ciphertext)

        elapsed = time.perf_counter() - started
        return _throughput_mb_s(processed, elapsed)

    throughput_mb_s = benchmark.pedantic(_run_once, rounds=1, iterations=1)

    benchmark.extra_info["algorithm"] = "aes-gcm"
    benchmark.extra_info["data_size_bytes"] = ONE_GIB
    benchmark.extra_info["target_mb_s"] = AES_GCM_TARGET_MB_S
    benchmark.extra_info["measured_mb_s"] = round(throughput_mb_s, 3)

    assert throughput_mb_s > AES_GCM_TARGET_MB_S


def benchmark_chacha20_throughput(benchmark: Any) -> None:
    """Encrypt 1 GiB with ChaCha20-Poly1305 and assert throughput target."""
    key = ChaCha20Poly1305.generate_key()
    cipher = ChaCha20Poly1305(key)
    payload = b"C" * CHACHA_CHUNK_BYTES
    associated_data = b"perf-chacha20"

    def _run_once() -> float:
        processed = 0
        started = time.perf_counter()

        for _ in range(CHACHA_CHUNK_COUNT):
            ciphertext, _nonce, _tag = cipher.encrypt(payload, associated_data)
            processed += len(ciphertext)

        elapsed = time.perf_counter() - started
        return _throughput_mb_s(processed, elapsed)

    throughput_mb_s = benchmark.pedantic(_run_once, rounds=1, iterations=1)

    benchmark.extra_info["algorithm"] = "chacha20-poly1305"
    benchmark.extra_info["data_size_bytes"] = ONE_GIB
    benchmark.extra_info["target_mb_s"] = CHACHA20_TARGET_MB_S
    benchmark.extra_info["measured_mb_s"] = round(throughput_mb_s, 3)

    assert throughput_mb_s > CHACHA20_TARGET_MB_S


def benchmark_kyber_throughput(benchmark: Any) -> None:
    """Benchmark Kyber key encapsulation throughput in operations per second."""
    kyber_kem_class = _load_kyber_kem_class()
    kem = kyber_kem_class()
    public_key, _secret_key = kem.generate_keypair()

    def _run_once() -> float:
        completed = 0
        started = time.perf_counter()

        for _ in range(KYBER_OPS_PER_RUN):
            _ciphertext, _shared_secret = kem.encapsulate(public_key)
            completed += 1

        elapsed = time.perf_counter() - started
        return completed / max(elapsed, 1e-9)

    throughput_ops_s = benchmark.pedantic(_run_once, rounds=1, iterations=1)

    benchmark.extra_info["algorithm"] = "kyber-768"
    benchmark.extra_info["operations"] = KYBER_OPS_PER_RUN
    benchmark.extra_info["target_ops_s"] = KYBER_TARGET_OPS_S
    benchmark.extra_info["measured_ops_s"] = round(throughput_ops_s, 3)

    assert throughput_ops_s > KYBER_TARGET_OPS_S


def benchmark_hybrid_pqc_throughput(benchmark: Any) -> None:
    """Benchmark hybrid payload throughput using dual symmetric encryption."""
    key_material = hashlib.sha256(b"hybrid-throughput-benchmark").digest()

    aes_cipher = AESGCM(key_material)
    chacha_key = hashlib.sha256(key_material + b"chacha-layer").digest()
    chacha_cipher = ChaCha20Poly1305(chacha_key)

    payload = b"H" * HYBRID_CHUNK_BYTES
    aad_outer = b"hybrid-outer"
    aad_inner = b"hybrid-inner"

    def _run_once() -> float:
        processed = 0
        started = time.perf_counter()

        for _ in range(HYBRID_CHUNK_COUNT):
            first_layer, _nonce_1, _tag_1 = aes_cipher.encrypt(payload, aad_outer)
            second_layer, _nonce_2, _tag_2 = chacha_cipher.encrypt(first_layer, aad_inner)
            processed += len(second_layer)

        elapsed = time.perf_counter() - started
        return _throughput_mb_s(processed, elapsed)

    throughput_mb_s = benchmark.pedantic(_run_once, rounds=1, iterations=1)

    benchmark.extra_info["algorithm"] = "hybrid-pqc"
    benchmark.extra_info["layers"] = "aes-gcm+chacha20-poly1305"
    benchmark.extra_info["data_size_bytes"] = ONE_GIB
    benchmark.extra_info["target_mb_s"] = HYBRID_PQC_TARGET_MB_S
    benchmark.extra_info["measured_mb_s"] = round(throughput_mb_s, 3)

    assert throughput_mb_s > HYBRID_PQC_TARGET_MB_S


def benchmark_aes_ni_accelerated_throughput(benchmark: Any) -> None:
    """Benchmark AES-NI accelerated path when hardware/backend are available."""
    accelerator = AESNIAccelerator(benchmark_duration_seconds=0.2)
    if not accelerator.is_available():
        pytest.skip("AES-NI accelerated backend is unavailable on this host")

    throughput_mb_s = benchmark.pedantic(accelerator.benchmark, rounds=3, iterations=1)
    comparison = accelerator.benchmark_comparison()

    benchmark.extra_info["mode"] = "with-aes-ni"
    benchmark.extra_info["hardware_available"] = comparison.hardware_available
    benchmark.extra_info["hardware_mb_s"] = comparison.hardware_mb_s
    benchmark.extra_info["software_mb_s"] = comparison.software_mb_s
    benchmark.extra_info["speedup"] = comparison.speedup

    assert throughput_mb_s > 0
    assert comparison.hardware_available is True
    assert comparison.hardware_mb_s is not None


def benchmark_aes_ni_software_fallback_throughput(benchmark: Any) -> None:
    """Benchmark forced software fallback path without AES-NI support."""
    accelerator = AESNIAccelerator(
        aes_ni_backend=_UnavailableAESNIBackend(),
        hardware_detector=_StaticHardwareDetector(aes_ni=False),
        benchmark_duration_seconds=0.2,
    )

    throughput_mb_s = benchmark.pedantic(accelerator.benchmark, rounds=3, iterations=1)
    comparison = accelerator.benchmark_comparison()

    benchmark.extra_info["mode"] = "without-aes-ni"
    benchmark.extra_info["hardware_available"] = comparison.hardware_available
    benchmark.extra_info["software_mb_s"] = comparison.software_mb_s

    assert throughput_mb_s > 0
    assert comparison.hardware_available is False
    assert comparison.hardware_mb_s is None
    assert comparison.software_mb_s > 0


def benchmark_hybrid_kem_encapsulation_throughput(benchmark: Any) -> None:
    """Benchmark hybrid KEM encapsulation throughput in operations per second."""
    kyber_kem_class = _load_kyber_kem_class()
    from src.pqc.hybrid_kem import HybridKEM

    hybrid_kem = HybridKEM()
    _classical_secret_key, classical_public_key = generate_keypair()
    kyber_kem = kyber_kem_class()
    pqc_public_key, _pqc_secret_key = kyber_kem.generate_keypair()

    operations = 1_500

    def _run_once() -> float:
        completed = 0
        started = time.perf_counter()

        for _ in range(operations):
            _ciphertext, _shared_secret = hybrid_kem.encapsulate(classical_public_key, pqc_public_key)
            completed += 1

        elapsed = time.perf_counter() - started
        return completed / max(elapsed, 1e-9)

    throughput_ops_s = benchmark.pedantic(_run_once, rounds=1, iterations=1)

    benchmark.extra_info["algorithm"] = "hybrid-kem"
    benchmark.extra_info["operations"] = operations
    benchmark.extra_info["measured_ops_s"] = round(throughput_ops_s, 3)

    assert throughput_ops_s > 0


@pytest.mark.benchmark(group="throughput")
def test_benchmark_aes_gcm_throughput(benchmark: Any) -> None:
    benchmark_aes_gcm_throughput(benchmark)


@pytest.mark.benchmark(group="throughput")
def test_benchmark_chacha20_throughput(benchmark: Any) -> None:
    benchmark_chacha20_throughput(benchmark)


@pytest.mark.benchmark(group="throughput")
def test_benchmark_kyber_throughput(benchmark: Any) -> None:
    benchmark_kyber_throughput(benchmark)


@pytest.mark.benchmark(group="throughput")
def test_benchmark_hybrid_pqc_throughput(benchmark: Any) -> None:
    benchmark_hybrid_pqc_throughput(benchmark)


@pytest.mark.benchmark(group="aes-ni")
def test_benchmark_aes_ni_accelerated_throughput(benchmark: Any) -> None:
    benchmark_aes_ni_accelerated_throughput(benchmark)


@pytest.mark.benchmark(group="aes-ni")
def test_benchmark_aes_ni_software_fallback_throughput(benchmark: Any) -> None:
    benchmark_aes_ni_software_fallback_throughput(benchmark)


@pytest.mark.benchmark(group="hybrid-kem")
def test_benchmark_hybrid_kem_encapsulation_throughput(benchmark: Any) -> None:
    benchmark_hybrid_kem_encapsulation_throughput(benchmark)
