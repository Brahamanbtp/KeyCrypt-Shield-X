"""Unit tests for src/optimization/crypto_optimizer.py."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


def _load_module():
    module_path = PROJECT_ROOT / "src/optimization/crypto_optimizer.py"
    spec = importlib.util.spec_from_file_location("crypto_optimizer_module", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load crypto_optimizer module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_high_entropy_payload_disables_compression() -> None:
    module = _load_module()
    optimizer = module.CryptoOptimizer(cache_file=None)

    profile = module.DataProfile(
        data_type="file",
        size_bytes=8 * 1024 * 1024,
        latency_budget_ms=75.0,
        metadata={"entropy": 7.9, "compressibility": 0.05},
    )

    assert optimizer.should_enable_compression(profile) is False


def test_compressible_low_latency_data_prefers_chacha20() -> None:
    module = _load_module()
    optimizer = module.CryptoOptimizer(cache_file=None)

    profile = module.DataProfile(
        data_type="stream",
        size_bytes=16 * 1024 * 1024,
        latency_budget_ms=12.0,
        metadata={"entropy": 4.2, "compressibility": 0.82},
    )

    selected = optimizer.optimize_algorithm_selection(profile)
    assert selected == "chacha20"


def test_chunk_size_uses_hardware_and_learned_cache() -> None:
    module = _load_module()
    optimizer = module.CryptoOptimizer(cache_file=None)

    hardware = module.HardwareProfile(
        hardware_id="node-a",
        cpu_cores=8,
        available_memory_bytes=16 * 1024 * 1024 * 1024,
        cpu_cache_size_bytes=16 * 1024 * 1024,
        disk_bandwidth_mb_s=1200.0,
        aes_ni_available=True,
    )

    initial_chunk = optimizer.optimize_chunk_size(512 * 1024 * 1024, hardware)

    optimizer.record_runtime_metrics(
        "node-a",
        "aes-gcm",
        throughput_mb_s=1800.0,
        chunk_size=8 * 1024 * 1024,
        parallel_workers=6,
    )
    adapted_chunk = optimizer.optimize_chunk_size(512 * 1024 * 1024, hardware)

    assert adapted_chunk >= initial_chunk
    assert adapted_chunk <= module.MAX_CHUNK_SIZE


def test_parallelization_scales_with_data_size() -> None:
    module = _load_module()
    optimizer = module.CryptoOptimizer(cache_file=None)

    small = optimizer.optimize_parallelization("encrypt", 256 * 1024)
    large = optimizer.optimize_parallelization("encrypt", 128 * 1024 * 1024)

    assert small.workers == 1
    assert large.workers >= 2
    assert large.batch_size_bytes >= small.batch_size_bytes
    assert large.use_async_pipeline is True


def test_benchmark_cache_persists_and_reloads(tmp_path: Path, monkeypatch) -> None:
    module = _load_module()
    cache_file = tmp_path / "optimizer-cache.json"

    optimizer = module.CryptoOptimizer(cache_file=cache_file)

    scores = {"aes-gcm": 950.0, "chacha20": 700.0}
    monkeypatch.setattr(
        optimizer,
        "_run_algorithm_microbenchmark",
        lambda algorithm: scores[algorithm],
    )

    cached = optimizer.benchmark_and_cache_results("bench-node")

    assert cache_file.is_file()
    assert cached.sample_count == 1
    assert cached.algorithm_scores["aes-gcm"] == 950.0

    reloaded = module.CryptoOptimizer(cache_file=cache_file)
    cached_again = reloaded.get_cached_benchmark("bench-node")
    assert cached_again is not None
    assert cached_again.sample_count == 1
    assert cached_again.algorithm_scores["aes-gcm"] == 950.0


def test_adaptive_metrics_can_shift_algorithm_choice() -> None:
    module = _load_module()
    optimizer = module.CryptoOptimizer(cache_file=None)

    profile = module.DataProfile(
        data_type="message",
        size_bytes=2 * 1024 * 1024,
        latency_budget_ms=50.0,
        metadata={"hardware_id": "node-b", "entropy": 6.1, "compressibility": 0.30},
    )

    optimizer.record_runtime_metrics("node-b", "aes-gcm", throughput_mb_s=600.0)
    optimizer.record_runtime_metrics("node-b", "chacha20", throughput_mb_s=1400.0)

    selected = optimizer.optimize_algorithm_selection(profile)
    assert selected == "chacha20"
