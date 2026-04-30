"""Unit tests for src/optimization/key_derivation_optimizer.py."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


def _load_module():
    module_path = PROJECT_ROOT / "src/optimization/key_derivation_optimizer.py"
    spec = importlib.util.spec_from_file_location("key_derivation_optimizer_module", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load key_derivation_optimizer module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_batch_key_derivation_is_deterministic_and_consistent() -> None:
    module = _load_module()
    optimizer = module.KeyDerivationOptimizer(cache_file=None)

    master_key = b"master-key-material-32-bytes!!"
    contexts = ["alpha", "beta", "gamma"]

    first = optimizer.batch_key_derivation(master_key, contexts)
    second = optimizer.batch_key_derivation(master_key, contexts)

    assert first == second
    assert len(first) == len(contexts)
    assert len({item for item in first}) == len(contexts)


def test_cached_derived_key_is_returned_for_matching_input() -> None:
    module = _load_module()
    optimizer = module.KeyDerivationOptimizer(cache_file=None)

    master_key = b"master-key-material-32-bytes!!"
    context = "documents"
    derived_key = b"\x01" * 32

    optimizer.cache_derived_keys(optimizer._master_key_id(master_key), context, derived_key, ttl=60)

    cached = optimizer.batch_key_derivation(master_key, [context])[0]
    assert cached == derived_key


def test_optimize_pbkdf2_iterations_uses_benchmark_data(monkeypatch) -> None:
    module = _load_module()
    optimizer = module.KeyDerivationOptimizer(cache_file=None, benchmark_iterations=10_000)

    monkeypatch.setattr(
        optimizer,
        "_benchmark_system",
        lambda target_time_ms: module.KDFBenchmarkResult(
            hardware_id="bench-hardware",
            target_time_ms=target_time_ms,
            benchmark_iterations=10_000,
            elapsed_ms=50.0,
            estimated_iterations=int(target_time_ms / 50.0 * 10_000),
            measured_iterations_per_second=200_000.0,
        ),
    )

    iterations = optimizer.optimize_pbkdf2_iterations(200)
    assert iterations == 40_000


def test_key_derivation_verification_round_trip() -> None:
    module = _load_module()
    optimizer = module.KeyDerivationOptimizer(cache_file=None)

    master_key = b"master-key-material-32-bytes!!"
    context = "payments"

    derived = optimizer.derive_verified_key(master_key, context)

    assert optimizer.verify_key_derivation_result(master_key, context, derived) is True


def test_hardware_kdf_detection_respects_cpu_flags(monkeypatch) -> None:
    module = _load_module()
    optimizer = module.KeyDerivationOptimizer(cache_file=None)

    monkeypatch.setattr(optimizer, "_cpu_flags", lambda: {"sse2", "keylocker", "aes"})

    assert optimizer.use_hardware_kdf_if_available() is True


def test_benchmark_cache_persists_and_reloads(tmp_path: Path, monkeypatch) -> None:
    module = _load_module()
    cache_file = tmp_path / "kdf-cache.json"
    optimizer = module.KeyDerivationOptimizer(cache_file=cache_file, benchmark_iterations=10_000)

    monkeypatch.setattr(
        optimizer,
        "_benchmark_system",
        lambda target_time_ms: module.KDFBenchmarkResult(
            hardware_id="hardware-x",
            target_time_ms=target_time_ms,
            benchmark_iterations=10_000,
            elapsed_ms=20.0,
            estimated_iterations=50_000,
            measured_iterations_per_second=500_000.0,
        ),
    )

    assert optimizer.optimize_pbkdf2_iterations(100) == 50_000
    assert cache_file.is_file()

    reloaded = module.KeyDerivationOptimizer(cache_file=cache_file, benchmark_iterations=10_000)
    monkeypatch.setattr(reloaded, "_benchmark_system", lambda target_time_ms: (_ for _ in ()).throw(RuntimeError("should not re-benchmark")))
    assert reloaded.optimize_pbkdf2_iterations(100) == 50_000
