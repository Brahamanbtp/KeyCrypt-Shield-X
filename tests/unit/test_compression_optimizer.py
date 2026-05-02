"""Unit tests for src/optimization/compression_optimizer.py."""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


def _load_module():
    module_path = PROJECT_ROOT / "src/optimization/compression_optimizer.py"
    spec = importlib.util.spec_from_file_location("compression_optimizer_module", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load compression_optimizer module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_should_compress_detects_repetitive_data() -> None:
    module = _load_module()
    optimizer = module.CompressionOptimizer(sample_size_bytes=64 * 1024)

    sample = b"A" * (64 * 1024)
    assert optimizer.should_compress(sample, compression_overhead_threshold=1.2) is True


def test_should_compress_rejects_high_entropy_data() -> None:
    module = _load_module()
    optimizer = module.CompressionOptimizer(sample_size_bytes=8 * 1024)

    sample = os.urandom(8 * 1024)
    assert optimizer.should_compress(sample, compression_overhead_threshold=1.2) is False


def test_select_compression_algorithm_respects_speed_priority() -> None:
    module = _load_module()
    optimizer = module.CompressionOptimizer()

    profile = module.DataCharacteristics(size_bytes=1024, entropy_bits_per_byte=5.0, compressibility=0.6)
    assert optimizer.select_compression_algorithm(profile, speed_priority=1.0) == "lz4"
    assert optimizer.select_compression_algorithm(profile, speed_priority=0.0) == "zstd:19"


def test_select_compression_algorithm_skips_low_compressibility() -> None:
    module = _load_module()
    optimizer = module.CompressionOptimizer()

    profile = module.DataCharacteristics(size_bytes=1024, entropy_bits_per_byte=7.6, compressibility=0.05)
    assert optimizer.select_compression_algorithm(profile, speed_priority=0.5) == "none"


def test_parallel_compression_frames_chunks() -> None:
    module = _load_module()
    optimizer = module.CompressionOptimizer(executor_workers=2)

    module.compress_bytes = lambda data, algorithm, level=None: b"X" + data

    data = b"Z" * (1024 * 4 + 100)
    framed = optimizer.parallel_compression(data, chunk_size=1024)

    cursor = 0
    chunks = 0
    while cursor + 4 <= len(framed):
        length = int.from_bytes(framed[cursor : cursor + 4], "big")
        cursor += 4 + length
        chunks += 1

    assert chunks == 5
    assert cursor == len(framed)


def test_record_throughput_influences_algorithm_choice() -> None:
    module = _load_module()
    optimizer = module.CompressionOptimizer()

    profile = module.DataCharacteristics(size_bytes=1024, entropy_bits_per_byte=5.0, compressibility=0.6)
    optimizer.record_throughput("lz4", input_bytes=1 * 1024 * 1024, elapsed_seconds=1.0)
    optimizer.record_throughput("zstd", input_bytes=4 * 1024 * 1024, elapsed_seconds=1.0)

    assert optimizer.select_compression_algorithm(profile, speed_priority=0.9) == "zstd:5"


def test_train_dictionary_returns_bytes_or_none() -> None:
    module = _load_module()
    optimizer = module.CompressionOptimizer()

    samples = [b"alpha" * 1024, b"beta" * 1024, b"gamma" * 1024]
    dictionary = optimizer.train_dictionary(samples, dict_size=8192)
    assert dictionary is None or isinstance(dictionary, bytes)


def test_compress_before_encrypt_respects_none_algorithm() -> None:
    module = _load_module()
    optimizer = module.CompressionOptimizer()

    data = b"payload" * 128
    assert optimizer.compress_before_encrypt(data, "none") == data
