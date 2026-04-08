"""Unit tests for src/hardware/gpu_batch_processor.py."""

from __future__ import annotations

import asyncio
import importlib.util
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


def _load_module():
    module_path = PROJECT_ROOT / "src/hardware/gpu_batch_processor.py"
    spec = importlib.util.spec_from_file_location("gpu_batch_processor_module", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load gpu_batch_processor module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _FakeGPUInfo:
    def __init__(self, *, cuda: bool, opencl: bool) -> None:
        self.cuda_available = cuda
        self.opencl_available = opencl


class _FakeDetector:
    def __init__(self, *, cuda: bool, opencl: bool) -> None:
        self._info = _FakeGPUInfo(cuda=cuda, opencl=opencl)

    def detect_gpu(self):
        return self._info


class _FakeGPUBackend:
    GPU_AVAILABLE = True

    def __init__(self) -> None:
        self.transfer_in_calls = 0
        self.kernel_calls = 0
        self.transfer_out_calls = 0

    def transfer_to_gpu(self, payloads):
        self.transfer_in_calls += 1
        return [bytes(item) for item in payloads]

    def run_encryption_kernel(self, plaintexts, keys):
        self.kernel_calls += 1
        return [
            bytes((byte ^ key[index % len(key)] ^ 0x7F) for index, byte in enumerate(plain))
            for plain, key in zip(plaintexts, keys)
        ]

    def transfer_from_gpu(self, payloads):
        self.transfer_out_calls += 1
        return payloads


class _UnavailableBackend:
    GPU_AVAILABLE = False


def test_encrypt_batch_gpu_uses_backend_when_available() -> None:
    module = _load_module()
    backend = _FakeGPUBackend()
    processor = module.GPUBatchProcessor(
        gpu_backend=backend,
        hardware_detector=_FakeDetector(cuda=True, opencl=False),
    )

    plaintexts = [b"hello", b"world"]
    keys = [b"k1", b"k2"]

    ciphertexts = asyncio.run(processor.encrypt_batch_gpu(plaintexts, keys))

    assert len(ciphertexts) == 2
    assert backend.transfer_in_calls >= 2
    assert backend.kernel_calls == 1
    assert backend.transfer_out_calls == 1


def test_encrypt_batch_gpu_falls_back_to_cpu_when_unavailable() -> None:
    module = _load_module()
    processor = module.GPUBatchProcessor(
        gpu_backend=_UnavailableBackend(),
        hardware_detector=_FakeDetector(cuda=False, opencl=False),
    )

    plaintexts = [b"alpha", b"beta"]
    keys = [b"key", b"key"]

    ciphertexts = asyncio.run(processor.encrypt_batch_gpu(plaintexts, keys))

    assert len(ciphertexts) == 2
    assert ciphertexts[0] != plaintexts[0]
    assert ciphertexts[1] != plaintexts[1]


def test_encrypt_batch_gpu_rejects_invalid_inputs() -> None:
    module = _load_module()
    processor = module.GPUBatchProcessor(
        gpu_backend=_UnavailableBackend(),
        hardware_detector=_FakeDetector(cuda=False, opencl=False),
    )

    try:
        asyncio.run(processor.encrypt_batch_gpu([b"a"], [b"k", b"k"]))
    except ValueError as exc:
        assert "same length" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected ValueError for mismatched batch sizes")


def test_benchmark_gpu_acceleration_returns_comparison() -> None:
    module = _load_module()
    processor = module.GPUBatchProcessor(
        gpu_backend=_FakeGPUBackend(),
        hardware_detector=_FakeDetector(cuda=True, opencl=False),
        benchmark_duration_seconds=0.01,
    )

    result = processor.benchmark_gpu_acceleration(batch_size=8, payload_size_bytes=256, key_size_bytes=16)

    assert result.cpu_throughput_mb_s > 0
    assert result.gpu_throughput_mb_s is not None
    assert result.gpu_avg_latency_ms is not None


def test_benchmark_gpu_acceleration_cpu_only_has_notes() -> None:
    module = _load_module()
    processor = module.GPUBatchProcessor(
        gpu_backend=_UnavailableBackend(),
        hardware_detector=_FakeDetector(cuda=False, opencl=False),
        benchmark_duration_seconds=0.01,
    )

    result = processor.benchmark_gpu_acceleration(batch_size=8, payload_size_bytes=128, key_size_bytes=16)

    assert result.gpu_available is False
    assert result.gpu_throughput_mb_s is None
    assert any("CUDA" in note or "OpenCL" in note for note in result.notes)
