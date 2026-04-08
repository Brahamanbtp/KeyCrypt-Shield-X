"""Unit tests for src/hardware/aes_ni_accelerator.py."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


def _load_module():
    module_path = PROJECT_ROOT / "src/hardware/aes_ni_accelerator.py"
    spec = importlib.util.spec_from_file_location("aes_ni_accelerator_module", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load aes_ni_accelerator module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _FakeDetector:
    def __init__(self, aes_ni: bool) -> None:
        self._aes_ni = aes_ni

    class _Features:
        def __init__(self, aes_ni: bool) -> None:
            self.aes_ni = aes_ni

    def detect_cpu_features(self):
        return _FakeDetector._Features(self._aes_ni)


class _HardwareBackend:
    AESNI_AVAILABLE = True

    def __init__(self) -> None:
        self.calls = 0

    def encrypt_block(self, plaintext: bytes, key: bytes) -> bytes:
        self.calls += 1
        # Distinct deterministic output to prove hardware path was used.
        return bytes((value ^ key[index % len(key)] ^ 0xAA) for index, value in enumerate(plaintext))


class _UnavailableBackend:
    AESNI_AVAILABLE = False


def test_is_available_true_when_backend_and_cpu_support_present() -> None:
    module = _load_module()
    backend = _HardwareBackend()
    accelerator = module.AESNIAccelerator(
        aes_ni_backend=backend,
        hardware_detector=_FakeDetector(aes_ni=True),
    )

    assert accelerator.is_available() is True


def test_encrypt_block_uses_hardware_backend_when_available() -> None:
    module = _load_module()
    backend = _HardwareBackend()
    accelerator = module.AESNIAccelerator(
        aes_ni_backend=backend,
        hardware_detector=_FakeDetector(aes_ni=True),
    )

    plaintext = b"\x01" * 16
    key = b"\x02" * 16

    output = accelerator.encrypt_block(plaintext, key)

    assert isinstance(output, bytes)
    assert len(output) == 16
    assert backend.calls > 0


def test_encrypt_block_falls_back_to_software_when_hardware_unavailable() -> None:
    module = _load_module()
    accelerator = module.AESNIAccelerator(
        aes_ni_backend=_UnavailableBackend(),
        hardware_detector=_FakeDetector(aes_ni=False),
    )

    # AES-128 ECB known-answer vector.
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

    output = accelerator.encrypt_block(plaintext, key)

    assert output.hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"


def test_benchmark_returns_throughput_and_comparison() -> None:
    module = _load_module()
    accelerator = module.AESNIAccelerator(
        aes_ni_backend=_HardwareBackend(),
        hardware_detector=_FakeDetector(aes_ni=True),
        benchmark_duration_seconds=0.01,
    )

    throughput = accelerator.benchmark()
    comparison = accelerator.benchmark_comparison()

    assert throughput > 0
    assert comparison.software_mb_s > 0
    assert comparison.hardware_available is True


def test_invalid_block_size_raises_value_error() -> None:
    module = _load_module()
    accelerator = module.AESNIAccelerator(
        aes_ni_backend=_UnavailableBackend(),
        hardware_detector=_FakeDetector(aes_ni=False),
    )

    try:
        accelerator.encrypt_block(b"short", b"\x00" * 16)
    except ValueError as exc:
        assert "exactly 16 bytes" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected ValueError for invalid plaintext block size")
