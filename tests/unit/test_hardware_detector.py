"""Unit tests for src/hardware/hardware_detector.py."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


def _load_module():
    module_path = PROJECT_ROOT / "src/hardware/hardware_detector.py"
    spec = importlib.util.spec_from_file_location("hardware_detector_module", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load hardware_detector module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_detect_cpu_features_from_cpuinfo_library(monkeypatch) -> None:
    module = _load_module()
    detector = module.HardwareDetector()

    monkeypatch.setattr(
        detector,
        "_load_cpu_info_from_library",
        lambda: {
            "flags": ["aes", "avx2", "avx512f", "sha_ni"],
            "vendor_id_raw": "GenuineIntel",
            "brand_raw": "Intel(R) Xeon(R)",
            "arch": "X86_64",
        },
    )

    cpu = detector.detect_cpu_features()

    assert cpu.aes_ni is True
    assert cpu.avx2 is True
    assert cpu.avx512 is True
    assert cpu.sha_extensions is True
    assert cpu.vendor == "GenuineIntel"


def test_detect_gpu_uses_cuda_and_opencl_sources(monkeypatch) -> None:
    module = _load_module()
    detector = module.HardwareDetector()

    monkeypatch.setattr(
        detector,
        "_detect_cuda_with_torch",
        lambda: {
            "cuda_available": True,
            "model": "NVIDIA A100",
            "cuda_device_count": 2,
            "cuda_capability": "8.0",
            "cuda_version": "12.2",
            "driver_version": "550.54",
        },
    )
    monkeypatch.setattr(detector, "_detect_opencl_platforms", lambda: ["NVIDIA CUDA"])

    gpu = detector.detect_gpu()

    assert gpu.available is True
    assert gpu.cuda_available is True
    assert gpu.opencl_available is True
    assert gpu.model == "NVIDIA A100"
    assert gpu.vendor == "NVIDIA"


def test_detect_fpga_discovers_devices_and_bitstreams(tmp_path: Path, monkeypatch) -> None:
    module = _load_module()

    bitstream_dir = tmp_path / "bitstreams"
    bitstream_dir.mkdir(parents=True, exist_ok=True)
    (bitstream_dir / "kernel.xclbin").write_bytes(b"test")

    detector = module.HardwareDetector(bitstream_dirs=[bitstream_dir])
    monkeypatch.setattr(
        detector,
        "_detect_fpga_pcie_devices",
        lambda: ["0000:03:00.0 Processing accelerators: Xilinx Device"],
    )

    fpga = detector.detect_fpga()

    assert fpga.available is True
    assert len(fpga.pcie_devices) == 1
    assert any(item.endswith("kernel.xclbin") for item in fpga.available_bitstreams)


def test_detect_hsm_aggregates_all_sources(monkeypatch) -> None:
    module = _load_module()
    detector = module.HardwareDetector()

    monkeypatch.setattr(
        detector,
        "_detect_yubikey_hsm_devices",
        lambda: [
            module.HSMDevice(
                name="YubiKey HSM",
                kind="yubikey-hsm",
                interface="usb",
                serial="123456",
                available=True,
            )
        ],
    )
    monkeypatch.setattr(
        detector,
        "_detect_pkcs11_modules",
        lambda: [
            module.HSMDevice(
                name="opensc-pkcs11.so",
                kind="pkcs11-module",
                interface="library",
                endpoint="/usr/lib/opensc-pkcs11.so",
                available=True,
            )
        ],
    )
    monkeypatch.setattr(
        detector,
        "_detect_network_hsm_devices",
        lambda: [
            module.HSMDevice(
                name="Network HSM",
                kind="network-hsm",
                interface="network",
                endpoint="10.0.0.10:1792",
                available=False,
            )
        ],
    )

    devices = detector.detect_hsm()

    assert len(devices) == 3
    assert any(item.kind == "yubikey-hsm" for item in devices)
    assert any(item.kind == "network-hsm" for item in devices)


def test_benchmark_performance_produces_speed_metrics() -> None:
    module = _load_module()
    detector = module.HardwareDetector(benchmark_duration_seconds=0.01)

    benchmark = detector.benchmark_performance()

    assert benchmark.cpu_hashlib_sha256_mb_s > 0
    assert benchmark.cpu_python_fallback_mb_s > 0
    assert benchmark.cpu_hash_speedup > 0


def test_detect_capabilities_returns_availability_dictionary(monkeypatch) -> None:
    module = _load_module()
    detector = module.HardwareDetector(benchmark_duration_seconds=0.01)

    monkeypatch.setattr(
        detector,
        "detect_cpu_features",
        lambda: module.CPUFeatures(
            aes_ni=True,
            avx2=False,
            avx512=False,
            sha_extensions=True,
            vendor="TestVendor",
            model_name="TestCPU",
            architecture="x86_64",
            flags=("aes",),
        ),
    )
    monkeypatch.setattr(
        detector,
        "detect_gpu",
        lambda: module.GPUInfo(
            available=True,
            model="TestGPU",
            vendor="NVIDIA",
            cuda_available=True,
            cuda_capability="8.0",
            cuda_device_count=1,
            cuda_version="12.0",
            opencl_available=False,
            opencl_platforms=(),
            driver_version="550",
        ),
    )
    monkeypatch.setattr(
        detector,
        "detect_fpga",
        lambda: module.FPGAInfo(
            available=False,
            pcie_devices=(),
            vendors=(),
            available_bitstreams=(),
        ),
    )
    monkeypatch.setattr(detector, "detect_hsm", lambda: [])
    monkeypatch.setattr(
        detector,
        "benchmark_performance",
        lambda: module.PerformanceBenchmark(
            cpu_hashlib_sha256_mb_s=100.0,
            cpu_python_fallback_mb_s=10.0,
            cpu_hash_speedup=10.0,
            simd_vectorized_mb_s=200.0,
            simd_scalar_mb_s=20.0,
            simd_speedup=10.0,
            gpu_cpu_matmul_ms=5.0,
            gpu_cuda_matmul_ms=1.0,
            gpu_speedup=5.0,
            notes=(),
        ),
    )

    capabilities = detector.detect_capabilities()

    assert capabilities["availability"]["cpu_aes_ni"] is True
    assert capabilities["availability"]["cuda_available"] is True
    assert capabilities["availability"]["fpga_available"] is False
    assert capabilities["availability"]["hardware_acceleration_available"] is True
