"""Hardware capability discovery and acceleration benchmarking.

This module provides a unified detector for runtime hardware acceleration
capabilities used by cryptographic and security workflows.

Detected hardware classes:
- CPU features (AES-NI, AVX2, AVX-512, SHA extensions)
- GPU acceleration (CUDA/OpenCL)
- FPGA cards and local bitstreams
- HSM devices (YubiKey HSM, PKCS#11 libraries, network HSM endpoints)

The detector also includes lightweight performance benchmarks to estimate
practical speed gains from available acceleration paths.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import socket
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, List, Mapping, Sequence

from src.utils.logging import get_logger


logger = get_logger("src.hardware.hardware_detector")


try:  # pragma: no cover - optional dependency boundary
    import cpuinfo as _cpuinfo
except Exception:  # pragma: no cover - optional dependency boundary
    _cpuinfo = None  # type: ignore[assignment]

try:  # pragma: no cover - optional dependency boundary
    import numpy as _np
except Exception:  # pragma: no cover - optional dependency boundary
    _np = None  # type: ignore[assignment]


@dataclass(frozen=True)
class CPUFeatures:
    """Detected CPU feature capabilities."""

    aes_ni: bool
    avx2: bool
    avx512: bool
    sha_extensions: bool
    vendor: str
    model_name: str
    architecture: str
    flags: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class GPUInfo:
    """Detected GPU acceleration capabilities."""

    available: bool
    model: str = ""
    vendor: str = ""
    cuda_available: bool = False
    cuda_capability: str | None = None
    cuda_device_count: int = 0
    cuda_version: str | None = None
    opencl_available: bool = False
    opencl_platforms: tuple[str, ...] = field(default_factory=tuple)
    driver_version: str | None = None


@dataclass(frozen=True)
class FPGAInfo:
    """Detected FPGA accelerator capabilities."""

    available: bool
    pcie_devices: tuple[str, ...] = field(default_factory=tuple)
    vendors: tuple[str, ...] = field(default_factory=tuple)
    available_bitstreams: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class HSMDevice:
    """Detected HSM device endpoint."""

    name: str
    kind: str
    interface: str
    endpoint: str | None = None
    serial: str | None = None
    available: bool = True
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PerformanceBenchmark:
    """Acceleration benchmark summary."""

    cpu_hashlib_sha256_mb_s: float
    cpu_python_fallback_mb_s: float
    cpu_hash_speedup: float
    simd_vectorized_mb_s: float | None = None
    simd_scalar_mb_s: float | None = None
    simd_speedup: float | None = None
    gpu_cpu_matmul_ms: float | None = None
    gpu_cuda_matmul_ms: float | None = None
    gpu_speedup: float | None = None
    notes: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class HardwareCapabilities:
    """Aggregate detected hardware capabilities."""

    cpu: CPUFeatures
    gpu: GPUInfo
    fpga: FPGAInfo
    hsm_devices: tuple[HSMDevice, ...]
    benchmark: PerformanceBenchmark
    availability: Mapping[str, bool]


class HardwareDetector:
    """Discover hardware acceleration capabilities and performance gains."""

    _BITSTREAM_EXTENSIONS = {".bit", ".bin", ".xclbin", ".sof", ".rbf"}
    _FPGA_MARKERS = (
        "xilinx",
        "altera",
        "intel fpga",
        "fpga",
        "zynq",
        "arria",
        "stratix",
        "acap",
    )
    _GPU_MARKERS = (
        "vga compatible controller",
        "3d controller",
        "display controller",
        "nvidia",
        "amd",
        "intel corporation",
    )

    def __init__(
        self,
        *,
        bitstream_dirs: Sequence[str | Path] | None = None,
        hsm_endpoints: Sequence[str] | None = None,
        command_timeout_seconds: float = 2.0,
        benchmark_duration_seconds: float = 0.12,
    ) -> None:
        if command_timeout_seconds <= 0:
            raise ValueError("command_timeout_seconds must be > 0")
        if benchmark_duration_seconds <= 0:
            raise ValueError("benchmark_duration_seconds must be > 0")

        self._command_timeout_seconds = float(command_timeout_seconds)
        self._benchmark_duration_seconds = float(benchmark_duration_seconds)

        default_bitstream_dirs = (
            Path("/lib/firmware"),
            Path("/opt/xilinx"),
            Path("/opt/intel/fpga"),
            Path("/usr/share/fpga"),
        )
        self._bitstream_dirs = tuple(
            Path(item).expanduser().resolve()
            for item in (bitstream_dirs or default_bitstream_dirs)
        )

        configured_hsm = tuple(hsm_endpoints or self._parse_hsm_endpoints_from_env())
        self._hsm_endpoints = tuple(item.strip() for item in configured_hsm if item.strip())

    def detect_cpu_features(self) -> CPUFeatures:
        """Detect CPU instruction-set capabilities used by crypto workloads."""
        info = self._load_cpu_info_from_library() or self._load_cpu_info_from_proc()

        flags = tuple(sorted(self._extract_cpu_flags(info)))
        flag_set = set(flags)

        aes_ni = self._feature_present(flag_set, ("aes", "aes_ni"))
        avx2 = "avx2" in flag_set
        avx512 = any(item.startswith("avx512") for item in flag_set)
        sha_extensions = self._feature_present(flag_set, ("sha", "sha_ni", "sha1", "sha2", "sha256"))

        vendor = str(
            info.get("vendor_id_raw")
            or info.get("vendor_id")
            or info.get("vendor")
            or "unknown"
        )
        model_name = str(
            info.get("brand_raw")
            or info.get("model name")
            or info.get("hardware")
            or "unknown"
        )
        architecture = str(info.get("arch") or platform.machine() or "unknown")

        return CPUFeatures(
            aes_ni=aes_ni,
            avx2=avx2,
            avx512=avx512,
            sha_extensions=sha_extensions,
            vendor=vendor,
            model_name=model_name,
            architecture=architecture,
            flags=flags,
        )

    def detect_gpu(self) -> GPUInfo:
        """Detect CUDA/OpenCL availability and GPU model information."""
        cuda = self._detect_cuda_with_torch()
        if not cuda.get("cuda_available", False):
            cuda = self._detect_cuda_with_nvidia_smi()

        opencl_platforms = self._detect_opencl_platforms()
        opencl_available = len(opencl_platforms) > 0

        model = str(cuda.get("model") or "").strip()
        if not model:
            pci_models = self._detect_gpu_models_from_pci()
            if pci_models:
                model = pci_models[0]

        vendor = self._guess_vendor(model)
        available = bool(model) or bool(cuda.get("cuda_available", False)) or opencl_available

        return GPUInfo(
            available=available,
            model=model,
            vendor=vendor,
            cuda_available=bool(cuda.get("cuda_available", False)),
            cuda_capability=self._none_if_empty(cuda.get("cuda_capability")),
            cuda_device_count=int(cuda.get("cuda_device_count", 0) or 0),
            cuda_version=self._none_if_empty(cuda.get("cuda_version")),
            opencl_available=opencl_available,
            opencl_platforms=tuple(opencl_platforms),
            driver_version=self._none_if_empty(cuda.get("driver_version")),
        )

    def detect_fpga(self) -> FPGAInfo:
        """Detect PCIe FPGA cards and available local bitstreams."""
        pcie_devices = self._detect_fpga_pcie_devices()
        bitstreams = self._discover_bitstreams(self._bitstream_dirs)

        vendors = tuple(sorted({self._guess_vendor(item) for item in pcie_devices if self._guess_vendor(item)}))
        available = bool(pcie_devices or bitstreams)

        return FPGAInfo(
            available=available,
            pcie_devices=tuple(sorted(pcie_devices)),
            vendors=vendors,
            available_bitstreams=tuple(sorted(bitstreams)),
        )

    def detect_hsm(self) -> List[HSMDevice]:
        """Detect attached and network-reachable HSM devices."""
        devices: list[HSMDevice] = []
        devices.extend(self._detect_yubikey_hsm_devices())
        devices.extend(self._detect_pkcs11_modules())
        devices.extend(self._detect_network_hsm_devices())

        unique: dict[tuple[str, str, str, str | None], HSMDevice] = {}
        for item in devices:
            key = (item.kind, item.interface, item.name, item.serial)
            unique[key] = item

        return list(unique.values())

    def benchmark_performance(self) -> PerformanceBenchmark:
        """Benchmark practical acceleration speed gains on this host."""
        notes: list[str] = []

        fast_hash_mb_s = self._benchmark_hashlib_sha256()
        fallback_hash_mb_s = self._benchmark_python_hash_fallback()
        if fallback_hash_mb_s > 0:
            hash_speedup = fast_hash_mb_s / fallback_hash_mb_s
        else:
            hash_speedup = 0.0
            notes.append("python fallback hash benchmark produced zero throughput")

        simd_vectorized_mb_s: float | None = None
        simd_scalar_mb_s: float | None = None
        simd_speedup: float | None = None

        simd_result = self._benchmark_simd_vectorization()
        if simd_result is None:
            notes.append("numpy not available; skipped SIMD vectorization benchmark")
        else:
            simd_vectorized_mb_s, simd_scalar_mb_s = simd_result
            if simd_scalar_mb_s > 0:
                simd_speedup = simd_vectorized_mb_s / simd_scalar_mb_s

        gpu_cpu_ms: float | None = None
        gpu_cuda_ms: float | None = None
        gpu_speedup: float | None = None

        gpu_result = self._benchmark_gpu_speedup()
        if gpu_result is None:
            notes.append("CUDA benchmark unavailable; skipped GPU speed benchmark")
        else:
            gpu_cpu_ms, gpu_cuda_ms = gpu_result
            if gpu_cuda_ms > 0:
                gpu_speedup = gpu_cpu_ms / gpu_cuda_ms

        return PerformanceBenchmark(
            cpu_hashlib_sha256_mb_s=fast_hash_mb_s,
            cpu_python_fallback_mb_s=fallback_hash_mb_s,
            cpu_hash_speedup=hash_speedup,
            simd_vectorized_mb_s=simd_vectorized_mb_s,
            simd_scalar_mb_s=simd_scalar_mb_s,
            simd_speedup=simd_speedup,
            gpu_cpu_matmul_ms=gpu_cpu_ms,
            gpu_cuda_matmul_ms=gpu_cuda_ms,
            gpu_speedup=gpu_speedup,
            notes=tuple(notes),
        )

    def detect_capabilities(self) -> dict[str, Any]:
        """Return capability dictionary with availability flags and benchmarks."""
        aggregate = self.detect_all()
        return {
            "cpu": asdict(aggregate.cpu),
            "gpu": asdict(aggregate.gpu),
            "fpga": asdict(aggregate.fpga),
            "hsm_devices": [asdict(item) for item in aggregate.hsm_devices],
            "benchmark": asdict(aggregate.benchmark),
            "availability": dict(aggregate.availability),
        }

    def detect_all(self) -> HardwareCapabilities:
        """Run full hardware detection and return aggregate capability view."""
        cpu = self.detect_cpu_features()
        gpu = self.detect_gpu()
        fpga = self.detect_fpga()
        hsm_devices = tuple(self.detect_hsm())
        benchmark = self.benchmark_performance()

        availability = {
            "cpu_aes_ni": cpu.aes_ni,
            "cpu_avx2": cpu.avx2,
            "cpu_avx512": cpu.avx512,
            "cpu_sha_extensions": cpu.sha_extensions,
            "gpu_available": gpu.available,
            "cuda_available": gpu.cuda_available,
            "opencl_available": gpu.opencl_available,
            "fpga_available": fpga.available,
            "hsm_available": any(item.available for item in hsm_devices),
            "hardware_acceleration_available": (
                cpu.aes_ni or cpu.avx2 or gpu.cuda_available or fpga.available
            ),
        }

        return HardwareCapabilities(
            cpu=cpu,
            gpu=gpu,
            fpga=fpga,
            hsm_devices=hsm_devices,
            benchmark=benchmark,
            availability=availability,
        )

    def _load_cpu_info_from_library(self) -> dict[str, Any] | None:
        if _cpuinfo is None:
            return None

        try:
            payload = _cpuinfo.get_cpu_info()
        except Exception as exc:
            logger.debug("cpuinfo library lookup failed: {}", exc)
            return None

        if isinstance(payload, dict):
            return payload
        return None

    def _load_cpu_info_from_proc(self) -> dict[str, Any]:
        proc_path = Path("/proc/cpuinfo")
        if not proc_path.exists():
            return {
                "arch": platform.machine() or "unknown",
            }

        try:
            content = proc_path.read_text(encoding="utf-8", errors="ignore")
        except Exception as exc:
            logger.debug("failed reading /proc/cpuinfo: {}", exc)
            return {
                "arch": platform.machine() or "unknown",
            }

        return self._parse_proc_cpuinfo(content)

    @staticmethod
    def _parse_proc_cpuinfo(content: str) -> dict[str, Any]:
        data: dict[str, Any] = {
            "flags": [],
        }

        for line in content.splitlines():
            if ":" not in line:
                continue

            key_raw, value_raw = line.split(":", 1)
            key = key_raw.strip().lower()
            value = value_raw.strip()

            if key in {"flags", "features"}:
                tokens = [item.strip().lower() for item in value.split() if item.strip()]
                existing = data.setdefault("flags", [])
                if isinstance(existing, list):
                    for item in tokens:
                        if item not in existing:
                            existing.append(item)
                continue

            if key == "model name" and "model name" not in data:
                data["model name"] = value
            elif key in {"hardware", "cpu part"} and "hardware" not in data:
                data["hardware"] = value
            elif key in {"vendor_id", "vendor", "cpu implementer"} and "vendor" not in data:
                data["vendor"] = value

        data.setdefault("arch", platform.machine() or "unknown")
        return data

    @staticmethod
    def _extract_cpu_flags(info: Mapping[str, Any]) -> set[str]:
        raw = info.get("flags")
        if isinstance(raw, list):
            return {str(item).strip().lower() for item in raw if str(item).strip()}
        if isinstance(raw, tuple):
            return {str(item).strip().lower() for item in raw if str(item).strip()}
        if isinstance(raw, str):
            return {item.strip().lower() for item in raw.split() if item.strip()}
        return set()

    @staticmethod
    def _feature_present(flags: set[str], names: Sequence[str]) -> bool:
        for name in names:
            probe = name.strip().lower()
            if probe in flags:
                return True
        return False

    def _detect_cuda_with_torch(self) -> dict[str, Any]:
        try:  # pragma: no cover - optional dependency boundary
            import torch
        except Exception:
            return {}

        try:
            if not bool(torch.cuda.is_available()):
                return {"cuda_available": False}

            device_count = int(torch.cuda.device_count())
            model = str(torch.cuda.get_device_name(0)) if device_count > 0 else ""
            capability = None
            if device_count > 0:
                major, minor = torch.cuda.get_device_capability(0)
                capability = f"{major}.{minor}"

            return {
                "cuda_available": True,
                "model": model,
                "cuda_device_count": device_count,
                "cuda_capability": capability,
                "cuda_version": getattr(torch.version, "cuda", None),
                "driver_version": None,
            }
        except Exception as exc:
            logger.debug("torch CUDA detection failed: {}", exc)
            return {}

    def _detect_cuda_with_nvidia_smi(self) -> dict[str, Any]:
        output = self._run_command(
            [
                "nvidia-smi",
                "--query-gpu=name,driver_version,compute_cap",
                "--format=csv,noheader",
            ]
        )
        if output is None:
            return {}

        lines = [item.strip() for item in output.splitlines() if item.strip()]
        if not lines:
            return {}

        first = lines[0]
        parts = [item.strip() for item in first.split(",")]
        model = parts[0] if len(parts) >= 1 else ""
        driver = parts[1] if len(parts) >= 2 else None
        capability = parts[2] if len(parts) >= 3 else None

        return {
            "cuda_available": True,
            "model": model,
            "cuda_device_count": len(lines),
            "cuda_capability": capability,
            "driver_version": driver,
            "cuda_version": None,
        }

    def _detect_opencl_platforms(self) -> list[str]:
        try:  # pragma: no cover - optional dependency boundary
            import pyopencl as cl

            platforms = cl.get_platforms()
            names = []
            for item in platforms:
                name = str(getattr(item, "name", "")).strip()
                if name:
                    names.append(name)
            if names:
                return names
        except Exception:
            pass

        output = self._run_command(["clinfo", "-l"])
        if output is None:
            return []

        names: list[str] = []
        for line in output.splitlines():
            stripped = line.strip()
            if "platform name" in stripped.lower() and ":" in stripped:
                _, value = stripped.split(":", 1)
                name = value.strip()
                if name:
                    names.append(name)

        return names

    def _detect_gpu_models_from_pci(self) -> list[str]:
        output = self._run_command(["lspci", "-nn"])
        if output is None:
            return []

        models: list[str] = []
        for line in output.splitlines():
            lowered = line.lower()
            if any(marker in lowered for marker in self._GPU_MARKERS):
                models.append(line.strip())

        return models

    def _detect_fpga_pcie_devices(self) -> list[str]:
        output = self._run_command(["lspci", "-nn"])
        if output is None:
            return []

        devices: list[str] = []
        for line in output.splitlines():
            lowered = line.lower()
            if any(marker in lowered for marker in self._FPGA_MARKERS):
                devices.append(line.strip())
        return devices

    def _discover_bitstreams(self, roots: Sequence[Path]) -> list[str]:
        discovered: list[str] = []

        for root in roots:
            if not root.exists() or not root.is_dir():
                continue

            discovered.extend(self._walk_bitstream_dir(root, max_depth=3, max_files=256))

        # Preserve deterministic order and uniqueness.
        return sorted(dict.fromkeys(discovered))

    def _walk_bitstream_dir(self, root: Path, *, max_depth: int, max_files: int) -> list[str]:
        results: list[str] = []

        for current_root, dirs, files in os.walk(root):
            current_path = Path(current_root)
            try:
                depth = len(current_path.relative_to(root).parts)
            except Exception:
                depth = 0

            if depth >= max_depth:
                dirs[:] = []

            for file_name in files:
                if len(results) >= max_files:
                    return results

                suffix = Path(file_name).suffix.lower()
                if suffix not in self._BITSTREAM_EXTENSIONS:
                    continue

                file_path = current_path / file_name
                results.append(str(file_path))

        return results

    def _detect_yubikey_hsm_devices(self) -> list[HSMDevice]:
        devices: list[HSMDevice] = []

        serial_output = self._run_command(["ykman", "list", "--serials"])
        if serial_output is not None:
            for line in serial_output.splitlines():
                serial = line.strip()
                if not serial:
                    continue
                devices.append(
                    HSMDevice(
                        name="YubiKey HSM",
                        kind="yubikey-hsm",
                        interface="usb",
                        serial=serial,
                        available=True,
                    )
                )
            if devices:
                return devices

        list_output = self._run_command(["lsusb"])
        if list_output is None:
            return devices

        for line in list_output.splitlines():
            if "yubico" not in line.lower():
                continue
            devices.append(
                HSMDevice(
                    name="YubiKey HSM",
                    kind="yubikey-hsm",
                    interface="usb",
                    serial=None,
                    available=True,
                    metadata={"lsusb": line.strip()},
                )
            )

        return devices

    def _detect_pkcs11_modules(self) -> list[HSMDevice]:
        search_roots = (
            Path("/usr/lib"),
            Path("/usr/lib64"),
            Path("/usr/local/lib"),
            Path("/usr/lib/x86_64-linux-gnu"),
        )

        found: list[HSMDevice] = []
        limit = 24

        for root in search_roots:
            if not root.exists() or not root.is_dir():
                continue

            pattern_results = sorted(root.rglob("*pkcs11*.so*"))
            for item in pattern_results:
                if len(found) >= limit:
                    return found
                if not item.is_file():
                    continue
                found.append(
                    HSMDevice(
                        name=item.name,
                        kind="pkcs11-module",
                        interface="library",
                        endpoint=str(item),
                        available=True,
                    )
                )

        return found

    def _detect_network_hsm_devices(self) -> list[HSMDevice]:
        devices: list[HSMDevice] = []

        for endpoint in self._hsm_endpoints:
            host, port = self._parse_endpoint(endpoint)
            available = self._check_tcp_endpoint(host, port, timeout_seconds=0.6)
            devices.append(
                HSMDevice(
                    name="Network HSM",
                    kind="network-hsm",
                    interface="network",
                    endpoint=f"{host}:{port}",
                    available=available,
                    metadata={"host": host, "port": port},
                )
            )

        return devices

    @staticmethod
    def _parse_hsm_endpoints_from_env() -> list[str]:
        merged = ",".join(
            filter(
                None,
                [
                    os.getenv("KEYCRYPT_HSM_ENDPOINTS", ""),
                    os.getenv("HSM_ENDPOINTS", ""),
                ],
            )
        )
        endpoints = [item.strip() for item in merged.split(",") if item.strip()]
        return endpoints

    @staticmethod
    def _parse_endpoint(value: str) -> tuple[str, int]:
        raw = value.strip()
        if ":" not in raw:
            return raw, 1792

        host, port_text = raw.rsplit(":", 1)
        host = host.strip()
        try:
            port = int(port_text.strip())
        except ValueError:
            port = 1792

        if port <= 0 or port > 65535:
            port = 1792

        return host, port

    @staticmethod
    def _check_tcp_endpoint(host: str, port: int, *, timeout_seconds: float) -> bool:
        try:
            with socket.create_connection((host, port), timeout=timeout_seconds):
                return True
        except Exception:
            return False

    def _benchmark_hashlib_sha256(self) -> float:
        data = os.urandom(256 * 1024)

        def work() -> None:
            hashlib.sha256(data).digest()

        return self._benchmark_throughput(work, payload_size_bytes=len(data))

    def _benchmark_python_hash_fallback(self) -> float:
        data = os.urandom(64 * 1024)

        def work() -> None:
            acc = 0
            for byte in data:
                acc = ((acc << 5) - acc + byte) & 0xFFFFFFFF
            _ = acc

        return self._benchmark_throughput(work, payload_size_bytes=len(data))

    def _benchmark_simd_vectorization(self) -> tuple[float, float] | None:
        if _np is None:
            return None

        data = _np.frombuffer(os.urandom(256 * 1024), dtype=_np.uint8)
        output = _np.empty_like(data)

        def vectorized() -> None:
            _np.bitwise_xor(data, 0x5A, out=output)

        scalar_data = bytes(data.tolist())

        def scalar() -> None:
            _ = bytes(item ^ 0x5A for item in scalar_data)

        vectorized_mb_s = self._benchmark_throughput(vectorized, payload_size_bytes=data.nbytes)
        scalar_mb_s = self._benchmark_throughput(scalar, payload_size_bytes=len(scalar_data))
        return vectorized_mb_s, scalar_mb_s

    def _benchmark_gpu_speedup(self) -> tuple[float, float] | None:
        try:  # pragma: no cover - optional dependency boundary
            import torch
        except Exception:
            return None

        try:
            if not bool(torch.cuda.is_available()):
                return None

            size = 384
            cpu_a = torch.rand((size, size), dtype=torch.float32)
            cpu_b = torch.rand((size, size), dtype=torch.float32)

            cpu_start = time.perf_counter()
            _ = cpu_a @ cpu_b
            cpu_ms = (time.perf_counter() - cpu_start) * 1000.0

            gpu_a = cpu_a.to("cuda")
            gpu_b = cpu_b.to("cuda")

            torch.cuda.synchronize()
            gpu_start = time.perf_counter()
            _ = gpu_a @ gpu_b
            torch.cuda.synchronize()
            gpu_ms = (time.perf_counter() - gpu_start) * 1000.0

            return cpu_ms, gpu_ms
        except Exception as exc:
            logger.debug("CUDA benchmark failed: {}", exc)
            return None

    def _benchmark_throughput(self, operation: Any, *, payload_size_bytes: int) -> float:
        start = time.perf_counter()
        iterations = 0

        while time.perf_counter() - start < self._benchmark_duration_seconds:
            operation()
            iterations += 1

        elapsed = max(time.perf_counter() - start, 1e-9)
        total_bytes = iterations * payload_size_bytes
        return (total_bytes / (1024.0 * 1024.0)) / elapsed

    def _run_command(self, command: Sequence[str]) -> str | None:
        try:
            completed = subprocess.run(
                list(command),
                check=False,
                capture_output=True,
                text=True,
                timeout=self._command_timeout_seconds,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None
        except Exception as exc:
            logger.debug("command execution failed {}: {}", json.dumps(list(command)), exc)
            return None

        if completed.returncode != 0:
            return None

        output = completed.stdout.strip()
        if not output:
            return None
        return output

    @staticmethod
    def _guess_vendor(text: str) -> str:
        lowered = str(text).lower()
        if not lowered:
            return ""
        if "nvidia" in lowered:
            return "NVIDIA"
        if "amd" in lowered or "advanced micro devices" in lowered:
            return "AMD"
        if "intel" in lowered:
            return "Intel"
        if "xilinx" in lowered:
            return "Xilinx"
        if "altera" in lowered:
            return "Altera"
        if "yubico" in lowered or "yubikey" in lowered:
            return "Yubico"
        return ""

    @staticmethod
    def _none_if_empty(value: Any) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        return text if text else None


__all__ = [
    "CPUFeatures",
    "FPGAInfo",
    "GPUInfo",
    "HSMDevice",
    "HardwareCapabilities",
    "HardwareDetector",
    "PerformanceBenchmark",
]
