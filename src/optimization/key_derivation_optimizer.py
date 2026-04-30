"""Adaptive key derivation optimization utilities.

This module extends existing KDF helpers with benchmark-driven PBKDF2 tuning,
derived-key caching, batch derivation, and optional hardware acceleration
awareness.
"""

from __future__ import annotations

import hashlib
import json
import hmac
import os
import platform
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from src.classical.kdf import derive_key


DEFAULT_TARGET_PBKDF2_ITERATIONS = 600_000
MIN_PBKDF2_ITERATIONS = 1
MAX_PBKDF2_ITERATIONS = 5_000_000
PBKDF2_SALT = b"keycrypt:key-derivation-optimizer"
PBKDF2_DERIVED_LENGTH = 32


@dataclass(frozen=True)
class KDFBenchmarkResult:
    """Benchmark summary used to tune PBKDF2 iteration counts."""

    hardware_id: str
    target_time_ms: int
    benchmark_iterations: int
    elapsed_ms: float
    estimated_iterations: int
    measured_iterations_per_second: float


@dataclass
class DerivedKeyCacheEntry:
    """Cached derived key material with TTL metadata."""

    master_key_id: str
    context: str
    derived_key: bytes
    expires_at: float
    created_at: float = field(default_factory=time.time)
    generation_count: int = 1

    def is_expired(self, now: float | None = None) -> bool:
        current_time = time.time() if now is None else float(now)
        return current_time >= self.expires_at


class KeyDerivationOptimizer:
    """Optimize PBKDF2 usage while preserving deterministic derivation results."""

    def __init__(
        self,
        *,
        cache_file: str | Path | None = ".keycrypt/kdf_optimizer_cache.json",
        benchmark_iterations: int = 50_000,
    ) -> None:
        if benchmark_iterations <= 0:
            raise ValueError("benchmark_iterations must be positive")

        self._cache_file = Path(cache_file).expanduser().resolve() if cache_file else None
        self._benchmark_iterations = int(benchmark_iterations)
        self._benchmark_cache: dict[str, KDFBenchmarkResult] = {}
        self._derived_key_cache: dict[tuple[str, str], DerivedKeyCacheEntry] = {}

        self._load_cache_from_disk()

    def optimize_pbkdf2_iterations(self, target_time_ms: int) -> int:
        """Estimate PBKDF2 iterations needed to approximate the target runtime."""
        if target_time_ms <= 0:
            raise ValueError("target_time_ms must be positive")

        hardware_id = self._hardware_fingerprint()
        benchmark = self._benchmark_cache.get(hardware_id)

        if benchmark is None or benchmark.target_time_ms != int(target_time_ms):
            benchmark = self._benchmark_system(target_time_ms=int(target_time_ms))
            self._benchmark_cache[hardware_id] = benchmark
            self._save_cache_to_disk()

        return self._clamp_iterations(benchmark.estimated_iterations)

    def cache_derived_keys(self, master_key_id: str, context: str, derived_key: bytes, ttl: int) -> None:
        """Cache a derived key result to avoid repeated recomputation."""
        if not isinstance(master_key_id, str) or not master_key_id.strip():
            raise ValueError("master_key_id must be non-empty")
        if not isinstance(context, str) or not context.strip():
            raise ValueError("context must be non-empty")
        self._require_bytes("derived_key", derived_key)
        if ttl <= 0:
            raise ValueError("ttl must be positive")

        entry = DerivedKeyCacheEntry(
            master_key_id=master_key_id.strip(),
            context=context,
            derived_key=bytes(derived_key),
            expires_at=time.time() + float(ttl),
        )
        self._derived_key_cache[(entry.master_key_id, entry.context)] = entry
        self._save_cache_to_disk()

    def batch_key_derivation(self, master_key: bytes, contexts: Sequence[str]) -> list[bytes]:
        """Derive multiple keys in one operation using a shared input-key setup."""
        self._require_bytes("master_key", master_key)
        if not master_key:
            raise ValueError("master_key must not be empty")
        if isinstance(contexts, (str, bytes)) or not isinstance(contexts, Sequence):
            raise TypeError("contexts must be a sequence of strings")

        results: list[bytes] = []
        for index, context in enumerate(contexts):
            if not isinstance(context, str):
                raise TypeError("contexts must contain strings")

            cache_key = (self._master_key_id(master_key), context)
            cached = self._derived_key_cache.get(cache_key)
            if cached is not None and not cached.is_expired():
                results.append(cached.derived_key)
                continue

            derived = derive_key(
                input_key_material=master_key,
                salt=self._context_salt(context, index),
                info=self._context_info(context, index),
                length=PBKDF2_DERIVED_LENGTH,
            )
            results.append(derived)
            self.cache_derived_keys(cache_key[0], context, derived, ttl=3600)

        return results

    def use_hardware_kdf_if_available(self) -> bool:
        """Detect Intel Key Locker or other hardware KDF acceleration support."""
        env_override = os.getenv("KEYCRYPT_USE_HARDWARE_KDF")
        if env_override is not None:
            return env_override.strip().lower() in {"1", "true", "yes", "on"}

        flags = self._cpu_flags()
        hardware_signals = {
            "keylocker",
            "intel_key_locker",
            "kl",
            "wde",
            "vkl",
            "vaes",
        }
        return bool(hardware_signals & flags)

    def verify_key_derivation_result(
        self,
        master_key: bytes,
        context: str,
        derived_key: bytes,
        *,
        salt: bytes | None = None,
        length: int = PBKDF2_DERIVED_LENGTH,
    ) -> bool:
        """Verify deterministic output for the same input parameters."""
        self._require_bytes("master_key", master_key)
        self._require_bytes("derived_key", derived_key)
        if not isinstance(context, str):
            raise TypeError("context must be str")

        effective_salt = PBKDF2_SALT if salt is None else salt
        self._require_bytes("salt", effective_salt)
        if length <= 0:
            raise ValueError("length must be positive")

        expected = self._derive_deterministic_key(
            master_key=master_key,
            context=context,
            salt=effective_salt,
            length=length,
        )
        return hmac.compare_digest(expected, derived_key)

    def derive_verified_key(
        self,
        master_key: bytes,
        context: str,
        *,
        salt: bytes | None = None,
        length: int = PBKDF2_DERIVED_LENGTH,
    ) -> bytes:
        """Derive a key and verify the result against the deterministic path."""
        derived = self._derive_deterministic_key(
            master_key=master_key,
            context=context,
            salt=PBKDF2_SALT if salt is None else salt,
            length=length,
        )
        if not self.verify_key_derivation_result(master_key, context, derived, salt=salt, length=length):
            raise RuntimeError("key derivation verification failed")
        return derived

    def _benchmark_system(self, *, target_time_ms: int) -> KDFBenchmarkResult:
        master_key = os.urandom(32)
        start = time.perf_counter()
        _ = hashlib.pbkdf2_hmac(
            "sha256",
            master_key,
            PBKDF2_SALT,
            self._benchmark_iterations,
            dklen=PBKDF2_DERIVED_LENGTH,
        )
        elapsed_ms = max((time.perf_counter() - start) * 1000.0, 0.001)
        iterations_per_second = self._benchmark_iterations / (elapsed_ms / 1000.0)
        estimated_iterations = int((target_time_ms / elapsed_ms) * self._benchmark_iterations)

        return KDFBenchmarkResult(
            hardware_id=self._hardware_fingerprint(),
            target_time_ms=target_time_ms,
            benchmark_iterations=self._benchmark_iterations,
            elapsed_ms=elapsed_ms,
            estimated_iterations=estimated_iterations,
            measured_iterations_per_second=iterations_per_second,
        )

    def _derive_deterministic_key(
        self,
        *,
        master_key: bytes,
        context: str,
        salt: bytes,
        length: int,
    ) -> bytes:
        context_bytes = context.encode("utf-8")
        return derive_key(
            input_key_material=master_key,
            salt=salt + context_bytes,
            info=b"keycrypt:key-derivation-optimizer:" + context_bytes,
            length=length,
        )

    def _load_cache_from_disk(self) -> None:
        if self._cache_file is None or not self._cache_file.is_file():
            return

        try:
            raw = json.loads(self._cache_file.read_text(encoding="utf-8"))
        except Exception:
            return

        if not isinstance(raw, dict):
            return

        benchmark_section = raw.get("benchmarks", {})
        if isinstance(benchmark_section, dict):
            for hardware_id, payload in benchmark_section.items():
                benchmark = self._deserialize_benchmark(hardware_id, payload)
                if benchmark is not None:
                    self._benchmark_cache[hardware_id] = benchmark

        cache_section = raw.get("derived_keys", {})
        if isinstance(cache_section, dict):
            for cache_key, payload in cache_section.items():
                entry = self._deserialize_derived_key(payload)
                if entry is not None:
                    self._derived_key_cache[(entry.master_key_id, entry.context)] = entry

    def _save_cache_to_disk(self) -> None:
        if self._cache_file is None:
            return

        serialised = {
            "benchmarks": {
                hardware_id: self._serialize_benchmark(benchmark)
                for hardware_id, benchmark in self._benchmark_cache.items()
            },
            "derived_keys": {
                f"{entry.master_key_id}:{entry.context}": self._serialize_derived_key(entry)
                for entry in self._derived_key_cache.values()
            },
        }

        self._cache_file.parent.mkdir(parents=True, exist_ok=True)
        self._cache_file.write_text(json.dumps(serialised, indent=2, sort_keys=True), encoding="utf-8")

    @staticmethod
    def _serialize_benchmark(benchmark: KDFBenchmarkResult) -> dict[str, Any]:
        return {
            "hardware_id": benchmark.hardware_id,
            "target_time_ms": benchmark.target_time_ms,
            "benchmark_iterations": benchmark.benchmark_iterations,
            "elapsed_ms": benchmark.elapsed_ms,
            "estimated_iterations": benchmark.estimated_iterations,
            "measured_iterations_per_second": benchmark.measured_iterations_per_second,
        }

    @staticmethod
    def _deserialize_benchmark(hardware_id: str, payload: Any) -> KDFBenchmarkResult | None:
        if not isinstance(payload, Mapping):
            return None

        try:
            return KDFBenchmarkResult(
                hardware_id=str(payload.get("hardware_id", hardware_id)),
                target_time_ms=int(payload["target_time_ms"]),
                benchmark_iterations=int(payload["benchmark_iterations"]),
                elapsed_ms=float(payload["elapsed_ms"]),
                estimated_iterations=int(payload["estimated_iterations"]),
                measured_iterations_per_second=float(payload["measured_iterations_per_second"]),
            )
        except Exception:
            return None

    @staticmethod
    def _serialize_derived_key(entry: DerivedKeyCacheEntry) -> dict[str, Any]:
        return {
            "master_key_id": entry.master_key_id,
            "context": entry.context,
            "derived_key_b64": entry.derived_key.hex(),
            "expires_at": entry.expires_at,
            "created_at": entry.created_at,
            "generation_count": entry.generation_count,
        }

    @staticmethod
    def _deserialize_derived_key(payload: Any) -> DerivedKeyCacheEntry | None:
        if not isinstance(payload, Mapping):
            return None

        try:
            return DerivedKeyCacheEntry(
                master_key_id=str(payload["master_key_id"]),
                context=str(payload["context"]),
                derived_key=bytes.fromhex(str(payload["derived_key_b64"])),
                expires_at=float(payload["expires_at"]),
                created_at=float(payload.get("created_at", time.time())),
                generation_count=max(1, int(payload.get("generation_count", 1))),
            )
        except Exception:
            return None

    def _hardware_fingerprint(self) -> str:
        cpu_info = platform.processor() or platform.machine() or "unknown"
        flags = ",".join(sorted(self._cpu_flags()))
        return hashlib.sha256(f"{cpu_info}|{flags}".encode("utf-8")).hexdigest()

    def _cpu_flags(self) -> set[str]:
        flags: set[str] = set()

        try:
            import cpuinfo  # type: ignore

            info = cpuinfo.get_cpu_info() or {}
            raw_flags = info.get("flags", [])
            if isinstance(raw_flags, Sequence):
                for item in raw_flags:
                    if isinstance(item, str):
                        flags.add(item.lower())
        except Exception:
            pass

        try:
            with open("/proc/cpuinfo", encoding="utf-8") as cpuinfo_file:
                for line in cpuinfo_file:
                    if line.lower().startswith("flags"):
                        _, raw_values = line.split(":", 1)
                        for item in raw_values.strip().split():
                            flags.add(item.lower())
                        break
        except Exception:
            pass

        return flags

    @staticmethod
    def _context_salt(context: str, index: int) -> bytes:
        return hashlib.sha256(f"{context}:{index}:salt".encode("utf-8")).digest()[:16]

    @staticmethod
    def _context_info(context: str, index: int) -> bytes:
        return f"keycrypt:kdf:batch:{index}:{context}".encode("utf-8")

    @staticmethod
    def _master_key_id(master_key: bytes) -> str:
        return hashlib.sha256(master_key).hexdigest()

    @staticmethod
    def _require_bytes(name: str, value: object) -> None:
        if not isinstance(value, bytes):
            raise TypeError(f"{name} must be bytes")

    @staticmethod
    def _clamp_iterations(value: int) -> int:
        return max(MIN_PBKDF2_ITERATIONS, min(MAX_PBKDF2_ITERATIONS, int(value)))


__all__ = [
    "DerivedKeyCacheEntry",
    "KDFBenchmarkResult",
    "KeyDerivationOptimizer",
]
