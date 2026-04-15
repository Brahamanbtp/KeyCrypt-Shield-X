"""Latency benchmark tests for symmetric crypto, KDF, and REST encryption APIs.

These benchmarks are intentionally opt-in because they are expensive.
Set KEYCRYPT_RUN_LATENCY_BENCHMARKS=1 to enable this module.
"""

from __future__ import annotations

import importlib
import math
import os
import sys
import time
from pathlib import Path
from typing import Any, Callable

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from src.classical.aes_gcm import AESGCM
from src.classical.kdf import stretch_password
from src.core.key_manager import KeyManager


TEN_KB = 10 * 1024
PBKDF2_ITERATIONS = 600_000

ENCRYPTION_P99_TARGET_MS = 10.0
KEY_DERIVATION_TARGET_MS = 500.0
API_P95_TARGET_MS = 100.0


def _env_enabled(name: str) -> bool:
    value = os.getenv(name, "")
    return value.strip().lower() in {"1", "true", "yes", "on"}


@pytest.fixture(autouse=True)
def _require_latency_opt_in() -> None:
    if not _env_enabled("KEYCRYPT_RUN_LATENCY_BENCHMARKS"):
        pytest.skip("Set KEYCRYPT_RUN_LATENCY_BENCHMARKS=1 to run latency benchmarks")


def _measure_latency_ms(operation: Callable[[], Any]) -> float:
    started = time.perf_counter()
    operation()
    return (time.perf_counter() - started) * 1000.0


def _collect_latency_samples_ms(operation: Callable[[], Any], sample_count: int) -> list[float]:
    if sample_count <= 0:
        raise ValueError("sample_count must be > 0")
    return [_measure_latency_ms(operation) for _ in range(sample_count)]


def _percentile_ms(samples_ms: list[float], percentile: int) -> float:
    if not samples_ms:
        raise ValueError("samples_ms must not be empty")
    if percentile <= 0 or percentile > 100:
        raise ValueError("percentile must be in range [1, 100]")

    ordered = sorted(samples_ms)
    rank = int(math.ceil((percentile / 100.0) * len(ordered)))
    index = min(max(rank - 1, 0), len(ordered) - 1)
    return ordered[index]


def _latency_percentiles(samples_ms: list[float]) -> tuple[float, float, float]:
    return (
        _percentile_ms(samples_ms, 50),
        _percentile_ms(samples_ms, 95),
        _percentile_ms(samples_ms, 99),
    )


def benchmark_encryption_latency_percentiles(
    benchmark: Any,
    record_property: pytest.RecordProperty,
) -> None:
    """Measure p50/p95/p99 encryption latency for a 10 KB payload."""
    cipher = AESGCM(AESGCM.generate_key())
    payload = b"E" * TEN_KB
    associated_data = b"latency-benchmark-encryption"

    def _encrypt_once() -> None:
        cipher.encrypt(payload, associated_data)

    cold_start_ms = _measure_latency_ms(_encrypt_once)
    warm_samples_ms = benchmark.pedantic(
        lambda: _collect_latency_samples_ms(_encrypt_once, sample_count=240),
        rounds=1,
        iterations=1,
    )
    p50_ms, p95_ms, p99_ms = _latency_percentiles(warm_samples_ms)

    benchmark.extra_info["workload"] = "10kb-encrypt"
    benchmark.extra_info["cold_start_ms"] = round(cold_start_ms, 4)
    benchmark.extra_info["warm_p50_ms"] = round(p50_ms, 4)
    benchmark.extra_info["warm_p95_ms"] = round(p95_ms, 4)
    benchmark.extra_info["warm_p99_ms"] = round(p99_ms, 4)
    benchmark.extra_info["cold_to_warm_p50_ratio"] = round(cold_start_ms / max(p50_ms, 1e-9), 4)
    benchmark.extra_info["target_p99_ms"] = ENCRYPTION_P99_TARGET_MS

    record_property("encryption_latency_cold_start_ms", round(cold_start_ms, 4))
    record_property("encryption_latency_p50_ms", round(p50_ms, 4))
    record_property("encryption_latency_p95_ms", round(p95_ms, 4))
    record_property("encryption_latency_p99_ms", round(p99_ms, 4))

    assert p99_ms < ENCRYPTION_P99_TARGET_MS


def benchmark_key_derivation_latency(
    benchmark: Any,
    record_property: pytest.RecordProperty,
) -> None:
    """Measure PBKDF2 (600k iterations) latency and validate the target."""
    password = "latency-benchmark-password"
    salt = b"0123456789abcdef"

    def _derive_once() -> None:
        stretch_password(
            password,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
            length=32,
            info=b"latency:kdf:pbkdf2",
        )

    cold_start_ms = _measure_latency_ms(_derive_once)
    warm_samples_ms = benchmark.pedantic(
        lambda: _collect_latency_samples_ms(_derive_once, sample_count=6),
        rounds=1,
        iterations=1,
    )
    p50_ms, p95_ms, p99_ms = _latency_percentiles(warm_samples_ms)

    benchmark.extra_info["workload"] = "pbkdf2-600k"
    benchmark.extra_info["cold_start_ms"] = round(cold_start_ms, 4)
    benchmark.extra_info["warm_p50_ms"] = round(p50_ms, 4)
    benchmark.extra_info["warm_p95_ms"] = round(p95_ms, 4)
    benchmark.extra_info["warm_p99_ms"] = round(p99_ms, 4)
    benchmark.extra_info["cold_to_warm_p50_ratio"] = round(cold_start_ms / max(p50_ms, 1e-9), 4)
    benchmark.extra_info["target_ms"] = KEY_DERIVATION_TARGET_MS
    benchmark.extra_info["iterations"] = PBKDF2_ITERATIONS

    record_property("kdf_latency_cold_start_ms", round(cold_start_ms, 4))
    record_property("kdf_latency_p50_ms", round(p50_ms, 4))
    record_property("kdf_latency_p95_ms", round(p95_ms, 4))
    record_property("kdf_latency_p99_ms", round(p99_ms, 4))

    assert p95_ms < KEY_DERIVATION_TARGET_MS


@pytest.fixture
def api_latency_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Any, dict[str, str], str]:
    fastapi_testclient = pytest.importorskip(
        "fastapi.testclient",
        reason="API latency benchmark requires FastAPI test client",
    )
    rest_api = importlib.import_module("src.api.rest_api")
    test_client_cls = getattr(fastapi_testclient, "TestClient")

    isolated_key_manager = KeyManager(db_path=tmp_path / "latency_api_key_manager.db", kek=b"L" * 32)
    monkeypatch.setattr(rest_api, "key_manager", isolated_key_manager)
    monkeypatch.setattr(rest_api, "rate_limiter", rest_api.RateLimiter(requests_per_second=50_000))

    with test_client_cls(rest_api.app) as client:
        token_response = client.post(
            "/auth/token",
            json={
                "username": rest_api.DEFAULT_API_USER,
                "password": rest_api.DEFAULT_API_PASSWORD,
            },
        )
        if token_response.status_code != 200:
            raise RuntimeError(f"failed to obtain API token: status={token_response.status_code}")

        access_token = token_response.json().get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise RuntimeError("API token response missing access_token")

        headers = {"Authorization": f"Bearer {access_token}"}
        key_response = client.post(
            "/keys/generate",
            json={"algorithm": "AES-256-GCM"},
            headers=headers,
        )
        if key_response.status_code != 200:
            raise RuntimeError(f"failed to create key for API latency benchmark: status={key_response.status_code}")

        key_id = key_response.json().get("key_id")
        if not isinstance(key_id, str) or not key_id:
            raise RuntimeError("key generation response missing key_id")

        yield client, headers, key_id


def benchmark_api_request_latency(
    benchmark: Any,
    api_latency_context: tuple[Any, dict[str, str], str],
    record_property: pytest.RecordProperty,
) -> None:
    """Measure REST /encrypt endpoint latency and validate p95 target."""
    client, headers, key_id = api_latency_context
    payload = b"A" * TEN_KB

    def _request_once() -> None:
        response = client.post(
            "/encrypt",
            params={"algorithm": "AES-256-GCM", "key_id": key_id},
            headers=headers,
            files={"file": ("latency-10kb.bin", payload, "application/octet-stream")},
        )
        if response.status_code != 200:
            raise RuntimeError(f"/encrypt returned status {response.status_code}")

    cold_start_ms = _measure_latency_ms(_request_once)
    warm_samples_ms = benchmark.pedantic(
        lambda: _collect_latency_samples_ms(_request_once, sample_count=60),
        rounds=1,
        iterations=1,
    )
    p50_ms, p95_ms, p99_ms = _latency_percentiles(warm_samples_ms)

    benchmark.extra_info["endpoint"] = "POST /encrypt"
    benchmark.extra_info["payload_bytes"] = TEN_KB
    benchmark.extra_info["cold_start_ms"] = round(cold_start_ms, 4)
    benchmark.extra_info["warm_p50_ms"] = round(p50_ms, 4)
    benchmark.extra_info["warm_p95_ms"] = round(p95_ms, 4)
    benchmark.extra_info["warm_p99_ms"] = round(p99_ms, 4)
    benchmark.extra_info["cold_to_warm_p50_ratio"] = round(cold_start_ms / max(p50_ms, 1e-9), 4)
    benchmark.extra_info["target_p95_ms"] = API_P95_TARGET_MS

    record_property("api_encrypt_latency_cold_start_ms", round(cold_start_ms, 4))
    record_property("api_encrypt_latency_p50_ms", round(p50_ms, 4))
    record_property("api_encrypt_latency_p95_ms", round(p95_ms, 4))
    record_property("api_encrypt_latency_p99_ms", round(p99_ms, 4))

    assert p95_ms < API_P95_TARGET_MS


@pytest.mark.benchmark(group="latency")
def test_benchmark_encryption_latency_percentiles(
    benchmark: Any,
    record_property: pytest.RecordProperty,
) -> None:
    benchmark_encryption_latency_percentiles(benchmark, record_property)


@pytest.mark.benchmark(group="latency")
def test_benchmark_key_derivation_latency(
    benchmark: Any,
    record_property: pytest.RecordProperty,
) -> None:
    benchmark_key_derivation_latency(benchmark, record_property)


@pytest.mark.benchmark(group="latency")
def test_benchmark_api_request_latency(
    benchmark: Any,
    api_latency_context: tuple[Any, dict[str, str], str],
    record_property: pytest.RecordProperty,
) -> None:
    benchmark_api_request_latency(benchmark, api_latency_context, record_property)
