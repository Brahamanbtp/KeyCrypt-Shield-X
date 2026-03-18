"""Timing attack resistance tests for cryptographic operations."""

from __future__ import annotations

import hmac
import math
import statistics
import sys
import timeit
from dataclasses import dataclass
from pathlib import Path
from statistics import NormalDist
from typing import Callable

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import src.classical.aes_gcm as aes_gcm_module
from src.classical.aes_gcm import AESGCM


TOTAL_RUNS = 10_000
BATCHES = 20
RUNS_PER_BATCH = TOTAL_RUNS // BATCHES
RELATIVE_DIFF_THRESHOLD = 0.05
P_VALUE_THRESHOLD = 0.01


@dataclass(frozen=True)
class TimingResult:
    mean_ns: float
    stdev_ns: float
    cov: float
    samples_ns: list[float]


@dataclass(frozen=True)
class TimingComparison:
    a: TimingResult
    b: TimingResult
    t_stat: float
    p_value: float
    relative_diff: float


def _measure_ns(operation: Callable[[], object]) -> TimingResult:
    """Collect batched per-call nanosecond timings using timeit."""
    timer = timeit.Timer(operation)

    # Warm up caches and interpreter paths before measurement.
    timer.timeit(number=200)

    batch_times = timer.repeat(repeat=BATCHES, number=RUNS_PER_BATCH)
    per_call_ns = [(seconds / RUNS_PER_BATCH) * 1e9 for seconds in batch_times]
    filtered = _iqr_filter(per_call_ns)

    mean_ns = statistics.mean(filtered)
    stdev_ns = statistics.stdev(filtered) if len(filtered) > 1 else 0.0
    cov = 0.0 if mean_ns == 0 else stdev_ns / mean_ns

    return TimingResult(mean_ns=mean_ns, stdev_ns=stdev_ns, cov=cov, samples_ns=filtered)


def _iqr_filter(values: list[float]) -> list[float]:
    """Filter strong outliers introduced by scheduler jitter."""
    if len(values) < 6:
        return values

    ordered = sorted(values)
    q1 = ordered[len(ordered) // 4]
    q3 = ordered[(len(ordered) * 3) // 4]
    iqr = q3 - q1

    lower = q1 - (1.5 * iqr)
    upper = q3 + (1.5 * iqr)
    filtered = [v for v in values if lower <= v <= upper]
    return filtered if len(filtered) >= 6 else values


def _welch_t_test_p_value(a: list[float], b: list[float]) -> tuple[float, float]:
    """Return Welch t-statistic and two-sided p-value (normal approximation)."""
    if len(a) < 2 or len(b) < 2:
        return 0.0, 1.0

    mean_a = statistics.mean(a)
    mean_b = statistics.mean(b)
    var_a = statistics.variance(a)
    var_b = statistics.variance(b)

    n_a = len(a)
    n_b = len(b)
    denom = math.sqrt((var_a / n_a) + (var_b / n_b))
    if denom == 0:
        return 0.0, 1.0

    t_stat = (mean_a - mean_b) / denom

    # With 40+ samples and aggregated timings, normal approximation is stable.
    p_two_sided = 2.0 * (1.0 - NormalDist().cdf(abs(t_stat)))
    return t_stat, max(0.0, min(1.0, p_two_sided))


def _compare_timing(op_a: Callable[[], object], op_b: Callable[[], object]) -> TimingComparison:
    result_a = _measure_ns(op_a)
    result_b = _measure_ns(op_b)

    t_stat, p_value = _welch_t_test_p_value(result_a.samples_ns, result_b.samples_ns)
    relative_diff = abs(result_a.mean_ns - result_b.mean_ns) / max(result_a.mean_ns, result_b.mean_ns)

    return TimingComparison(
        a=result_a,
        b=result_b,
        t_stat=t_stat,
        p_value=p_value,
        relative_diff=relative_diff,
    )


def _assert_no_timing_leak(comparison: TimingComparison, label: str) -> None:
    """Assert timing distributions have negligible variance and no strong separation."""
    assert comparison.relative_diff < RELATIVE_DIFF_THRESHOLD, (
        f"{label}: timing mean difference indicates possible leak "
        f"(diff={comparison.relative_diff:.4f}, threshold={RELATIVE_DIFF_THRESHOLD:.4f}, "
        f"mean_a_ns={comparison.a.mean_ns:.2f}, mean_b_ns={comparison.b.mean_ns:.2f})"
    )

    if comparison.p_value < P_VALUE_THRESHOLD and comparison.relative_diff >= RELATIVE_DIFF_THRESHOLD:
        pytest.fail(
            f"{label}: statistically significant timing leak detected "
            f"(p={comparison.p_value:.6f}, t={comparison.t_stat:.4f}, diff={comparison.relative_diff:.4f})"
        )


@pytest.fixture
def deterministic_nonce(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stabilize nonce generation cost for timing analysis."""

    def _fixed_urandom(length: int) -> bytes:
        return b"\xA5" * length

    monkeypatch.setattr(aes_gcm_module.os, "urandom", _fixed_urandom)


@pytest.mark.security
def test_encryption_constant_time_for_different_plaintext_values_same_size(deterministic_nonce: None) -> None:
    """Encryption time should not depend on plaintext value for equal-sized inputs."""
    key = b"\x11" * 32
    cipher = AESGCM(key)

    plaintext_a = b"\x00" * 4096
    plaintext_b = b"\xFF" * 4096
    aad = b"timing-test-aad"

    comparison = _compare_timing(
        lambda: cipher.encrypt(plaintext_a, aad),
        lambda: cipher.encrypt(plaintext_b, aad),
    )

    _assert_no_timing_leak(comparison, "plaintext-value")


@pytest.mark.security
def test_encryption_constant_time_for_different_keys(deterministic_nonce: None) -> None:
    """Encryption time should be stable across different key values."""
    cipher_a = AESGCM(b"\x01" * 32)
    cipher_b = AESGCM(b"\x02" * 32)

    plaintext = b"A" * 4096
    aad = b"timing-test-aad"

    comparison = _compare_timing(
        lambda: cipher_a.encrypt(plaintext, aad),
        lambda: cipher_b.encrypt(plaintext, aad),
    )

    _assert_no_timing_leak(comparison, "key-value")


@pytest.mark.security
def test_decryption_constant_time_valid_vs_invalid_authentication_tag() -> None:
    """Decryption timing should not leak tag validity information."""
    key = AESGCM.generate_key()
    cipher = AESGCM(key)

    plaintext = b"confidential payload" * 32
    aad = b"auth-test"
    ciphertext, nonce, tag = cipher.encrypt(plaintext, aad)

    bad_tag = bytearray(tag)
    bad_tag[0] ^= 0x01
    invalid_tag = bytes(bad_tag)

    def decrypt_valid() -> None:
        try:
            _ = cipher.decrypt(ciphertext, aad, nonce, tag)
            raise ValueError("synthetic balanced path")
        except ValueError:
            return

    def decrypt_invalid() -> None:
        try:
            _ = cipher.decrypt(ciphertext, aad, nonce, invalid_tag)
        except ValueError:
            return
        raise AssertionError("invalid tag unexpectedly decrypted")

    comparison = _compare_timing(decrypt_valid, decrypt_invalid)

    _assert_no_timing_leak(comparison, "valid-vs-invalid-tag")


@pytest.mark.security
def test_constant_time_comparisons() -> None:
    """Constant-time compare should not vary materially by mismatch position."""
    target = b"A" * 4096
    same = b"A" * 4096
    first_diff = b"B" + (b"A" * 4095)
    last_diff = (b"A" * 4095) + b"B"

    comparison_equal_vs_first = _compare_timing(
        lambda: hmac.compare_digest(target, same),
        lambda: hmac.compare_digest(target, first_diff),
    )
    _assert_no_timing_leak(comparison_equal_vs_first, "compare-digest-eq-vs-first")

    comparison_first_vs_last = _compare_timing(
        lambda: hmac.compare_digest(target, first_diff),
        lambda: hmac.compare_digest(target, last_diff),
    )
    _assert_no_timing_leak(comparison_first_vs_last, "compare-digest-first-vs-last")
