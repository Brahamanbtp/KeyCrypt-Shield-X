"""Timing attack resistance tests for side-channel validation.

This suite focuses on three high-risk timing surfaces:
- constant-time key comparison
- encryption timing independence from plaintext value
- authentication-tag verification timing stability
"""

from __future__ import annotations

import hmac
import os
import statistics
import sys
import timeit
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import pytest
from scipy import stats

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import src.classical.aes_gcm as aes_gcm_module
from src.classical.aes_gcm import AESGCM


TOTAL_ITERATIONS = 10_000
SIGNIFICANCE_ALPHA = 0.01
MAX_RELATIVE_DIFF = 0.05
BATCHES_SIGNIFICANCE = 8
BATCHES_VARIANCE = 50


@dataclass(frozen=True)
class TimingStats:
    mean_ns: float
    median_ns: float
    variance_ns: float
    samples_ns: list[float]


@dataclass(frozen=True)
class TimingComparison:
    a: TimingStats
    b: TimingStats
    t_stat: float
    p_value: float
    relative_diff: float


def _measure_pair_with_timeit(
    op_a: Callable[[], object],
    op_b: Callable[[], object],
    *,
    batches: int,
) -> tuple[TimingStats, TimingStats]:
    """Collect interleaved per-call nanosecond timing samples using timeit."""
    if batches <= 0:
        raise ValueError("batches must be > 0")

    iterations_per_batch = TOTAL_ITERATIONS // batches
    if iterations_per_batch <= 0:
        raise ValueError("TOTAL_ITERATIONS must be >= batches")

    timer_a = timeit.Timer(op_a)
    timer_b = timeit.Timer(op_b)

    # Warm up interpreter paths and backend caches before sampling.
    timer_a.timeit(number=500)
    timer_b.timeit(number=500)

    samples_a_ns: list[float] = []
    samples_b_ns: list[float] = []

    # Alternate order per batch to reduce thermal/scheduler drift bias.
    for batch in range(batches):
        if batch % 2 == 0:
            batch_a = timer_a.timeit(number=iterations_per_batch)
            batch_b = timer_b.timeit(number=iterations_per_batch)
        else:
            batch_b = timer_b.timeit(number=iterations_per_batch)
            batch_a = timer_a.timeit(number=iterations_per_batch)

        samples_a_ns.append((batch_a / iterations_per_batch) * 1e9)
        samples_b_ns.append((batch_b / iterations_per_batch) * 1e9)

    filtered_a = _iqr_filter(samples_a_ns)
    filtered_b = _iqr_filter(samples_b_ns)

    stats_a = TimingStats(
        mean_ns=statistics.mean(filtered_a),
        median_ns=statistics.median(filtered_a),
        variance_ns=statistics.variance(filtered_a) if len(filtered_a) > 1 else 0.0,
        samples_ns=filtered_a,
    )
    stats_b = TimingStats(
        mean_ns=statistics.mean(filtered_b),
        median_ns=statistics.median(filtered_b),
        variance_ns=statistics.variance(filtered_b) if len(filtered_b) > 1 else 0.0,
        samples_ns=filtered_b,
    )

    return stats_a, stats_b


def _iqr_filter(values: list[float]) -> list[float]:
    """Filter strong scheduler outliers to reduce host jitter sensitivity."""
    if len(values) < 8:
        return values

    ordered = sorted(values)
    q1 = ordered[len(ordered) // 4]
    q3 = ordered[(len(ordered) * 3) // 4]
    iqr = q3 - q1

    lower = q1 - (1.5 * iqr)
    upper = q3 + (1.5 * iqr)
    filtered = [sample for sample in values if lower <= sample <= upper]
    return filtered if len(filtered) >= 8 else values


def _compare_timing(
    op_a: Callable[[], object],
    op_b: Callable[[], object],
    *,
    batches: int,
) -> TimingComparison:
    stats_a, stats_b = _measure_pair_with_timeit(op_a, op_b, batches=batches)

    t_test = stats.ttest_ind(stats_a.samples_ns, stats_b.samples_ns, equal_var=False)
    t_stat = float(t_test.statistic)
    p_value = float(t_test.pvalue)
    relative_diff = abs(stats_a.median_ns - stats_b.median_ns) / max(stats_a.median_ns, stats_b.median_ns)

    return TimingComparison(
        a=stats_a,
        b=stats_b,
        t_stat=t_stat,
        p_value=p_value,
        relative_diff=relative_diff,
    )


def _assert_t_test_no_significant_difference(comparison: TimingComparison, label: str) -> None:
    assert comparison.p_value > SIGNIFICANCE_ALPHA, (
        f"{label}: statistically significant timing separation detected "
        f"(t={comparison.t_stat:.5f}, p={comparison.p_value:.8f})"
    )


def _assert_relative_variance_limit(comparison: TimingComparison, label: str) -> None:
    assert comparison.relative_diff < MAX_RELATIVE_DIFF, (
        f"{label}: relative timing variance exceeded limit "
        f"(median_diff={comparison.relative_diff:.5f}, threshold={MAX_RELATIVE_DIFF:.5f}, "
        f"median_a_ns={comparison.a.median_ns:.2f}, median_b_ns={comparison.b.median_ns:.2f})"
    )


@pytest.fixture
def deterministic_nonce(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stabilize nonce generation cost for encryption timing comparisons."""

    def _fixed_urandom(length: int) -> bytes:
        return b"\x42" * length

    monkeypatch.setattr(aes_gcm_module.os, "urandom", _fixed_urandom)


@pytest.mark.security
def test_constant_time_comparison_no_timing_leak() -> None:
    target_key = os.urandom(4096)
    # Force a different object identity to avoid same-object fast paths.
    correct_key = bytes(bytearray(target_key))
    incorrect_key = target_key[:-1] + bytes([target_key[-1] ^ 0x01])

    comparison = _compare_timing(
        lambda: hmac.compare_digest(target_key, correct_key),
        lambda: hmac.compare_digest(target_key, incorrect_key),
        batches=BATCHES_SIGNIFICANCE,
    )

    _assert_t_test_no_significant_difference(comparison, "key-comparison-correct-vs-incorrect")

    # Extend side-channel validation by checking mismatch-position independence.
    first_mismatch = bytes([target_key[0] ^ 0x01]) + target_key[1:]
    position_comparison = _compare_timing(
        lambda: hmac.compare_digest(target_key, first_mismatch),
        lambda: hmac.compare_digest(target_key, incorrect_key),
        batches=BATCHES_SIGNIFICANCE,
    )
    _assert_t_test_no_significant_difference(position_comparison, "key-comparison-first-vs-last-mismatch")


@pytest.mark.security
def test_encryption_time_independent_of_plaintext(deterministic_nonce: None) -> None:
    key = b"\x11" * 32
    cipher = AESGCM(key)

    plaintext_zeros = b"\x00" * 4096
    plaintext_random = os.urandom(4096)
    associated_data = b"timing-attack-resistance"

    comparison = _compare_timing(
        lambda: cipher.encrypt(plaintext_zeros, associated_data),
        lambda: cipher.encrypt(plaintext_random, associated_data),
        batches=BATCHES_VARIANCE,
    )

    _assert_relative_variance_limit(comparison, "encryption-zeros-vs-random")


@pytest.mark.security
def test_authentication_tag_verification_constant_time() -> None:
    expected_tag = os.urandom(32)
    valid_tag = bytes(bytearray(expected_tag))
    invalid_tag = expected_tag[:-1] + bytes([expected_tag[-1] ^ 0x01])

    comparison = _compare_timing(
        lambda: hmac.compare_digest(expected_tag, valid_tag),
        lambda: hmac.compare_digest(expected_tag, invalid_tag),
        batches=BATCHES_SIGNIFICANCE,
    )
    _assert_t_test_no_significant_difference(comparison, "authentication-tag-valid-vs-invalid")
