"""Tests for constant-time operation utilities."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import src.security.constant_time_ops as ct_module
from src.security.constant_time_ops import (
    constant_time_compare,
    constant_time_find,
    constant_time_select,
)


def test_constant_time_compare_equal_values() -> None:
    assert constant_time_compare(b"abcd", b"abcd") is True


def test_constant_time_compare_different_values_same_length() -> None:
    assert constant_time_compare(b"abcd", b"abce") is False


def test_constant_time_compare_rejects_mismatched_lengths() -> None:
    with pytest.raises(ValueError, match="same length"):
        constant_time_compare(b"abc", b"ab")


def test_constant_time_compare_rejects_non_bytes() -> None:
    with pytest.raises(TypeError, match="must be bytes"):
        constant_time_compare("abc", b"abc")  # type: ignore[arg-type]


def test_constant_time_select_returns_expected_branchless_value() -> None:
    assert constant_time_select(True, 10, 20) == 10
    assert constant_time_select(False, 10, 20) == 20


def test_constant_time_select_requires_bool_condition() -> None:
    with pytest.raises(TypeError, match="condition must be bool"):
        constant_time_select(1, "a", "b")  # type: ignore[arg-type]


def test_constant_time_find_returns_first_index() -> None:
    assert constant_time_find(b"abcabc", b"abc") == 0
    assert constant_time_find(b"zabcabc", b"abc") == 1


def test_constant_time_find_not_found() -> None:
    assert constant_time_find(b"abcdef", b"xyz") == -1


def test_constant_time_find_empty_needle() -> None:
    assert constant_time_find(b"abcdef", b"") == 0


def test_constant_time_find_rejects_non_bytes_inputs() -> None:
    with pytest.raises(TypeError, match="haystack must be bytes"):
        constant_time_find("abcdef", b"abc")  # type: ignore[arg-type]

    with pytest.raises(TypeError, match="needle must be bytes"):
        constant_time_find(b"abcdef", "abc")  # type: ignore[arg-type]


def test_constant_time_find_scans_all_positions_even_after_match(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def _spy_compare(left: bytes, right: bytes) -> bool:
        nonlocal calls
        calls += 1
        return left == right

    monkeypatch.setattr(ct_module.secrets, "compare_digest", _spy_compare)

    haystack = b"aaaaaa"
    needle = b"aa"
    max_start = len(haystack) - len(needle) + 1

    assert constant_time_find(haystack, needle) == 0
    assert calls == max_start
