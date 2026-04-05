"""Constant-time utility operations to reduce timing-attack leakage.

Timing attacks exploit data-dependent execution differences, such as:
- Returning early on the first mismatched byte during secret comparison.
- Branching directly on secret conditions.
- Stopping substring searches at the first match.

This module provides best-effort constant-time helpers for Python code:
- `constant_time_compare` uses `secrets.compare_digest` for equal-length bytes.
- `constant_time_select` performs branchless value selection using index math.
- `constant_time_find` scans all candidate positions and avoids early-exit logic.

Limitations:
- Python cannot guarantee strict machine-level constant time in all scenarios.
- These helpers primarily remove obvious high-level timing leaks and should be
  combined with hardened cryptographic primitives for sensitive workflows.
"""

from __future__ import annotations

import secrets
from typing import TypeVar


T = TypeVar("T")


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Compare two byte strings in constant time.

    Args:
        a: First byte string.
        b: Second byte string.

    Returns:
        True when `a` and `b` are identical, else False.

    Raises:
        TypeError: If either argument is not bytes.
        ValueError: If lengths differ.

    Notes:
        The function enforces equal length before calling compare_digest to
        avoid accidental use with variable-length secret inputs.
    """
    _require_bytes("a", a)
    _require_bytes("b", b)

    if len(a) != len(b):
        raise ValueError("a and b must have the same length")

    return secrets.compare_digest(a, b)


def constant_time_select(condition: bool, true_val: T, false_val: T) -> T:
    """Select between two values without explicit branching.

    Args:
        condition: Boolean selector.
        true_val: Value returned when condition is True.
        false_val: Value returned when condition is False.

    Returns:
        `true_val` if `condition` else `false_val`.

    Raises:
        TypeError: If condition is not bool.

    Notes:
        This avoids direct if/else branching in the selection path. In CPython,
        this is still best-effort and not a strict hardware-level guarantee.
    """
    if not isinstance(condition, bool):
        raise TypeError("condition must be bool")

    return (false_val, true_val)[int(condition)]


def constant_time_find(haystack: bytes, needle: bytes) -> int:
    """Find first `needle` occurrence in `haystack` without early exit.

    Args:
        haystack: Byte string to search.
        needle: Byte string to find.

    Returns:
        The first matching index, or -1 when not found. Empty `needle` returns
        0 to match `bytes.find` semantics.

    Raises:
        TypeError: If inputs are not bytes.

    Notes:
        The search scans every candidate window and records the first match via
        arithmetic masking, rather than breaking once a match is found.
    """
    _require_bytes("haystack", haystack)
    _require_bytes("needle", needle)

    needle_len = len(needle)
    haystack_len = len(haystack)

    if needle_len == 0:
        return 0
    if needle_len > haystack_len:
        return -1

    first_index = 0
    found = 0
    max_start = haystack_len - needle_len + 1

    for idx in range(max_start):
        window = haystack[idx : idx + needle_len]
        is_match = int(secrets.compare_digest(window, needle))

        take = is_match & (found ^ 1)
        first_index = (take * idx) + ((take ^ 1) * first_index)
        found |= is_match

    return constant_time_select(bool(found), first_index, -1)


def _require_bytes(name: str, value: object) -> None:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")


__all__ = [
    "constant_time_compare",
    "constant_time_select",
    "constant_time_find",
]
