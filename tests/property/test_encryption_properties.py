"""Property-based encryption validation with Hypothesis.

This module verifies algebraic and statistical properties of authenticated
encryption using randomized binary, text, and structured payloads.
"""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path
from typing import Any

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from src.classical.aes_gcm import AESGCM
from src.classical.chacha20_poly1305 import ChaCha20Poly1305


ASCII_CHARS = st.characters(min_codepoint=32, max_codepoint=126)
ALGORITHMS = st.sampled_from(["aes-gcm", "chacha20"])
KEYS = st.binary(min_size=32, max_size=32)
NONCE_SIZE = 12
TAG_SIZE = 16


def _structured_to_bytes(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=True).encode("utf-8")


def _expand_to_min_length(payload: bytes, *, minimum: int, maximum: int) -> bytes:
    base = payload or b"{}"
    if len(base) >= minimum:
        return base[:maximum]

    repeats = (minimum + len(base) - 1) // len(base)
    expanded = (base * repeats)[:minimum]
    return expanded[:maximum]


_STRUCTURED_JSON = st.recursive(
    st.one_of(
        st.none(),
        st.booleans(),
        st.integers(min_value=-(10**9), max_value=10**9),
        st.floats(allow_nan=False, allow_infinity=False, width=32),
        st.text(alphabet=ASCII_CHARS, min_size=0, max_size=64),
    ),
    lambda children: st.one_of(
        st.lists(children, min_size=0, max_size=8),
        st.dictionaries(
            st.text(alphabet=ASCII_CHARS, min_size=1, max_size=16),
            children,
            min_size=0,
            max_size=8,
        ),
    ),
    max_leaves=20,
)


RANDOMIZED_PLAINTEXTS = st.one_of(
    st.binary(min_size=0, max_size=4096),
    st.text(alphabet=ASCII_CHARS, min_size=0, max_size=2048).map(lambda value: value.encode("utf-8")),
    _STRUCTURED_JSON.map(_structured_to_bytes),
)

RANDOMNESS_PLAINTEXTS = st.one_of(
    st.binary(min_size=128, max_size=2048),
    st.text(alphabet=ASCII_CHARS, min_size=128, max_size=1024).map(lambda value: value.encode("utf-8")),
    _STRUCTURED_JSON.map(_structured_to_bytes).map(
        lambda payload: _expand_to_min_length(payload, minimum=128, maximum=2048)
    ),
)


def _chi_square_statistic(sample: bytes) -> float:
    if not sample:
        raise ValueError("sample must be non-empty")

    expected = len(sample) / 256.0
    counts = [0] * 256
    for value in sample:
        counts[value] += 1

    return sum(((count - expected) ** 2) / expected for count in counts)


def _chi_square_z_score(statistic: float, dof: int) -> float:
    if dof <= 1:
        raise ValueError("degrees of freedom must be greater than 1")

    # Wilson-Hilferty transformation approximates chi-square as normal.
    ratio = statistic / float(dof)
    transformed = ratio ** (1.0 / 3.0)
    mean = 1.0 - (2.0 / (9.0 * dof))
    stddev = math.sqrt(2.0 / (9.0 * dof))
    return (transformed - mean) / stddev


def _encrypt_packed(algorithm: str, key: bytes, plaintext: bytes, associated_data: bytes) -> bytes:
    if algorithm == "aes-gcm":
        cipher = AESGCM(key)
    else:
        cipher = ChaCha20Poly1305(key)

    ciphertext, nonce, tag = cipher.encrypt(plaintext, associated_data)
    return nonce + tag + ciphertext


def _decrypt_packed(algorithm: str, key: bytes, packed_ciphertext: bytes, associated_data: bytes) -> bytes:
    nonce = packed_ciphertext[:NONCE_SIZE]
    tag = packed_ciphertext[NONCE_SIZE : NONCE_SIZE + TAG_SIZE]
    ciphertext = packed_ciphertext[NONCE_SIZE + TAG_SIZE :]

    if algorithm == "aes-gcm":
        cipher = AESGCM(key)
    else:
        cipher = ChaCha20Poly1305(key)

    return cipher.decrypt(ciphertext, associated_data, nonce, tag)


def _ciphertext_sample(
    algorithm: str,
    plaintext: bytes,
    *,
    key: bytes,
    associated_data: bytes,
    target_bytes: int = 4096,
) -> bytes:
    sample = bytearray()
    base = plaintext if plaintext else b"\x00"
    counter = 0

    while len(sample) < target_bytes:
        payload = base + counter.to_bytes(4, "big")
        packed = _encrypt_packed(algorithm, key, payload, associated_data)
        sample.extend(packed)
        counter += 1

    return bytes(sample[:target_bytes])


@settings(max_examples=120, deadline=None)
@given(plaintext=RANDOMIZED_PLAINTEXTS, key=KEYS, algorithm=ALGORITHMS)
def test_property_encryption_decryption_inverses(
    plaintext: bytes,
    key: bytes,
    algorithm: str,
) -> None:
    aad = b"property-inverse"

    packed = _encrypt_packed(algorithm, key, plaintext, aad)
    restored = _decrypt_packed(algorithm, key, packed, aad)

    assert restored == plaintext


@settings(max_examples=120, deadline=None)
@given(plaintext=RANDOMIZED_PLAINTEXTS, key1=KEYS, key2=KEYS, algorithm=ALGORITHMS)
def test_property_different_keys_produce_different_ciphertexts(
    plaintext: bytes,
    key1: bytes,
    key2: bytes,
    algorithm: str,
) -> None:
    assume(key1 != key2)

    aad = b"property-key-separation"

    ciphertext_a = _encrypt_packed(algorithm, key1, plaintext, aad)
    ciphertext_b = _encrypt_packed(algorithm, key2, plaintext, aad)

    assert ciphertext_a != ciphertext_b


@settings(max_examples=40, deadline=None)
@given(plaintext=RANDOMNESS_PLAINTEXTS, key=KEYS, algorithm=ALGORITHMS)
def test_property_ciphertext_indistinguishable_from_random(
    plaintext: bytes,
    key: bytes,
    algorithm: str,
) -> None:
    aad = b"property-randomness"

    sample = _ciphertext_sample(algorithm, plaintext, key=key, associated_data=aad)
    chi_square = _chi_square_statistic(sample)
    z_score = _chi_square_z_score(chi_square, 255)

    # For secure ciphertext, chi-square should remain within a broad normal band.
    assert abs(z_score) <= 6.0


@settings(max_examples=140, deadline=None)
@given(
    plaintext=RANDOMIZED_PLAINTEXTS,
    key=KEYS,
    algorithm=ALGORITHMS,
    tamper_index_seed=st.integers(min_value=0, max_value=10**6),
    tamper_mask=st.integers(min_value=1, max_value=255),
)
def test_property_authentication_tag_prevents_tampering(
    plaintext: bytes,
    key: bytes,
    algorithm: str,
    tamper_index_seed: int,
    tamper_mask: int,
) -> None:
    aad = b"property-authenticity"

    ciphertext = _encrypt_packed(algorithm, key, plaintext, aad)
    restored = _decrypt_packed(algorithm, key, ciphertext, aad)
    assert restored == plaintext

    index = tamper_index_seed % len(ciphertext)
    tampered = bytearray(ciphertext)
    tampered[index] ^= tamper_mask

    with pytest.raises(Exception):
        _decrypt_packed(algorithm, key, bytes(tampered), aad)
