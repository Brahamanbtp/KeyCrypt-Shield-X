"""Unit tests for src.classical.aes_gcm.AESGCM."""

from __future__ import annotations

import sys
from typing import Final
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.classical.aes_gcm import AESGCM


AAD_TEXT: Final[bytes] = b"keycrypt-associated-data"


@pytest.fixture
def key() -> bytes:
    """Provide a fresh valid AES-256 key for each test."""
    return AESGCM.generate_key()


@pytest.fixture
def cipher(key: bytes) -> AESGCM:
    """Provide a cipher instance bound to a valid key."""
    return AESGCM(key)


def test_key_generation() -> None:
    """Generated keys should be 32 bytes and randomly unique."""
    key_a = AESGCM.generate_key()
    key_b = AESGCM.generate_key()

    assert isinstance(key_a, bytes)
    assert isinstance(key_b, bytes)
    assert len(key_a) == AESGCM.KEY_SIZE
    assert len(key_b) == AESGCM.KEY_SIZE
    assert key_a != key_b


@pytest.mark.parametrize(
    ("plaintext", "associated_data"),
    [
        (b"hello world", None),
        (b"", None),
        (b"confidential payload", b"meta:v1"),
        (bytes(range(64)), b"binary-aad"),
    ],
)
def test_encrypt_decrypt_roundtrip(
    cipher: AESGCM,
    plaintext: bytes,
    associated_data: bytes | None,
) -> None:
    """Encryption followed by decryption should return original plaintext."""
    ciphertext, nonce, tag = cipher.encrypt(plaintext, associated_data)
    restored = cipher.decrypt(ciphertext, associated_data, nonce, tag)

    assert restored == plaintext


@pytest.mark.parametrize("tamper_index", [0, 1, 7])
def test_authentication_tag_verification(
    cipher: AESGCM,
    tamper_index: int,
) -> None:
    """Any ciphertext modification must fail authentication."""
    plaintext = b"important secret"
    ciphertext, nonce, tag = cipher.encrypt(plaintext, AAD_TEXT)

    if len(ciphertext) == 0:
        pytest.skip("ciphertext is empty; tampering index is invalid")

    idx = tamper_index % len(ciphertext)
    tampered = bytearray(ciphertext)
    tampered[idx] ^= 0x01

    with pytest.raises(ValueError, match="Authentication failed"):
        cipher.decrypt(bytes(tampered), AAD_TEXT, nonce, tag)


def test_nonce_uniqueness(cipher: AESGCM) -> None:
    """Repeated encryption should produce distinct nonces and payloads."""
    plaintext = b"same plaintext"

    ciphertext_a, nonce_a, tag_a = cipher.encrypt(plaintext, AAD_TEXT)
    ciphertext_b, nonce_b, tag_b = cipher.encrypt(plaintext, AAD_TEXT)

    assert nonce_a != nonce_b
    assert (ciphertext_a, tag_a) != (ciphertext_b, tag_b)


def test_associated_data(cipher: AESGCM) -> None:
    """Associated data must be authenticated and remain external to plaintext."""
    plaintext = b"payload"
    aad = b"header:v1"

    ciphertext, nonce, tag = cipher.encrypt(plaintext, aad)

    # AD is not encrypted data output; it is supplied separately as input.
    assert aad != plaintext
    assert aad not in ciphertext

    assert cipher.decrypt(ciphertext, aad, nonce, tag) == plaintext

    with pytest.raises(ValueError, match="Authentication failed"):
        cipher.decrypt(ciphertext, b"header:v2", nonce, tag)


@pytest.mark.parametrize("bad_size", [0, 1, 16, 24, 31, 33, 64])
def test_invalid_key_size(bad_size: int) -> None:
    """Invalid key lengths should be rejected at construction time."""
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        AESGCM(b"\x00" * bad_size)


@settings(max_examples=100)
@given(
    plaintext=st.binary(min_size=0, max_size=4096),
    associated_data=st.one_of(st.none(), st.binary(min_size=0, max_size=256)),
)
def test_roundtrip_property_based(
    plaintext: bytes,
    associated_data: bytes | None,
) -> None:
    """Property: decrypt(encrypt(m)) == m for arbitrary binary payloads."""
    key = AESGCM.generate_key()
    cipher = AESGCM(key)
    ciphertext, nonce, tag = cipher.encrypt(plaintext, associated_data)
    restored = cipher.decrypt(ciphertext, associated_data, nonce, tag)

    assert restored == plaintext
