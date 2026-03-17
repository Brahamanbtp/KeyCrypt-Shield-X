"""HKDF-SHA256 key derivation utilities for KeyCrypt Shield X.

This module provides:
- Single-key derivation
- Multi-key derivation
- Forward-secure key ratcheting
- Password stretching helper

Security notes:
- Use a random salt for each independent derivation context.
- Do not reuse the same (IKM, salt, info) tuple across unrelated domains.
- Ratcheting should securely erase old chain keys after deriving the next key.
"""

from __future__ import annotations

import hmac
import os
from typing import Final

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SHA256_DIGEST_SIZE: Final[int] = 32
DEFAULT_STRETCH_ITERATIONS: Final[int] = 600_000
MAX_DERIVE_LENGTH: Final[int] = 255 * SHA256_DIGEST_SIZE


def derive_key(
    input_key_material: bytes,
    salt: bytes,
    info: bytes,
    length: int,
) -> bytes:
    """Derive a key with HKDF-SHA256.

    Args:
        input_key_material: Source keying material (IKM).
        salt: Salt bytes (recommended random, 16+ bytes).
        info: Context/application-specific info string.
        length: Output key length in bytes.

    Returns:
        Derived key bytes of requested length.

    Raises:
        TypeError: For invalid argument types.
        ValueError: For invalid lengths or empty key material.
    """
    _require_bytes("input_key_material", input_key_material)
    _require_bytes("salt", salt)
    _require_bytes("info", info)

    if not input_key_material:
        raise ValueError("input_key_material must not be empty")
    if length <= 0 or length > MAX_DERIVE_LENGTH:
        raise ValueError(f"length must be in range [1, {MAX_DERIVE_LENGTH}]")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(input_key_material)


def derive_multiple_keys(
    ikm: bytes,
    salt: bytes,
    key_count: int,
    key_length: int,
) -> list[bytes]:
    """Derive multiple independent keys from one input key material source.

    Each key is derived with domain-separated HKDF info labels:
    `b"keycrypt:multi:{index}"`.

    Args:
        ikm: Input key material.
        salt: Salt bytes.
        key_count: Number of keys to derive.
        key_length: Length in bytes for each key.

    Returns:
        List of derived keys.

    Raises:
        TypeError: For invalid argument types.
        ValueError: For invalid counts/length.
    """
    _require_bytes("ikm", ikm)
    _require_bytes("salt", salt)

    if key_count <= 0:
        raise ValueError("key_count must be >= 1")
    if key_length <= 0 or key_length > MAX_DERIVE_LENGTH:
        raise ValueError(f"key_length must be in range [1, {MAX_DERIVE_LENGTH}]")

    return [
        derive_key(
            input_key_material=ikm,
            salt=salt,
            info=f"keycrypt:multi:{index}".encode("ascii"),
            length=key_length,
        )
        for index in range(key_count)
    ]


def ratchet_key(chain_key: bytes, *, context: bytes = b"keycrypt:ratchet") -> tuple[bytes, bytes]:
    """Advance a chain key for forward secrecy.

    Returns:
        A tuple of `(next_chain_key, message_key)`.

    Notes:
    - Compromising a current chain key does not reveal previously derived keys.
    - Callers should wipe old chain keys from memory where practical.
    """
    _require_bytes("chain_key", chain_key)
    _require_bytes("context", context)

    if not chain_key:
        raise ValueError("chain_key must not be empty")

    next_chain_key = derive_key(chain_key, salt=b"KC-RATCHET-CHAIN", info=context + b":chain", length=32)
    message_key = derive_key(chain_key, salt=b"KC-RATCHET-MSG", info=context + b":message", length=32)
    return next_chain_key, message_key


def stretch_password(
    password: str,
    *,
    salt: bytes | None = None,
    iterations: int = DEFAULT_STRETCH_ITERATIONS,
    length: int = 32,
    info: bytes = b"keycrypt:password-stretch",
) -> tuple[bytes, bytes]:
    """Stretch a password into strong key material and domain-separate via HKDF.

    The function first uses PBKDF2-HMAC-SHA256 for computational hardening, then
    passes the result through HKDF-SHA256 for context binding.

    Args:
        password: User password string.
        salt: Optional salt. Random 16-byte salt is generated when omitted.
        iterations: PBKDF2 iteration count.
        length: Final key length.
        info: HKDF info for domain separation.

    Returns:
        `(derived_key, used_salt)`.
    """
    if not isinstance(password, str):
        raise TypeError("password must be str")
    if not password:
        raise ValueError("password must not be empty")
    if salt is not None:
        _require_bytes("salt", salt)

    if iterations < 100_000:
        raise ValueError("iterations must be >= 100000")
    if length <= 0 or length > MAX_DERIVE_LENGTH:
        raise ValueError(f"length must be in range [1, {MAX_DERIVE_LENGTH}]")

    used_salt = salt if salt is not None else os.urandom(16)

    pbkdf2 = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=used_salt,
        iterations=iterations,
    )
    stretched = pbkdf2.derive(password.encode("utf-8"))

    final_key = derive_key(
        input_key_material=stretched,
        salt=used_salt,
        info=info,
        length=length,
    )
    return final_key, used_salt


def verify_stretched_password(
    password: str,
    expected_key: bytes,
    salt: bytes,
    *,
    iterations: int = DEFAULT_STRETCH_ITERATIONS,
    info: bytes = b"keycrypt:password-stretch",
) -> bool:
    """Verify a password by re-deriving and constant-time comparing derived key."""
    if not isinstance(password, str):
        raise TypeError("password must be str")
    _require_bytes("expected_key", expected_key)
    _require_bytes("salt", salt)

    candidate_key, _ = stretch_password(
        password,
        salt=salt,
        iterations=iterations,
        length=len(expected_key),
        info=info,
    )
    return hmac.compare_digest(candidate_key, expected_key)


def _require_bytes(name: str, value: object) -> None:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")


__all__ = [
    "derive_key",
    "derive_multiple_keys",
    "ratchet_key",
    "stretch_password",
    "verify_stretched_password",
]
