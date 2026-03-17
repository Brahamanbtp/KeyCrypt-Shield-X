"""EdDSA (Ed25519) digital signature utilities.

This module provides deterministic Ed25519 signature operations with:
- Raw key generation
- Signing
- Verification
- Batch verification over multiple signature records

Security notes:
- Ed25519 signatures are deterministic by design; no external nonce is needed.
- Signatures are handled in canonical raw encoding (64 bytes: R || S).
- Batch verification here is implemented as iterative verification over a batch
  of inputs, not multi-scalar cryptographic aggregation.
"""

from __future__ import annotations

import hmac
from typing import Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

PUBLIC_KEY_SIZE = 32
PRIVATE_KEY_SIZE = 32
SIGNATURE_SIZE = 64

# Ed25519 subgroup order L in little-endian integer form.
_ED25519_L = 2**252 + 27742317777372353535851937790883648493


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate an Ed25519 keypair.

    Returns:
        A tuple of `(private_key_bytes, public_key_bytes)` in raw 32-byte format.
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_bytes, public_bytes


def sign(private_key: bytes, message: bytes) -> bytes:
    """Create a deterministic Ed25519 signature.

    Args:
        private_key: Raw Ed25519 private key bytes (32 bytes).
        message: Message bytes to sign.

    Returns:
        Canonically encoded 64-byte Ed25519 signature.

    Raises:
        TypeError: If inputs are not bytes.
        ValueError: If key length is invalid or produced signature is non-canonical.
        RuntimeError: For unexpected signing backend failures.
    """
    _require_bytes("private_key", private_key)
    _require_bytes("message", message)

    if not _constant_time_len_equal(len(private_key), PRIVATE_KEY_SIZE):
        raise ValueError("private_key must be exactly 32 bytes (Ed25519 raw format)")

    try:
        key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
        signature = key.sign(message)

        if not _is_canonical_signature(signature):
            raise ValueError("generated signature is not canonical")
        return signature
    except ValueError:
        raise
    except Exception as exc:  # pragma: no cover - defensive crypto boundary
        raise RuntimeError("Ed25519 signing failed") from exc


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature.

    Args:
        public_key: Raw Ed25519 public key bytes (32 bytes).
        message: Message bytes that were signed.
        signature: Raw Ed25519 signature bytes (64 bytes, canonical encoding).

    Returns:
        True if the signature is valid and canonical, else False.

    Raises:
        TypeError: If inputs are not bytes.
        ValueError: If public key length is invalid.
        RuntimeError: For unexpected verification backend failures.
    """
    _require_bytes("public_key", public_key)
    _require_bytes("message", message)
    _require_bytes("signature", signature)

    if not _constant_time_len_equal(len(public_key), PUBLIC_KEY_SIZE):
        raise ValueError("public_key must be exactly 32 bytes (Ed25519 raw format)")
    if not _is_canonical_signature(signature):
        return False

    try:
        key = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
        key.verify(signature, message)
        return True
    except InvalidSignature:
        return False
    except ValueError:
        return False
    except Exception as exc:  # pragma: no cover - defensive crypto boundary
        raise RuntimeError("Ed25519 verification failed") from exc


def verify_batch(
    records: Iterable[tuple[bytes, bytes, bytes]],
    *,
    fail_fast: bool = True,
) -> bool | list[bool]:
    """Verify multiple signatures.

    Args:
        records: Iterable of `(public_key, message, signature)` tuples.
        fail_fast: If True, returns False immediately on first invalid signature.
            If False, returns a list of per-record verification results.

    Returns:
        `True` when all signatures are valid (fail_fast mode), otherwise `False`.
        If `fail_fast=False`, returns a list of booleans for each record.

    Raises:
        TypeError: If records contain invalid tuple structures.
        ValueError: If any record uses invalid key lengths.
        RuntimeError: For unexpected verification backend failures.
    """
    if fail_fast:
        for record in records:
            _validate_batch_record(record)
            if not verify(record[0], record[1], record[2]):
                return False
        return True

    results: list[bool] = []
    for record in records:
        _validate_batch_record(record)
        results.append(verify(record[0], record[1], record[2]))
    return results


def _validate_batch_record(record: object) -> None:
    if not isinstance(record, tuple) or len(record) != 3:
        raise TypeError("Each batch record must be a tuple(public_key, message, signature)")


def _is_canonical_signature(signature: bytes) -> bool:
    if not _constant_time_len_equal(len(signature), SIGNATURE_SIZE):
        return False

    s = int.from_bytes(signature[32:], byteorder="little", signed=False)
    return s < _ED25519_L


def _constant_time_len_equal(actual: int, expected: int) -> bool:
    return hmac.compare_digest(actual.to_bytes(2, "big"), expected.to_bytes(2, "big"))


def _require_bytes(name: str, value: object) -> None:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")


__all__ = ["generate_keypair", "sign", "verify", "verify_batch"]
