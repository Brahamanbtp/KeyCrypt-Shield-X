"""ECIES using Curve25519 (X25519) and AES-256-GCM.

This module implements a compact ECIES construction with the following stack:
- Asymmetric key exchange: X25519
- Symmetric key derivation: HKDF-SHA256
- Symmetric authenticated encryption: AES-256-GCM

Ciphertext wire format:
    MAGIC(4) || ephemeral_public_key(32) || nonce(12) || ciphertext_and_tag(N)

Security notes:
- A fresh ephemeral private key is generated per encryption operation.
- Nonces are random and must never repeat for the same derived key.
- Authentication failures must be treated as hard security failures.
"""

from __future__ import annotations

import hmac
import os
from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC: Final[bytes] = b"KCX1"
PUBLIC_KEY_SIZE: Final[int] = 32
PRIVATE_KEY_SIZE: Final[int] = 32
NONCE_SIZE: Final[int] = 12
TAG_SIZE: Final[int] = 16
HKDF_INFO: Final[bytes] = b"KeyCrypt-Shield-X ECIES X25519 AES-256-GCM v1"


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate an X25519 key pair.

    Returns:
        A tuple of (private_key_bytes, public_key_bytes) in raw 32-byte format.
    """
    private_key = x25519.X25519PrivateKey.generate()
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


def encrypt(public_key: bytes, message: bytes) -> bytes:
    """Encrypt a message using recipient X25519 public key.

    Args:
        public_key: Recipient public key (32 raw bytes).
        message: Plaintext bytes.

    Returns:
        Serialized ECIES ciphertext bytes.

    Raises:
        TypeError: If arguments are not bytes.
        ValueError: If public key length is invalid.
        RuntimeError: If encryption fails unexpectedly.
    """
    _require_bytes("public_key", public_key)
    _require_bytes("message", message)

    if not _constant_time_len_equal(len(public_key), PUBLIC_KEY_SIZE):
        raise ValueError("public_key must be exactly 32 bytes (X25519 raw format)")

    try:
        recipient_public = x25519.X25519PublicKey.from_public_bytes(public_key)
        ephemeral_private = x25519.X25519PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        shared_secret = ephemeral_private.exchange(recipient_public)
        symmetric_key = _derive_key(shared_secret, ephemeral_public)

        nonce = os.urandom(NONCE_SIZE)
        aad = MAGIC + ephemeral_public
        ciphertext_and_tag = AESGCM(symmetric_key).encrypt(nonce, message, aad)

        return MAGIC + ephemeral_public + nonce + ciphertext_and_tag
    except ValueError:
        raise
    except Exception as exc:  # pragma: no cover - defensive crypto boundary
        raise RuntimeError("ECIES encryption failed") from exc


def decrypt(private_key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt a serialized ECIES payload with an X25519 private key.

    Args:
        private_key: Recipient private key (32 raw bytes).
        ciphertext: Serialized ECIES payload bytes.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        TypeError: If arguments are not bytes.
        ValueError: If key/ciphertext is malformed or authentication fails.
        RuntimeError: If decryption fails unexpectedly.
    """
    _require_bytes("private_key", private_key)
    _require_bytes("ciphertext", ciphertext)

    if not _constant_time_len_equal(len(private_key), PRIVATE_KEY_SIZE):
        raise ValueError("private_key must be exactly 32 bytes (X25519 raw format)")

    min_size = len(MAGIC) + PUBLIC_KEY_SIZE + NONCE_SIZE + TAG_SIZE
    if len(ciphertext) < min_size:
        raise ValueError("ciphertext is too short to be a valid ECIES payload")

    magic = ciphertext[: len(MAGIC)]
    if not hmac.compare_digest(magic, MAGIC):
        raise ValueError("ciphertext has invalid format header")

    try:
        offset = len(MAGIC)
        ephemeral_public = ciphertext[offset : offset + PUBLIC_KEY_SIZE]
        offset += PUBLIC_KEY_SIZE

        nonce = ciphertext[offset : offset + NONCE_SIZE]
        offset += NONCE_SIZE

        ciphertext_and_tag = ciphertext[offset:]

        recipient_private = x25519.X25519PrivateKey.from_private_bytes(private_key)
        sender_ephemeral_public = x25519.X25519PublicKey.from_public_bytes(ephemeral_public)

        shared_secret = recipient_private.exchange(sender_ephemeral_public)
        symmetric_key = _derive_key(shared_secret, ephemeral_public)

        aad = MAGIC + ephemeral_public
        return AESGCM(symmetric_key).decrypt(nonce, ciphertext_and_tag, aad)
    except InvalidTag as exc:
        raise ValueError("authentication failed: invalid key or tampered ciphertext") from exc
    except ValueError:
        raise
    except Exception as exc:  # pragma: no cover - defensive crypto boundary
        raise RuntimeError("ECIES decryption failed") from exc


def _derive_key(shared_secret: bytes, context: bytes) -> bytes:
    """Derive a 32-byte AES key from X25519 shared secret using HKDF-SHA256."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=HKDF_INFO + context,
    ).derive(shared_secret)


def _constant_time_len_equal(actual: int, expected: int) -> bool:
    return hmac.compare_digest(actual.to_bytes(2, "big"), expected.to_bytes(2, "big"))


def _require_bytes(name: str, value: object) -> None:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")


__all__ = ["generate_keypair", "encrypt", "decrypt"]
