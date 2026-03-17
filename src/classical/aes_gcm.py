"""AES-256-GCM authenticated encryption utilities.

Security notes:
- AES-GCM requires a unique nonce per key. Never reuse a nonce with the same key.
- Always pass identical associated data during encryption and decryption.
- Authentication failures must be treated as security failures; never ignore them.
- Store keys securely (for example in an HSM, KMS, or protected key vault).
"""

from __future__ import annotations

import hmac
import os
from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class AESGCM:
    """Implements AES-256-GCM authenticated encryption.

    This class provides a minimal interface for generating keys and performing
    authenticated encryption/decryption with AES-256-GCM.

    Attributes:
        key: Raw 32-byte AES key.

    Raises:
        ValueError: If the supplied key length is invalid.
    """

    KEY_SIZE: Final[int] = 32
    NONCE_SIZE: Final[int] = 12
    TAG_SIZE: Final[int] = 16

    def __init__(self, key: bytes) -> None:
        self._require_bytes("key", key)
        if not self._constant_time_len_equal(len(key), self.KEY_SIZE):
            raise ValueError("AES-256-GCM key must be exactly 32 bytes")
        self.key = key

    @staticmethod
    def generate_key() -> bytes:
        """Generate a new random AES-256 key.

        Returns:
            A cryptographically secure 32-byte key.
        """
        return os.urandom(AESGCM.KEY_SIZE)

    def encrypt(
        self,
        plaintext: bytes,
        associated_data: bytes | None = None,
    ) -> tuple[bytes, bytes, bytes]:
        """Encrypt plaintext with AES-256-GCM.

        Args:
            plaintext: Data to encrypt.
            associated_data: Optional authenticated but unencrypted data.

        Returns:
            A tuple of `(ciphertext, nonce, tag)`.

        Raises:
            TypeError: If plaintext or associated_data have invalid types.
            RuntimeError: If encryption fails unexpectedly.

        Security notes:
        - The returned nonce must be stored and provided for decryption.
        - Associated data must match exactly during decryption.
        """
        self._require_bytes("plaintext", plaintext)
        if associated_data is not None:
            self._require_bytes("associated_data", associated_data)

        nonce = os.urandom(self.NONCE_SIZE)

        try:
            encryptor = Cipher(
                algorithms.AES(self.key),
                modes.GCM(nonce),
            ).encryptor()

            if associated_data:
                encryptor.authenticate_additional_data(associated_data)

            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            tag = encryptor.tag
            return ciphertext, nonce, tag
        except Exception as exc:  # pragma: no cover - defensive crypto boundary
            raise RuntimeError("AES-GCM encryption failed") from exc

    def decrypt(
        self,
        ciphertext: bytes,
        associated_data: bytes | None,
        nonce: bytes,
        tag: bytes,
    ) -> bytes:
        """Decrypt and authenticate AES-256-GCM ciphertext.

        Args:
            ciphertext: Encrypted payload.
            associated_data: Authenticated additional data used during encryption.
            nonce: 12-byte nonce used during encryption.
            tag: 16-byte GCM authentication tag.

        Returns:
            The decrypted plaintext.

        Raises:
            TypeError: If inputs have invalid types.
            ValueError: If nonce/tag sizes are invalid or authentication fails.
            RuntimeError: For unexpected low-level decryption failures.

        Security notes:
        - Authentication failure indicates tampering or key/AAD mismatch.
        - Do not distinguish failure causes in external error messages.
        - Tag verification is performed by the cryptography backend using
          constant-time operations.
        """
        self._require_bytes("ciphertext", ciphertext)
        self._require_bytes("nonce", nonce)
        self._require_bytes("tag", tag)
        if associated_data is not None:
            self._require_bytes("associated_data", associated_data)

        if not self._constant_time_len_equal(len(nonce), self.NONCE_SIZE):
            raise ValueError("Nonce must be exactly 12 bytes for AES-GCM")
        if not self._constant_time_len_equal(len(tag), self.TAG_SIZE):
            raise ValueError("Authentication tag must be exactly 16 bytes")

        try:
            decryptor = Cipher(
                algorithms.AES(self.key),
                modes.GCM(nonce, tag),
            ).decryptor()

            if associated_data:
                decryptor.authenticate_additional_data(associated_data)

            return decryptor.update(ciphertext) + decryptor.finalize()
        except InvalidTag as exc:
            raise ValueError("Authentication failed: invalid key, tag, nonce, or associated data") from exc
        except Exception as exc:  # pragma: no cover - defensive crypto boundary
            raise RuntimeError("AES-GCM decryption failed") from exc

    @staticmethod
    def _constant_time_len_equal(actual: int, expected: int) -> bool:
        """Compare lengths in constant time to reduce side-channel leakage."""
        return hmac.compare_digest(actual.to_bytes(2, "big"), expected.to_bytes(2, "big"))

    @staticmethod
    def _require_bytes(name: str, value: object) -> None:
        if not isinstance(value, bytes):
            raise TypeError(f"{name} must be bytes")


__all__ = ["AESGCM"]
