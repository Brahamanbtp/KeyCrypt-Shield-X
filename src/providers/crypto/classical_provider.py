"""Classical cryptography provider adapter.

This module exposes a `CryptoProvider` implementation that wraps existing
classical primitives without modifying them. It normalizes algorithm selection
and payload handling behind a common provider interface.
"""

from __future__ import annotations

from typing import Any, Literal, Mapping

from src.abstractions.crypto_provider import CryptoProvider
from src.classical.aes_gcm import AESGCM
from src.classical.chacha20_poly1305 import ChaCha20Poly1305


class ClassicalCryptoProvider(CryptoProvider):
    """Adapter over existing classical cryptographic implementations.

    Supported algorithms:
    - ``"aes-gcm"`` mapped to ``src.classical.aes_gcm.AESGCM``
    - ``"chacha20"`` mapped to ``src.classical.chacha20_poly1305.ChaCha20Poly1305``

    Context requirements:
    - Encryption context must provide a 32-byte `key`.
    - Optional `associated_data` may be supplied as bytes.
    - Decryption context may either supply `nonce` and `tag`, or ciphertext
      can be provided in the provider's packed format:
      ``nonce(12) + tag(16) + ciphertext``.
    """

    _NONCE_SIZE = 12
    _TAG_SIZE = 16

    def __init__(self, algorithm: Literal["aes-gcm", "chacha20"]) -> None:
        """Initialize the classical adapter for a specific algorithm."""
        normalized = algorithm.strip().lower()
        if normalized not in {"aes-gcm", "chacha20"}:
            raise ValueError("algorithm must be 'aes-gcm' or 'chacha20'")
        self._algorithm: Literal["aes-gcm", "chacha20"] = normalized  # type: ignore[assignment]

    def encrypt(self, plaintext: bytes, context: EncryptionContext) -> bytes:
        """Encrypt plaintext and return packed bytes.

        Returned payload format is ``nonce + tag + ciphertext`` to keep the
        `CryptoProvider` interface byte-oriented while preserving required AEAD
        artifacts.
        """
        self._require_bytes("plaintext", plaintext)

        key = self._extract_required_bytes(context, "key")
        associated_data = self._extract_optional_bytes(context, "associated_data")

        engine = self._make_engine(key)
        ciphertext, nonce, tag = engine.encrypt(plaintext, associated_data)
        return nonce + tag + ciphertext

    def decrypt(self, ciphertext: bytes, context: DecryptionContext) -> bytes:
        """Decrypt packed payload or explicit ciphertext + context artifacts."""
        self._require_bytes("ciphertext", ciphertext)

        key = self._extract_required_bytes(context, "key")
        associated_data = self._extract_optional_bytes(context, "associated_data")

        nonce = self._extract_optional_bytes(context, "nonce")
        tag = self._extract_optional_bytes(context, "tag")

        if nonce is None or tag is None:
            nonce, tag, raw_ciphertext = self._unpack_payload(ciphertext)
        else:
            raw_ciphertext = ciphertext

        engine = self._make_engine(key)
        return engine.decrypt(raw_ciphertext, associated_data, nonce, tag)

    def get_algorithm_name(self) -> str:
        """Return normalized algorithm identifier used by this provider."""
        return self._algorithm

    def get_security_level(self) -> int:
        """Return nominal security level for supported classical AEAD modes."""
        return 256

    def _make_engine(self, key: bytes) -> AESGCM | ChaCha20Poly1305:
        if self._algorithm == "aes-gcm":
            return AESGCM(key)
        return ChaCha20Poly1305(key)

    def _unpack_payload(self, payload: bytes) -> tuple[bytes, bytes, bytes]:
        min_len = self._NONCE_SIZE + self._TAG_SIZE + 1
        if len(payload) < min_len:
            raise ValueError("ciphertext is too short for packed nonce/tag format")

        nonce = payload[: self._NONCE_SIZE]
        tag = payload[self._NONCE_SIZE : self._NONCE_SIZE + self._TAG_SIZE]
        raw_ciphertext = payload[self._NONCE_SIZE + self._TAG_SIZE :]
        return nonce, tag, raw_ciphertext

    @staticmethod
    def _extract_required_bytes(context: Any, key: str) -> bytes:
        value = ClassicalCryptoProvider._extract_value(context, key)
        if not isinstance(value, bytes):
            raise ValueError(f"context.{key} must be bytes")
        return value

    @staticmethod
    def _extract_optional_bytes(context: Any, key: str) -> bytes | None:
        value = ClassicalCryptoProvider._extract_value(context, key)
        if value is None:
            return None
        if not isinstance(value, bytes):
            raise ValueError(f"context.{key} must be bytes when provided")
        return value

    @staticmethod
    def _extract_value(context: Any, key: str) -> Any:
        if isinstance(context, Mapping):
            return context.get(key)
        return getattr(context, key, None)

    @staticmethod
    def _require_bytes(name: str, value: object) -> None:
        if not isinstance(value, bytes):
            raise TypeError(f"{name} must be bytes")


__all__ = ["ClassicalCryptoProvider"]
