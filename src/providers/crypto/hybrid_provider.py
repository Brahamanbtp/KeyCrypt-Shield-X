"""Hybrid classical+PQC cryptography provider adapter.

This module implements a `CryptoProvider` wrapper over the existing
`HybridKEM` implementation and does not modify upstream PQC code.

Supported algorithm:
- hybrid-kem (ECIES + Kyber-768)
"""

from __future__ import annotations

import hashlib
from typing import Any, Mapping

from src.abstractions.crypto_provider import CryptoProvider

try:
    from src.pqc.hybrid_kem import HybridKEM
except Exception as exc:  # pragma: no cover - optional dependency boundary
    HybridKEM = None  # type: ignore[assignment]
    _HYBRID_IMPORT_ERROR = exc
else:
    _HYBRID_IMPORT_ERROR = None


class HybridCryptoProvider(CryptoProvider):
    """Adapter that delegates hybrid KEM operations to `HybridKEM`.

    Context requirements for encryption:
    - recipient_classical_public_key: bytes
    - recipient_pqc_public_key: bytes

    Context requirements for decryption:
    - recipient_classical_secret_key: bytes
    - recipient_pqc_secret_key: bytes

    Ciphertext wire format used by this adapter:
    - HYBRID_CT_LEN(4) || HYBRID_CT || WRAPPED_PLAINTEXT
    """

    _LEN_PREFIX_SIZE = 4
    _ALGORITHM_NAME = "hybrid-kem"

    def __init__(self) -> None:
        self._ensure_available()

    def encrypt(self, plaintext: bytes, context: EncryptionContext) -> bytes:
        """Encrypt plaintext using hybrid shared-secret encapsulation."""
        self._require_bytes("plaintext", plaintext)
        self._ensure_available()

        classical_pk = self._extract_required_bytes(context, "recipient_classical_public_key")
        pqc_pk = self._extract_required_bytes(context, "recipient_pqc_public_key")

        kem = HybridKEM()
        hybrid_ciphertext, shared_secret = kem.encapsulate(classical_pk, pqc_pk)

        keystream = self._expand_keystream(shared_secret, len(plaintext))
        wrapped_plaintext = self._xor_bytes(plaintext, keystream)

        return self._pack(hybrid_ciphertext, wrapped_plaintext)

    def decrypt(self, ciphertext: bytes, context: DecryptionContext) -> bytes:
        """Decrypt adapter-packed ciphertext using hybrid decapsulation."""
        self._require_bytes("ciphertext", ciphertext)
        self._ensure_available()

        classical_sk = self._extract_required_bytes(context, "recipient_classical_secret_key")
        pqc_sk = self._extract_required_bytes(context, "recipient_pqc_secret_key")

        hybrid_ciphertext, wrapped_plaintext = self._unpack(ciphertext)

        kem = HybridKEM()
        shared_secret = kem.decapsulate(classical_sk, pqc_sk, hybrid_ciphertext)

        keystream = self._expand_keystream(shared_secret, len(wrapped_plaintext))
        return self._xor_bytes(wrapped_plaintext, keystream)

    def get_algorithm_name(self) -> str:
        """Return the normalized adapter algorithm identifier."""
        return self._ALGORITHM_NAME

    def get_security_level(self) -> int:
        """Return nominal security level for the hybrid KEM profile."""
        return 3

    @classmethod
    def _pack(cls, hybrid_ciphertext: bytes, wrapped_plaintext: bytes) -> bytes:
        if len(hybrid_ciphertext) > 0xFFFFFFFF:
            raise ValueError("hybrid ciphertext section too large")
        return len(hybrid_ciphertext).to_bytes(cls._LEN_PREFIX_SIZE, "big") + hybrid_ciphertext + wrapped_plaintext

    @classmethod
    def _unpack(cls, payload: bytes) -> tuple[bytes, bytes]:
        if len(payload) < cls._LEN_PREFIX_SIZE + 1:
            raise ValueError("ciphertext is too short")

        hybrid_len = int.from_bytes(payload[: cls._LEN_PREFIX_SIZE], "big")
        start = cls._LEN_PREFIX_SIZE
        end = start + hybrid_len

        if end > len(payload) - 1:
            raise ValueError("ciphertext payload is malformed")

        hybrid_ciphertext = payload[start:end]
        wrapped_plaintext = payload[end:]

        if not wrapped_plaintext:
            raise ValueError("ciphertext payload is missing wrapped plaintext section")

        return hybrid_ciphertext, wrapped_plaintext

    @staticmethod
    def _extract_required_bytes(context: Any, key: str) -> bytes:
        value = HybridCryptoProvider._extract_value(context, key)
        if not isinstance(value, bytes):
            raise ValueError(f"context.{key} must be bytes")
        return value

    @staticmethod
    def _extract_value(context: Any, key: str) -> Any:
        if isinstance(context, Mapping):
            return context.get(key)
        return getattr(context, key, None)

    @staticmethod
    def _expand_keystream(seed: bytes, length: int) -> bytes:
        if length < 0:
            raise ValueError("length must be non-negative")
        if length == 0:
            return b""

        blocks: list[bytes] = []
        generated = 0
        counter = 0

        while generated < length:
            block = hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
            blocks.append(block)
            generated += len(block)
            counter += 1

        return b"".join(blocks)[:length]

    @staticmethod
    def _xor_bytes(left: bytes, right: bytes) -> bytes:
        if len(left) != len(right):
            raise ValueError("byte sequences must be the same length")
        return bytes(a ^ b for a, b in zip(left, right))

    @staticmethod
    def _require_bytes(name: str, value: object) -> None:
        if not isinstance(value, bytes):
            raise TypeError(f"{name} must be bytes")

    @staticmethod
    def _missing_dependency_message(error: Exception | None) -> str:
        reason = f": {error}" if error is not None else ""
        return (
            f"Hybrid PQC provider is unavailable{reason}. "
            "Install compatible liboqs/oqs-python dependencies to enable HybridKEM."
        )

    def _ensure_available(self) -> None:
        if HybridKEM is None:
            raise RuntimeError(self._missing_dependency_message(_HYBRID_IMPORT_ERROR))


__all__ = ["HybridCryptoProvider"]
