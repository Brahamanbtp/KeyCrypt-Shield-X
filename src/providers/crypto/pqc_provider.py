"""Post-quantum cryptography provider adapter.

This module implements a `CryptoProvider` adapter over existing PQC
implementations without modifying them. It supports:
- kyber-768 via KyberKEM
- dilithium-3 via DilithiumSigner

Graceful degradation is provided when optional PQC dependencies are missing.
"""

from __future__ import annotations

import hashlib
from typing import Any, Literal, Mapping

from src.abstractions.crypto_provider import CryptoProvider

try:
    from src.pqc.kyber import KyberKEM
except Exception as exc:  # pragma: no cover - optional dependency boundary
    KyberKEM = None  # type: ignore[assignment]
    _KYBER_IMPORT_ERROR = exc
else:
    _KYBER_IMPORT_ERROR = None

try:
    from src.pqc.dilithium import DilithiumSigner
except Exception as exc:  # pragma: no cover - optional dependency boundary
    DilithiumSigner = None  # type: ignore[assignment]
    _DILITHIUM_IMPORT_ERROR = exc
else:
    _DILITHIUM_IMPORT_ERROR = None


class PQCCryptoProvider(CryptoProvider):
    """Adapter over existing PQC implementations.

    Supported algorithms:
    - "kyber-768": KEM-based hybrid payload protection.
    - "dilithium-3": signature-backed payload authenticity wrapper.

    Context for "kyber-768":
    - encrypt requires recipient_public_key: bytes
    - decrypt requires recipient_secret_key: bytes

    Context for "dilithium-3":
    - encrypt requires signing_secret_key: bytes
    - decrypt requires verification_public_key: bytes
    - optional signature_context: str | bytes | None
    """

    _LEN_PREFIX_SIZE = 4

    def __init__(self, algorithm: Literal["kyber-768", "dilithium-3"]) -> None:
        normalized = algorithm.strip().lower()
        if normalized not in {"kyber-768", "dilithium-3"}:
            raise ValueError("algorithm must be 'kyber-768' or 'dilithium-3'")

        self._algorithm: Literal["kyber-768", "dilithium-3"] = normalized  # type: ignore[assignment]
        self._ensure_algorithm_available()

    def encrypt(self, plaintext: bytes, context: EncryptionContext) -> bytes:
        """Encrypt using selected PQC adapter semantics."""
        self._require_bytes("plaintext", plaintext)

        if self._algorithm == "kyber-768":
            return self._encrypt_kyber(plaintext, context)
        return self._encrypt_dilithium(plaintext, context)

    def decrypt(self, ciphertext: bytes, context: DecryptionContext) -> bytes:
        """Decrypt using selected PQC adapter semantics."""
        self._require_bytes("ciphertext", ciphertext)

        if self._algorithm == "kyber-768":
            return self._decrypt_kyber(ciphertext, context)
        return self._decrypt_dilithium(ciphertext, context)

    def get_algorithm_name(self) -> str:
        return self._algorithm

    def get_security_level(self) -> int:
        return 3

    def _encrypt_kyber(self, plaintext: bytes, context: Any) -> bytes:
        if KyberKEM is None:
            raise RuntimeError(self._missing_dependency_message("kyber-768", _KYBER_IMPORT_ERROR))

        public_key = self._extract_required_bytes(context, "recipient_public_key")
        kem = KyberKEM()
        kem_ciphertext, shared_secret = kem.encapsulate(public_key)

        keystream = self._expand_keystream(shared_secret, len(plaintext))
        wrapped_plaintext = self._xor_bytes(plaintext, keystream)

        return self._pack_parts(kem_ciphertext, wrapped_plaintext)

    def _decrypt_kyber(self, ciphertext: bytes, context: Any) -> bytes:
        if KyberKEM is None:
            raise RuntimeError(self._missing_dependency_message("kyber-768", _KYBER_IMPORT_ERROR))

        secret_key = self._extract_required_bytes(context, "recipient_secret_key")
        kem_ciphertext, wrapped_plaintext = self._unpack_parts(ciphertext)

        kem = KyberKEM()
        shared_secret = kem.decapsulate(secret_key, kem_ciphertext)

        keystream = self._expand_keystream(shared_secret, len(wrapped_plaintext))
        return self._xor_bytes(wrapped_plaintext, keystream)

    def _encrypt_dilithium(self, plaintext: bytes, context: Any) -> bytes:
        if DilithiumSigner is None:
            raise RuntimeError(self._missing_dependency_message("dilithium-3", _DILITHIUM_IMPORT_ERROR))

        secret_key = self._extract_required_bytes(context, "signing_secret_key")
        signature_context = self._extract_optional_signature_context(context)

        signer = DilithiumSigner()
        signature = signer.sign(secret_key, plaintext, context=signature_context)

        return self._pack_parts(signature, plaintext)

    def _decrypt_dilithium(self, ciphertext: bytes, context: Any) -> bytes:
        if DilithiumSigner is None:
            raise RuntimeError(self._missing_dependency_message("dilithium-3", _DILITHIUM_IMPORT_ERROR))

        public_key = self._extract_required_bytes(context, "verification_public_key")
        signature, payload = self._unpack_parts(ciphertext)

        signer = DilithiumSigner()
        if not signer.verify(public_key, payload, signature):
            raise ValueError("Dilithium verification failed")

        return payload

    def _ensure_algorithm_available(self) -> None:
        if self._algorithm == "kyber-768" and KyberKEM is None:
            raise RuntimeError(self._missing_dependency_message("kyber-768", _KYBER_IMPORT_ERROR))
        if self._algorithm == "dilithium-3" and DilithiumSigner is None:
            raise RuntimeError(self._missing_dependency_message("dilithium-3", _DILITHIUM_IMPORT_ERROR))

    @staticmethod
    def _missing_dependency_message(algorithm: str, error: Exception | None) -> str:
        reason = f": {error}" if error is not None else ""
        return (
            f"PQC provider for {algorithm} is unavailable{reason}. "
            "Install compatible liboqs/oqs-python dependencies to enable this algorithm."
        )

    @staticmethod
    def _extract_required_bytes(context: Any, key: str) -> bytes:
        value = PQCCryptoProvider._extract_value(context, key)
        if not isinstance(value, bytes):
            raise ValueError(f"context.{key} must be bytes")
        return value

    @staticmethod
    def _extract_optional_signature_context(context: Any) -> str | bytes | None:
        value = PQCCryptoProvider._extract_value(context, "signature_context")
        if value is None or isinstance(value, (str, bytes)):
            return value
        raise ValueError("context.signature_context must be str, bytes, or None")

    @staticmethod
    def _extract_value(context: Any, key: str) -> Any:
        if isinstance(context, Mapping):
            return context.get(key)
        return getattr(context, key, None)

    @classmethod
    def _pack_parts(cls, first: bytes, second: bytes) -> bytes:
        if len(first) > 0xFFFFFFFF:
            raise ValueError("first payload section too large")
        return len(first).to_bytes(cls._LEN_PREFIX_SIZE, "big") + first + second

    @classmethod
    def _unpack_parts(cls, payload: bytes) -> tuple[bytes, bytes]:
        if len(payload) < cls._LEN_PREFIX_SIZE + 1:
            raise ValueError("ciphertext is too short")

        first_len = int.from_bytes(payload[: cls._LEN_PREFIX_SIZE], "big")
        start = cls._LEN_PREFIX_SIZE
        end = start + first_len

        if end > len(payload) - 1:
            raise ValueError("ciphertext payload is malformed")

        first = payload[start:end]
        second = payload[end:]
        if not second:
            raise ValueError("ciphertext payload is missing second section")

        return first, second

    @staticmethod
    def _expand_keystream(seed: bytes, length: int) -> bytes:
        if length < 0:
            raise ValueError("length must be non-negative")
        if length == 0:
            return b""

        blocks = []
        counter = 0
        while sum(len(block) for block in blocks) < length:
            counter_bytes = counter.to_bytes(4, "big")
            blocks.append(hashlib.sha256(seed + counter_bytes).digest())
            counter += 1
        return b"".join(blocks)[:length]

    @staticmethod
    def _xor_bytes(left: bytes, right: bytes) -> bytes:
        if len(left) != len(right):
            raise ValueError("byte sequences must have equal length")
        return bytes(a ^ b for a, b in zip(left, right))

    @staticmethod
    def _require_bytes(name: str, value: object) -> None:
        if not isinstance(value, bytes):
            raise TypeError(f"{name} must be bytes")


__all__ = ["PQCCryptoProvider"]
