"""Kyber-768 (ML-KEM-768) key encapsulation wrapper using liboqs.

This module provides a thin, defensive wrapper around liboqs for a
Kyber-768-style KEM interface.
"""

from __future__ import annotations

import base64
import hmac
from dataclasses import dataclass

import oqs


class KyberKEMError(Exception):
    """Raised when Kyber KEM operations fail or inputs are invalid."""


@dataclass(frozen=True)
class KyberParameters:
    """Security and size parameters for Kyber-768."""

    algorithm: str = "Kyber768"
    nist_level: int = 3
    ind_cca: bool = True
    public_key_bytes: int = 1184
    secret_key_bytes: int = 2400
    ciphertext_bytes: int = 1088
    shared_secret_bytes: int = 32


class KyberKEM:
    """NIST Kyber-768 key encapsulation wrapper.

    The wrapper prefers the algorithm name "Kyber768" and falls back to
    "ML-KEM-768" if required by the installed liboqs version.
    """

    PARAMETERS = KyberParameters()
    PRIMARY_ALGORITHM = "Kyber768"
    FALLBACK_ALGORITHM = "ML-KEM-768"

    def __init__(self) -> None:
        self.algorithm = self._resolve_algorithm_name()

    def generate_keypair(self) -> tuple[bytes, bytes]:
        """Generate a public/secret keypair.

        Returns:
            Tuple of (public_key, secret_key) as raw bytes.
        """
        try:
            with oqs.KeyEncapsulation(self.algorithm) as kem:
                public_key = kem.generate_keypair()
                secret_key = kem.export_secret_key()
                self._validate_public_key(public_key)
                self._validate_secret_key(secret_key)
                return public_key, secret_key
        except Exception as exc:  # pragma: no cover - crypto boundary
            raise KyberKEMError("Failed to generate Kyber keypair") from exc

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        """Encapsulate a shared secret to a recipient public key.

        Args:
            public_key: Recipient Kyber public key bytes.

        Returns:
            Tuple of (ciphertext, shared_secret).
        """
        self._require_bytes("public_key", public_key)
        self._validate_public_key(public_key)

        try:
            with oqs.KeyEncapsulation(self.algorithm) as kem:
                ciphertext, shared_secret = kem.encap_secret(public_key)
                self._validate_ciphertext(ciphertext)
                self._validate_shared_secret(shared_secret)
                return ciphertext, shared_secret
        except Exception as exc:  # pragma: no cover - crypto boundary
            raise KyberKEMError("Failed to encapsulate shared secret") from exc

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate a shared secret from ciphertext.

        Args:
            secret_key: Recipient Kyber secret key bytes.
            ciphertext: Encapsulated ciphertext bytes.

        Returns:
            Shared secret bytes.
        """
        self._require_bytes("secret_key", secret_key)
        self._require_bytes("ciphertext", ciphertext)
        self._validate_secret_key(secret_key)
        self._validate_ciphertext(ciphertext)

        try:
            with self._kem_with_secret_key(secret_key) as kem:
                shared_secret = kem.decap_secret(ciphertext)
                self._validate_shared_secret(shared_secret)
                return shared_secret
        except Exception as exc:  # pragma: no cover - crypto boundary
            raise KyberKEMError("Failed to decapsulate shared secret") from exc

    @staticmethod
    def serialize_bytes(data: bytes) -> str:
        """Serialize binary key or ciphertext data to URL-safe base64 text."""
        KyberKEM._require_bytes("data", data)
        return base64.urlsafe_b64encode(data).decode("ascii")

    @staticmethod
    def deserialize_bytes(encoded: str) -> bytes:
        """Deserialize URL-safe base64 text back into binary data."""
        if not isinstance(encoded, str):
            raise KyberKEMError("encoded must be a string")
        try:
            return base64.urlsafe_b64decode(encoded.encode("ascii"))
        except Exception as exc:
            raise KyberKEMError("Invalid base64 data") from exc

    def _resolve_algorithm_name(self) -> str:
        available = set(oqs.get_enabled_kem_mechanisms())
        if self.PRIMARY_ALGORITHM in available:
            return self.PRIMARY_ALGORITHM
        if self.FALLBACK_ALGORITHM in available:
            return self.FALLBACK_ALGORITHM
        raise KyberKEMError(
            "Kyber KEM is not available in this liboqs build; expected Kyber768 or ML-KEM-768"
        )

    def _kem_with_secret_key(self, secret_key: bytes):
        # liboqs-python versions vary: some accept secret_key in constructor,
        # others provide import_secret_key on a constructed object.
        try:
            return oqs.KeyEncapsulation(self.algorithm, secret_key)
        except TypeError:
            kem = oqs.KeyEncapsulation(self.algorithm)
            if not hasattr(kem, "import_secret_key"):
                kem.free()
                raise KyberKEMError("Installed liboqs binding cannot import secret keys")
            kem.import_secret_key(secret_key)
            return kem

    def _validate_public_key(self, public_key: bytes) -> None:
        if not self._length_matches(public_key, self.PARAMETERS.public_key_bytes):
            raise KyberKEMError(
                f"Invalid public key length: expected {self.PARAMETERS.public_key_bytes} bytes"
            )

    def _validate_secret_key(self, secret_key: bytes) -> None:
        if not self._length_matches(secret_key, self.PARAMETERS.secret_key_bytes):
            raise KyberKEMError(
                f"Invalid secret key length: expected {self.PARAMETERS.secret_key_bytes} bytes"
            )

    def _validate_ciphertext(self, ciphertext: bytes) -> None:
        if not self._length_matches(ciphertext, self.PARAMETERS.ciphertext_bytes):
            raise KyberKEMError(
                f"Invalid ciphertext length: expected {self.PARAMETERS.ciphertext_bytes} bytes"
            )

    def _validate_shared_secret(self, shared_secret: bytes) -> None:
        if not self._length_matches(shared_secret, self.PARAMETERS.shared_secret_bytes):
            raise KyberKEMError(
                f"Invalid shared secret length: expected {self.PARAMETERS.shared_secret_bytes} bytes"
            )

    @staticmethod
    def _length_matches(data: bytes, expected: int) -> bool:
        return hmac.compare_digest(len(data).to_bytes(2, "big"), expected.to_bytes(2, "big"))

    @staticmethod
    def _require_bytes(name: str, value: object) -> None:
        if not isinstance(value, bytes):
            raise KyberKEMError(f"{name} must be bytes")


__all__ = ["KyberKEM", "KyberKEMError", "KyberParameters"]
