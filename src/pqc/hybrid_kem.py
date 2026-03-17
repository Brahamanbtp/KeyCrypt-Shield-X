"""Hybrid KEM combining classical ECIES and post-quantum Kyber-768.

This construction provides defense-in-depth by requiring both a classical and a
post-quantum component to recover the final shared secret. The final key is
derived from both component shared secrets via HKDF-SHA256.

Design:
- Classical path: ECIES encrypts a random 32-byte secret to classical public key.
- PQC path: Kyber-768 encapsulates a 32-byte shared secret.
- Combiner: HKDF-SHA256 derives final secret from classical || pqc secrets.

Ciphertext wire format:
    MAGIC(4) || VERSION(1) || SALT(16) || ECIES_LEN(2) || ECIES_CT ||
    KYBER_LEN(2) || KYBER_CT
"""

from __future__ import annotations

import hmac
import os
import struct
from dataclasses import dataclass
from typing import Final

from src.classical import ecies
from src.classical.kdf import derive_key
from src.pqc.kyber import KyberKEM, KyberKEMError


class HybridKEMError(Exception):
    """Raised when hybrid KEM operations fail or inputs are invalid."""


@dataclass(frozen=True)
class HybridKEMParameters:
    """Security and format parameters for hybrid encapsulation."""

    final_shared_secret_bytes: int = 32
    classical_secret_bytes: int = 32
    kdf_salt_bytes: int = 16
    version: int = 1


@dataclass(frozen=True)
class HybridCiphertext:
    """Structured representation of hybrid ciphertext components."""

    salt: bytes
    classical_ciphertext: bytes
    pqc_ciphertext: bytes

    MAGIC: Final[bytes] = b"HKEM"

    def serialize(self) -> bytes:
        if len(self.classical_ciphertext) > 0xFFFF:
            raise HybridKEMError("classical ciphertext too long")
        if len(self.pqc_ciphertext) > 0xFFFF:
            raise HybridKEMError("pqc ciphertext too long")

        return b"".join(
            [
                self.MAGIC,
                bytes([1]),
                self.salt,
                struct.pack(">H", len(self.classical_ciphertext)),
                self.classical_ciphertext,
                struct.pack(">H", len(self.pqc_ciphertext)),
                self.pqc_ciphertext,
            ]
        )

    @classmethod
    def deserialize(cls, data: bytes) -> "HybridCiphertext":
        if not isinstance(data, bytes):
            raise HybridKEMError("ciphertext must be bytes")

        min_size = 4 + 1 + 16 + 2 + 2
        if len(data) < min_size:
            raise HybridKEMError("hybrid ciphertext is too short")

        if not hmac.compare_digest(data[:4], cls.MAGIC):
            raise HybridKEMError("invalid hybrid ciphertext magic header")

        version = data[4]
        if version != 1:
            raise HybridKEMError(f"unsupported hybrid ciphertext version: {version}")

        offset = 5
        salt = data[offset : offset + 16]
        offset += 16

        (classical_len,) = struct.unpack(">H", data[offset : offset + 2])
        offset += 2

        if len(data) < offset + classical_len + 2:
            raise HybridKEMError("invalid classical ciphertext length")

        classical_ciphertext = data[offset : offset + classical_len]
        offset += classical_len

        (pqc_len,) = struct.unpack(">H", data[offset : offset + 2])
        offset += 2

        if len(data) != offset + pqc_len:
            raise HybridKEMError("invalid pqc ciphertext length")

        pqc_ciphertext = data[offset : offset + pqc_len]

        return cls(
            salt=salt,
            classical_ciphertext=classical_ciphertext,
            pqc_ciphertext=pqc_ciphertext,
        )


class HybridKEM:
    """Hybrid KEM combining ECIES and Kyber-768.

    Security property:
    - Decapsulation requires both classical and PQC private keys.
    - An attacker must break both component schemes to recover the final secret.
    """

    PARAMETERS = HybridKEMParameters()
    _KDF_INFO: Final[bytes] = b"KeyCrypt-Shield-X HybridKEM v1"

    def __init__(self) -> None:
        self.kyber = KyberKEM()

    def encapsulate(self, classical_pk: bytes, pqc_pk: bytes) -> tuple[bytes, bytes]:
        """Encapsulate a hybrid shared secret for recipient key pair.

        Args:
            classical_pk: Receiver ECIES/X25519 public key bytes.
            pqc_pk: Receiver Kyber-768 public key bytes.

        Returns:
            Tuple of `(hybrid_ciphertext, shared_secret)`.

        Raises:
            HybridKEMError: If validation or encapsulation fails.
        """
        self._require_bytes("classical_pk", classical_pk)
        self._require_bytes("pqc_pk", pqc_pk)

        try:
            classical_secret = os.urandom(self.PARAMETERS.classical_secret_bytes)
            classical_ciphertext = ecies.encrypt(classical_pk, classical_secret)

            pqc_ciphertext, pqc_secret = self.kyber.encapsulate(pqc_pk)

            salt = os.urandom(self.PARAMETERS.kdf_salt_bytes)
            hybrid_secret = self._combine_secrets(classical_secret, pqc_secret, salt)

            payload = HybridCiphertext(
                salt=salt,
                classical_ciphertext=classical_ciphertext,
                pqc_ciphertext=pqc_ciphertext,
            ).serialize()
            return payload, hybrid_secret
        except (ValueError, TypeError, KyberKEMError, HybridKEMError) as exc:
            raise HybridKEMError(f"hybrid encapsulation failed: {exc}") from exc
        except Exception as exc:  # pragma: no cover - defensive crypto boundary
            raise HybridKEMError("hybrid encapsulation failed unexpectedly") from exc

    def decapsulate(self, classical_sk: bytes, pqc_sk: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate a hybrid shared secret.

        Args:
            classical_sk: Receiver ECIES/X25519 private key bytes.
            pqc_sk: Receiver Kyber-768 private key bytes.
            ciphertext: Hybrid ciphertext produced by encapsulate().

        Returns:
            Recovered 32-byte hybrid shared secret.

        Raises:
            HybridKEMError: If parsing, decapsulation, or validation fails.
        """
        self._require_bytes("classical_sk", classical_sk)
        self._require_bytes("pqc_sk", pqc_sk)
        self._require_bytes("ciphertext", ciphertext)

        try:
            payload = HybridCiphertext.deserialize(ciphertext)

            classical_secret = ecies.decrypt(classical_sk, payload.classical_ciphertext)
            pqc_secret = self.kyber.decapsulate(pqc_sk, payload.pqc_ciphertext)

            return self._combine_secrets(classical_secret, pqc_secret, payload.salt)
        except (ValueError, TypeError, KyberKEMError, HybridKEMError) as exc:
            raise HybridKEMError(f"hybrid decapsulation failed: {exc}") from exc
        except Exception as exc:  # pragma: no cover - defensive crypto boundary
            raise HybridKEMError("hybrid decapsulation failed unexpectedly") from exc

    def _combine_secrets(self, classical_secret: bytes, pqc_secret: bytes, salt: bytes) -> bytes:
        self._require_bytes("classical_secret", classical_secret)
        self._require_bytes("pqc_secret", pqc_secret)
        self._require_bytes("salt", salt)

        if not self._len_equals(classical_secret, self.PARAMETERS.classical_secret_bytes):
            raise HybridKEMError(
                f"invalid classical shared secret length: expected {self.PARAMETERS.classical_secret_bytes}"
            )
        if not self._len_equals(salt, self.PARAMETERS.kdf_salt_bytes):
            raise HybridKEMError(f"invalid KDF salt length: expected {self.PARAMETERS.kdf_salt_bytes}")

        ikm = classical_secret + pqc_secret
        return derive_key(
            input_key_material=ikm,
            salt=salt,
            info=self._KDF_INFO,
            length=self.PARAMETERS.final_shared_secret_bytes,
        )

    @staticmethod
    def _len_equals(value: bytes, expected: int) -> bool:
        return hmac.compare_digest(len(value).to_bytes(2, "big"), expected.to_bytes(2, "big"))

    @staticmethod
    def _require_bytes(name: str, value: object) -> None:
        if not isinstance(value, bytes):
            raise HybridKEMError(f"{name} must be bytes")


__all__ = ["HybridKEM", "HybridKEMError", "HybridKEMParameters", "HybridCiphertext"]
