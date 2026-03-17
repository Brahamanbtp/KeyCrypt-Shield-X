"""Hybrid digital signatures combining EdDSA (Ed25519) and Dilithium-3.

The hybrid construction signs a single SHA-256 digest with both schemes and
requires both signatures to validate. This preserves classical assurances
(Ed25519) while adding post-quantum resilience (Dilithium-3).

Wire format:
    MAGIC(4) || VERSION(1) || FLAGS(1) || ED_LEN(2) || DIL_LEN(2) ||
    ed_signature || dilithium_signature
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass

from src.classical import eddsa
from src.pqc.dilithium import DilithiumError, DilithiumSigner


class HybridSignatureError(Exception):
    """Raised for hybrid signature validation or cryptographic failures."""


@dataclass(frozen=True)
class HybridSignatureBlob:
    """Structured representation of a hybrid signature payload."""

    ed25519_signature: bytes
    dilithium_signature: bytes
    deterministic: bool

    MAGIC = b"HSG1"
    VERSION = 1
    _DETERMINISTIC_FLAG = 0x01

    def serialize(self) -> bytes:
        if len(self.ed25519_signature) > 0xFFFF:
            raise HybridSignatureError("Ed25519 signature is too long")
        if len(self.dilithium_signature) > 0xFFFF:
            raise HybridSignatureError("Dilithium signature is too long")

        flags = self._DETERMINISTIC_FLAG if self.deterministic else 0

        return b"".join(
            [
                self.MAGIC,
                bytes([self.VERSION]),
                bytes([flags]),
                struct.pack(">H", len(self.ed25519_signature)),
                struct.pack(">H", len(self.dilithium_signature)),
                self.ed25519_signature,
                self.dilithium_signature,
            ]
        )

    @classmethod
    def deserialize(cls, data: bytes) -> "HybridSignatureBlob":
        if not isinstance(data, bytes):
            raise HybridSignatureError("signature data must be bytes")

        min_len = 4 + 1 + 1 + 2 + 2
        if len(data) < min_len:
            raise HybridSignatureError("hybrid signature is too short")

        if not hmac.compare_digest(data[:4], cls.MAGIC):
            raise HybridSignatureError("invalid hybrid signature magic")

        version = data[4]
        if version != cls.VERSION:
            raise HybridSignatureError(f"unsupported hybrid signature version: {version}")

        flags = data[5]
        deterministic = bool(flags & cls._DETERMINISTIC_FLAG)

        offset = 6
        (ed_len,) = struct.unpack(">H", data[offset : offset + 2])
        offset += 2
        (dil_len,) = struct.unpack(">H", data[offset : offset + 2])
        offset += 2

        if len(data) != offset + ed_len + dil_len:
            raise HybridSignatureError("hybrid signature length fields are invalid")

        ed_sig = data[offset : offset + ed_len]
        offset += ed_len
        dil_sig = data[offset : offset + dil_len]

        return cls(
            ed25519_signature=ed_sig,
            dilithium_signature=dil_sig,
            deterministic=deterministic,
        )


class HybridSignature:
    """Hybrid signature interface for Ed25519 + Dilithium-3.

    Message flow:
    1. Compute SHA-256(message) once.
    2. Sign digest with Ed25519.
    3. Sign same digest with Dilithium-3.
    4. Bundle both signatures into a compact binary payload.
    """

    def __init__(self) -> None:
        self._dilithium = DilithiumSigner()

    def sign(
        self,
        ed25519_secret_key: bytes,
        dilithium_secret_key: bytes,
        message: bytes,
        *,
        context: str | bytes | None = None,
        randomized: bool = True,
        deterministic: bool = False,
    ) -> bytes:
        """Generate a hybrid signature over a SHA-256 message digest.

        Args:
            ed25519_secret_key: Raw Ed25519 private key bytes.
            dilithium_secret_key: Raw Dilithium-3 private key bytes.
            message: Message bytes to sign.
            context: Optional context passed to Dilithium domain separation.
            randomized: Enables randomized mode for Dilithium wrapper.
            deterministic: Enables deterministic mode for Dilithium wrapper and
                records deterministic mode flag in serialized payload.

        Returns:
            Serialized hybrid signature payload.

        Raises:
            HybridSignatureError: If input validation or signing fails.
        """
        self._require_bytes("ed25519_secret_key", ed25519_secret_key)
        self._require_bytes("dilithium_secret_key", dilithium_secret_key)
        self._require_bytes("message", message)

        if deterministic and randomized:
            raise HybridSignatureError("deterministic and randomized modes are mutually exclusive")

        try:
            digest = self._hash_once(message)
            ed_sig = eddsa.sign(ed25519_secret_key, digest)
            dil_sig = self._dilithium.sign(
                dilithium_secret_key,
                digest,
                context=context,
                randomized=randomized,
                deterministic=deterministic,
            )

            return HybridSignatureBlob(
                ed25519_signature=ed_sig,
                dilithium_signature=dil_sig,
                deterministic=deterministic,
            ).serialize()
        except (TypeError, ValueError, RuntimeError, DilithiumError, HybridSignatureError) as exc:
            raise HybridSignatureError(f"hybrid signing failed: {exc}") from exc
        except Exception as exc:  # pragma: no cover - defensive crypto boundary
            raise HybridSignatureError("hybrid signing failed unexpectedly") from exc

    def verify(
        self,
        ed25519_public_key: bytes,
        dilithium_public_key: bytes,
        message: bytes,
        signature: bytes,
    ) -> bool:
        """Verify hybrid signature by requiring both component verifications.

        Args:
            ed25519_public_key: Raw Ed25519 public key bytes.
            dilithium_public_key: Raw Dilithium-3 public key bytes.
            message: Original message bytes.
            signature: Serialized hybrid signature payload.

        Returns:
            True only if both Ed25519 and Dilithium signatures verify.
        """
        try:
            self._require_bytes("ed25519_public_key", ed25519_public_key)
            self._require_bytes("dilithium_public_key", dilithium_public_key)
            self._require_bytes("message", message)
            self._require_bytes("signature", signature)

            digest = self._hash_once(message)
            payload = self.deserialize(signature)

            ed_ok = eddsa.verify(ed25519_public_key, digest, payload.ed25519_signature)
            if not ed_ok:
                return False

            dil_ok = self._dilithium.verify(dilithium_public_key, digest, payload.dilithium_signature)
            return bool(dil_ok)
        except (TypeError, ValueError, RuntimeError, DilithiumError, HybridSignatureError):
            return False
        except Exception:
            return False

    @staticmethod
    def serialize(payload: HybridSignatureBlob) -> bytes:
        """Serialize a HybridSignatureBlob instance to compact bytes."""
        if not isinstance(payload, HybridSignatureBlob):
            raise HybridSignatureError("payload must be HybridSignatureBlob")
        return payload.serialize()

    @staticmethod
    def deserialize(data: bytes) -> HybridSignatureBlob:
        """Deserialize compact bytes into HybridSignatureBlob."""
        return HybridSignatureBlob.deserialize(data)

    @staticmethod
    def _hash_once(message: bytes) -> bytes:
        return hashlib.sha256(message).digest()

    @staticmethod
    def _require_bytes(name: str, value: object) -> None:
        if not isinstance(value, bytes):
            raise HybridSignatureError(f"{name} must be bytes")


__all__ = ["HybridSignature", "HybridSignatureError", "HybridSignatureBlob"]
