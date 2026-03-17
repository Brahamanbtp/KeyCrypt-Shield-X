"""Dilithium-3 (post-quantum) digital signature wrapper using liboqs.

This module exposes a defensive wrapper around the NIST-selected lattice-based
signature family through liboqs.

Security overview:
- Dilithium-3 targets NIST security level 3 and is designed to resist attacks
  from both classical and quantum adversaries.
- Signatures are EUF-CMA secure in the intended model when keys are generated
  with strong entropy and implementation guidance is followed.
- Context binding is supported here to provide domain separation across
  protocols (for example, API signing vs. storage metadata signing).
- Randomized mode adds per-signature entropy at the wrapper layer to reduce
  cross-context misuse risk and provide stronger unlinkability properties.

Note:
- This wrapper supports both historical naming ("Dilithium3") and newer
  liboqs naming ("ML-DSA-65") when available.
"""

from __future__ import annotations

import hmac
import os
from dataclasses import dataclass

import oqs


class DilithiumError(Exception):
    """Raised when Dilithium operations fail or inputs are invalid."""


@dataclass(frozen=True)
class DilithiumParameters:
    """Security and size parameters for Dilithium-3."""

    algorithm: str = "Dilithium3"
    nist_level: int = 3
    existential_unforgeability: str = "EUF-CMA"
    public_key_bytes: int = 1952
    secret_key_bytes: int = 4000
    signature_bytes: int = 3293
    randomizer_bytes: int = 32


class DilithiumSigner:
    """Dilithium-3 signature API with context and mode support.

    The public interface matches common signing workflows:
    - generate_keypair()
    - sign(secret_key, message, ...)
    - verify(public_key, message, signature)

    Signature wire format:
        MAGIC(4) || FLAGS(1) || CTX_LEN(1) || context || randomizer || raw_signature

    Flags:
    - bit0 (0x01): randomized signing enabled
    """

    PARAMETERS = DilithiumParameters()
    PRIMARY_ALGORITHM = "Dilithium3"
    FALLBACK_ALGORITHM = "ML-DSA-65"

    _MAGIC = b"KXD3"
    _RANDOMIZED_FLAG = 0x01
    _DOMAIN_PREFIX = b"keycrypt:dilithium3:v1"

    def __init__(self) -> None:
        self.algorithm = self._resolve_algorithm_name()

    def generate_keypair(self) -> tuple[bytes, bytes]:
        """Generate a Dilithium-3 keypair.

        Returns:
            Tuple of (public_key, secret_key) as raw bytes.
        """
        try:
            with oqs.Signature(self.algorithm) as signer:
                public_key = signer.generate_keypair()
                secret_key = signer.export_secret_key()
                self._validate_public_key(public_key)
                self._validate_secret_key(secret_key)
                return public_key, secret_key
        except Exception as exc:  # pragma: no cover - crypto boundary
            raise DilithiumError("Failed to generate Dilithium keypair") from exc

    def sign(
        self,
        secret_key: bytes,
        message: bytes,
        *,
        context: str | bytes | None = None,
        randomized: bool = True,
        deterministic: bool = False,
    ) -> bytes:
        """Sign a message with Dilithium-3.

        Args:
            secret_key: Raw secret key bytes.
            message: Message bytes to sign.
            context: Optional context string/bytes for domain separation.
            randomized: Enables wrapper-level randomizer bytes in signed payload.
            deterministic: Disables wrapper randomizer to keep preprocessing
                deterministic for a fixed (message, context).

        Returns:
            Encoded signature bytes that include context/mode metadata.

        Raises:
            DilithiumError: On malformed inputs or signing failures.

        Security notes:
        - In deterministic mode, this wrapper removes its own randomness layer.
          Backend determinism depends on the liboqs implementation details.
        - In randomized mode, a random 32-byte value is injected into the
          signed transcript to strengthen context separation across sessions.
        """
        self._require_bytes("secret_key", secret_key)
        self._require_bytes("message", message)
        self._validate_secret_key(secret_key)

        if deterministic and randomized:
            raise DilithiumError("deterministic and randomized modes are mutually exclusive")

        context_bytes = self._normalize_context(context)
        if len(context_bytes) > 255:
            raise DilithiumError("context must be at most 255 bytes")

        use_randomizer = not deterministic and randomized
        randomizer = os.urandom(self.PARAMETERS.randomizer_bytes) if use_randomizer else b""

        sign_input = self._build_signing_input(message, context_bytes, randomizer)

        try:
            with self._signer_with_secret_key(secret_key) as signer:
                raw_signature = signer.sign(sign_input)
                self._validate_raw_signature(raw_signature)
                return self._encode_signature(context_bytes, randomizer, raw_signature)
        except DilithiumError:
            raise
        except Exception as exc:  # pragma: no cover - crypto boundary
            raise DilithiumError("Failed to sign message with Dilithium") from exc

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify a Dilithium-3 signature.

        Args:
            public_key: Raw public key bytes.
            message: Message bytes that were signed.
            signature: Encoded signature blob returned by sign().

        Returns:
            True if signature verifies, otherwise False.

        Raises:
            DilithiumError: For malformed key material and non-bytes inputs.
        """
        self._require_bytes("public_key", public_key)
        self._require_bytes("message", message)
        self._require_bytes("signature", signature)
        self._validate_public_key(public_key)

        try:
            context_bytes, randomizer, raw_signature = self._decode_signature(signature)
            sign_input = self._build_signing_input(message, context_bytes, randomizer)

            with oqs.Signature(self.algorithm) as signer:
                return bool(signer.verify(sign_input, raw_signature, public_key))
        except DilithiumError:
            return False
        except Exception:
            return False

    def _build_signing_input(self, message: bytes, context: bytes, randomizer: bytes) -> bytes:
        return (
            self._DOMAIN_PREFIX
            + bytes([len(context)])
            + context
            + bytes([len(randomizer)])
            + randomizer
            + message
        )

    def _encode_signature(self, context: bytes, randomizer: bytes, raw_signature: bytes) -> bytes:
        flags = self._RANDOMIZED_FLAG if randomizer else 0
        return self._MAGIC + bytes([flags]) + bytes([len(context)]) + context + randomizer + raw_signature

    def _decode_signature(self, signature_blob: bytes) -> tuple[bytes, bytes, bytes]:
        min_header = 6
        if len(signature_blob) < min_header:
            raise DilithiumError("signature blob is too short")

        if not hmac.compare_digest(signature_blob[:4], self._MAGIC):
            raise DilithiumError("invalid signature header")

        flags = signature_blob[4]
        context_len = signature_blob[5]

        offset = 6
        if len(signature_blob) < offset + context_len:
            raise DilithiumError("invalid signature context length")

        context = signature_blob[offset : offset + context_len]
        offset += context_len

        randomized = bool(flags & self._RANDOMIZED_FLAG)
        randomizer_len = self.PARAMETERS.randomizer_bytes if randomized else 0

        if len(signature_blob) < offset + randomizer_len + 1:
            raise DilithiumError("signature blob is incomplete")

        randomizer = signature_blob[offset : offset + randomizer_len]
        offset += randomizer_len

        raw_signature = signature_blob[offset:]
        self._validate_raw_signature(raw_signature)
        return context, randomizer, raw_signature

    def _resolve_algorithm_name(self) -> str:
        available = set(oqs.get_enabled_sig_mechanisms())
        if self.PRIMARY_ALGORITHM in available:
            return self.PRIMARY_ALGORITHM
        if self.FALLBACK_ALGORITHM in available:
            return self.FALLBACK_ALGORITHM
        raise DilithiumError(
            "Dilithium is not available in this liboqs build; expected Dilithium3 or ML-DSA-65"
        )

    def _signer_with_secret_key(self, secret_key: bytes):
        # liboqs-python API differs across versions.
        try:
            return oqs.Signature(self.algorithm, secret_key)
        except TypeError:
            signer = oqs.Signature(self.algorithm)
            if not hasattr(signer, "import_secret_key"):
                signer.free()
                raise DilithiumError("Installed liboqs binding cannot import secret keys")
            signer.import_secret_key(secret_key)
            return signer

    def _validate_public_key(self, public_key: bytes) -> None:
        if not self._length_matches(public_key, self.PARAMETERS.public_key_bytes):
            raise DilithiumError(
                f"invalid public key length: expected {self.PARAMETERS.public_key_bytes} bytes"
            )

    def _validate_secret_key(self, secret_key: bytes) -> None:
        if not self._length_matches(secret_key, self.PARAMETERS.secret_key_bytes):
            raise DilithiumError(
                f"invalid secret key length: expected {self.PARAMETERS.secret_key_bytes} bytes"
            )

    def _validate_raw_signature(self, signature: bytes) -> None:
        if not signature:
            raise DilithiumError("signature must not be empty")

        # Dilithium signatures are fixed-size in common parameterizations.
        # Some bindings may return slightly different encodings, so we allow
        # values up to the known size and reject obvious malformed lengths.
        if len(signature) > self.PARAMETERS.signature_bytes:
            raise DilithiumError(
                f"signature too long: maximum {self.PARAMETERS.signature_bytes} bytes"
            )

    @staticmethod
    def _normalize_context(context: str | bytes | None) -> bytes:
        if context is None:
            return b""
        if isinstance(context, str):
            return context.encode("utf-8")
        if isinstance(context, bytes):
            return context
        raise DilithiumError("context must be str, bytes, or None")

    @staticmethod
    def _length_matches(data: bytes, expected: int) -> bool:
        return hmac.compare_digest(len(data).to_bytes(2, "big"), expected.to_bytes(2, "big"))

    @staticmethod
    def _require_bytes(name: str, value: object) -> None:
        if not isinstance(value, bytes):
            raise DilithiumError(f"{name} must be bytes")


__all__ = ["DilithiumSigner", "DilithiumParameters", "DilithiumError"]
