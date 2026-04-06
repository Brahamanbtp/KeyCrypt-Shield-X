"""Educational custom crypto provider plugin for developers.

WARNING:
- This implementation uses a simple XOR stream operation.
- XOR is NOT secure for production cryptography.
- Do not use this provider for real secrets, regulated data, or deployment.

Purpose:
- Show plugin developers how to implement the CryptoProvider interface.
- Provide a tiny, easy-to-read reference implementation.
- Demonstrate context-driven key extraction and deterministic behavior.
"""

from __future__ import annotations

import warnings
from typing import Any, Mapping

from src.abstractions.crypto_provider import CryptoProvider


class ExampleXORCryptoProvider(CryptoProvider):
    """Educational CryptoProvider example using XOR.

    Security warning:
    - XOR with a repeated key is cryptographically weak.
    - This class exists only as a plugin-development reference.

    Supported context key fields:
    - context.key
    - context.xor_key
    - context.metadata["key"]
    - context.metadata["xor_key"]
    - mapping-style equivalents when context is a dict-like object
    """

    def __init__(self, *, default_key: bytes | None = None, emit_warning: bool = True) -> None:
        # Keep an optional fallback key to simplify experimentation.
        # Real providers should require key material from secure key management.
        if default_key is not None:
            self._require_non_empty_bytes("default_key", default_key)
        self._default_key = default_key

        # Emit a loud runtime warning so this sample cannot be mistaken for
        # production-grade cryptography.
        if emit_warning:
            warnings.warn(
                "ExampleXORCryptoProvider is for educational use only. "
                "XOR encryption is NOT secure.",
                RuntimeWarning,
                stacklevel=2,
            )

    def encrypt(self, plaintext: bytes, context: EncryptionContext) -> bytes:
        """Encrypt plaintext bytes using XOR with key material from context.

        Educational note:
        XOR encryption is a byte-wise operation where each plaintext byte is
        combined with one key byte. The key bytes are repeated in a cycle.
        """
        # Validate input type early so plugin users get a clear error message.
        self._require_bytes("plaintext", plaintext)

        # Pull the XOR key from the provided context object or mapping.
        key = self._extract_key_from_context(context)

        # XOR is symmetric: the exact same transformation is used for both
        # encryption and decryption.
        return self._xor_bytes(plaintext, key)

    def decrypt(self, ciphertext: bytes, context: DecryptionContext) -> bytes:
        """Decrypt ciphertext bytes using XOR with key material from context.

        Educational note:
        Because XOR is reversible by applying the same operation twice,
        decryption is the same function as encryption.
        """
        # Validate ciphertext input for consistent provider behavior.
        self._require_bytes("ciphertext", ciphertext)

        # Use the same context key extraction logic as encrypt().
        key = self._extract_key_from_context(context)

        # Apply XOR again to recover original plaintext.
        return self._xor_bytes(ciphertext, key)

    def get_algorithm_name(self) -> str:
        # Keep the algorithm name explicit so policy/routing layers can mark
        # this provider as educational and non-production.
        return "XOR-EDUCATIONAL"

    def get_security_level(self) -> int:
        # Return the minimum nominal level to discourage accidental selection
        # for higher-assurance policy requirements.
        return 1

    def _extract_key_from_context(self, context: Any) -> bytes:
        # Accept a few field names to make this sample easy to integrate in
        # different plugin experiments.
        candidates = (
            self._extract_value(context, "key"),
            self._extract_value(context, "xor_key"),
        )

        for candidate in candidates:
            if isinstance(candidate, bytes) and candidate:
                return candidate

        # If context exposes a metadata container, check there too.
        metadata = self._extract_value(context, "metadata")
        if isinstance(metadata, Mapping):
            meta_key = metadata.get("key")
            meta_xor_key = metadata.get("xor_key")
            if isinstance(meta_key, bytes) and meta_key:
                return meta_key
            if isinstance(meta_xor_key, bytes) and meta_xor_key:
                return meta_xor_key

        # Fall back to constructor-provided key for quick demos.
        if isinstance(self._default_key, bytes) and self._default_key:
            return self._default_key

        # If no key is available, fail with actionable guidance.
        raise ValueError(
            "XOR key not found in context. Provide bytes in context.key, "
            "context.xor_key, or metadata['key']/metadata['xor_key']."
        )

    @staticmethod
    def _xor_bytes(data: bytes, key: bytes) -> bytes:
        # Defensive checks keep this helper safe to call from both encrypt and
        # decrypt paths.
        ExampleXORCryptoProvider._require_non_empty_bytes("data", data)
        ExampleXORCryptoProvider._require_non_empty_bytes("key", key)

        # Repeat key bytes across the full payload length.
        key_len = len(key)

        # XOR each payload byte with the corresponding repeated key byte.
        return bytes(byte ^ key[index % key_len] for index, byte in enumerate(data))

    @staticmethod
    def _extract_value(context: Any, field: str) -> Any:
        # Support both mapping-like and attribute-style contexts to mirror
        # common plugin integration patterns in this repository.
        if isinstance(context, Mapping):
            return context.get(field)
        return getattr(context, field, None)

    @staticmethod
    def _require_bytes(name: str, value: object) -> None:
        if not isinstance(value, bytes):
            raise TypeError(f"{name} must be bytes")

    @staticmethod
    def _require_non_empty_bytes(name: str, value: object) -> None:
        if not isinstance(value, bytes) or len(value) == 0:
            raise ValueError(f"{name} must be non-empty bytes")


__all__ = ["ExampleXORCryptoProvider"]
