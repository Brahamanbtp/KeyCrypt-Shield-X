"""Abstract interfaces for cryptographic primitive providers.

This module defines the provider contract used by higher-level orchestration
code to interact with concrete cryptographic implementations in a uniform way.

The abstraction is intentionally minimal and stable:
- `encrypt` and `decrypt` define the core data transformation behavior.
- `get_algorithm_name` exposes a human-readable algorithm identifier.
- `get_security_level` exposes a numeric security level for policy decisions.

Concrete implementations in algorithm-specific packages should subclass
`CryptoProvider` and implement all abstract methods.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class CryptoProvider(ABC):
    """Base interface for cryptographic primitive providers.

    A `CryptoProvider` encapsulates a specific cryptographic primitive
    implementation (for example, AES-GCM, ChaCha20-Poly1305, Kyber, or hybrid
    constructions) behind a common API. This allows orchestration layers to
    choose algorithms dynamically while preserving a consistent call pattern.

    Implementations should:
    - Validate inputs and context objects.
    - Raise explicit exceptions for invalid state or malformed data.
    - Keep behavior deterministic with respect to provided context.
    - Report stable algorithm and security metadata.
    """

    @abstractmethod
    def encrypt(self, plaintext: bytes, context: EncryptionContext) -> bytes:
        """Encrypt plaintext using provider-specific semantics.

        Parameters:
            plaintext: Raw message bytes to protect.
            context: Encryption configuration and metadata required by the
                concrete provider. This may include key identifiers, nonce/IV
                strategy, associated data, and policy flags.

        Returns:
            Serialized ciphertext bytes produced by the provider.

        Raises:
            ValueError: If inputs are invalid for the provider.
            RuntimeError: If the provider cannot complete the operation.
        """

    @abstractmethod
    def decrypt(self, ciphertext: bytes, context: DecryptionContext) -> bytes:
        """Decrypt ciphertext using provider-specific semantics.

        Parameters:
            ciphertext: Serialized encrypted bytes produced by a compatible
                provider.
            context: Decryption configuration and metadata required by the
                concrete provider. This may include key identifiers,
                associated data, and integrity verification options.

        Returns:
            The recovered plaintext bytes.

        Raises:
            ValueError: If ciphertext or context is invalid.
            RuntimeError: If decryption or integrity validation fails.
        """

    @abstractmethod
    def get_algorithm_name(self) -> str:
        """Return a stable, human-readable identifier for the algorithm.

        Returns:
            A non-empty algorithm name such as ``"AES-GCM-256"`` or
            ``"KYBER-768-HYBRID"``.
        """

    @abstractmethod
    def get_security_level(self) -> int:
        """Return the provider's security level as an integer.

        The returned value is intended for policy and risk-based routing.
        Implementations should document the scale they use (for example,
        NIST level mappings or equivalent bit-security approximations).

        Returns:
            A positive integer representing security strength.
        """
