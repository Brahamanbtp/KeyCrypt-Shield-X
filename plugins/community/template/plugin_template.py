"""Quick-start plugin template for KeyCrypt provider developers.

This file is a scaffold that demonstrates a consistent plugin structure with:
- Interface implementation skeleton
- Configuration loading in __init__
- Logging integration
- Error handling conventions
- Type hints and developer-facing docstrings

STEP-BY-STEP QUICK START:
1. Copy this file and rename it for your plugin (for example: acme_provider.py).
2. Rename `TemplatePluginProvider` to your real provider class name.
3. Choose your interface:
   - Keep `CryptoProvider` for encryption providers.
   - Or replace the base class with another abstraction (for example,
     `KeyProvider` or `StorageProvider`) and implement that interface's
     required methods.
4. Update configuration keys in `TemplateConfig` and `_load_config`.
5. Replace TODO sections inside each abstract method with real logic.
6. Add unit tests before shipping your provider.

IMPORTANT:
- This template intentionally raises `NotImplementedError` in abstract
  methods so developers must provide real implementations.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Mapping

from src.abstractions.crypto_provider import CryptoProvider

# NOTE:
# The abstraction currently references EncryptionContext/DecryptionContext names
# in method signatures. We keep aliases here so this template is import-safe
# even before developers wire in project-specific context classes.
EncryptionContext = Any
DecryptionContext = Any


@dataclass(frozen=True)
class TemplateConfig:
    """Typed configuration consumed by TemplatePluginProvider.

    Attributes:
        provider_name: Human-readable provider identifier.
        enabled: Whether provider should accept operations.
        strict_mode: If true, enforce stricter runtime checks.
        default_timeout_seconds: Optional operation timeout hint.
    """

    provider_name: str = "template-provider"
    enabled: bool = True
    strict_mode: bool = False
    default_timeout_seconds: float = 10.0


class TemplateProviderError(RuntimeError):
    """Raised when provider operations fail unexpectedly."""


class TemplatePluginProvider(CryptoProvider):
    """Boilerplate CryptoProvider implementation for plugin authors.

    By default this scaffold targets `CryptoProvider`. To use a different
    interface, replace the base class and update method stubs accordingly.
    """

    def __init__(self, config: Mapping[str, Any] | None = None) -> None:
        """Initialize provider state and load plugin configuration.

        Args:
            config: Optional mapping of runtime configuration values.

        Raises:
            ValueError: If config contains invalid values.
        """
        # STEP 1: Keep logger setup in __init__ so every provider instance has
        # predictable observability.
        self._logger = logging.getLogger(self.__class__.__name__)

        # STEP 2: Normalize and validate config in one place.
        self._config = self._load_config(config)

        # STEP 3: Apply logger level based on config so plugin behavior is easy
        # to inspect while debugging integrations.
        self._logger.setLevel(logging.DEBUG if self._config.strict_mode else logging.INFO)
        self._logger.debug("Provider initialized with config: %s", self._config)

    def encrypt(self, plaintext: bytes, context: EncryptionContext) -> bytes:
        """Encrypt plaintext bytes.

        TODO IMPLEMENTATION STEPS:
        1. Validate plaintext and context fields your algorithm requires.
        2. Resolve key/nonce/associated-data inputs from context.
        3. Perform encryption and return serialized ciphertext bytes.
        4. Add structured debug logging (never log secrets).
        """
        self._require_bytes("plaintext", plaintext)
        self._ensure_enabled("encrypt")

        try:
            self._logger.debug("Starting encrypt operation; input_size=%d", len(plaintext))

            # TODO: Replace with real encryption logic.
            raise NotImplementedError("TODO: implement encrypt() for this provider")
        except NotImplementedError:
            raise
        except Exception as exc:
            raise self._wrap_error("encrypt", exc) from exc

    def decrypt(self, ciphertext: bytes, context: DecryptionContext) -> bytes:
        """Decrypt ciphertext bytes.

        TODO IMPLEMENTATION STEPS:
        1. Validate ciphertext and required context parameters.
        2. Parse ciphertext envelope/metadata format if applicable.
        3. Perform decryption and return plaintext bytes.
        4. Validate authenticity/integrity where required.
        """
        self._require_bytes("ciphertext", ciphertext)
        self._ensure_enabled("decrypt")

        try:
            self._logger.debug("Starting decrypt operation; input_size=%d", len(ciphertext))

            # TODO: Replace with real decryption logic.
            raise NotImplementedError("TODO: implement decrypt() for this provider")
        except NotImplementedError:
            raise
        except Exception as exc:
            raise self._wrap_error("decrypt", exc) from exc

    def get_algorithm_name(self) -> str:
        """Return algorithm identifier for policy/routing decisions.

        TODO:
        - Return a stable, non-empty name such as "AES-GCM-256".
        """
        # TODO: Replace with your algorithm identifier.
        return "TEMPLATE-ALGORITHM"

    def get_security_level(self) -> int:
        """Return numeric security level used by policy engines.

        TODO:
        - Return an integer consistent with your project's policy scale.
        """
        # TODO: Replace with your provider's real security level mapping.
        return 1

    def _load_config(self, config: Mapping[str, Any] | None) -> TemplateConfig:
        """Validate and normalize raw configuration into a typed object.

        Args:
            config: Optional runtime configuration mapping.

        Returns:
            A validated `TemplateConfig` instance.

        Raises:
            ValueError: If config values are invalid.
        """
        raw = dict(config or {})

        provider_name = str(raw.get("provider_name", "template-provider")).strip()
        if not provider_name:
            raise ValueError("config.provider_name must be a non-empty string")

        enabled = bool(raw.get("enabled", True))
        strict_mode = bool(raw.get("strict_mode", False))

        timeout_raw = raw.get("default_timeout_seconds", 10.0)
        try:
            timeout = float(timeout_raw)
        except (TypeError, ValueError) as exc:
            raise ValueError("config.default_timeout_seconds must be numeric") from exc
        if timeout <= 0:
            raise ValueError("config.default_timeout_seconds must be > 0")

        return TemplateConfig(
            provider_name=provider_name,
            enabled=enabled,
            strict_mode=strict_mode,
            default_timeout_seconds=timeout,
        )

    def _ensure_enabled(self, operation: str) -> None:
        """Guard operation entrypoints when provider is disabled."""
        if not self._config.enabled:
            raise TemplateProviderError(
                f"Provider '{self._config.provider_name}' is disabled; cannot run {operation}"
            )

    def _wrap_error(self, operation: str, error: Exception) -> TemplateProviderError:
        """Convert internal exceptions into a stable provider error type."""
        self._logger.exception("Provider operation failed: %s", operation)
        return TemplateProviderError(f"{operation} failed: {error}")

    @staticmethod
    def _require_bytes(name: str, value: object) -> None:
        if not isinstance(value, bytes):
            raise TypeError(f"{name} must be bytes")


# OPTIONAL EXPANSION GUIDE:
# If your plugin should implement a different interface, replace the base class
# and provide that interface's required abstract methods, for example:
# - KeyProvider: get_key(), generate_key(), rotate_key(), list_keys()
# - StorageProvider: async write(), read(), delete(), list_objects()


__all__ = [
    "TemplateConfig",
    "TemplateProviderError",
    "TemplatePluginProvider",
]
