"""Dependency injection container for provider composition.

This module defines the core DI container used to construct and wire provider
implementations while keeping concrete classes loosely coupled.
"""

from __future__ import annotations

from typing import Any, Iterable

from dependency_injector import containers, providers

from src.providers.crypto.classical_provider import ClassicalCryptoProvider
from src.providers.keys.local_key_provider import LocalKeyProvider
from src.providers.storage.local_storage_provider import LocalStorageProvider


class CoreContainer(containers.DeclarativeContainer):
    """Core DI container for cryptography, key, and storage providers."""

    config = providers.Configuration()

    crypto_provider = providers.Singleton(
        ClassicalCryptoProvider,
        algorithm="aes-gcm",
    )
    key_provider = providers.Singleton(LocalKeyProvider)
    storage_provider = providers.Singleton(LocalStorageProvider)

    def wire(
        self,
        modules: Iterable[Any] | None = None,
        packages: Iterable[Any] | None = None,
    ) -> None:
        """Wire container providers into target modules/packages.

        Args:
            modules: Optional modules to wire for dependency injection.
            packages: Optional packages to wire for dependency injection.
        """
        super().wire(modules=modules, packages=packages)


__all__ = ["CoreContainer"]
