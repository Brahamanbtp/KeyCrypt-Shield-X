"""Factory for dynamic dependency injection container construction.

This module builds and manages named DI containers using configuration-driven
provider selection while remaining compatible with the existing CoreContainer.
"""

from __future__ import annotations

import importlib
import threading
from copy import deepcopy
from types import ModuleType
from typing import Any, Mapping, TypeAlias

from dependency_injector import providers

from src.abstractions.crypto_provider import CryptoProvider
from src.abstractions.key_provider import KeyProvider
from src.abstractions.storage_provider import StorageProvider
from src.orchestration.dependency_container import CoreContainer


Configuration: TypeAlias = Mapping[str, Any]
DependencyContainer: TypeAlias = CoreContainer


class ContainerFactory:
    """Builds and manages named DI containers from runtime configuration.

    Supported environments include arbitrary named containers such as
    `production`, `testing`, and `development`.

    Provider selection is config-driven and supports custom provider
    registration per interface.
    """

    _DEFAULT_PROVIDER_CONFIG: dict[str, dict[str, Any]] = {
        "crypto": {"name": "classical", "kwargs": {"algorithm": "aes-gcm"}},
        "key": {"name": "local", "kwargs": {}},
        "storage": {"name": "local", "kwargs": {}},
    }

    _PROVIDER_MODULE_MAP: dict[str, dict[str, str]] = {
        "crypto": {
            "classical": "src.providers.crypto.classical_provider:ClassicalCryptoProvider",
            "pqc": "src.providers.crypto.pqc_provider:PQCCryptoProvider",
            "hybrid": "src.providers.crypto.hybrid_provider:HybridCryptoProvider",
        },
        "key": {
            "local": "src.providers.keys.local_key_provider:LocalKeyProvider",
            "hsm": "src.providers.keys.hsm_key_provider:HSMKeyProvider",
            "kms": "src.providers.keys.kms_key_provider:KMSKeyProvider",
        },
        "storage": {
            "local": "src.providers.storage.local_storage_provider:LocalStorageProvider",
            "s3": "src.providers.storage.s3_storage_provider:S3StorageProvider",
            "gcs": "src.providers.storage.gcs_storage_provider:GCSStorageProvider",
        },
    }

    _INTERFACE_BY_KIND: dict[str, type[Any]] = {
        "crypto": CryptoProvider,
        "key": KeyProvider,
        "storage": StorageProvider,
    }

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._containers: dict[str, DependencyContainer] = {}
        self._container_configs: dict[str, dict[str, Any]] = {}
        self._custom_providers: dict[type[Any], type[Any]] = {}

    def create_container(self, config: Configuration) -> DependencyContainer:
        """Create or update a named DI container from configuration.

        Args:
            config: Runtime configuration with provider and wiring options.

        Returns:
            Configured `DependencyContainer` instance.
        """
        normalized = self._normalize_config(config)
        container_name = self._container_name(normalized)

        with self._lock:
            current = self._containers.get(container_name)
            if current is not None and self._container_configs.get(container_name) == normalized:
                return current

            if current is not None:
                self._safe_unwire(current)

            container = self._build_container(normalized)
            self._containers[container_name] = container
            self._container_configs[container_name] = normalized
            return container

    def register_custom_provider(self, interface: type[Any], implementation: type[Any]) -> None:
        """Register a custom implementation for an interface.

        The custom implementation is used when a config section for the same
        provider kind is not explicitly set.
        """
        if not isinstance(interface, type):
            raise TypeError("interface must be a class/type")
        if not isinstance(implementation, type):
            raise TypeError("implementation must be a class/type")
        if not issubclass(implementation, interface):
            raise TypeError("implementation must subclass the provided interface")

        with self._lock:
            self._custom_providers[interface] = implementation

    def reset_container(self) -> None:
        """Clear and rebuild all currently known named containers."""
        with self._lock:
            previous_configs = deepcopy(self._container_configs)
            previous_containers = list(self._containers.values())

            for container in previous_containers:
                self._safe_unwire(container)

            self._containers.clear()
            self._container_configs.clear()

            for _, cfg in previous_configs.items():
                container = self._build_container(cfg)
                name = self._container_name(cfg)
                self._containers[name] = container
                self._container_configs[name] = cfg

    def _build_container(self, config: dict[str, Any]) -> DependencyContainer:
        container = CoreContainer()
        container.config.from_dict(config)

        crypto_cls, crypto_kwargs = self._resolve_provider("crypto", config)
        key_cls, key_kwargs = self._resolve_provider("key", config)
        storage_cls, storage_kwargs = self._resolve_provider("storage", config)

        container.crypto_provider.override(providers.Singleton(crypto_cls, **crypto_kwargs))
        container.key_provider.override(providers.Singleton(key_cls, **key_kwargs))
        container.storage_provider.override(providers.Singleton(storage_cls, **storage_kwargs))

        modules, packages = self._resolve_wiring(config)
        if modules or packages:
            container.wire(modules=modules or None, packages=packages or None)

        return container

    def _resolve_provider(self, kind: str, config: dict[str, Any]) -> tuple[type[Any], dict[str, Any]]:
        providers_config = config.get("providers", {})
        if not isinstance(providers_config, Mapping):
            raise ValueError("config.providers must be a mapping when provided")

        raw_selection = providers_config.get(kind)
        explicit_selection = kind in providers_config

        if explicit_selection:
            name, kwargs = self._parse_provider_selection(raw_selection, kind)
            implementation = self._resolve_named_provider(kind, name)
            return implementation, kwargs

        interface = self._INTERFACE_BY_KIND[kind]
        if interface in self._custom_providers:
            return self._custom_providers[interface], {}

        defaults = deepcopy(self._DEFAULT_PROVIDER_CONFIG[kind])
        default_name = str(defaults["name"])
        default_kwargs = dict(defaults.get("kwargs", {}))
        implementation = self._resolve_named_provider(kind, default_name)
        return implementation, default_kwargs

    @staticmethod
    def _parse_provider_selection(raw_selection: Any, kind: str) -> tuple[str, dict[str, Any]]:
        if isinstance(raw_selection, str):
            return raw_selection.strip().lower(), {}

        if isinstance(raw_selection, Mapping):
            name = raw_selection.get("name")
            if not isinstance(name, str) or not name.strip():
                raise ValueError(f"config.providers.{kind}.name must be a non-empty string")

            kwargs = raw_selection.get("kwargs", {})
            if kwargs is None:
                kwargs = {}
            if not isinstance(kwargs, Mapping):
                raise ValueError(f"config.providers.{kind}.kwargs must be a mapping")

            return name.strip().lower(), dict(kwargs)

        raise ValueError(
            f"config.providers.{kind} must be either a provider name string or a mapping"
        )

    def _resolve_named_provider(self, kind: str, name: str) -> type[Any]:
        if ":" in name and "." in name:
            return self._import_symbol(name)

        mapping = self._PROVIDER_MODULE_MAP.get(kind, {})
        symbol = mapping.get(name)
        if symbol is None:
            supported = ", ".join(sorted(mapping.keys())) or "none"
            raise ValueError(
                f"unknown provider '{name}' for kind '{kind}'. Supported: {supported}"
            )

        return self._import_symbol(symbol)

    @staticmethod
    def _import_symbol(symbol: str) -> type[Any]:
        module_name, sep, attr_name = symbol.partition(":")
        if not sep or not module_name or not attr_name:
            raise ValueError("provider symbol must be in format 'module.path:ClassName'")

        module = importlib.import_module(module_name)
        candidate = getattr(module, attr_name, None)
        if not isinstance(candidate, type):
            raise ValueError(f"provider symbol does not resolve to a class: {symbol}")
        return candidate

    @staticmethod
    def _resolve_wiring(config: dict[str, Any]) -> tuple[list[ModuleType], list[ModuleType]]:
        wiring = config.get("wiring", {})
        if wiring is None:
            return [], []
        if not isinstance(wiring, Mapping):
            raise ValueError("config.wiring must be a mapping when provided")

        modules = ContainerFactory._import_targets(wiring.get("modules", []), "modules")
        packages = ContainerFactory._import_targets(wiring.get("packages", []), "packages")
        return modules, packages

    @staticmethod
    def _import_targets(raw: Any, field_name: str) -> list[ModuleType]:
        if raw is None:
            return []
        if not isinstance(raw, list):
            raise ValueError(f"config.wiring.{field_name} must be a list")

        targets: list[ModuleType] = []
        for item in raw:
            if isinstance(item, ModuleType):
                targets.append(item)
                continue

            if not isinstance(item, str) or not item.strip():
                raise ValueError(
                    f"config.wiring.{field_name} entries must be import-path strings or module objects"
                )

            targets.append(importlib.import_module(item.strip()))

        return targets

    @staticmethod
    def _normalize_config(config: Configuration) -> dict[str, Any]:
        if not isinstance(config, Mapping):
            raise TypeError("config must be a mapping")
        return deepcopy(dict(config))

    @staticmethod
    def _container_name(config: Mapping[str, Any]) -> str:
        raw_name = config.get("container_name") or config.get("environment") or "default"
        if not isinstance(raw_name, str) or not raw_name.strip():
            raise ValueError("container_name/environment must be a non-empty string")
        return raw_name.strip().lower()

    @staticmethod
    def _safe_unwire(container: DependencyContainer) -> None:
        try:
            container.unwire()
        except Exception:
            pass


__all__: list[str] = [
    "Configuration",
    "DependencyContainer",
    "ContainerFactory",
]
