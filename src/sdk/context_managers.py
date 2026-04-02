"""Convenience context managers for SDK session lifecycle.

This module provides sync and async context-manager helpers that build DI
containers from user-friendly configuration kwargs and yield ready-to-use SDK
clients.

Examples:
    from src.sdk.context_managers import keycrypt_session

    with keycrypt_session(algorithm="aes") as kc:
        artifact = kc.encrypt_file("report.txt")

    # Async usage
    import asyncio
    from src.sdk.context_managers import keycrypt_session_async

    async def main() -> None:
        async with keycrypt_session_async(algorithm="chacha20") as kc:
            result = await kc.encrypt_file_async("report.txt")
            print(result.encrypted_path)

    asyncio.run(main())
"""

from __future__ import annotations

from contextlib import asynccontextmanager, contextmanager
from typing import Any, AsyncIterator, Iterator, Mapping

from src.orchestration.container_factory import ContainerFactory
from src.orchestration.dependency_container import CoreContainer
from src.sdk.async_client import AsyncKeyCryptClient
from src.sdk.client import KeyCryptClient


_CRYPTO_ALIASES = {
    "aes": ("classical", {"algorithm": "aes-gcm"}),
    "aes-gcm": ("classical", {"algorithm": "aes-gcm"}),
    "aes-256-gcm": ("classical", {"algorithm": "aes-gcm"}),
    "chacha": ("classical", {"algorithm": "chacha20"}),
    "chacha20": ("classical", {"algorithm": "chacha20"}),
    "chacha20-poly1305": ("classical", {"algorithm": "chacha20"}),
    "kyber": ("pqc", {"algorithm": "kyber-768"}),
    "kyber-768": ("pqc", {"algorithm": "kyber-768"}),
    "dilithium": ("pqc", {"algorithm": "dilithium-3"}),
    "dilithium-3": ("pqc", {"algorithm": "dilithium-3"}),
    "pqc": ("pqc", {"algorithm": "kyber-768"}),
    "hybrid": ("hybrid", {}),
    "hybrid-kem": ("hybrid", {}),
    "auto": ("classical", {"algorithm": "aes-gcm"}),
}


@contextmanager
def keycrypt_session(**config: Any) -> Iterator[KeyCryptClient]:
    """Create a synchronous KeyCrypt SDK session.

    Args:
        **config: Configuration kwargs used to auto-configure provider
            bindings. Common options include:
            - algorithm: str (for example: "aes", "chacha20", "pqc", "hybrid")
            - crypto_provider: str
            - key_provider: str
            - storage_provider: str
            - container_name / environment: str
            - crypto_kwargs / key_kwargs / storage_kwargs: dict

    Yields:
        Configured `KeyCryptClient` instance.
    """
    container = _create_container_from_kwargs(config)
    client = KeyCryptClient(container=container)

    try:
        yield client
    finally:
        client.close()


@asynccontextmanager
async def keycrypt_session_async(**config: Any) -> AsyncIterator[AsyncKeyCryptClient]:
    """Create an asynchronous KeyCrypt SDK session.

    Args:
        **config: Same provider-configuration kwargs supported by
            `keycrypt_session()`.

    Yields:
        Configured `AsyncKeyCryptClient` instance.
    """
    container = _create_container_from_kwargs(config)

    async with AsyncKeyCryptClient(container=container) as client:
        yield client


def _create_container_from_kwargs(config: Mapping[str, Any]) -> CoreContainer:
    normalized = _normalize_factory_config(config)
    factory = ContainerFactory()
    return factory.create_container(normalized)


def _normalize_factory_config(config: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(config)
    normalized: dict[str, Any] = {}

    container_name = raw.pop("container_name", None)
    environment = raw.pop("environment", None)
    if container_name is not None:
        normalized["container_name"] = _require_non_empty_text(container_name, "container_name")
    if environment is not None:
        normalized["environment"] = _require_non_empty_text(environment, "environment")

    providers_section = raw.pop("providers", {})
    if providers_section is None:
        providers_section = {}
    if not isinstance(providers_section, Mapping):
        raise TypeError("providers must be a mapping when provided")

    providers: dict[str, Any] = {str(k): v for k, v in providers_section.items()}

    algorithm = str(raw.pop("algorithm", "auto")).strip().lower()
    crypto_provider_name = raw.pop("crypto_provider", None)
    crypto_kwargs = _optional_mapping(raw.pop("crypto_kwargs", {}), "crypto_kwargs")

    if "crypto" not in providers:
        inferred_name, inferred_kwargs = _infer_crypto_provider(algorithm)
        selected_name = (
            _require_non_empty_text(crypto_provider_name, "crypto_provider").lower()
            if crypto_provider_name is not None
            else inferred_name
        )

        merged_crypto_kwargs = dict(inferred_kwargs)
        merged_crypto_kwargs.update(crypto_kwargs)
        providers["crypto"] = _selection_payload(selected_name, merged_crypto_kwargs)

    key_provider_name = raw.pop("key_provider", None)
    key_kwargs = _optional_mapping(raw.pop("key_kwargs", {}), "key_kwargs")
    if "key" not in providers and key_provider_name is not None:
        selected_name = _require_non_empty_text(key_provider_name, "key_provider").lower()
        providers["key"] = _selection_payload(selected_name, key_kwargs)

    storage_provider_name = raw.pop("storage_provider", None)
    storage_kwargs = _optional_mapping(raw.pop("storage_kwargs", {}), "storage_kwargs")
    if "storage" not in providers and storage_provider_name is not None:
        selected_name = _require_non_empty_text(storage_provider_name, "storage_provider").lower()
        providers["storage"] = _selection_payload(selected_name, storage_kwargs)

    if providers:
        normalized["providers"] = providers

    wiring_modules = raw.pop("wiring_modules", None)
    wiring_packages = raw.pop("wiring_packages", None)
    if wiring_modules is not None or wiring_packages is not None:
        normalized["wiring"] = {
            "modules": list(wiring_modules or []),
            "packages": list(wiring_packages or []),
        }

    # Pass through additional config keys so callers can target future options.
    normalized.update(raw)
    return normalized


def _infer_crypto_provider(algorithm: str) -> tuple[str, dict[str, Any]]:
    normalized = algorithm.strip().lower()
    selected = _CRYPTO_ALIASES.get(normalized)
    if selected is None:
        supported = ", ".join(sorted(_CRYPTO_ALIASES.keys()))
        raise ValueError(f"unsupported algorithm '{algorithm}'. Supported values: {supported}")

    name, kwargs = selected
    return name, dict(kwargs)


def _selection_payload(name: str, kwargs: dict[str, Any]) -> Any:
    if kwargs:
        return {
            "name": name,
            "kwargs": dict(kwargs),
        }
    return name


def _optional_mapping(value: Any, field_name: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise TypeError(f"{field_name} must be a mapping when provided")
    return dict(value)


def _require_non_empty_text(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value.strip()


__all__: list[str] = [
    "keycrypt_session",
    "keycrypt_session_async",
]
