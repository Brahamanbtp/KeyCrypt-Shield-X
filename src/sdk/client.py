"""High-level synchronous SDK client for KeyCrypt operations.

This module exposes a user-friendly client that orchestrates encryption and
decryption workflows via dependency-injected providers.

Example:
    from src.sdk.client import KeyCryptClient

    with KeyCryptClient() as client:
        encrypted = client.encrypt_file("report.pdf", algorithm="auto")
        client.decrypt_file(encrypted.encrypted_path, output="report.decrypted.pdf")
"""

from __future__ import annotations

import asyncio
import base64
import json
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Mapping, TypeVar

from src.abstractions.crypto_provider import CryptoProvider
from src.abstractions.key_provider import KeyGenerationParams, KeyMaterial, KeyProvider
from src.abstractions.storage_provider import StorageProvider
from src.orchestration.dependency_container import CoreContainer


T = TypeVar("T")


@dataclass(frozen=True)
class EncryptedFile:
    """Represents an encrypted file artifact created by `KeyCryptClient`.

    Attributes:
        source_path: Original plaintext file path.
        encrypted_path: Path to SDK manifest describing encrypted payload.
        object_id: Storage object identifier returned by StorageProvider.
        key_id: Key identifier used for encryption.
        algorithm: Provider algorithm used for encryption.
        encrypted_size: Stored ciphertext size in bytes.
        metadata: Additional persisted metadata.
    """

    source_path: str
    encrypted_path: str
    object_id: str
    key_id: str
    algorithm: str
    encrypted_size: int
    metadata: dict[str, Any] = field(default_factory=dict)


class KeyCryptClient:
    """Synchronous SDK client for high-level file encryption workflows.

    The client resolves crypto, key, and storage providers via dependency
    injection from `CoreContainer` and presents a simple sync API.

    Example:
        from src.sdk.client import KeyCryptClient

        with KeyCryptClient() as client:
            encrypted = client.encrypt_file("sample.txt", algorithm="chacha20")
            client.decrypt_file(encrypted.encrypted_path, output="sample.restored.txt")
    """

    _MANIFEST_VERSION = "1.0.0"

    def __init__(self, container: CoreContainer | None = None) -> None:
        """Initialize SDK client with optional externally managed container.

        Args:
            container: Optional DI container. When omitted, a default
                `CoreContainer` is created and managed by the client.
        """
        self._container = container or CoreContainer()
        self._owns_container = container is None
        self._closed = False

    def __enter__(self) -> KeyCryptClient:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    def close(self) -> None:
        """Release client-managed resources."""
        if self._closed:
            return

        if self._owns_container:
            try:
                self._container.unwire()
            except Exception:
                pass

        self._closed = True

    def encrypt_file(self, path: str, algorithm: str = "auto") -> EncryptedFile:
        """Encrypt a file and return an `EncryptedFile` descriptor.

        Args:
            path: Path to plaintext source file.
            algorithm: Requested crypto algorithm. Use "auto" to keep container
                default provider algorithm.

        Returns:
            `EncryptedFile` containing manifest path and storage metadata.

        Example:
            client = KeyCryptClient()
            artifact = client.encrypt_file("notes.txt", algorithm="auto")
            print(artifact.encrypted_path)
        """
        self._ensure_open()

        source = Path(path)
        if not source.exists() or not source.is_file():
            raise FileNotFoundError(f"source file not found: {source}")

        plaintext = source.read_bytes()

        crypto_provider = self._resolve_crypto_provider(algorithm)
        key_provider = self._resolve_key_provider()
        storage_provider = self._resolve_storage_provider()

        provider_algorithm = crypto_provider.get_algorithm_name()
        key_material = self._resolve_key_material(key_provider, provider_algorithm)

        associated_data = self._build_associated_data(source, provider_algorithm)
        context = {
            "key": key_material.material,
            "key_id": key_material.key_id,
            "associated_data": associated_data,
        }

        ciphertext = crypto_provider.encrypt(plaintext, context)

        storage_metadata = {
            "source_file": str(source),
            "algorithm": provider_algorithm,
            "key_id": key_material.key_id,
            "associated_data_b64": base64.b64encode(associated_data).decode("ascii"),
            "created_at": time.time(),
            "sdk": "keycrypt-client",
        }

        object_id = self._run_async(storage_provider.write(ciphertext, storage_metadata))

        manifest_path = source.with_suffix(source.suffix + ".kcx.json")
        manifest = {
            "version": self._MANIFEST_VERSION,
            "source_path": str(source),
            "object_id": object_id,
            "key_id": key_material.key_id,
            "algorithm": provider_algorithm,
            "encrypted_size": len(ciphertext),
            "metadata": storage_metadata,
        }
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        return EncryptedFile(
            source_path=str(source),
            encrypted_path=str(manifest_path),
            object_id=str(object_id),
            key_id=key_material.key_id,
            algorithm=provider_algorithm,
            encrypted_size=len(ciphertext),
            metadata=storage_metadata,
        )

    def decrypt_file(self, encrypted_path: str, output: str) -> None:
        """Decrypt a file artifact generated by `encrypt_file`.

        Args:
            encrypted_path: Path to SDK manifest produced by `encrypt_file`.
            output: Destination path for recovered plaintext.

        Example:
            client = KeyCryptClient()
            client.decrypt_file("notes.txt.kcx.json", output="notes.restored.txt")
        """
        self._ensure_open()

        manifest_file = Path(encrypted_path)
        if not manifest_file.exists() or not manifest_file.is_file():
            raise FileNotFoundError(f"encrypted manifest not found: {manifest_file}")

        manifest = self._load_manifest(manifest_file)

        crypto_provider = self._resolve_crypto_provider(str(manifest["algorithm"]))
        key_provider = self._resolve_key_provider()
        storage_provider = self._resolve_storage_provider()

        object_id = str(manifest["object_id"])
        ciphertext, _ = self._run_async(storage_provider.read(object_id))

        key_id = str(manifest["key_id"])
        key_material = key_provider.get_key(key_id)

        metadata = manifest.get("metadata", {})
        associated_data = self._decode_associated_data(metadata)

        context = {
            "key": key_material.material,
            "key_id": key_id,
            "associated_data": associated_data,
        }

        plaintext = crypto_provider.decrypt(ciphertext, context)

        destination = Path(output)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(plaintext)

    def _resolve_crypto_provider(self, algorithm: str) -> CryptoProvider:
        provider = self._container.crypto_provider()

        if not isinstance(provider, CryptoProvider):
            raise TypeError("container.crypto_provider did not resolve a CryptoProvider")

        requested = (algorithm or "auto").strip().lower()
        if requested == "auto":
            return provider

        current = provider.get_algorithm_name().strip().lower()
        if current == requested:
            return provider

        provider_cls = type(provider)
        try:
            overridden = provider_cls(requested)
        except Exception as exc:
            raise ValueError(
                f"requested algorithm '{requested}' is not supported by active crypto provider"
            ) from exc

        if not isinstance(overridden, CryptoProvider):
            raise TypeError("resolved overridden crypto provider does not implement CryptoProvider")

        return overridden

    def _resolve_key_provider(self) -> KeyProvider:
        provider = self._container.key_provider()
        if not isinstance(provider, KeyProvider):
            raise TypeError("container.key_provider did not resolve a KeyProvider")
        return provider

    def _resolve_storage_provider(self) -> StorageProvider:
        provider = self._container.storage_provider()
        if not isinstance(provider, StorageProvider):
            raise TypeError("container.storage_provider did not resolve a StorageProvider")
        return provider

    @staticmethod
    def _resolve_key_material(key_provider: KeyProvider, provider_algorithm: str) -> KeyMaterial:
        key_algo = KeyCryptClient._map_provider_algorithm_to_key_algorithm(provider_algorithm)
        key_id = key_provider.generate_key(KeyGenerationParams(algorithm=key_algo))
        return key_provider.get_key(key_id)

    @staticmethod
    def _map_provider_algorithm_to_key_algorithm(provider_algorithm: str) -> str:
        normalized = provider_algorithm.strip().lower()
        if normalized in {"aes-gcm", "aes-256-gcm"}:
            return "AES-256-GCM"
        if normalized in {"chacha20", "chacha20-poly1305"}:
            return "CHACHA20-POLY1305"
        if "hybrid" in normalized:
            return "KYBER-HYBRID"
        if "kyber" in normalized:
            return "KYBER-AES-GCM"
        if "dilithium" in normalized:
            return "DILITHIUM-AES-GCM"
        return provider_algorithm.strip().upper() or "AES-256-GCM"

    @staticmethod
    def _build_associated_data(source: Path, algorithm: str) -> bytes:
        payload = f"keycrypt-sdk|source={source.name}|algorithm={algorithm}"
        return payload.encode("utf-8")

    @staticmethod
    def _load_manifest(path: Path) -> dict[str, Any]:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("manifest root must be a JSON object")

        for key in ("object_id", "key_id", "algorithm"):
            if key not in payload or not isinstance(payload[key], str) or not payload[key].strip():
                raise ValueError(f"manifest missing required field: {key}")

        metadata = payload.get("metadata", {})
        if metadata is not None and not isinstance(metadata, dict):
            raise ValueError("manifest metadata must be an object")

        return payload

    @staticmethod
    def _decode_associated_data(metadata: Mapping[str, Any]) -> bytes | None:
        encoded = metadata.get("associated_data_b64")
        if encoded is None:
            return None
        if not isinstance(encoded, str):
            raise ValueError("metadata.associated_data_b64 must be a base64 string")
        return base64.b64decode(encoded.encode("ascii"))

    @staticmethod
    def _run_async(awaitable: Awaitable[T]) -> T:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(awaitable)

        result_box: dict[str, T] = {}
        error_box: dict[str, BaseException] = {}

        def _runner() -> None:
            try:
                result_box["value"] = asyncio.run(awaitable)
            except BaseException as exc:  # pragma: no cover - defensive bridge path
                error_box["error"] = exc

        thread = threading.Thread(target=_runner, daemon=True)
        thread.start()
        thread.join()

        if "error" in error_box:
            raise RuntimeError(f"async provider execution failed: {error_box['error']}") from error_box["error"]

        return result_box["value"]

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("KeyCryptClient is closed")


__all__: list[str] = [
    "EncryptedFile",
    "KeyCryptClient",
]
