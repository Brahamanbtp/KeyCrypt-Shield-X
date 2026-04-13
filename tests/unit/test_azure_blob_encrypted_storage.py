"""Unit tests for src/integrations/azure_blob_encrypted_storage.py."""

from __future__ import annotations

import asyncio
import importlib.util
import sys
from dataclasses import dataclass
from typing import Any

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


def _load_module():
    module_path = PROJECT_ROOT / "src/integrations/azure_blob_encrypted_storage.py"
    spec = importlib.util.spec_from_file_location("azure_blob_encrypted_storage_module", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load azure_blob_encrypted_storage module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _FakeProvider:
    def encrypt(self, plaintext: bytes, context: dict[str, Any]) -> bytes:
        _ = context
        return b"enc:" + plaintext

    def decrypt(self, ciphertext: bytes, context: dict[str, Any]) -> bytes:
        _ = context
        if not ciphertext.startswith(b"enc:"):
            raise ValueError("invalid ciphertext")
        return ciphertext[4:]

    def get_algorithm_name(self) -> str:
        return "FAKE-ALG"

    def get_security_level(self) -> int:
        return 128


@dataclass(frozen=True)
class _FakeBlobProperties:
    metadata: dict[str, str]
    size: int
    etag: str
    version_id: str


@dataclass(frozen=True)
class _FakeBlobItem:
    name: str
    version_id: str | None
    size: int
    etag: str
    metadata: dict[str, str]


class _FakeDownloader:
    def __init__(self, data: bytes) -> None:
        self._data = data

    async def readall(self) -> bytes:
        return self._data


class _FakeBlobClient:
    def __init__(self, container: str, blob_name: str, backing_store: dict[str, Any]) -> None:
        self._container = container
        self._blob_name = blob_name
        self._store = backing_store

    async def upload_blob(self, data: bytes, overwrite: bool = False, metadata: dict[str, str] | None = None) -> dict[str, Any]:
        _ = overwrite

        container_store = self._store.setdefault(self._container, {})
        versions = container_store.setdefault(self._blob_name, [])

        version_id = f"v{len(versions) + 1}"
        item = {
            "version_id": version_id,
            "body": bytes(data),
            "metadata": dict(metadata or {}),
            "etag": f"etag-{version_id}",
        }
        versions.append(item)
        return {"version_id": version_id}

    async def download_blob(self) -> _FakeDownloader:
        latest = self._latest()
        return _FakeDownloader(latest["body"])

    async def get_blob_properties(self) -> _FakeBlobProperties:
        latest = self._latest()
        return _FakeBlobProperties(
            metadata=dict(latest["metadata"]),
            size=len(latest["body"]),
            etag=latest["etag"],
            version_id=latest["version_id"],
        )

    def _latest(self) -> dict[str, Any]:
        container_store = self._store.get(self._container, {})
        versions = container_store.get(self._blob_name, [])
        if not versions:
            raise RuntimeError("blob not found")
        return versions[-1]


class _FakeContainerClient:
    def __init__(self, container: str, backing_store: dict[str, Any]) -> None:
        self._container = container
        self._store = backing_store

    async def create_container(self) -> None:
        self._store.setdefault(self._container, {})

    def get_blob_client(self, blob_name: str) -> _FakeBlobClient:
        return _FakeBlobClient(self._container, blob_name, self._store)

    def list_blobs(self, include: list[str] | None = None):
        include_versions = bool(include and "versions" in include)
        container_store = self._store.get(self._container, {})

        async def _iterator():
            for blob_name, versions in container_store.items():
                if not versions:
                    continue

                if include_versions:
                    iterable = versions
                else:
                    iterable = [versions[-1]]

                for entry in iterable:
                    yield _FakeBlobItem(
                        name=blob_name,
                        version_id=entry["version_id"],
                        size=len(entry["body"]),
                        etag=entry["etag"],
                        metadata=dict(entry["metadata"]),
                    )

        return _iterator()


class _FakeBlobServiceClient:
    def __init__(self) -> None:
        self._store: dict[str, Any] = {}

    def get_container_client(self, container: str) -> _FakeContainerClient:
        return _FakeContainerClient(container, self._store)

    def versions_for(self, container: str, blob_name: str) -> list[dict[str, Any]]:
        return list(self._store.get(container, {}).get(blob_name, []))


@dataclass(frozen=True)
class _FakeKeyProperties:
    version: str


@dataclass(frozen=True)
class _FakeKey:
    id: str
    properties: _FakeKeyProperties


class _FakeKeyVaultClient:
    async def get_key(self, key_name: str) -> _FakeKey:
        return _FakeKey(
            id=f"https://vault.vault.azure.net/keys/{key_name}/123456",
            properties=_FakeKeyProperties(version="123456"),
        )


def test_upload_and_download_encrypted_blob_round_trip_with_key_vault() -> None:
    module = _load_module()
    provider = _FakeProvider()
    blob_client = _FakeBlobServiceClient()
    key_vault_client = _FakeKeyVaultClient()

    module.configure_azure_blob_encrypted_storage(
        blob_service_client=blob_client,
        key_name="app-key",
        key_vault_client=key_vault_client,
    )

    asyncio.run(
        module.upload_encrypted_blob(
            "cont",
            "doc.bin",
            b"hello-azure",
            provider,
        )
    )

    recovered = asyncio.run(module.download_encrypted_blob("cont", "doc.bin", provider))
    assert recovered == b"hello-azure"

    versions = blob_client.versions_for("cont", "doc.bin")
    assert len(versions) == 1
    metadata = versions[0]["metadata"]
    assert metadata["keycrypt_encrypted"] == "true"
    assert metadata["keycrypt_kv_key_id"].startswith("https://vault.vault.azure.net/keys/app-key")
    assert metadata["keycrypt_kv_key_version"] == "123456"


def test_blob_versioning_encrypts_each_version_separately() -> None:
    module = _load_module()
    provider = _FakeProvider()
    blob_client = _FakeBlobServiceClient()

    module.configure_azure_blob_encrypted_storage(blob_service_client=blob_client)

    asyncio.run(module.upload_encrypted_blob("cont", "doc.bin", b"same-data", provider))
    asyncio.run(module.upload_encrypted_blob("cont", "doc.bin", b"same-data", provider))

    versions = blob_client.versions_for("cont", "doc.bin")
    assert len(versions) == 2
    assert versions[0]["body"] != versions[1]["body"]


def test_list_encrypted_blobs_returns_only_encrypted_versions() -> None:
    module = _load_module()
    provider = _FakeProvider()
    blob_client = _FakeBlobServiceClient()

    module.configure_azure_blob_encrypted_storage(blob_service_client=blob_client)

    asyncio.run(module.upload_encrypted_blob("cont", "enc-a.bin", b"a", provider))
    asyncio.run(module.upload_encrypted_blob("cont", "enc-a.bin", b"b", provider))

    # inject one non-encrypted blob version directly to validate filtering behavior
    plain_blob_client = blob_client.get_container_client("cont").get_blob_client("plain.bin")
    asyncio.run(plain_blob_client.upload_blob(b"raw", overwrite=True, metadata={}))

    blobs = asyncio.run(module.list_encrypted_blobs("cont"))

    assert len(blobs) == 2
    assert all(item.encrypted for item in blobs)
    assert {item.version_id for item in blobs} == {"v1", "v2"}
    assert all(item.name == "enc-a.bin" for item in blobs)
