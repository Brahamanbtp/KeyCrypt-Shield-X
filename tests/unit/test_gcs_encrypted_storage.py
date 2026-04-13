"""Unit tests for src/integrations/gcs_encrypted_storage.py."""

from __future__ import annotations

import asyncio
import importlib.util
import sys
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


def _load_module():
    module_path = PROJECT_ROOT / "src/integrations/gcs_encrypted_storage.py"
    spec = importlib.util.spec_from_file_location("gcs_encrypted_storage_module", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load gcs_encrypted_storage module")

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


class _FakeBlob:
    def __init__(self, name: str, encryption_key: bytes | None = None) -> None:
        self.name = name
        self.encryption_key = encryption_key
        self.metadata: dict[str, str] = {}
        self.data: bytes = b""
        self.chunk_size: int | None = None
        self.upload_from_filename_calls: list[dict[str, Any]] = []

    def upload_from_string(self, data: bytes, content_type: str | None = None) -> None:
        _ = content_type
        self.data = bytes(data)

    def upload_from_filename(self, filename: str, content_type: str | None = None) -> None:
        _ = content_type
        self.upload_from_filename_calls.append({"filename": filename})
        self.data = Path(filename).read_bytes()

    def download_as_bytes(self) -> bytes:
        return bytes(self.data)

    def reload(self) -> None:
        return None


class _FakeBucket:
    def __init__(self, name: str) -> None:
        self.name = name
        self._blobs: dict[str, _FakeBlob] = {}
        self.lifecycle_rules: list[dict[str, Any]] = []
        self.patch_calls = 0

    def blob(self, object_name: str, encryption_key: bytes | None = None) -> _FakeBlob:
        blob = self._blobs.get(object_name)
        if blob is None:
            blob = _FakeBlob(object_name, encryption_key=encryption_key)
            self._blobs[object_name] = blob
        elif encryption_key is not None:
            blob.encryption_key = encryption_key
        return blob

    def add_lifecycle_delete_rule(self, age: int) -> None:
        self.lifecycle_rules.append({"action": {"type": "Delete"}, "condition": {"age": int(age)}})

    def patch(self) -> None:
        self.patch_calls += 1


class _FakeGCSClient:
    def __init__(self) -> None:
        self._buckets: dict[str, _FakeBucket] = {}

    def bucket(self, bucket_name: str) -> _FakeBucket:
        if bucket_name not in self._buckets:
            self._buckets[bucket_name] = _FakeBucket(bucket_name)
        return self._buckets[bucket_name]


def test_upload_encrypted_object_writes_ciphertext_metadata_csek_and_lifecycle(tmp_path: Path) -> None:
    module = _load_module()
    provider = _FakeProvider()
    client = _FakeGCSClient()

    source = tmp_path / "plain.bin"
    source.write_bytes(b"hello-gcs")

    module.configure_gcs_encrypted_storage(
        client=client,
        csek_key=b"0123456789abcdef0123456789abcdef",
        retention_period_seconds=200000,
        default_provider=provider,
    )

    asyncio.run(module.upload_encrypted_object("bucket-a", "obj-a", source, provider))

    bucket = client.bucket("bucket-a")
    blob = bucket.blob("obj-a")

    assert blob.data.startswith(b"enc:")
    assert blob.metadata["keycrypt_encrypted"] == "true"
    assert blob.metadata["keycrypt_mode"] == "file"
    assert blob.metadata["keycrypt_csek"] == "true"

    assert blob.encryption_key == b"0123456789abcdef0123456789abcdef"

    assert bucket.lifecycle_rules
    assert bucket.lifecycle_rules[0]["condition"]["age"] == 3


def test_download_encrypted_object_decrypts_to_destination(tmp_path: Path) -> None:
    module = _load_module()
    provider = _FakeProvider()
    client = _FakeGCSClient()

    source = tmp_path / "plain.bin"
    source.write_bytes(b"payload")

    module.configure_gcs_encrypted_storage(client=client, default_provider=provider)
    asyncio.run(module.upload_encrypted_object("bucket-b", "obj-b", source, provider))

    target = tmp_path / "nested" / "out.bin"
    asyncio.run(module.download_encrypted_object("bucket-b", "obj-b", target, provider))

    assert target.read_bytes() == b"payload"


def test_resumable_upload_encrypted_uses_default_provider_and_filename_upload(tmp_path: Path) -> None:
    module = _load_module()
    provider = _FakeProvider()
    client = _FakeGCSClient()

    source = tmp_path / "large.bin"
    source.write_bytes(b"chunk-1" + b"chunk-2")

    module.configure_gcs_encrypted_storage(
        client=client,
        default_provider=provider,
        resumable_chunk_size=5 * 1024 * 1024 + 123,
    )

    asyncio.run(module.resumable_upload_encrypted("bucket-c", "obj-c", source))

    blob = client.bucket("bucket-c").blob("obj-c")
    assert blob.upload_from_filename_calls
    assert blob.data.startswith(b"enc:")
    assert blob.metadata["keycrypt_mode"] == "resumable"

    assert blob.chunk_size is not None
    assert blob.chunk_size % (256 * 1024) == 0


def test_resumable_upload_requires_default_provider(tmp_path: Path) -> None:
    module = _load_module()
    client = _FakeGCSClient()

    source = tmp_path / "plain.bin"
    source.write_bytes(b"x")

    module.configure_gcs_encrypted_storage(client=client, default_provider=None)

    try:
        asyncio.run(module.resumable_upload_encrypted("bucket-d", "obj-d", source))
    except ValueError as exc:
        assert "default_provider" in str(exc)
    else:
        raise AssertionError("expected ValueError when default_provider is missing")
