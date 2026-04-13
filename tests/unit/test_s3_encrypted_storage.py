"""Unit tests for src/integrations/s3_encrypted_storage.py."""

from __future__ import annotations

import asyncio
import importlib.util
import sys
from pathlib import Path
from typing import Any, AsyncIterator


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


def _load_module():
    module_path = PROJECT_ROOT / "src/integrations/s3_encrypted_storage.py"
    spec = importlib.util.spec_from_file_location("s3_encrypted_storage_module", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load s3_encrypted_storage module")

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
        return "TEST-ALG"

    def get_security_level(self) -> int:
        return 128


class _FakeBody:
    def __init__(self, data: bytes) -> None:
        self._data = data

    async def read(self) -> bytes:
        return self._data


class _FakeS3Client:
    def __init__(self) -> None:
        self.objects: dict[tuple[str, str], dict[str, Any]] = {}
        self.put_calls: list[dict[str, Any]] = []
        self.get_calls: list[dict[str, Any]] = []

        self.create_multipart_calls: list[dict[str, Any]] = []
        self.upload_part_calls: list[dict[str, Any]] = []
        self.complete_multipart_calls: list[dict[str, Any]] = []
        self.abort_multipart_calls: list[dict[str, Any]] = []

        self._multipart_counter = 0
        self._multipart_sessions: dict[str, dict[str, Any]] = {}

    async def put_object(self, **kwargs: Any) -> dict[str, Any]:
        self.put_calls.append(dict(kwargs))
        bucket = kwargs["Bucket"]
        key = kwargs["Key"]
        self.objects[(bucket, key)] = {
            "Body": bytes(kwargs["Body"]),
            "Metadata": dict(kwargs.get("Metadata", {})),
            "Args": dict(kwargs),
        }
        return {"ETag": '"etag-put"'}

    async def get_object(self, **kwargs: Any) -> dict[str, Any]:
        self.get_calls.append(dict(kwargs))
        bucket = kwargs["Bucket"]
        key = kwargs["Key"]
        stored = self.objects[(bucket, key)]
        return {
            "Body": _FakeBody(stored["Body"]),
            "Metadata": dict(stored.get("Metadata", {})),
        }

    async def create_multipart_upload(self, **kwargs: Any) -> dict[str, Any]:
        self.create_multipart_calls.append(dict(kwargs))
        self._multipart_counter += 1
        upload_id = f"upload-{self._multipart_counter}"
        self._multipart_sessions[upload_id] = {
            "Bucket": kwargs["Bucket"],
            "Key": kwargs["Key"],
            "Metadata": dict(kwargs.get("Metadata", {})),
            "Parts": {},
            "Args": dict(kwargs),
        }
        return {"UploadId": upload_id}

    async def upload_part(self, **kwargs: Any) -> dict[str, Any]:
        self.upload_part_calls.append(dict(kwargs))
        upload_id = kwargs["UploadId"]
        part_number = int(kwargs["PartNumber"])
        self._multipart_sessions[upload_id]["Parts"][part_number] = bytes(kwargs["Body"])
        return {"ETag": f'"etag-{part_number}"'}

    async def complete_multipart_upload(self, **kwargs: Any) -> dict[str, Any]:
        self.complete_multipart_calls.append(dict(kwargs))
        upload_id = kwargs["UploadId"]
        session = self._multipart_sessions[upload_id]

        ordered_parts = []
        for entry in kwargs["MultipartUpload"]["Parts"]:
            ordered_parts.append(session["Parts"][int(entry["PartNumber"])])

        payload = b"".join(ordered_parts)
        self.objects[(session["Bucket"], session["Key"])] = {
            "Body": payload,
            "Metadata": dict(session.get("Metadata", {})),
            "Args": dict(session.get("Args", {})),
        }
        return {"ETag": '"etag-complete"'}

    async def abort_multipart_upload(self, **kwargs: Any) -> dict[str, Any]:
        self.abort_multipart_calls.append(dict(kwargs))
        return {"Aborted": True}


def test_upload_encrypted_puts_ciphertext_with_metadata_and_ssec(tmp_path: Path) -> None:
    module = _load_module()
    provider = _FakeProvider()
    client = _FakeS3Client()

    file_path = tmp_path / "source.bin"
    file_path.write_bytes(b"hello-s3")

    module.configure_s3_encrypted_storage(
        client=client,
        sse_customer_key=b"0123456789abcdef0123456789abcdef",
        default_provider=provider,
    )

    asyncio.run(module.upload_encrypted("bucket-a", "obj-a", file_path, provider))

    stored = client.objects[("bucket-a", "obj-a")]
    assert stored["Body"] == b"enc:hello-s3"

    metadata = stored["Metadata"]
    assert metadata["keycrypt_mode"] == "file"
    assert metadata["keycrypt_version"] == "1"

    put_call = client.put_calls[-1]
    assert put_call["SSECustomerAlgorithm"] == "AES256"
    assert put_call["SSECustomerKey"]
    assert put_call["SSECustomerKeyMD5"]


def test_download_encrypted_gets_and_decrypts_to_path(tmp_path: Path) -> None:
    module = _load_module()
    provider = _FakeProvider()
    client = _FakeS3Client()

    client.objects[("bucket-b", "obj-b")] = {
        "Body": b"enc:payload-data",
        "Metadata": {"keycrypt_mode": "file"},
        "Args": {},
    }

    out_path = tmp_path / "nested" / "result.bin"

    module.configure_s3_encrypted_storage(
        client=client,
        sse_customer_key=b"0123456789abcdef0123456789abcdef",
        default_provider=provider,
    )

    asyncio.run(module.download_encrypted("bucket-b", "obj-b", out_path, provider))

    assert out_path.read_bytes() == b"payload-data"

    get_call = client.get_calls[-1]
    assert get_call["SSECustomerAlgorithm"] == "AES256"
    assert get_call["SSECustomerKey"]
    assert get_call["SSECustomerKeyMD5"]


def test_streaming_upload_encrypted_encrypts_chunks_and_completes_multipart() -> None:
    module = _load_module()
    provider = _FakeProvider()
    client = _FakeS3Client()

    module.configure_s3_encrypted_storage(client=client, default_provider=provider)

    async def _stream() -> AsyncIterator[bytes]:
        yield b"chunk-1"
        yield b"chunk-2"

    asyncio.run(module.streaming_upload_encrypted("bucket-c", "obj-c", _stream()))

    assert client.create_multipart_calls
    assert client.upload_part_calls
    assert client.complete_multipart_calls

    final = client.objects[("bucket-c", "obj-c")]
    assert final["Body"] == b"enc:chunk-1enc:chunk-2"
    assert final["Metadata"]["keycrypt_mode"] == "stream"


def test_streaming_upload_encrypted_requires_default_provider() -> None:
    module = _load_module()
    client = _FakeS3Client()

    module.configure_s3_encrypted_storage(client=client, default_provider=None)

    async def _stream() -> AsyncIterator[bytes]:
        yield b"x"

    try:
        asyncio.run(module.streaming_upload_encrypted("bucket-d", "obj-d", _stream()))
    except ValueError as exc:
        assert "default_provider" in str(exc)
    else:
        raise AssertionError("expected ValueError when default_provider is missing")
