"""Unit tests for src.observability.audit_storage."""

from __future__ import annotations

import asyncio
from dataclasses import replace
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.observability.audit_event_schema import AccessEvent, EncryptionEvent
from src.observability.audit_storage import (
    AuditFilter,
    AuditStorage,
    BlockchainAuditBackend,
    PostgreSQLAuditBackend,
    S3AuditBackend,
)


def _run(coro):
    return asyncio.run(coro)


def test_blockchain_append_query_and_integrity() -> None:
    backend = BlockchainAuditBackend()
    storage = AuditStorage(backend=backend)

    first = EncryptionEvent(
        actor="svc-crypto",
        resource="/keys/prod/key-1",
        action="encrypt",
        outcome="success",
        algorithm="AES-256-GCM",
        key_id="key-1",
        data_size=256,
        duration=0.003,
    )
    second = AccessEvent(
        actor="svc-authz",
        resource="/keys/prod/key-1",
        action="authorize",
        outcome="allow",
        resource_accessed="/keys/prod/key-1",
        access_granted=True,
    )

    first_id = _run(storage.append_event(first))
    second_id = _run(storage.append_event(second))

    assert first_id == first.event_id
    assert second_id == second.event_id

    queried = _run(storage.query_events(AuditFilter(event_type="encryption"), limit=10))
    assert len(queried) == 1
    assert queried[0].event_id == first.event_id

    assert _run(storage.verify_integrity(second.event_id)) is True


def test_integrity_verification_detects_tampering() -> None:
    backend = BlockchainAuditBackend()
    storage = AuditStorage(backend=backend)

    event = EncryptionEvent(
        actor="svc-crypto",
        resource="/keys/prod/key-2",
        action="encrypt",
        outcome="success",
        algorithm="CHACHA20-POLY1305",
        key_id="key-2",
        data_size=512,
        duration=0.005,
    )

    _run(storage.append_event(event))
    assert _run(storage.verify_integrity(event.event_id)) is True

    original = backend._records[0]  # noqa: SLF001
    tampered_event = original.event.model_copy(update={"action": "tampered"})
    tampered_record = replace(original, event=tampered_event)
    backend._records[0] = tampered_record  # noqa: SLF001
    backend._index_by_event_id[event.event_id] = tampered_record  # noqa: SLF001

    assert _run(storage.verify_integrity(event.event_id)) is False


def test_postgresql_schema_sql_enforces_append_only_triggers() -> None:
    statements = PostgreSQLAuditBackend.build_immutable_schema_sql("audit_events")
    sql_blob = "\n".join(statements)

    assert "BEFORE UPDATE ON audit_events" in sql_blob
    assert "BEFORE DELETE ON audit_events" in sql_blob
    assert "append-only and immutable" in sql_blob


def test_s3_backend_uses_object_lock_on_append() -> None:
    class _FakeBody:
        def __init__(self, data: bytes) -> None:
            self._data = data

        async def read(self) -> bytes:
            return self._data

    class _FakeS3Client:
        def __init__(self) -> None:
            self.objects: dict[str, bytes] = {}
            self.put_calls: list[dict[str, Any]] = []

        async def list_objects_v2(self, **kwargs: Any) -> dict[str, Any]:
            prefix = str(kwargs.get("Prefix", ""))
            keys = sorted(key for key in self.objects if key.startswith(prefix))
            return {
                "Contents": [{"Key": key} for key in keys],
                "IsTruncated": False,
            }

        async def put_object(self, **kwargs: Any) -> dict[str, Any]:
            key = str(kwargs["Key"])
            body = kwargs["Body"]
            if isinstance(body, bytes):
                payload = body
            else:
                payload = bytes(body)

            self.objects[key] = payload
            self.put_calls.append(dict(kwargs))
            return {"ETag": "fake"}

        async def get_object(self, **kwargs: Any) -> dict[str, Any]:
            key = str(kwargs["Key"])
            return {"Body": _FakeBody(self.objects[key])}

    fake_client = _FakeS3Client()
    backend = S3AuditBackend(
        bucket_name="audit-bucket",
        prefix="audit-events",
        object_lock_mode="COMPLIANCE",
        object_lock_retention_days=30,
        client=fake_client,
    )
    storage = AuditStorage(backend=backend)

    event = EncryptionEvent(
        actor="svc",
        resource="/keys/k1",
        action="encrypt",
        outcome="success",
        algorithm="AES-256-GCM",
        key_id="k1",
        data_size=128,
        duration=0.001,
    )

    _run(storage.append_event(event))

    assert len(fake_client.put_calls) == 1
    put_kwargs = fake_client.put_calls[0]
    assert put_kwargs["ObjectLockMode"] == "COMPLIANCE"
    assert "ObjectLockRetainUntilDate" in put_kwargs

    body_json = json.loads(fake_client.objects[next(iter(fake_client.objects))].decode("utf-8"))
    assert body_json["event"]["event_id"] == event.event_id
