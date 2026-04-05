"""Immutable audit storage with multi-backend persistence.

The storage layer preserves append-only audit semantics and extends tamper
evidence through:
- Hash chaining (each event references previous event hash).
- Cryptographic signatures (Ed25519 signed audit records).
- Multiple backends: PostgreSQL, S3 object lock, and blockchain-style chain.

Primary API:
- append_event(event) -> event_id
- query_events(filters, limit) -> list[AuditEvent]
- verify_integrity(event_id) -> bool
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import Any, Awaitable, Callable, List, Mapping

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from src.observability.audit_event_schema import (
    AccessEvent,
    AuditEvent,
    ConfigChangeEvent,
    EncryptionEvent,
    KeyRotationEvent,
)
from src.utils.logging import get_logger, log_security_event

try:  # pragma: no cover - optional dependency boundary
    import asyncpg
except Exception as exc:  # pragma: no cover - optional dependency boundary
    asyncpg = None  # type: ignore[assignment]
    _ASYNCPG_IMPORT_ERROR = exc
else:
    _ASYNCPG_IMPORT_ERROR = None

try:  # pragma: no cover - optional dependency boundary
    import aioboto3
except Exception as exc:  # pragma: no cover - optional dependency boundary
    aioboto3 = None  # type: ignore[assignment]
    _AIOBOTO3_IMPORT_ERROR = exc
else:
    _AIOBOTO3_IMPORT_ERROR = None


logger = get_logger("src.observability.audit_storage")

_GENESIS_PREVIOUS_HASH = "0" * 64
_SIGNATURE_ALGORITHM = "ed25519"


class AuditStorageError(Exception):
    """Raised when audit storage operations fail."""


class AuditFilter(BaseModel):
    """Typed query filter for audit event retrieval."""

    model_config = ConfigDict(extra="forbid")

    event_id: str | None = None
    event_type: str | None = None
    actor: str | None = None
    resource: str | None = None
    action: str | None = None
    outcome: str | None = None
    since: datetime | None = None
    until: datetime | None = None
    signer_id: str | None = None

    @field_validator(
        "event_id",
        "event_type",
        "actor",
        "resource",
        "action",
        "outcome",
        "signer_id",
    )
    @classmethod
    def _strip_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @model_validator(mode="after")
    def _validate_range(self) -> "AuditFilter":
        if self.since is not None and self.until is not None and self.since > self.until:
            raise ValueError("since must be <= until")
        return self


@dataclass(frozen=True)
class SignedAuditRecord:
    """Signed immutable audit record persisted by a backend."""

    sequence: int
    event: AuditEvent
    previous_event_hash: str
    event_hash: str
    chain_hash: str
    signature_b64: str
    signature_algorithm: str
    signer_id: str
    public_key_b64: str
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    backend_metadata: dict[str, Any] = field(default_factory=dict)

    def to_payload(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "event": self.event.to_payload(),
            "previous_event_hash": self.previous_event_hash,
            "event_hash": self.event_hash,
            "chain_hash": self.chain_hash,
            "signature_b64": self.signature_b64,
            "signature_algorithm": self.signature_algorithm,
            "signer_id": self.signer_id,
            "public_key_b64": self.public_key_b64,
            "created_at": self.created_at.astimezone(UTC).isoformat(),
            "backend_metadata": dict(self.backend_metadata),
        }

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "SignedAuditRecord":
        event_payload = payload.get("event")
        if not isinstance(event_payload, Mapping):
            raise ValueError("record payload missing 'event' object")

        event = _parse_audit_event(dict(event_payload))

        created_raw = payload.get("created_at")
        if isinstance(created_raw, datetime):
            created_at = created_raw.astimezone(UTC)
        elif isinstance(created_raw, str):
            created_at = datetime.fromisoformat(created_raw)
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=UTC)
            else:
                created_at = created_at.astimezone(UTC)
        else:
            created_at = datetime.now(UTC)

        backend_metadata_raw = payload.get("backend_metadata", {})
        if not isinstance(backend_metadata_raw, Mapping):
            backend_metadata_raw = {}

        return cls(
            sequence=int(payload.get("sequence", 0)),
            event=event,
            previous_event_hash=str(payload.get("previous_event_hash", "")),
            event_hash=str(payload.get("event_hash", "")),
            chain_hash=str(payload.get("chain_hash", "")),
            signature_b64=str(payload.get("signature_b64", "")),
            signature_algorithm=str(payload.get("signature_algorithm", "")),
            signer_id=str(payload.get("signer_id", "")),
            public_key_b64=str(payload.get("public_key_b64", "")),
            created_at=created_at,
            backend_metadata=dict(backend_metadata_raw),
        )


class AuditStorageBackend(ABC):
    """Abstract backend contract for immutable audit persistence."""

    @abstractmethod
    async def append_record(self, record: SignedAuditRecord) -> SignedAuditRecord:
        """Persist a signed record and return stored record with sequence."""

    @abstractmethod
    async def query_records(self, filters: AuditFilter, limit: int) -> list[SignedAuditRecord]:
        """Query signed records matching filters."""

    @abstractmethod
    async def get_record(self, event_id: str) -> SignedAuditRecord | None:
        """Retrieve one record by event id."""

    @abstractmethod
    async def get_latest_record(self) -> SignedAuditRecord | None:
        """Return latest record in append order."""

    @abstractmethod
    async def get_records_until(self, event_id: str) -> list[SignedAuditRecord]:
        """Return records from genesis up to event_id (inclusive)."""


class BlockchainAuditBackend(AuditStorageBackend):
    """In-memory blockchain-style backend for maximum tamper-evidence semantics.

    This backend stores immutable blocks where each block embeds the previous
    chain hash and the signed record payload.
    """

    def __init__(
        self,
        *,
        anchor_callback: Callable[[dict[str, Any]], Awaitable[None] | None] | None = None,
    ) -> None:
        self._records: list[SignedAuditRecord] = []
        self._index_by_event_id: dict[str, SignedAuditRecord] = {}
        self._anchor_callback = anchor_callback
        self._lock = asyncio.Lock()

    async def append_record(self, record: SignedAuditRecord) -> SignedAuditRecord:
        async with self._lock:
            event_id = record.event.event_id
            if event_id in self._index_by_event_id:
                raise AuditStorageError(f"event_id {event_id} already exists")

            sequence = len(self._records) + 1
            stored = replace(
                record,
                sequence=sequence,
                created_at=datetime.now(UTC),
            )

            self._records.append(stored)
            self._index_by_event_id[event_id] = stored

        if self._anchor_callback is not None:
            maybe_awaitable = self._anchor_callback(
                {
                    "sequence": stored.sequence,
                    "event_id": stored.event.event_id,
                    "chain_hash": stored.chain_hash,
                    "event_hash": stored.event_hash,
                }
            )
            if asyncio.iscoroutine(maybe_awaitable):
                await maybe_awaitable

        return stored

    async def query_records(self, filters: AuditFilter, limit: int) -> list[SignedAuditRecord]:
        if limit <= 0:
            return []

        async with self._lock:
            selected = [record for record in reversed(self._records) if _record_matches_filter(record, filters)]
            return selected[:limit]

    async def get_record(self, event_id: str) -> SignedAuditRecord | None:
        async with self._lock:
            return self._index_by_event_id.get(event_id)

    async def get_latest_record(self) -> SignedAuditRecord | None:
        async with self._lock:
            return self._records[-1] if self._records else None

    async def get_records_until(self, event_id: str) -> list[SignedAuditRecord]:
        async with self._lock:
            target = self._index_by_event_id.get(event_id)
            if target is None:
                return []
            return list(self._records[: target.sequence])


class PostgreSQLAuditBackend(AuditStorageBackend):
    """PostgreSQL backend with append-only table and immutable triggers."""

    _IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

    def __init__(
        self,
        *,
        dsn: str | None = None,
        table_name: str = "audit_events",
        pool: Any | None = None,
    ) -> None:
        self._table_name = self._validate_identifier(table_name)

        if pool is None and asyncpg is None:
            raise RuntimeError(
                "PostgreSQLAuditBackend requires asyncpg"
                + _format_import_reason(_ASYNCPG_IMPORT_ERROR)
            )

        self._dsn = dsn
        self._pool = pool
        self._init_lock = asyncio.Lock()
        self._initialized = False

    @classmethod
    def build_immutable_schema_sql(cls, table_name: str) -> list[str]:
        """Build SQL statements for append-only table + immutable triggers."""
        name = cls._validate_identifier(table_name)
        function_name = f"{name}_immutable_guard"
        trigger_update = f"{name}_prevent_update"
        trigger_delete = f"{name}_prevent_delete"

        create_table = f"""
CREATE TABLE IF NOT EXISTS {name} (
    sequence BIGSERIAL PRIMARY KEY,
    event_id TEXT UNIQUE NOT NULL,
    event_json JSONB NOT NULL,
    event_type TEXT NOT NULL,
    actor TEXT NOT NULL,
    resource TEXT NOT NULL,
    action TEXT NOT NULL,
    outcome TEXT NOT NULL,
    event_timestamp TIMESTAMPTZ NOT NULL,
    previous_event_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL,
    chain_hash TEXT UNIQUE NOT NULL,
    signature_b64 TEXT NOT NULL,
    signature_algorithm TEXT NOT NULL,
    signer_id TEXT NOT NULL,
    public_key_b64 TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    backend_metadata JSONB NOT NULL DEFAULT '{{}}'::jsonb
);
""".strip()

        create_guard_function = f"""
CREATE OR REPLACE FUNCTION {function_name}()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit table % is append-only and immutable', TG_TABLE_NAME;
END;
$$ LANGUAGE plpgsql;
""".strip()

        create_update_trigger = f"""
DROP TRIGGER IF EXISTS {trigger_update} ON {name};
CREATE TRIGGER {trigger_update}
BEFORE UPDATE ON {name}
FOR EACH ROW EXECUTE FUNCTION {function_name}();
""".strip()

        create_delete_trigger = f"""
DROP TRIGGER IF EXISTS {trigger_delete} ON {name};
CREATE TRIGGER {trigger_delete}
BEFORE DELETE ON {name}
FOR EACH ROW EXECUTE FUNCTION {function_name}();
""".strip()

        return [create_table, create_guard_function, create_update_trigger, create_delete_trigger]

    async def append_record(self, record: SignedAuditRecord) -> SignedAuditRecord:
        await self._ensure_initialized()
        pool = await self._get_pool()

        query = f"""
INSERT INTO {self._table_name} (
    event_id,
    event_json,
    event_type,
    actor,
    resource,
    action,
    outcome,
    event_timestamp,
    previous_event_hash,
    event_hash,
    chain_hash,
    signature_b64,
    signature_algorithm,
    signer_id,
    public_key_b64,
    backend_metadata
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8,
    $9, $10, $11, $12, $13, $14, $15, $16
)
RETURNING sequence, created_at;
""".strip()

        event_payload = record.event.to_payload()

        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                query,
                record.event.event_id,
                event_payload,
                record.event.event_type,
                record.event.actor,
                record.event.resource,
                record.event.action,
                record.event.outcome,
                record.event.timestamp,
                record.previous_event_hash,
                record.event_hash,
                record.chain_hash,
                record.signature_b64,
                record.signature_algorithm,
                record.signer_id,
                record.public_key_b64,
                record.backend_metadata,
            )

        return replace(
            record,
            sequence=int(row["sequence"]),
            created_at=row["created_at"].astimezone(UTC),
        )

    async def query_records(self, filters: AuditFilter, limit: int) -> list[SignedAuditRecord]:
        await self._ensure_initialized()
        pool = await self._get_pool()

        conditions: list[str] = []
        args: list[Any] = []

        def _bind(value: Any) -> str:
            args.append(value)
            return f"${len(args)}"

        if filters.event_id:
            conditions.append(f"event_id = {_bind(filters.event_id)}")
        if filters.event_type:
            conditions.append(f"event_type = {_bind(filters.event_type)}")
        if filters.actor:
            conditions.append(f"actor = {_bind(filters.actor)}")
        if filters.resource:
            conditions.append(f"resource = {_bind(filters.resource)}")
        if filters.action:
            conditions.append(f"action = {_bind(filters.action)}")
        if filters.outcome:
            conditions.append(f"outcome = {_bind(filters.outcome)}")
        if filters.since is not None:
            conditions.append(f"event_timestamp >= {_bind(filters.since)}")
        if filters.until is not None:
            conditions.append(f"event_timestamp <= {_bind(filters.until)}")
        if filters.signer_id:
            conditions.append(f"signer_id = {_bind(filters.signer_id)}")

        where = ""
        if conditions:
            where = " WHERE " + " AND ".join(conditions)

        args.append(max(limit, 1))
        limit_bind = f"${len(args)}"

        query = f"""
SELECT sequence, event_json, previous_event_hash, event_hash, chain_hash,
       signature_b64, signature_algorithm, signer_id, public_key_b64,
       created_at, backend_metadata
FROM {self._table_name}
{where}
ORDER BY sequence DESC
LIMIT {limit_bind};
""".strip()

        async with pool.acquire() as conn:
            rows = await conn.fetch(query, *args)

        return [self._row_to_record(row) for row in rows]

    async def get_record(self, event_id: str) -> SignedAuditRecord | None:
        await self._ensure_initialized()
        pool = await self._get_pool()

        query = f"""
SELECT sequence, event_json, previous_event_hash, event_hash, chain_hash,
       signature_b64, signature_algorithm, signer_id, public_key_b64,
       created_at, backend_metadata
FROM {self._table_name}
WHERE event_id = $1
LIMIT 1;
""".strip()

        async with pool.acquire() as conn:
            row = await conn.fetchrow(query, event_id)

        if row is None:
            return None
        return self._row_to_record(row)

    async def get_latest_record(self) -> SignedAuditRecord | None:
        await self._ensure_initialized()
        pool = await self._get_pool()

        query = f"""
SELECT sequence, event_json, previous_event_hash, event_hash, chain_hash,
       signature_b64, signature_algorithm, signer_id, public_key_b64,
       created_at, backend_metadata
FROM {self._table_name}
ORDER BY sequence DESC
LIMIT 1;
""".strip()

        async with pool.acquire() as conn:
            row = await conn.fetchrow(query)

        if row is None:
            return None
        return self._row_to_record(row)

    async def get_records_until(self, event_id: str) -> list[SignedAuditRecord]:
        await self._ensure_initialized()
        pool = await self._get_pool()

        seq_query = f"SELECT sequence FROM {self._table_name} WHERE event_id = $1 LIMIT 1;"

        async with pool.acquire() as conn:
            seq_row = await conn.fetchrow(seq_query, event_id)
            if seq_row is None:
                return []

            target_sequence = int(seq_row["sequence"])

            rows = await conn.fetch(
                f"""
SELECT sequence, event_json, previous_event_hash, event_hash, chain_hash,
       signature_b64, signature_algorithm, signer_id, public_key_b64,
       created_at, backend_metadata
FROM {self._table_name}
WHERE sequence <= $1
ORDER BY sequence ASC;
""".strip(),
                target_sequence,
            )

        return [self._row_to_record(row) for row in rows]

    async def _ensure_initialized(self) -> None:
        if self._initialized:
            return

        async with self._init_lock:
            if self._initialized:
                return

            pool = await self._get_pool()
            statements = self.build_immutable_schema_sql(self._table_name)

            async with pool.acquire() as conn:
                for statement in statements:
                    await conn.execute(statement)

            self._initialized = True

    async def _get_pool(self) -> Any:
        if self._pool is not None:
            return self._pool

        if asyncpg is None:
            raise RuntimeError(
                "PostgreSQLAuditBackend requires asyncpg"
                + _format_import_reason(_ASYNCPG_IMPORT_ERROR)
            )

        if not self._dsn:
            raise ValueError("dsn is required for PostgreSQLAuditBackend when pool is not provided")

        self._pool = await asyncpg.create_pool(self._dsn, min_size=1, max_size=4)
        return self._pool

    def _row_to_record(self, row: Mapping[str, Any]) -> SignedAuditRecord:
        payload = {
            "sequence": int(row["sequence"]),
            "event": dict(row["event_json"]),
            "previous_event_hash": str(row["previous_event_hash"]),
            "event_hash": str(row["event_hash"]),
            "chain_hash": str(row["chain_hash"]),
            "signature_b64": str(row["signature_b64"]),
            "signature_algorithm": str(row["signature_algorithm"]),
            "signer_id": str(row["signer_id"]),
            "public_key_b64": str(row["public_key_b64"]),
            "created_at": row["created_at"],
            "backend_metadata": dict(row.get("backend_metadata", {})),
        }
        return SignedAuditRecord.from_payload(payload)

    @classmethod
    def _validate_identifier(cls, value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("table_name must be a non-empty string")
        normalized = value.strip()
        if cls._IDENTIFIER_RE.fullmatch(normalized) is None:
            raise ValueError("table_name must be a valid SQL identifier")
        return normalized


class S3AuditBackend(AuditStorageBackend):
    """S3 backend using write-once object lock retention semantics."""

    def __init__(
        self,
        *,
        bucket_name: str,
        prefix: str = "audit-events",
        region_name: str | None = None,
        endpoint_url: str | None = None,
        object_lock_mode: str = "COMPLIANCE",
        object_lock_retention_days: int = 3650,
        client: Any | None = None,
        session: Any | None = None,
    ) -> None:
        if not isinstance(bucket_name, str) or not bucket_name.strip():
            raise ValueError("bucket_name must be a non-empty string")
        if not isinstance(prefix, str) or not prefix.strip():
            raise ValueError("prefix must be a non-empty string")
        if object_lock_retention_days <= 0:
            raise ValueError("object_lock_retention_days must be > 0")

        self._bucket_name = bucket_name.strip()
        self._prefix = prefix.strip().strip("/")
        self._region_name = region_name
        self._endpoint_url = endpoint_url
        self._object_lock_mode = object_lock_mode.strip().upper()
        self._object_lock_retention_days = int(object_lock_retention_days)

        if client is None and aioboto3 is None:
            raise RuntimeError(
                "S3AuditBackend requires aioboto3"
                + _format_import_reason(_AIOBOTO3_IMPORT_ERROR)
            )

        self._client = client
        self._session = session or (aioboto3.Session() if aioboto3 is not None else None)
        self._lock = asyncio.Lock()

    async def append_record(self, record: SignedAuditRecord) -> SignedAuditRecord:
        async with self._lock:
            latest = await self.get_latest_record()
            sequence = 1 if latest is None else latest.sequence + 1

            stored = replace(
                record,
                sequence=sequence,
                created_at=datetime.now(UTC),
            )

            key = self._key_for(stored)
            payload_bytes = _canonical_json(stored.to_payload()).encode("utf-8")

            async def _op(client: Any) -> None:
                put_kwargs: dict[str, Any] = {
                    "Bucket": self._bucket_name,
                    "Key": key,
                    "Body": payload_bytes,
                    "ContentType": "application/json",
                }

                if self._object_lock_mode in {"COMPLIANCE", "GOVERNANCE"}:
                    put_kwargs["ObjectLockMode"] = self._object_lock_mode
                    put_kwargs["ObjectLockRetainUntilDate"] = (
                        datetime.now(UTC) + timedelta(days=self._object_lock_retention_days)
                    )

                await client.put_object(**put_kwargs)

            await self._with_client(_op)
            return stored

    async def query_records(self, filters: AuditFilter, limit: int) -> list[SignedAuditRecord]:
        if limit <= 0:
            return []

        keys = await self._list_keys()
        keys.sort(reverse=True)

        selected: list[SignedAuditRecord] = []
        for key in keys:
            record = await self._load_record_by_key(key)
            if _record_matches_filter(record, filters):
                selected.append(record)
                if len(selected) >= limit:
                    break

        return selected

    async def get_record(self, event_id: str) -> SignedAuditRecord | None:
        keys = await self._list_keys()
        suffix = f"-{event_id}.json"

        for key in keys:
            if key.endswith(suffix):
                return await self._load_record_by_key(key)

        return None

    async def get_latest_record(self) -> SignedAuditRecord | None:
        keys = await self._list_keys()
        if not keys:
            return None

        latest_key = max(keys)
        return await self._load_record_by_key(latest_key)

    async def get_records_until(self, event_id: str) -> list[SignedAuditRecord]:
        keys = await self._list_keys()
        keys.sort()

        collected: list[SignedAuditRecord] = []
        for key in keys:
            record = await self._load_record_by_key(key)
            collected.append(record)
            if record.event.event_id == event_id:
                return collected

        return []

    async def _with_client(self, operation: Callable[[Any], Awaitable[Any]]) -> Any:
        if self._client is not None:
            return await operation(self._client)

        if self._session is None:
            raise RuntimeError("S3 session is unavailable")

        async with self._session.client(
            "s3",
            region_name=self._region_name,
            endpoint_url=self._endpoint_url,
        ) as client:
            return await operation(client)

    async def _list_keys(self) -> list[str]:
        prefix = f"{self._prefix}/"
        keys: list[str] = []
        token: str | None = None

        while True:
            async def _op(client: Any) -> dict[str, Any]:
                params: dict[str, Any] = {
                    "Bucket": self._bucket_name,
                    "Prefix": prefix,
                }
                if token is not None:
                    params["ContinuationToken"] = token
                return await client.list_objects_v2(**params)

            page = await self._with_client(_op)
            contents = page.get("Contents", [])
            for item in contents:
                key = item.get("Key")
                if isinstance(key, str) and key.endswith(".json"):
                    keys.append(key)

            if not bool(page.get("IsTruncated")):
                break

            next_token = page.get("NextContinuationToken")
            token = str(next_token) if next_token is not None else None

            if token is None:
                break

        return keys

    async def _load_record_by_key(self, key: str) -> SignedAuditRecord:
        async def _op(client: Any) -> bytes:
            response = await client.get_object(Bucket=self._bucket_name, Key=key)
            body = response.get("Body")
            if body is None:
                raise AuditStorageError("S3 object body is missing")

            data = await body.read()
            return bytes(data)

        blob = await self._with_client(_op)
        payload = json.loads(blob.decode("utf-8"))
        return SignedAuditRecord.from_payload(payload)

    def _key_for(self, record: SignedAuditRecord) -> str:
        return f"{self._prefix}/{record.sequence:020d}-{record.event.event_id}.json"


class AuditStorage:
    """High-level immutable audit storage API with pluggable backends."""

    def __init__(
        self,
        *,
        backend: AuditStorageBackend | None = None,
        backend_name: str = "blockchain",
        backend_options: Mapping[str, Any] | None = None,
        audit_private_key: str | bytes | None = None,
        signer_id: str = "keycrypt-audit-storage",
    ) -> None:
        self._backend = backend or self.build_backend(backend_name, **dict(backend_options or {}))
        self._signer_id = self._require_non_empty("signer_id", signer_id)
        self._private_key = self._load_or_generate_private_key(audit_private_key)
        self._public_key_raw = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        self._append_lock = asyncio.Lock()

    @staticmethod
    def build_backend(backend_name: str, **backend_options: Any) -> AuditStorageBackend:
        """Construct backend implementation by name."""
        if not isinstance(backend_name, str) or not backend_name.strip():
            raise ValueError("backend_name must be a non-empty string")

        normalized = backend_name.strip().lower()
        if normalized in {"postgres", "postgresql"}:
            return PostgreSQLAuditBackend(**backend_options)
        if normalized == "s3":
            return S3AuditBackend(**backend_options)
        if normalized == "blockchain":
            return BlockchainAuditBackend(**backend_options)

        raise ValueError("unsupported backend_name; expected postgresql, s3, or blockchain")

    async def append_event(self, event: AuditEvent) -> str:
        """Append one signed immutable event and return event_id."""
        if not isinstance(event, AuditEvent):
            raise TypeError("event must be an AuditEvent instance")

        async with self._append_lock:
            latest = await self._backend.get_latest_record()
            previous_event_hash = latest.chain_hash if latest is not None else _GENESIS_PREVIOUS_HASH

            event_hash = self._hash_event(event)
            chain_hash = self._hash_chain(
                event_id=event.event_id,
                previous_event_hash=previous_event_hash,
                event_hash=event_hash,
            )

            signature_b64 = self._sign_record(
                event_id=event.event_id,
                event_hash=event_hash,
                previous_event_hash=previous_event_hash,
                chain_hash=chain_hash,
            )

            record = SignedAuditRecord(
                sequence=0,
                event=event,
                previous_event_hash=previous_event_hash,
                event_hash=event_hash,
                chain_hash=chain_hash,
                signature_b64=signature_b64,
                signature_algorithm=_SIGNATURE_ALGORITHM,
                signer_id=self._signer_id,
                public_key_b64=base64.b64encode(self._public_key_raw).decode("ascii"),
                created_at=datetime.now(UTC),
                backend_metadata={},
            )

            stored = await self._backend.append_record(record)

        log_security_event(
            "audit_event_appended",
            severity="INFO",
            actor=self._signer_id,
            target=event.event_id,
            details={
                "event_type": event.event_type,
                "sequence": stored.sequence,
                "backend": self._backend.__class__.__name__,
            },
        )

        return event.event_id

    async def query_events(self, filters: AuditFilter, limit: int) -> List[AuditEvent]:
        """Query events by typed filters and return audit event models."""
        if isinstance(filters, Mapping):
            filters = AuditFilter.model_validate(filters)
        elif not isinstance(filters, AuditFilter):
            raise TypeError("filters must be AuditFilter or mapping")

        if not isinstance(limit, int) or limit <= 0:
            raise ValueError("limit must be a positive integer")

        records = await self._backend.query_records(filters, limit)
        return [record.event for record in records]

    async def verify_integrity(self, event_id: str) -> bool:
        """Verify hash chain and signatures up to the specified event id."""
        normalized_event_id = self._require_non_empty("event_id", event_id)
        records = await self._backend.get_records_until(normalized_event_id)

        if not records:
            return False

        expected_previous_hash = _GENESIS_PREVIOUS_HASH
        target_seen = False

        for record in records:
            if record.previous_event_hash != expected_previous_hash:
                return False

            recomputed_event_hash = self._hash_event(record.event)
            if recomputed_event_hash != record.event_hash:
                return False

            recomputed_chain_hash = self._hash_chain(
                event_id=record.event.event_id,
                previous_event_hash=record.previous_event_hash,
                event_hash=record.event_hash,
            )
            if recomputed_chain_hash != record.chain_hash:
                return False

            if record.signature_algorithm != _SIGNATURE_ALGORITHM:
                return False

            if not self._verify_record_signature(record):
                return False

            expected_previous_hash = record.chain_hash
            if record.event.event_id == normalized_event_id:
                target_seen = True

        return target_seen

    @staticmethod
    def _hash_event(event: AuditEvent) -> str:
        return _sha256_text(_canonical_json(event.to_payload()))

    @staticmethod
    def _hash_chain(*, event_id: str, previous_event_hash: str, event_hash: str) -> str:
        payload = {
            "event_id": event_id,
            "previous_event_hash": previous_event_hash,
            "event_hash": event_hash,
        }
        return _sha256_text(_canonical_json(payload))

    def _sign_record(
        self,
        *,
        event_id: str,
        event_hash: str,
        previous_event_hash: str,
        chain_hash: str,
    ) -> str:
        message = _signature_message(
            event_id=event_id,
            event_hash=event_hash,
            previous_event_hash=previous_event_hash,
            chain_hash=chain_hash,
            signer_id=self._signer_id,
        )
        signature = self._private_key.sign(message)
        return base64.b64encode(signature).decode("ascii")

    def _verify_record_signature(self, record: SignedAuditRecord) -> bool:
        try:
            public_bytes = base64.b64decode(record.public_key_b64)
            signature = base64.b64decode(record.signature_b64)
            public_key = Ed25519PublicKey.from_public_bytes(public_bytes)

            message = _signature_message(
                event_id=record.event.event_id,
                event_hash=record.event_hash,
                previous_event_hash=record.previous_event_hash,
                chain_hash=record.chain_hash,
                signer_id=record.signer_id,
            )
            public_key.verify(signature, message)
            return True
        except Exception:
            return False

    @staticmethod
    def _load_or_generate_private_key(value: str | bytes | None) -> Ed25519PrivateKey:
        if value is None:
            return Ed25519PrivateKey.generate()

        if isinstance(value, str):
            text = value.strip()
            if not text:
                raise ValueError("audit_private_key cannot be empty")

            if text.startswith("-----BEGIN"):
                raw = text.encode("utf-8")
                loaded = serialization.load_pem_private_key(raw, password=None)
                if not isinstance(loaded, Ed25519PrivateKey):
                    raise ValueError("audit_private_key PEM must contain Ed25519 private key")
                return loaded

            try:
                key_bytes = base64.b64decode(text)
            except Exception as exc:
                raise ValueError("audit_private_key string must be base64 or PEM") from exc
            return Ed25519PrivateKey.from_private_bytes(key_bytes)

        if isinstance(value, bytes):
            if not value:
                raise ValueError("audit_private_key bytes cannot be empty")

            if value.startswith(b"-----BEGIN"):
                loaded = serialization.load_pem_private_key(value, password=None)
                if not isinstance(loaded, Ed25519PrivateKey):
                    raise ValueError("audit_private_key PEM must contain Ed25519 private key")
                return loaded

            return Ed25519PrivateKey.from_private_bytes(value)

        raise TypeError("audit_private_key must be str, bytes, or None")

    @staticmethod
    def _require_non_empty(name: str, value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must be a non-empty string")
        return value.strip()


def _parse_audit_event(payload: dict[str, Any]) -> AuditEvent:
    event_type = str(payload.get("event_type", "")).strip()
    if event_type == "encryption":
        return EncryptionEvent.model_validate(payload)
    if event_type == "key_rotation":
        return KeyRotationEvent.model_validate(payload)
    if event_type == "access":
        return AccessEvent.model_validate(payload)
    if event_type == "config_change":
        return ConfigChangeEvent.model_validate(payload)
    return AuditEvent.model_validate(payload)


def _record_matches_filter(record: SignedAuditRecord, filters: AuditFilter) -> bool:
    event = record.event

    if filters.event_id and event.event_id != filters.event_id:
        return False
    if filters.event_type and event.event_type != filters.event_type:
        return False
    if filters.actor and event.actor != filters.actor:
        return False
    if filters.resource and event.resource != filters.resource:
        return False
    if filters.action and event.action != filters.action:
        return False
    if filters.outcome and event.outcome != filters.outcome:
        return False
    if filters.signer_id and record.signer_id != filters.signer_id:
        return False

    event_ts = event.timestamp.astimezone(UTC)
    if filters.since is not None:
        since_ts = filters.since if filters.since.tzinfo is not None else filters.since.replace(tzinfo=UTC)
        if event_ts < since_ts.astimezone(UTC):
            return False
    if filters.until is not None:
        until_ts = filters.until if filters.until.tzinfo is not None else filters.until.replace(tzinfo=UTC)
        if event_ts > until_ts.astimezone(UTC):
            return False

    return True


def _signature_message(
    *,
    event_id: str,
    event_hash: str,
    previous_event_hash: str,
    chain_hash: str,
    signer_id: str,
) -> bytes:
    payload = {
        "event_id": event_id,
        "event_hash": event_hash,
        "previous_event_hash": previous_event_hash,
        "chain_hash": chain_hash,
        "signer_id": signer_id,
        "signature_algorithm": _SIGNATURE_ALGORITHM,
    }
    return _canonical_json(payload).encode("utf-8")


def _canonical_json(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"), default=str)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _format_import_reason(error: Exception | None) -> str:
    if error is None:
        return ""
    return f": {error}"


__all__ = [
    "ValidationError",
    "AuditStorageError",
    "AuditFilter",
    "SignedAuditRecord",
    "AuditStorageBackend",
    "PostgreSQLAuditBackend",
    "S3AuditBackend",
    "BlockchainAuditBackend",
    "AuditStorage",
]
