"""Local key provider adapter over the existing KeyManager.

This module implements the `KeyProvider` abstraction by delegating key
lifecycle operations to `src.core.key_manager.KeyManager` without modifying the
core key manager implementation.
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Any, List, Optional

from ...abstractions.key_provider import (
    KeyFilter,
    KeyGenerationParams,
    KeyMaterial,
    KeyMetadata,
    KeyProvider,
)
from ...core.key_manager import KeyManager


class LocalKeyProvider(KeyProvider):
    """KeyProvider implementation backed by local KeyManager storage."""

    def __init__(
        self,
        db_path: str | Path = "key_manager.db",
        *,
        kek: bytes | None = None,
        kek_env_var: str = "KEYCRYPT_KEK_B64",
    ) -> None:
        """Create a LocalKeyProvider and initialize the wrapped KeyManager."""
        self._key_manager = KeyManager(db_path=db_path, kek=kek, kek_env_var=kek_env_var)

    def get_key(self, key_id: str) -> KeyMaterial:
        """Retrieve key material and associated metadata via KeyManager."""
        material = self._key_manager.get_key(key_id)
        record = self._key_manager.get_key_record(key_id)

        return KeyMaterial(
            key_id=record.key_id,
            algorithm=record.algorithm,
            material=material,
            version=1,
            metadata=record.metadata,
        )

    def generate_key(self, params: KeyGenerationParams) -> str:
        """Generate a new key by delegating to KeyManager.generate_master_key."""
        if not isinstance(params, KeyGenerationParams):
            raise TypeError("params must be KeyGenerationParams")

        created = self._key_manager.generate_master_key(params.algorithm)
        key_id = created.get("key_id")
        if not isinstance(key_id, str) or not key_id:
            raise RuntimeError("KeyManager returned an invalid key_id")
        return key_id

    def rotate_key(self, key_id: str) -> str:
        """Rotate an existing key and return replacement key identifier."""
        result = self._key_manager.rotate_key(key_id, reason="provider_rotation")
        new_key_id = result.get("new_key_id")
        if not isinstance(new_key_id, str) or not new_key_id:
            raise RuntimeError("KeyManager returned an invalid new_key_id")
        return new_key_id

    def list_keys(self, filter: Optional[KeyFilter]) -> List[KeyMetadata]:
        """List key metadata records from local KeyManager storage.

        KeyManager does not currently expose a public list API, so this adapter
        reads metadata rows through the manager's established connection.
        """
        key_filter = filter or KeyFilter()

        query = (
            "SELECT key_id, algorithm, metadata, created_at, expires_at, revoked_at, revoked_reason, deleted "
            "FROM keys ORDER BY created_at DESC"
        )

        with self._key_manager._lock, self._key_manager._connect() as conn:  # type: ignore[attr-defined]
            conn.row_factory = sqlite3.Row
            rows = conn.execute(query).fetchall()

        now = time.time()
        items: List[KeyMetadata] = []

        for row in rows:
            algorithm = str(row["algorithm"])
            if key_filter.algorithm and algorithm.lower() != key_filter.algorithm.lower():
                continue

            metadata = self._key_manager._parse_metadata(row["metadata"])  # type: ignore[attr-defined]
            tags = metadata.get("tags", {}) if isinstance(metadata.get("tags", {}), dict) else {}

            if key_filter.tags and not self._matches_tags(tags, key_filter.tags):
                continue

            status = self._derive_status(
                deleted=int(row["deleted"]),
                revoked_at=row["revoked_at"],
                expires_at=row["expires_at"],
                now=now,
            )

            if key_filter.active_only and status != "active":
                continue
            if not key_filter.include_retired and status in {"revoked", "expired", "deleted"}:
                continue

            items.append(
                KeyMetadata(
                    key_id=str(row["key_id"]),
                    algorithm=algorithm,
                    provider="local",
                    version=1,
                    created_at=float(row["created_at"]),
                    expires_at=float(row["expires_at"]) if row["expires_at"] is not None else None,
                    status=status,
                    tags=tags,
                    metadata=metadata,
                )
            )

            if key_filter.limit is not None and key_filter.limit > 0 and len(items) >= key_filter.limit:
                break

        return items

    @staticmethod
    def _matches_tags(candidate: dict[str, str], required: Any) -> bool:
        if not isinstance(required, dict):
            return False
        for key, value in required.items():
            if candidate.get(key) != value:
                return False
        return True

    @staticmethod
    def _derive_status(*, deleted: int, revoked_at: Any, expires_at: Any, now: float) -> str:
        if deleted == 1:
            return "deleted"
        if revoked_at is not None:
            return "revoked"
        if expires_at is not None and float(expires_at) <= now:
            return "expired"
        return "active"


__all__ = ["LocalKeyProvider"]
