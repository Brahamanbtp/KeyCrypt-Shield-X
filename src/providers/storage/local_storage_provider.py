"""Async storage provider adapter over SecureLocalStorage.

This module wraps the synchronous local storage backend with an asynchronous
`StorageProvider` implementation using `asyncio.to_thread`.
"""

from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
from typing import Any, AsyncIterator, Tuple

from ...abstractions.storage_provider import StorageProvider
from ...storage.local_storage import SecureLocalStorage


class LocalStorageProvider(StorageProvider):
    """Async adapter for the synchronous SecureLocalStorage backend."""

    def __init__(self, root_dir: str | Path = "chunk_store") -> None:
        """Initialize the wrapped local storage backend."""
        self._backend = SecureLocalStorage(root_dir=root_dir)

    async def write(self, data: bytes, metadata: dict[str, Any]) -> str:
        """Store payload bytes and return the derived object identifier."""
        if not isinstance(data, bytes) or not data:
            raise ValueError("data must be non-empty bytes")
        if not isinstance(metadata, dict):
            raise TypeError("metadata must be a dictionary")

        object_id = hashlib.sha256(data).hexdigest()
        await asyncio.to_thread(self._backend.store_chunk, object_id, data, metadata)
        return object_id

    async def read(self, object_id: str) -> Tuple[bytes, dict[str, Any]]:
        """Read object payload and metadata by object identifier."""
        data, metadata = await asyncio.to_thread(self._backend.retrieve_chunk, object_id)
        return data, metadata

    async def delete(self, object_id: str) -> bool:
        """Delete object if present and return whether it existed."""
        existed = await asyncio.to_thread(self._object_exists, object_id)
        if not existed:
            return False

        await asyncio.to_thread(self._backend.delete_chunk, object_id)
        return True

    async def list_objects(self, prefix: str) -> AsyncIterator[str]:
        """Asynchronously yield stored object identifiers matching prefix."""
        if not isinstance(prefix, str):
            raise TypeError("prefix must be a string")

        object_ids = await asyncio.to_thread(self._scan_object_ids)
        for object_id in object_ids:
            if object_id.startswith(prefix.lower()):
                yield object_id

    def _object_exists(self, object_id: str) -> bool:
        try:
            chunk_path = self._backend._chunk_path(object_id)  # type: ignore[attr-defined]
            meta_path = self._backend._meta_path(object_id)  # type: ignore[attr-defined]
        except Exception:
            return False
        return chunk_path.exists() and meta_path.exists()

    def _scan_object_ids(self) -> list[str]:
        root = self._backend.root_dir
        if not root.exists():
            return []

        ids: list[str] = []
        for path in root.rglob("*.bin"):
            name = path.stem.lower()
            if len(name) == 64 and all(ch in "0123456789abcdef" for ch in name):
                ids.append(name)

        ids.sort()
        return ids


__all__ = ["LocalStorageProvider"]
