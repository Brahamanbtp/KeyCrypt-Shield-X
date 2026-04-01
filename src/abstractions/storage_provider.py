"""Abstract storage provider interface for pluggable storage backends.

This module defines a minimal asynchronous contract for object storage used by
higher-level encryption and orchestration flows. Concrete implementations may
target local disk, cloud object stores, distributed content networks, or other
persistence systems while exposing identical behavior to callers.

The interface is intentionally backend-agnostic and focused on core operations:
write, read, delete, and object enumeration.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, AsyncIterator, Tuple


class StorageProvider(ABC):
    """Abstract base class for asynchronous storage backends.

    Implementations should provide durable object storage semantics and map
    backend-specific failures into predictable exceptions for callers.

    Notes for implementers:
    - `write` should return a stable object identifier.
    - `read` should return the exact stored payload plus metadata.
    - `delete` should be idempotent where possible.
    - `list_objects` should stream identifiers asynchronously.
    """

    @abstractmethod
    async def write(self, data: bytes, metadata: dict[str, Any]) -> str:
        """Persist an object and return its identifier.

        Args:
            data: Raw bytes to store.
            metadata: Arbitrary object metadata associated with the write.

        Returns:
            A provider-generated object identifier.

        Raises:
            ValueError: If input payload or metadata is invalid.
            RuntimeError: If the backend write operation fails.
        """

    @abstractmethod
    async def read(self, object_id: str) -> Tuple[bytes, dict[str, Any]]:
        """Retrieve a previously stored object and its metadata.

        Args:
            object_id: Unique identifier previously returned by `write`.

        Returns:
            A tuple `(data, metadata)` where `data` is the stored payload bytes
            and `metadata` contains associated object attributes.

        Raises:
            ValueError: If `object_id` is malformed.
            RuntimeError: If the backend cannot retrieve the object.
        """

    @abstractmethod
    async def delete(self, object_id: str) -> bool:
        """Delete an object by identifier.

        Args:
            object_id: Unique identifier of the object to remove.

        Returns:
            `True` when the object was deleted, or `False` when no matching
            object existed.

        Raises:
            ValueError: If `object_id` is malformed.
            RuntimeError: If the backend delete operation fails.
        """

    @abstractmethod
    async def list_objects(self, prefix: str) -> AsyncIterator[str]:
        """Asynchronously iterate object identifiers matching a prefix.

        Args:
            prefix: Prefix used to scope object enumeration.

        Yields:
            Object identifiers that match the provided prefix.

        Raises:
            ValueError: If `prefix` is invalid for the backend.
            RuntimeError: If object listing fails.
        """
