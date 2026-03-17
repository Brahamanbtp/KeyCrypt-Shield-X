"""Local filesystem backend for encrypted chunk storage.

Design goals:
- Content-addressable storage keyed by SHA-256 chunk id
- Directory fan-out by prefix (first 2 hex chars)
- Metadata persistence for encryption context
- Integrity verification on retrieval
- Secure deletion with overwrite passes
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any


class SecureLocalStorage:
    """Filesystem storage backend for encrypted chunks."""

    def __init__(self, root_dir: str | Path = "chunk_store") -> None:
        self.root_dir = Path(root_dir)
        self.root_dir.mkdir(parents=True, exist_ok=True)

    def store_chunk(self, chunk_id: str, encrypted_data: bytes, metadata: dict[str, Any]) -> Path:
        """Store encrypted chunk bytes and associated metadata on disk.

        Args:
            chunk_id: Expected SHA-256 hex digest of encrypted_data.
            encrypted_data: Encrypted chunk payload bytes.
            metadata: Chunk metadata (nonce, aad, tag, algorithm, etc.).

        Returns:
            Path to stored chunk file.
        """
        self._validate_chunk_id(chunk_id)
        if not isinstance(encrypted_data, bytes) or not encrypted_data:
            raise ValueError("encrypted_data must be non-empty bytes")
        if not isinstance(metadata, dict):
            raise TypeError("metadata must be a dictionary")

        computed = hashlib.sha256(encrypted_data).hexdigest()
        if computed != chunk_id.lower():
            raise ValueError("chunk_id does not match SHA-256(encrypted_data)")

        chunk_path = self._chunk_path(chunk_id)
        meta_path = self._meta_path(chunk_id)
        chunk_path.parent.mkdir(parents=True, exist_ok=True)

        checksum = hashlib.sha256(encrypted_data).hexdigest()
        payload = {
            "chunk_id": chunk_id.lower(),
            "data_checksum": checksum,
            "size": len(encrypted_data),
            "metadata": metadata,
        }

        temp_chunk = chunk_path.with_suffix(".tmp")
        temp_meta = meta_path.with_suffix(".tmp")

        with temp_chunk.open("wb") as handle:
            handle.write(encrypted_data)

        with temp_meta.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, separators=(",", ":"), sort_keys=True)

        temp_chunk.replace(chunk_path)
        temp_meta.replace(meta_path)

        return chunk_path

    def retrieve_chunk(self, chunk_id: str) -> tuple[bytes, dict[str, Any]]:
        """Retrieve encrypted chunk bytes and metadata with integrity checks."""
        self._validate_chunk_id(chunk_id)

        chunk_path = self._chunk_path(chunk_id)
        meta_path = self._meta_path(chunk_id)

        if not chunk_path.exists() or not meta_path.exists():
            raise FileNotFoundError(f"chunk not found: {chunk_id}")

        encrypted_data = chunk_path.read_bytes()

        with meta_path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)

        if not isinstance(payload, dict):
            raise ValueError("invalid metadata payload")

        stored_chunk_id = str(payload.get("chunk_id", "")).lower()
        if stored_chunk_id != chunk_id.lower():
            raise ValueError("chunk id mismatch in metadata")

        computed_hash = hashlib.sha256(encrypted_data).hexdigest()
        if computed_hash != chunk_id.lower():
            raise ValueError("chunk integrity verification failed: content hash mismatch")

        data_checksum = str(payload.get("data_checksum", "")).lower()
        if data_checksum != computed_hash:
            raise ValueError("chunk integrity verification failed: checksum mismatch")

        size = int(payload.get("size", -1))
        if size != len(encrypted_data):
            raise ValueError("chunk integrity verification failed: size mismatch")

        metadata = payload.get("metadata", {})
        if not isinstance(metadata, dict):
            raise ValueError("invalid metadata object")

        return encrypted_data, metadata

    def delete_chunk(self, chunk_id: str, *, overwrite_passes: int = 2) -> None:
        """Securely delete chunk and metadata by overwriting before unlink.

        Args:
            chunk_id: SHA-256 chunk identifier.
            overwrite_passes: Number of overwrite passes for the chunk payload.
        """
        self._validate_chunk_id(chunk_id)
        if overwrite_passes < 1:
            raise ValueError("overwrite_passes must be >= 1")

        chunk_path = self._chunk_path(chunk_id)
        meta_path = self._meta_path(chunk_id)

        if chunk_path.exists():
            self._secure_overwrite(chunk_path, overwrite_passes)
            chunk_path.unlink(missing_ok=True)

        if meta_path.exists():
            self._secure_overwrite(meta_path, 1)
            meta_path.unlink(missing_ok=True)

    def _chunk_path(self, chunk_id: str) -> Path:
        normalized = chunk_id.lower()
        subdir = normalized[:2]
        return self.root_dir / subdir / f"{normalized}.bin"

    def _meta_path(self, chunk_id: str) -> Path:
        normalized = chunk_id.lower()
        subdir = normalized[:2]
        return self.root_dir / subdir / f"{normalized}.meta.json"

    @staticmethod
    def _validate_chunk_id(chunk_id: str) -> None:
        if not isinstance(chunk_id, str):
            raise TypeError("chunk_id must be a string")
        normalized = chunk_id.lower()
        if len(normalized) != 64 or any(ch not in "0123456789abcdef" for ch in normalized):
            raise ValueError("chunk_id must be a 64-character SHA-256 hex string")

    @staticmethod
    def _secure_overwrite(path: Path, passes: int) -> None:
        size = path.stat().st_size
        if size == 0:
            return

        with path.open("r+b") as handle:
            for idx in range(passes):
                handle.seek(0)
                if idx == passes - 1:
                    handle.write(b"\x00" * size)
                else:
                    handle.write(os.urandom(size))
                handle.flush()
                os.fsync(handle.fileno())


__all__ = ["SecureLocalStorage"]
