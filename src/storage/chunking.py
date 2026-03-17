"""File chunking and parallel chunk encryption utilities.

This module provides chunk-based processing for large-file encryption flows.
Chunks are encrypted independently using AES-256-GCM and can be reassembled
with integrity verification.
"""

from __future__ import annotations

import hashlib
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Generator, Iterable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


DEFAULT_CHUNK_SIZE = 1024 * 1024
GCM_NONCE_SIZE = 12
GCM_TAG_SIZE = 16


@dataclass(frozen=True)
class FileChunk:
    chunk_id: int
    data: bytes
    hash: str
    size: int


@dataclass(frozen=True)
class EncryptedChunk:
    chunk_id: int
    ciphertext: bytes
    hash: str
    encryption_metadata: dict[str, Any]
    authentication_tag: bytes


class FileChunker:
    """Chunk, encrypt, and reassemble large files.

    Encryption details:
    - AES-256-GCM per chunk
    - Per-chunk nonce
    - Additional authenticated data (AAD) binds chunk metadata
    """

    def __init__(self, key: bytes | None = None) -> None:
        self._key = key

    def chunk_file(self, filepath: str | Path, chunk_size: int = DEFAULT_CHUNK_SIZE) -> Generator[FileChunk, None, None]:
        """Yield file chunks from disk.

        Args:
            filepath: Source file path.
            chunk_size: Chunk size in bytes, default is 1MB.

        Yields:
            FileChunk objects containing plaintext bytes and SHA-256 hash.
        """
        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive")

        source = Path(filepath)
        if not source.exists() or not source.is_file():
            raise FileNotFoundError(f"file not found: {source}")

        with source.open("rb") as handle:
            chunk_id = 0
            while True:
                data = handle.read(chunk_size)
                if not data:
                    break

                digest = hashlib.sha256(data).hexdigest()
                yield FileChunk(
                    chunk_id=chunk_id,
                    data=data,
                    hash=digest,
                    size=len(data),
                )
                chunk_id += 1

    def encrypt_chunks(
        self,
        chunks: Iterable[FileChunk],
        key: bytes,
        *,
        max_workers: int | None = None,
        progress_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> list[EncryptedChunk]:
        """Encrypt chunks in parallel with ThreadPoolExecutor.

        Args:
            chunks: Iterable of FileChunk entries.
            key: AES key (16, 24, or 32 bytes).
            max_workers: Optional thread pool size.
            progress_callback: Optional callback invoked after each completed chunk.

        Returns:
            List of EncryptedChunk sorted by chunk_id.
        """
        self._validate_key(key)
        self._key = key

        chunk_list = list(chunks)
        total = len(chunk_list)
        if total == 0:
            return []

        workers = max_workers if max_workers is not None else min(32, max(2, os.cpu_count() or 2))
        encrypted: list[EncryptedChunk] = []
        completed = 0

        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_map = {executor.submit(self._encrypt_one_chunk, chunk, key): chunk.chunk_id for chunk in chunk_list}

            for future in as_completed(future_map):
                result = future.result()
                encrypted.append(result)

                completed += 1
                if progress_callback is not None:
                    progress_callback(
                        {
                            "stage": "encrypt",
                            "completed": completed,
                            "total": total,
                            "progress": completed / total,
                            "chunk_id": result.chunk_id,
                        }
                    )

        encrypted.sort(key=lambda c: c.chunk_id)
        return encrypted

    def reassemble_file(
        self,
        encrypted_chunks: Iterable[EncryptedChunk | dict[str, Any]],
        output_path: str | Path,
        *,
        key: bytes | None = None,
        progress_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> Path:
        """Decrypt encrypted chunks and write a reassembled output file.

        Args:
            encrypted_chunks: Sequence of EncryptedChunk objects or equivalent dictionaries.
            output_path: File path for reconstructed plaintext.
            key: Optional AES key; falls back to previously used key.
            progress_callback: Optional callback invoked after each decrypted chunk.

        Returns:
            Path to the reconstructed output file.
        """
        effective_key = key if key is not None else self._key
        if effective_key is None:
            raise ValueError("no key available: pass key explicitly or call encrypt_chunks first")
        self._validate_key(effective_key)

        chunks = [self._coerce_encrypted_chunk(c) for c in encrypted_chunks]
        chunks.sort(key=lambda c: c.chunk_id)

        destination = Path(output_path)
        destination.parent.mkdir(parents=True, exist_ok=True)

        total = len(chunks)
        with destination.open("wb") as handle:
            for index, chunk in enumerate(chunks, start=1):
                plaintext = self._decrypt_one_chunk(chunk, effective_key)
                digest = hashlib.sha256(plaintext).hexdigest()
                if digest != chunk.hash:
                    raise ValueError(f"chunk integrity check failed for chunk_id={chunk.chunk_id}")

                handle.write(plaintext)

                if progress_callback is not None:
                    progress_callback(
                        {
                            "stage": "reassemble",
                            "completed": index,
                            "total": total,
                            "progress": (index / total) if total else 1.0,
                            "chunk_id": chunk.chunk_id,
                        }
                    )

        return destination

    def _encrypt_one_chunk(self, chunk: FileChunk, key: bytes) -> EncryptedChunk:
        nonce = os.urandom(GCM_NONCE_SIZE)
        aad = f"chunk:{chunk.chunk_id}|hash:{chunk.hash}|size:{chunk.size}".encode("utf-8")

        encrypted = AESGCM(key).encrypt(nonce, chunk.data, aad)
        ciphertext = encrypted[:-GCM_TAG_SIZE]
        tag = encrypted[-GCM_TAG_SIZE:]

        metadata = {
            "algorithm": "AES-256-GCM" if len(key) == 32 else "AES-GCM",
            "nonce": nonce.hex(),
            "aad": aad.decode("utf-8"),
            "size": chunk.size,
        }

        return EncryptedChunk(
            chunk_id=chunk.chunk_id,
            ciphertext=ciphertext,
            hash=chunk.hash,
            encryption_metadata=metadata,
            authentication_tag=tag,
        )

    def _decrypt_one_chunk(self, chunk: EncryptedChunk, key: bytes) -> bytes:
        nonce_hex = chunk.encryption_metadata.get("nonce")
        aad_text = chunk.encryption_metadata.get("aad")
        if not isinstance(nonce_hex, str) or not isinstance(aad_text, str):
            raise ValueError(f"invalid encryption metadata for chunk_id={chunk.chunk_id}")

        nonce = bytes.fromhex(nonce_hex)
        if len(nonce) != GCM_NONCE_SIZE:
            raise ValueError(f"invalid nonce size for chunk_id={chunk.chunk_id}")

        aad = aad_text.encode("utf-8")
        combined = chunk.ciphertext + chunk.authentication_tag
        return AESGCM(key).decrypt(nonce, combined, aad)

    @staticmethod
    def _validate_key(key: bytes) -> None:
        if not isinstance(key, bytes):
            raise TypeError("key must be bytes")
        if len(key) not in {16, 24, 32}:
            raise ValueError("key must be 16, 24, or 32 bytes for AES-GCM")

    @staticmethod
    def _coerce_encrypted_chunk(value: EncryptedChunk | dict[str, Any]) -> EncryptedChunk:
        if isinstance(value, EncryptedChunk):
            return value

        if not isinstance(value, dict):
            raise TypeError("encrypted_chunks must contain EncryptedChunk or dict entries")

        required = {"chunk_id", "ciphertext", "hash", "encryption_metadata", "authentication_tag"}
        missing = required - set(value.keys())
        if missing:
            raise ValueError(f"encrypted chunk missing fields: {', '.join(sorted(missing))}")

        return EncryptedChunk(
            chunk_id=int(value["chunk_id"]),
            ciphertext=bytes(value["ciphertext"]),
            hash=str(value["hash"]),
            encryption_metadata=dict(value["encryption_metadata"]),
            authentication_tag=bytes(value["authentication_tag"]),
        )


__all__ = ["FileChunk", "EncryptedChunk", "FileChunker"]
