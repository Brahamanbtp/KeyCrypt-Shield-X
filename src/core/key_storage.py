"""Encrypted key storage backend with SQLCipher-compatible SQLite access.

Features:
- SQLCipher PRAGMA key support (when linked SQLite supports SQLCipher)
- Envelope-style key material encryption at application layer
- Master key derivation from password using Argon2id
- Automatic expiry status updates
- Key rotation scheduling helpers
"""

from __future__ import annotations

import base64
import os
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.utils.logging import get_logger


logger = get_logger("src.core.key_storage")


class KeyStorageError(Exception):
    """Base error for key storage operations."""


@dataclass(frozen=True)
class KeyEntry:
    id: str
    algorithm: str
    created_at: float
    expires_at: float | None
    status: str


class KeyStorage:
    """Encrypted key storage backend for lifecycle-managed keys."""

    _STATUSES = {"active", "expired", "revoked", "rotating", "deleted"}

    def __init__(
        self,
        db_path: str | Path = "key_storage.db",
        *,
        password_env_var: str = "KEY_STORAGE_PASSWORD",
        salt_env_var: str = "KEY_STORAGE_SALT_B64",
        derived_key_env_var: str = "KEY_STORAGE_MASTER_KEY_B64",
        rotation_window_seconds: int = 7 * 24 * 3600,
    ) -> None:
        self.db_path = Path(db_path)
        self.password_env_var = password_env_var
        self.salt_env_var = salt_env_var
        self.derived_key_env_var = derived_key_env_var
        self.rotation_window_seconds = rotation_window_seconds
        self._lock = threading.RLock()

        self._master_key = self._derive_and_store_master_key()
        self._sqlcipher_key = base64.urlsafe_b64encode(self._master_key).decode("ascii")

        self._init_schema()

    def store_key(
        self,
        key_id: str,
        key_material: bytes,
        algorithm: str,
        *,
        expires_at: float | None = None,
        status: str = "active",
    ) -> None:
        """Store encrypted key material with metadata."""
        self._validate_key_id(key_id)
        self._require_bytes("key_material", key_material)

        if not algorithm or not isinstance(algorithm, str):
            raise ValueError("algorithm must be a non-empty string")
        self._validate_status(status)

        now = time.time()
        if expires_at is not None and expires_at <= now:
            status = "expired"

        nonce = os.urandom(12)
        aad = self._aad(key_id, algorithm)
        encrypted_key_material = nonce + AESGCM(self._master_key).encrypt(nonce, key_material, aad)

        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO keys
                (id, encrypted_key_material, algorithm, created_at, expires_at, status)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (key_id, encrypted_key_material, algorithm.upper().strip(), now, expires_at, status),
            )
            conn.commit()

        logger.info(
            "stored key id={key_id} algorithm={algorithm} expires_at={expires_at} status={status}",
            key_id=key_id,
            algorithm=algorithm,
            expires_at=expires_at,
            status=status,
        )

    def retrieve_key(self, key_id: str) -> bytes:
        """Retrieve decrypted key material if key is active and not expired."""
        self._validate_key_id(key_id)
        self._expire_due_keys()

        with self._lock, self._connect() as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                """
                SELECT id, encrypted_key_material, algorithm, created_at, expires_at, status
                FROM keys
                WHERE id = ?
                LIMIT 1
                """,
                (key_id,),
            ).fetchone()

        if row is None:
            raise KeyStorageError(f"key not found: {key_id}")

        status = str(row["status"]).lower()
        if status != "active":
            raise KeyStorageError(f"key {key_id} is not retrievable (status={status})")

        payload = row["encrypted_key_material"]
        if not isinstance(payload, (bytes, bytearray)) or len(payload) < 13:
            raise KeyStorageError("stored key payload is invalid")

        nonce = bytes(payload[:12])
        ciphertext = bytes(payload[12:])

        aad = self._aad(str(row["id"]), str(row["algorithm"]))
        try:
            key = AESGCM(self._master_key).decrypt(nonce, ciphertext, aad)
        except Exception as exc:
            raise KeyStorageError(f"failed to decrypt key {key_id}") from exc

        return key

    def list_keys(self, *, include_deleted: bool = False) -> list[KeyEntry]:
        """List key metadata, with automatic expiry update before query."""
        self._expire_due_keys()

        sql = """
            SELECT id, algorithm, created_at, expires_at, status
            FROM keys
        """
        params: tuple[Any, ...] = ()
        if not include_deleted:
            sql += " WHERE status != ?"
            params = ("deleted",)
        sql += " ORDER BY created_at DESC"

        with self._lock, self._connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(sql, params).fetchall()

        return [
            KeyEntry(
                id=str(row["id"]),
                algorithm=str(row["algorithm"]),
                created_at=float(row["created_at"]),
                expires_at=float(row["expires_at"]) if row["expires_at"] is not None else None,
                status=str(row["status"]),
            )
            for row in rows
        ]

    def update_key_status(self, key_id: str, status: str) -> None:
        """Update key lifecycle status."""
        self._validate_key_id(key_id)
        self._validate_status(status)

        with self._lock, self._connect() as conn:
            cur = conn.execute("UPDATE keys SET status = ? WHERE id = ?", (status, key_id))
            conn.commit()

        if cur.rowcount == 0:
            raise KeyStorageError(f"key not found: {key_id}")

        logger.info("updated key status id={key_id} status={status}", key_id=key_id, status=status)

    def keys_due_for_rotation(self, *, within_seconds: int | None = None) -> list[KeyEntry]:
        """Return active keys nearing expiry within configured rotation window."""
        self._expire_due_keys()
        horizon = time.time() + float(within_seconds if within_seconds is not None else self.rotation_window_seconds)

        with self._lock, self._connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT id, algorithm, created_at, expires_at, status
                FROM keys
                WHERE status = 'active'
                  AND expires_at IS NOT NULL
                  AND expires_at <= ?
                ORDER BY expires_at ASC
                """,
                (horizon,),
            ).fetchall()

        due = [
            KeyEntry(
                id=str(row["id"]),
                algorithm=str(row["algorithm"]),
                created_at=float(row["created_at"]),
                expires_at=float(row["expires_at"]) if row["expires_at"] is not None else None,
                status=str(row["status"]),
            )
            for row in rows
        ]

        for entry in due:
            logger.warning(
                "key due for rotation id={key_id} expires_at={expires_at}",
                key_id=entry.id,
                expires_at=entry.expires_at,
            )

        return due

    def _expire_due_keys(self) -> None:
        now = time.time()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                UPDATE keys
                SET status = 'expired'
                WHERE status = 'active'
                  AND expires_at IS NOT NULL
                  AND expires_at <= ?
                """,
                (now,),
            )
            conn.commit()

    def _init_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS keys (
                    id TEXT PRIMARY KEY,
                    encrypted_key_material BLOB NOT NULL,
                    algorithm TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL,
                    status TEXT NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_keys_status ON keys(status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_keys_expires_at ON keys(expires_at)")
            conn.commit()

    def _derive_and_store_master_key(self) -> bytes:
        password = os.getenv(self.password_env_var)
        if not password:
            raise KeyStorageError(
                f"Missing password environment variable: {self.password_env_var}"
            )

        salt_b64 = os.getenv(self.salt_env_var)
        if salt_b64:
            try:
                salt = base64.b64decode(salt_b64)
            except Exception as exc:
                raise KeyStorageError(f"Invalid base64 in {self.salt_env_var}") from exc
        else:
            salt = os.urandom(16)
            os.environ[self.salt_env_var] = base64.b64encode(salt).decode("ascii")

        master_key = hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            type=Type.ID,
        )

        os.environ[self.derived_key_env_var] = base64.b64encode(master_key).decode("ascii")
        logger.info(
            "derived master key with Argon2id and stored in env var {env_var}",
            env_var=self.derived_key_env_var,
        )
        return master_key

    def _connect(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)

        # SQLCipher-compatible pragma; no-op on standard SQLite builds.
        try:
            escaped = self._sqlcipher_key.replace("'", "''")
            conn.execute(f"PRAGMA key = '{escaped}'")
        except sqlite3.DatabaseError:
            # Fallback for non-SQLCipher SQLite builds.
            pass

        return conn

    @staticmethod
    def _aad(key_id: str, algorithm: str) -> bytes:
        return f"{key_id}|{algorithm.upper().strip()}".encode("utf-8")

    def _validate_status(self, status: str) -> None:
        if status not in self._STATUSES:
            raise ValueError(f"status must be one of: {', '.join(sorted(self._STATUSES))}")

    @staticmethod
    def _validate_key_id(key_id: str) -> None:
        if not isinstance(key_id, str) or not key_id.strip():
            raise ValueError("key_id must be a non-empty string")

    @staticmethod
    def _require_bytes(name: str, value: object) -> None:
        if not isinstance(value, bytes):
            raise TypeError(f"{name} must be bytes")


__all__ = ["KeyStorage", "KeyStorageError", "KeyEntry"]
