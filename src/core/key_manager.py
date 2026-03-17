"""Lifecycle key management with encrypted SQLite storage.

This module implements a comprehensive key manager with:
- Master key generation
- Session key derivation via HKDF
- Key rotation and revocation
- Secure retrieval with expiry/revocation checks
- Cryptographic erasure
- Envelope encryption and key wrapping
- Persistent audit logging
"""

from __future__ import annotations

import base64
import json
import os
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.keywrap import InvalidUnwrap, aes_key_unwrap, aes_key_wrap

from src.utils.logging import get_logger, log_security_event


logger = get_logger("src.core.key_manager")


class KeyManagerError(Exception):
    """Base key manager error."""


class KeyNotFoundError(KeyManagerError):
    """Raised when key id does not exist."""


class KeyRevokedError(KeyManagerError):
    """Raised when key has been revoked."""


class KeyExpiredError(KeyManagerError):
    """Raised when key is expired."""


@dataclass(frozen=True)
class KeyRecord:
    key_id: str
    algorithm: str
    created_at: float
    expires_at: float | None
    revoked_at: float | None
    revoked_reason: str | None
    metadata: dict[str, Any]


class KeyManager:
    """Lifecycle key manager with envelope-encrypted SQLite storage."""

    _KEY_SIZES = {
        "AES-256-GCM": 32,
        "CHACHA20-POLY1305": 32,
        "XCHACHA20-POLY1305": 32,
        "KYBER-HYBRID": 32,
        "KYBER-AES-GCM": 32,
        "DILITHIUM-AES-GCM": 32,
    }

    def __init__(
        self,
        db_path: str | Path = "key_manager.db",
        *,
        kek: bytes | None = None,
        kek_env_var: str = "KEYCRYPT_KEK_B64",
    ) -> None:
        self.db_path = Path(db_path)
        self._lock = threading.RLock()
        self._kek = self._load_or_generate_kek(kek, kek_env_var)
        self._init_db()

    def generate_master_key(self, algorithm: str) -> dict[str, Any]:
        """Generate and persist a new master key with metadata.

        Args:
            algorithm: Key algorithm profile name.

        Returns:
            Dict containing key metadata and plaintext key bytes.
        """
        normalized_algorithm = algorithm.strip().upper()
        if not normalized_algorithm:
            raise ValueError("algorithm must be non-empty")

        key_size = self._KEY_SIZES.get(normalized_algorithm, 32)
        key_material = os.urandom(key_size)

        key_id = uuid.uuid4().hex
        created_at = time.time()
        rotation_days = 90
        expires_at = created_at + rotation_days * 86400

        metadata = {
            "key_size": key_size,
            "rotation_period_days": rotation_days,
            "algorithm": normalized_algorithm,
        }

        wrapped_dek, nonce, ciphertext = self._envelope_encrypt(
            key_id=key_id,
            algorithm=normalized_algorithm,
            plaintext=key_material,
            metadata=metadata,
        )

        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO keys (
                    key_id, algorithm, wrapped_dek, nonce, ciphertext,
                    metadata, created_at, expires_at, revoked_at, revoked_reason, deleted
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, 0)
                """,
                (
                    key_id,
                    normalized_algorithm,
                    wrapped_dek,
                    nonce,
                    ciphertext,
                    json.dumps(metadata, separators=(",", ":")),
                    created_at,
                    expires_at,
                ),
            )
            conn.commit()

        self._audit("generate_master_key", key_id, {"algorithm": normalized_algorithm, "key_size": key_size})
        log_security_event(
            "key_generated",
            severity="INFO",
            actor="key_manager",
            target=key_id,
            details={"algorithm": normalized_algorithm, "key_size": key_size},
        )

        return {
            "key_id": key_id,
            "algorithm": normalized_algorithm,
            "key": key_material,
            "created_at": created_at,
            "expires_at": expires_at,
            "metadata": metadata,
        }

    def derive_session_key(self, master_key: bytes, context: bytes | str, *, length: int = 32) -> bytes:
        """Derive a session key from a master key using HKDF-SHA256."""
        if not isinstance(master_key, bytes) or not master_key:
            raise ValueError("master_key must be non-empty bytes")
        if isinstance(context, str):
            context_bytes = context.encode("utf-8")
        elif isinstance(context, bytes):
            context_bytes = context
        else:
            raise TypeError("context must be str or bytes")

        if length <= 0 or length > 64:
            raise ValueError("length must be in range [1, 64]")

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=None,
            info=b"KeyCrypt-Shield-X session key" + context_bytes,
        )
        return hkdf.derive(master_key)

    def rotate_key(self, key_id: str, reason: str) -> dict[str, Any]:
        """Rotate an existing key by revoking it and issuing a replacement."""
        if not reason.strip():
            raise ValueError("reason must be non-empty")

        record = self._get_key_row(key_id)
        algorithm = str(record["algorithm"])

        old_key = self.get_key(key_id)
        replacement = self.generate_master_key(algorithm)

        # Revoke old key after successful replacement generation.
        revoked_at = time.time()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                UPDATE keys
                SET revoked_at = ?, revoked_reason = ?
                WHERE key_id = ?
                """,
                (revoked_at, reason, key_id),
            )
            conn.commit()

        self._audit(
            "rotate_key",
            key_id,
            {
                "reason": reason,
                "replacement_key_id": replacement["key_id"],
                "algorithm": algorithm,
            },
        )
        log_security_event(
            "key_rotated",
            severity="WARNING",
            actor="key_manager",
            target=key_id,
            details={"reason": reason, "replacement_key_id": replacement["key_id"]},
        )

        return {
            "old_key_id": key_id,
            "old_key": old_key,
            "new_key_id": replacement["key_id"],
            "new_key": replacement["key"],
            "algorithm": algorithm,
            "revoked_reason": reason,
        }

    def get_key(self, key_id: str) -> bytes:
        """Retrieve and decrypt a key when active and non-expired."""
        row = self._get_key_row(key_id)
        self._ensure_usable(row)

        try:
            metadata = self._parse_metadata(row["metadata"])
            plaintext = self._envelope_decrypt(
                key_id=row["key_id"],
                algorithm=row["algorithm"],
                wrapped_dek=row["wrapped_dek"],
                nonce=row["nonce"],
                ciphertext=row["ciphertext"],
                metadata=metadata,
            )
            self._audit("get_key", key_id, {"status": "ok"})
            return plaintext
        except KeyManagerError:
            raise
        except Exception as exc:
            raise KeyManagerError(f"failed to decrypt key {key_id}") from exc

    def secure_delete_key(self, key_id: str) -> None:
        """Cryptographically erase a key by destroying wrapped DEK and ciphertext."""
        row = self._get_key_row(key_id)

        destroyed_wrapped_dek = os.urandom(len(row["wrapped_dek"]))
        destroyed_nonce = os.urandom(len(row["nonce"]))
        destroyed_ciphertext = os.urandom(len(row["ciphertext"]))
        deleted_at = time.time()

        with self._lock, self._connect() as conn:
            conn.execute(
                """
                UPDATE keys
                SET wrapped_dek = ?, nonce = ?, ciphertext = ?, deleted = 1,
                    revoked_at = COALESCE(revoked_at, ?),
                    revoked_reason = COALESCE(revoked_reason, 'secure_delete')
                WHERE key_id = ?
                """,
                (destroyed_wrapped_dek, destroyed_nonce, destroyed_ciphertext, deleted_at, key_id),
            )
            conn.commit()

        self._audit("secure_delete_key", key_id, {"status": "erased"})
        log_security_event(
            "key_deleted",
            severity="WARNING",
            actor="key_manager",
            target=key_id,
            details={"method": "cryptographic_erasure"},
        )

    def wrap_key(self, key_material: bytes) -> bytes:
        """Wrap arbitrary key material under manager KEK (AES Key Wrap)."""
        if not isinstance(key_material, bytes) or not key_material:
            raise ValueError("key_material must be non-empty bytes")

        if len(key_material) % 8 != 0:
            # RFC 3394 key wrap requires multiples of 64 bits.
            padded = key_material + b"\x00" * (8 - (len(key_material) % 8))
            wrapped = aes_key_wrap(self._kek, padded)
            return b"P" + bytes([len(key_material)]) + wrapped

        wrapped = aes_key_wrap(self._kek, key_material)
        return b"N" + wrapped

    def unwrap_key(self, wrapped_key: bytes) -> bytes:
        """Unwrap key material previously wrapped by wrap_key()."""
        if not isinstance(wrapped_key, bytes) or len(wrapped_key) < 2:
            raise ValueError("wrapped_key is invalid")

        mode = wrapped_key[:1]
        payload = wrapped_key[1:]

        try:
            if mode == b"N":
                return aes_key_unwrap(self._kek, payload)

            if mode == b"P":
                original_length = payload[0]
                unwrapped = aes_key_unwrap(self._kek, payload[1:])
                return unwrapped[:original_length]
        except InvalidUnwrap as exc:
            raise KeyManagerError("key unwrap failed") from exc

        raise ValueError("wrapped_key has unknown encoding")

    def get_key_record(self, key_id: str) -> KeyRecord:
        """Return key metadata record without disclosing key bytes."""
        row = self._get_key_row(key_id)
        return KeyRecord(
            key_id=row["key_id"],
            algorithm=row["algorithm"],
            created_at=float(row["created_at"]),
            expires_at=float(row["expires_at"]) if row["expires_at"] is not None else None,
            revoked_at=float(row["revoked_at"]) if row["revoked_at"] is not None else None,
            revoked_reason=row["revoked_reason"],
            metadata=self._parse_metadata(row["metadata"]),
        )

    def _init_db(self) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS keys (
                    key_id TEXT PRIMARY KEY,
                    algorithm TEXT NOT NULL,
                    wrapped_dek BLOB NOT NULL,
                    nonce BLOB NOT NULL,
                    ciphertext BLOB NOT NULL,
                    metadata TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL,
                    revoked_at REAL,
                    revoked_reason TEXT,
                    deleted INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event TEXT NOT NULL,
                    key_id TEXT,
                    ts REAL NOT NULL,
                    details TEXT NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_keys_revoked ON keys(revoked_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_keys_expires ON keys(expires_at)")
            conn.commit()

    def _envelope_encrypt(
        self,
        *,
        key_id: str,
        algorithm: str,
        plaintext: bytes,
        metadata: dict[str, Any],
    ) -> tuple[bytes, bytes, bytes]:
        dek = os.urandom(32)
        nonce = os.urandom(12)
        aad = self._aad_for(key_id, algorithm, metadata)

        ciphertext = AESGCM(dek).encrypt(nonce, plaintext, aad)
        wrapped_dek = aes_key_wrap(self._kek, dek)
        return wrapped_dek, nonce, ciphertext

    def _envelope_decrypt(
        self,
        *,
        key_id: str,
        algorithm: str,
        wrapped_dek: bytes,
        nonce: bytes,
        ciphertext: bytes,
        metadata: dict[str, Any],
    ) -> bytes:
        try:
            dek = aes_key_unwrap(self._kek, wrapped_dek)
        except InvalidUnwrap as exc:
            raise KeyManagerError("failed to unwrap DEK") from exc

        aad = self._aad_for(key_id, algorithm, metadata)
        try:
            return AESGCM(dek).decrypt(nonce, ciphertext, aad)
        except Exception as exc:
            raise KeyManagerError("failed to decrypt envelope ciphertext") from exc

    def _ensure_usable(self, row: sqlite3.Row) -> None:
        if int(row["deleted"]) == 1:
            raise KeyNotFoundError(f"key {row['key_id']} has been securely deleted")

        if row["revoked_at"] is not None:
            reason = row["revoked_reason"] or "unknown"
            raise KeyRevokedError(f"key {row['key_id']} is revoked: {reason}")

        expires_at = row["expires_at"]
        if expires_at is not None and float(expires_at) <= time.time():
            raise KeyExpiredError(f"key {row['key_id']} is expired")

    def _get_key_row(self, key_id: str) -> sqlite3.Row:
        if not isinstance(key_id, str) or not key_id.strip():
            raise ValueError("key_id must be a non-empty string")

        with self._lock, self._connect() as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                """
                SELECT key_id, algorithm, wrapped_dek, nonce, ciphertext,
                       metadata, created_at, expires_at, revoked_at,
                       revoked_reason, deleted
                FROM keys
                WHERE key_id = ?
                LIMIT 1
                """,
                (key_id,),
            ).fetchone()

        if row is None:
            raise KeyNotFoundError(f"key {key_id} not found")
        return row

    def _audit(self, event: str, key_id: str | None, details: dict[str, Any]) -> None:
        payload = json.dumps(details, separators=(",", ":"), default=str)
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_log (event, key_id, ts, details)
                VALUES (?, ?, ?, ?)
                """,
                (event, key_id, time.time(), payload),
            )
            conn.commit()

        logger.info("key audit event={event} key_id={key_id} details={details}", event=event, key_id=key_id, details=payload)

    def _aad_for(self, key_id: str, algorithm: str, metadata: dict[str, Any]) -> bytes:
        payload = {
            "key_id": key_id,
            "algorithm": algorithm,
            "metadata": metadata,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _parse_metadata(self, value: str | bytes) -> dict[str, Any]:
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        parsed = json.loads(value)
        if not isinstance(parsed, dict):
            raise KeyManagerError("metadata must decode to an object")
        return parsed

    def _load_or_generate_kek(self, kek: bytes | None, env_var: str) -> bytes:
        if kek is None:
            env_value = os.getenv(env_var)
            if env_value:
                try:
                    kek = base64.b64decode(env_value)
                except Exception as exc:
                    raise ValueError(f"invalid base64 in env var {env_var}") from exc

        if kek is None:
            kek = os.urandom(32)
            logger.warning(
                "No KEK configured; generated ephemeral KEK for process lifetime only. "
                "Set {env_var} for persistent key access.",
                env_var=env_var,
            )

        if len(kek) not in {16, 24, 32}:
            raise ValueError("KEK must be 16, 24, or 32 bytes for AES key wrap")

        return kek

    def _connect(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        return sqlite3.connect(self.db_path)


__all__ = [
    "KeyManager",
    "KeyRecord",
    "KeyManagerError",
    "KeyNotFoundError",
    "KeyRevokedError",
    "KeyExpiredError",
]
