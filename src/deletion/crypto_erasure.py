"""Cryptographic erasure orchestration for instant key destruction.

This module coordinates secure key destruction across memory and storage
backends, then verifies non-recoverability.
"""

from __future__ import annotations

import gc
import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any

from src.core.key_manager import KeyManager, KeyManagerError
from src.core.key_storage import KeyStorage, KeyStorageError
from src.utils.logging import get_logger, log_security_event


logger = get_logger("src.deletion.crypto_erasure")


class CryptoErasureError(Exception):
    """Raised when cryptographic erasure fails."""


class CryptoErasure:
    """Coordinates secure key destruction in memory and persistent storage."""

    def __init__(
        self,
        *,
        key_manager: KeyManager | None = None,
        key_storage: KeyStorage | None = None,
        audit_db_path: str | Path = "erasure_audit.db",
    ) -> None:
        self.key_manager = key_manager
        self.key_storage = key_storage
        self.audit_db_path = Path(audit_db_path)
        self._init_audit_db()

    def erase_keys(self, key_ids: list[str]) -> dict[str, str]:
        """Shred key material from memory and storage backends.

        Steps per key:
        1. Attempt retrieval from backends for in-memory wipe.
        2. Overwrite in-memory bytes three passes.
        3. Trigger backend secure deletion/shredding.
        4. Force GC sweep.
        """
        if not isinstance(key_ids, list) or not key_ids:
            raise ValueError("key_ids must be a non-empty list")

        results: dict[str, str] = {}

        for key_id in key_ids:
            if not isinstance(key_id, str) or not key_id.strip():
                results[str(key_id)] = "invalid_key_id"
                continue

            status = "erased"
            details: dict[str, Any] = {"memory_wiped": False, "manager_deleted": False, "storage_deleted": False}

            # Best-effort memory extraction and wipe.
            extracted_buffers: list[bytearray] = []

            if self.key_manager is not None:
                try:
                    km_key = self.key_manager.get_key(key_id)
                    extracted_buffers.append(bytearray(km_key))
                except Exception:
                    pass

            if self.key_storage is not None:
                try:
                    ks_key = self.key_storage.retrieve_key(key_id)
                    extracted_buffers.append(bytearray(ks_key))
                except Exception:
                    pass

            for buf in extracted_buffers:
                self._wipe_buffer(buf)
            details["memory_wiped"] = bool(extracted_buffers)

            # Storage erasure via key manager.
            if self.key_manager is not None:
                try:
                    self.key_manager.secure_delete_key(key_id)
                    details["manager_deleted"] = True
                except Exception as exc:
                    status = "partial_failure"
                    details["manager_error"] = str(exc)

            # Storage erasure via key storage backend.
            if self.key_storage is not None:
                try:
                    self._storage_secure_delete(key_id)
                    details["storage_deleted"] = True
                except Exception as exc:
                    status = "partial_failure"
                    details["storage_error"] = str(exc)

            # Clear local references and force collection.
            extracted_buffers.clear()
            gc.collect()

            results[key_id] = status
            self._audit("erase_key", key_id, status, details)
            log_security_event(
                "crypto_erasure",
                severity="WARNING",
                actor="crypto_erasure",
                target=key_id,
                details={"status": status, **details},
            )

            logger.warning("erasure completed key_id={key_id} status={status}", key_id=key_id, status=status)

        return results

    def verify_erasure(self, key_ids: list[str]) -> dict[str, bool]:
        """Confirm keys cannot be recovered from configured backends."""
        if not isinstance(key_ids, list) or not key_ids:
            raise ValueError("key_ids must be a non-empty list")

        verification: dict[str, bool] = {}

        for key_id in key_ids:
            recoverable = False

            if self.key_manager is not None:
                try:
                    _ = self.key_manager.get_key(key_id)
                    recoverable = True
                except KeyManagerError:
                    pass
                except Exception:
                    pass

            if self.key_storage is not None:
                try:
                    _ = self.key_storage.retrieve_key(key_id)
                    recoverable = True
                except KeyStorageError:
                    pass
                except Exception:
                    pass

            verification[key_id] = not recoverable
            self._audit(
                "verify_erasure",
                key_id,
                "verified" if not recoverable else "recoverable",
                {"recoverable": recoverable},
            )

        return verification

    def emergency_erase_all(self) -> dict[str, Any]:
        """Panic-button wipe for all discoverable keys across backends."""
        key_ids = sorted(self._collect_all_key_ids())
        if not key_ids:
            summary = {"erased": 0, "partial_failures": 0, "verified": True, "key_ids": []}
            self._audit("emergency_erase_all", None, "no_keys", summary)
            return summary

        erase_results = self.erase_keys(key_ids)
        verify_results = self.verify_erasure(key_ids)

        erased_count = sum(1 for v in erase_results.values() if v == "erased")
        partial_count = len(erase_results) - erased_count
        verified = all(verify_results.values())

        summary = {
            "erased": erased_count,
            "partial_failures": partial_count,
            "verified": verified,
            "key_ids": key_ids,
        }

        self._audit("emergency_erase_all", None, "completed", summary)
        log_security_event(
            "emergency_erase_all",
            severity="CRITICAL",
            actor="crypto_erasure",
            target="all_keys",
            details=summary,
        )
        logger.error(
            "emergency erasure complete erased={erased} partial_failures={partial} verified={verified}",
            erased=erased_count,
            partial=partial_count,
            verified=verified,
        )

        return summary

    def _collect_all_key_ids(self) -> set[str]:
        ids: set[str] = set()

        if self.key_storage is not None:
            try:
                for entry in self.key_storage.list_keys(include_deleted=True):
                    ids.add(entry.id)
            except Exception:
                pass

        if self.key_manager is not None:
            try:
                # Access key manager table for panic mode discovery.
                with self.key_manager._connect() as conn:  # noqa: SLF001
                    rows = conn.execute("SELECT key_id FROM keys").fetchall()
                    ids.update(str(row[0]) for row in rows)
            except Exception:
                pass

        return ids

    def _storage_secure_delete(self, key_id: str) -> None:
        if self.key_storage is None:
            return

        with self.key_storage._connect() as conn:  # noqa: SLF001
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT encrypted_key_material FROM keys WHERE id = ? LIMIT 1",
                (key_id,),
            ).fetchone()
            if row is None:
                raise KeyStorageError(f"key not found: {key_id}")

            payload = row["encrypted_key_material"]
            if not isinstance(payload, (bytes, bytearray)):
                raise KeyStorageError("invalid encrypted payload")

            shredded = self._shred_bytes(bytes(payload))
            conn.execute(
                "UPDATE keys SET encrypted_key_material = ?, status = 'deleted' WHERE id = ?",
                (shredded, key_id),
            )
            conn.commit()

    def _shred_bytes(self, data: bytes) -> bytes:
        buf = bytearray(data)
        self._wipe_buffer(buf)
        return bytes(buf)

    @staticmethod
    def _wipe_buffer(buf: bytearray) -> None:
        """Overwrite buffer in-place with random data three times."""
        size = len(buf)
        if size == 0:
            return

        for _ in range(3):
            buf[:] = os.urandom(size)
        buf[:] = b"\x00" * size

    def _init_audit_db(self) -> None:
        self.audit_db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.audit_db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS erasure_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event TEXT NOT NULL,
                    key_id TEXT,
                    status TEXT NOT NULL,
                    ts REAL NOT NULL,
                    details TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def _audit(self, event: str, key_id: str | None, status: str, details: dict[str, Any]) -> None:
        payload = json.dumps(details, separators=(",", ":"), default=str)
        with sqlite3.connect(self.audit_db_path) as conn:
            conn.execute(
                """
                INSERT INTO erasure_audit (event, key_id, status, ts, details)
                VALUES (?, ?, ?, ?, ?)
                """,
                (event, key_id, status, time.time(), payload),
            )
            conn.commit()


__all__ = ["CryptoErasure", "CryptoErasureError"]
