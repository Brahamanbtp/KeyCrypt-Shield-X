"""Unit tests for KeyManager lifecycle management."""

from __future__ import annotations

import sqlite3
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.core import key_manager as km_module
from src.core.key_manager import (
    KeyExpiredError,
    KeyManager,
    KeyManagerError,
    KeyNotFoundError,
    KeyRevokedError,
)


@pytest.fixture
def manager(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> KeyManager:
    """Create a KeyManager backed by an isolated temp SQLite database."""
    mocked_security_event = MagicMock()
    monkeypatch.setattr(km_module, "log_security_event", mocked_security_event)

    db_path = tmp_path / "key_manager_test.db"
    return KeyManager(db_path=db_path, kek=b"K" * 32)


def _db_row(manager: KeyManager, key_id: str) -> sqlite3.Row:
    with manager._connect() as conn:  # noqa: SLF001
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT key_id, algorithm, wrapped_dek, nonce, ciphertext,
                   metadata, created_at, expires_at, revoked_at,
                   revoked_reason, deleted
            FROM keys WHERE key_id = ?
            """,
            (key_id,),
        ).fetchone()
    assert row is not None
    return row


def test_key_generation_and_storage(manager: KeyManager) -> None:
    """Generated key should be persisted in encrypted envelope form."""
    result = manager.generate_master_key("AES-256-GCM")

    assert result["key_id"]
    assert result["algorithm"] == "AES-256-GCM"
    assert len(result["key"]) == 32

    row = _db_row(manager, result["key_id"])
    assert row["algorithm"] == "AES-256-GCM"
    assert row["deleted"] == 0
    assert row["revoked_at"] is None
    assert row["wrapped_dek"]
    assert row["nonce"]
    assert row["ciphertext"]

    # Encrypted envelope bytes should not be raw key material.
    assert result["key"] not in row["ciphertext"]


def test_key_retrieval(manager: KeyManager) -> None:
    """Stored key should be retrievable when active and non-expired."""
    created = manager.generate_master_key("CHACHA20-POLY1305")
    restored = manager.get_key(created["key_id"])

    assert restored == created["key"]


def test_key_expiry(manager: KeyManager) -> None:
    """Expired keys should raise KeyExpiredError."""
    created = manager.generate_master_key("AES-256-GCM")

    with manager._connect() as conn:  # noqa: SLF001
        conn.execute("UPDATE keys SET expires_at = ? WHERE key_id = ?", (time.time() - 1, created["key_id"]))
        conn.commit()

    with pytest.raises(KeyExpiredError, match="expired"):
        manager.get_key(created["key_id"])


def test_key_rotation(manager: KeyManager) -> None:
    """Rotating a key should revoke old key and activate replacement."""
    created = manager.generate_master_key("AES-256-GCM")
    rotated = manager.rotate_key(created["key_id"], "scheduled_rotation")

    assert rotated["old_key_id"] == created["key_id"]
    assert rotated["old_key"] == created["key"]
    assert rotated["new_key_id"] != created["key_id"]
    assert len(rotated["new_key"]) == 32

    with pytest.raises(KeyRevokedError, match="revoked"):
        manager.get_key(created["key_id"])

    assert manager.get_key(rotated["new_key_id"]) == rotated["new_key"]


def test_concurrent_key_access(manager: KeyManager) -> None:
    """Concurrent reads of the same key should be consistent and thread-safe."""
    created = manager.generate_master_key("AES-256-GCM")
    expected = created["key"]

    def read_key() -> bytes:
        return manager.get_key(created["key_id"])

    with ThreadPoolExecutor(max_workers=12) as executor:
        results = list(executor.map(lambda _: read_key(), range(48)))

    assert len(results) == 48
    assert all(value == expected for value in results)


def test_key_derivation(manager: KeyManager) -> None:
    """Session key derivation should be deterministic per context and sized correctly."""
    created = manager.generate_master_key("AES-256-GCM")
    master_key = created["key"]

    session_a1 = manager.derive_session_key(master_key, "ctx:alpha", length=32)
    session_a2 = manager.derive_session_key(master_key, "ctx:alpha", length=32)
    session_b = manager.derive_session_key(master_key, "ctx:beta", length=32)

    assert len(session_a1) == 32
    assert session_a1 == session_a2
    assert session_a1 != session_b


def test_secure_deletion(manager: KeyManager) -> None:
    """Secure deletion should mark key deleted and make retrieval impossible."""
    created = manager.generate_master_key("AES-256-GCM")
    key_id = created["key_id"]

    before = _db_row(manager, key_id)
    before_wrapped = before["wrapped_dek"]
    before_nonce = before["nonce"]
    before_ciphertext = before["ciphertext"]

    manager.secure_delete_key(key_id)

    after = _db_row(manager, key_id)
    assert after["deleted"] == 1
    assert after["revoked_at"] is not None
    assert after["wrapped_dek"] != before_wrapped
    assert after["nonce"] != before_nonce
    assert after["ciphertext"] != before_ciphertext

    with pytest.raises(KeyNotFoundError, match="securely deleted"):
        manager.get_key(key_id)


def test_key_record_and_row_validation(manager: KeyManager) -> None:
    """Record API should expose metadata and validate key ids."""
    created = manager.generate_master_key("AES-256-GCM")
    record = manager.get_key_record(created["key_id"])

    assert record.key_id == created["key_id"]
    assert record.algorithm == "AES-256-GCM"
    assert record.metadata["key_size"] == 32

    with pytest.raises(ValueError, match="non-empty string"):
        manager.get_key("   ")

    with pytest.raises(KeyNotFoundError, match="not found"):
        manager.get_key("missing-key-id")


def test_generation_and_rotation_input_validation(manager: KeyManager) -> None:
    """Input validation should reject empty algorithms and rotation reasons."""
    with pytest.raises(ValueError, match="algorithm must be non-empty"):
        manager.generate_master_key("   ")

    created = manager.generate_master_key("AES-256-GCM")
    with pytest.raises(ValueError, match="reason must be non-empty"):
        manager.rotate_key(created["key_id"], "  ")


def test_derive_session_key_validation(manager: KeyManager) -> None:
    """Session derivation should validate master key, context, and length."""
    with pytest.raises(ValueError, match="master_key must be non-empty bytes"):
        manager.derive_session_key(b"", "ctx")

    with pytest.raises(TypeError, match="context must be str or bytes"):
        manager.derive_session_key(b"A" * 32, 123)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match=r"range \[1, 64\]"):
        manager.derive_session_key(b"A" * 32, "ctx", length=0)

    assert len(manager.derive_session_key(b"A" * 32, b"ctx-bytes", length=16)) == 16


def test_wrap_unwrap_modes_and_validation(manager: KeyManager) -> None:
    """Both normal and padded wrap modes should roundtrip and validate input."""
    aligned = b"A" * 32
    padded = b"B" * 13

    wrapped_aligned = manager.wrap_key(aligned)
    wrapped_padded = manager.wrap_key(padded)

    assert wrapped_aligned.startswith(b"N")
    assert wrapped_padded.startswith(b"P")
    assert manager.unwrap_key(wrapped_aligned) == aligned
    assert manager.unwrap_key(wrapped_padded) == padded

    with pytest.raises(ValueError, match="non-empty bytes"):
        manager.wrap_key(b"")

    with pytest.raises(ValueError, match="wrapped_key is invalid"):
        manager.unwrap_key(b"x")

    with pytest.raises(ValueError, match="unknown encoding"):
        manager.unwrap_key(b"X" + wrapped_aligned[1:])

    with pytest.raises(KeyManagerError, match="key unwrap failed"):
        manager.unwrap_key(b"N" + b"bad-unwrappable-bytes")


def test_get_key_wraps_unexpected_parse_errors(manager: KeyManager) -> None:
    """Unexpected parse/decrypt errors should be wrapped as KeyManagerError."""
    created = manager.generate_master_key("AES-256-GCM")
    key_id = created["key_id"]

    with manager._connect() as conn:  # noqa: SLF001
        conn.execute("UPDATE keys SET metadata = ? WHERE key_id = ?", ("not-json", key_id))
        conn.commit()

    with pytest.raises(KeyManagerError, match=f"failed to decrypt key {key_id}"):
        manager.get_key(key_id)


def test_private_envelope_and_metadata_error_paths(manager: KeyManager) -> None:
    """Private helpers should raise expected security errors on invalid data."""
    created = manager.generate_master_key("AES-256-GCM")
    row = _db_row(manager, created["key_id"])
    metadata = manager._parse_metadata(row["metadata"])  # noqa: SLF001

    with pytest.raises(KeyManagerError, match="failed to unwrap DEK"):
        manager._envelope_decrypt(  # noqa: SLF001
            key_id=row["key_id"],
            algorithm=row["algorithm"],
            wrapped_dek=b"invalid",
            nonce=row["nonce"],
            ciphertext=row["ciphertext"],
            metadata=metadata,
        )

    with pytest.raises(KeyManagerError, match="failed to decrypt envelope ciphertext"):
        manager._envelope_decrypt(  # noqa: SLF001
            key_id=row["key_id"],
            algorithm=row["algorithm"],
            wrapped_dek=row["wrapped_dek"],
            nonce=b"\x00" * 12,
            ciphertext=b"broken",
            metadata=metadata,
        )

    parsed = manager._parse_metadata(b'{"ok": true}')  # noqa: SLF001
    assert parsed == {"ok": True}

    with pytest.raises(KeyManagerError, match="must decode to an object"):
        manager._parse_metadata("[]")  # noqa: SLF001


def test_get_key_reraises_keymanagererror(manager: KeyManager, monkeypatch: pytest.MonkeyPatch) -> None:
    """get_key should re-raise KeyManagerError from internals without wrapping."""
    created = manager.generate_master_key("AES-256-GCM")

    def _boom(**_: object) -> bytes:
        raise KeyManagerError("boom")

    monkeypatch.setattr(manager, "_envelope_decrypt", _boom)

    with pytest.raises(KeyManagerError, match="boom"):
        manager.get_key(created["key_id"])


def test_kek_loading_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """KEK should load from env, reject invalid env/base length, and auto-generate."""
    monkeypatch.setattr(km_module, "log_security_event", MagicMock())
    monkeypatch.delenv("TEST_KEK_ENV", raising=False)

    # No explicit KEK and no env -> generated ephemeral KEK.
    generated = KeyManager(db_path=tmp_path / "gen.db", kek=None, kek_env_var="TEST_KEK_ENV")
    assert len(generated._kek) == 32  # noqa: SLF001

    # Valid env KEK should be accepted.
    monkeypatch.setenv("TEST_KEK_ENV", "QUFBQUFBQUFBQUFBQUFBQQ==")  # 16 bytes of 'A'
    from_env = KeyManager(db_path=tmp_path / "env.db", kek=None, kek_env_var="TEST_KEK_ENV")
    assert len(from_env._kek) == 16  # noqa: SLF001

    # Invalid base64 should fail.
    monkeypatch.setenv("TEST_KEK_ENV", "not-base64@@")
    with pytest.raises(ValueError, match="invalid base64"):
        KeyManager(db_path=tmp_path / "bad-env.db", kek=None, kek_env_var="TEST_KEK_ENV")

    # Invalid explicit KEK length should fail.
    with pytest.raises(ValueError, match="KEK must be 16, 24, or 32 bytes"):
        KeyManager(db_path=tmp_path / "bad-kek.db", kek=b"short")
