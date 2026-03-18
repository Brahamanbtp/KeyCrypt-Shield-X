"""End-to-end integration test for complete encryption and deletion workflow."""

from __future__ import annotations

import hashlib
import os
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.core import key_manager as km_module
from src.core.key_manager import KeyManager, KeyRevokedError
from src.deletion import crypto_erasure as ce_module
from src.deletion.crypto_erasure import CryptoErasure
from src.deletion.physical_overwrite import SecureDelete
from src.deletion.trust_index import calculate_dti
from src.storage.chunking import DEFAULT_CHUNK_SIZE, EncryptedChunk, FileChunker
from src.storage.local_storage import SecureLocalStorage


TEST_FILE_SIZE = 10 * 1024 * 1024


@pytest.fixture
def workflow_paths(tmp_path: Path) -> dict[str, Path]:
    """Create temporary directories and file paths for integration workflow."""
    data_dir = tmp_path / "data"
    chunks_dir = tmp_path / "chunks"
    out_dir = tmp_path / "out"

    data_dir.mkdir(parents=True, exist_ok=True)
    chunks_dir.mkdir(parents=True, exist_ok=True)
    out_dir.mkdir(parents=True, exist_ok=True)

    return {
        "source": data_dir / "sample_10mb.bin",
        "recovered": out_dir / "recovered.bin",
        "rotated_recovered": out_dir / "rotated_recovered.bin",
        "chunks_root": chunks_dir,
        "db": tmp_path / "keys.db",
        "audit_db": tmp_path / "erasure_audit.db",
    }


@pytest.fixture
def patched_security(monkeypatch: pytest.MonkeyPatch) -> None:
    """Mock external security-event logging dependencies."""
    monkeypatch.setattr(km_module, "log_security_event", MagicMock())
    monkeypatch.setattr(ce_module, "log_security_event", MagicMock())


@pytest.fixture
def safe_secure_delete(monkeypatch: pytest.MonkeyPatch) -> None:
    """Patch overwrite open flags for test environments without O_DIRECT-safe writes."""

    def _safe_open_for_overwrite(path: Path) -> int:
        flags = os.O_RDWR | (os.O_SYNC if hasattr(os, "O_SYNC") else 0)
        return os.open(path, flags)

    monkeypatch.setattr(SecureDelete, "_open_for_overwrite", staticmethod(_safe_open_for_overwrite))


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def test_end_to_end_hybrid_encryption_workflow(
    workflow_paths: dict[str, Path],
    patched_security: None,
    safe_secure_delete: None,
    record_property: pytest.RecordProperty,
) -> None:
    """Validate full lifecycle: encrypt/store/retrieve/decrypt/rotate/delete/verify."""
    source_file = workflow_paths["source"]
    recovered_file = workflow_paths["recovered"]
    rotated_recovered_file = workflow_paths["rotated_recovered"]

    # 1) Generate realistic 10MB test data and initial key profile.
    source_file.write_bytes(os.urandom(TEST_FILE_SIZE))
    original_hash = _sha256(source_file)

    manager = KeyManager(db_path=workflow_paths["db"], kek=b"K" * 32)
    chunker = FileChunker()
    storage = SecureLocalStorage(root_dir=workflow_paths["chunks_root"])

    master = manager.generate_master_key("KYBER-HYBRID")
    old_key_id = master["key_id"]
    old_key = master["key"]

    # 2) Encrypt source chunks and measure performance.
    encrypt_start = time.perf_counter()
    plaintext_chunks = list(chunker.chunk_file(source_file, chunk_size=DEFAULT_CHUNK_SIZE))
    encrypted_chunks = chunker.encrypt_chunks(plaintext_chunks, old_key, max_workers=4)
    encrypt_seconds = time.perf_counter() - encrypt_start

    # 3) Store encrypted chunks in local secure storage backend.
    stored_records: list[tuple[int, str, str]] = []
    for chunk in encrypted_chunks:
        payload = chunk.ciphertext + chunk.authentication_tag
        digest = hashlib.sha256(payload).hexdigest()
        metadata = {
            **chunk.encryption_metadata,
            "chunk_id": chunk.chunk_id,
            "plaintext_hash": chunk.hash,
            "tag_hex": chunk.authentication_tag.hex(),
        }
        storage.store_chunk(digest, payload, metadata)
        stored_records.append((chunk.chunk_id, digest, chunk.hash))

    # 4) Retrieve chunks and decrypt into output file.
    retrieved_chunks: list[EncryptedChunk] = []
    for chunk_id, digest, plaintext_hash in sorted(stored_records, key=lambda item: item[0]):
        payload, metadata = storage.retrieve_chunk(digest)
        auth_tag = bytes.fromhex(str(metadata["tag_hex"]))
        ciphertext = payload[: -len(auth_tag)]
        enc_meta = {
            "algorithm": metadata.get("algorithm"),
            "nonce": metadata.get("nonce"),
            "aad": metadata.get("aad"),
            "size": metadata.get("size"),
        }
        retrieved_chunks.append(
            EncryptedChunk(
                chunk_id=chunk_id,
                ciphertext=ciphertext,
                hash=plaintext_hash,
                encryption_metadata=enc_meta,
                authentication_tag=auth_tag,
            )
        )

    decrypt_start = time.perf_counter()
    chunker.reassemble_file(retrieved_chunks, recovered_file, key=old_key)
    decrypt_seconds = time.perf_counter() - decrypt_start

    # 5) Verify decrypted output matches source content hash.
    recovered_hash = _sha256(recovered_file)
    assert recovered_hash == original_hash

    # 6) Rotate keys.
    rotation = manager.rotate_key(old_key_id, "integration_rotation")
    new_key_id = rotation["new_key_id"]
    new_key = rotation["new_key"]

    # 7) Verify migration path: old data remains decryptable post-rotation and can be re-encrypted with new key.
    with pytest.raises(KeyRevokedError):
        manager.get_key(old_key_id)

    assert manager.get_key(new_key_id) == new_key

    migrated_chunks = chunker.encrypt_chunks(list(chunker.chunk_file(recovered_file)), new_key, max_workers=4)
    chunker.reassemble_file(migrated_chunks, rotated_recovered_file, key=new_key)
    assert _sha256(rotated_recovered_file) == original_hash

    # 8) Securely delete files and keys.
    deleter = SecureDelete()
    source_delete = deleter.overwrite_file(source_file, passes=3)
    recovered_delete = deleter.overwrite_file(recovered_file, passes=3)
    rotated_delete = deleter.overwrite_file(rotated_recovered_file, passes=3)

    for _, digest, _ in stored_records:
        storage.delete_chunk(digest, overwrite_passes=2)

    erasure = CryptoErasure(key_manager=manager, audit_db_path=workflow_paths["audit_db"])
    erasure_results = erasure.erase_keys([old_key_id, new_key_id])
    key_verification = erasure.verify_erasure([old_key_id, new_key_id])

    # 9) Verify deletion trust index threshold.
    dti_report = calculate_dti(
        source_file,
        {
            "original_size_bytes": TEST_FILE_SIZE,
            "dti_target": 0.99,
            "artifact_paths": [str(recovered_file), str(rotated_recovered_file)],
            "erasure_results": erasure_results,
            "key_verification": key_verification,
            "key_erasure_verified": all(key_verification.values()),
        },
    )

    assert source_delete["deleted"]
    assert recovered_delete["deleted"]
    assert rotated_delete["deleted"]
    assert all(status in {"erased", "partial_failure"} for status in erasure_results.values())
    assert all(key_verification.values())
    assert dti_report["dti"] > 0.99
    assert dti_report["target_met"]

    # Performance metrics for visibility in test reports.
    total_seconds = encrypt_seconds + decrypt_seconds
    throughput_mb_s = (TEST_FILE_SIZE / (1024 * 1024)) / max(total_seconds, 1e-9)
    assert throughput_mb_s > 0

    record_property("encrypt_seconds", round(encrypt_seconds, 4))
    record_property("decrypt_seconds", round(decrypt_seconds, 4))
    record_property("throughput_mb_s", round(throughput_mb_s, 4))
    record_property("dti", round(float(dti_report["dti"]), 6))
