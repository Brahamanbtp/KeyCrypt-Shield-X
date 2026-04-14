"""End-to-end integration tests for complete encryption workflows.

This suite covers:
- 100MB streaming encryption/decryption with throughput assertions.
- Multi-algorithm layered encryption pipelines.
- Key rotation with re-encryption verification.
- Distributed threshold reconstruction across 5 nodes.
- Optional docker-compose orchestration hook for service-backed runs.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Iterator, Sequence

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from src.abstractions.crypto_provider import CryptoProvider
from src.core.key_manager import KeyManager, KeyRevokedError
from src.providers.crypto.async_crypto_provider import AsyncCryptoProvider
from src.providers.crypto.classical_provider import ClassicalCryptoProvider
from src.providers.crypto.threshold_provider import Party, ThresholdCryptoProvider
from src.providers.keys.async_key_provider import AsyncLocalKeyProvider
from src.sdk.async_operations import DecryptConfig, EncryptConfig, decrypt_file_async
from src.sdk.streaming_operations import encrypt_large_file_streaming
from src.storage.chunking import FileChunker


HUNDRED_MB = 100 * 1024 * 1024
THROUGHPUT_TARGET_MB_S = 100.0
DOCKER_COMPOSE_FILE = PROJECT_ROOT / "deployment/docker/docker-compose.yml"


class _AsyncDelegatingProvider(AsyncCryptoProvider):
    def __init__(self, provider: CryptoProvider) -> None:
        self._provider = provider

    def encrypt(self, plaintext: bytes, context: Any) -> bytes:
        return self._provider.encrypt(plaintext, context)

    def decrypt(self, ciphertext: bytes, context: Any) -> bytes:
        return self._provider.decrypt(ciphertext, context)

    def get_algorithm_name(self) -> str:
        return self._provider.get_algorithm_name()

    def get_security_level(self) -> int:
        return self._provider.get_security_level()


class _DeterministicShamirBackend:
    @staticmethod
    def split_secret(secret: bytes, threshold: int, shares: int) -> list[dict[str, Any]]:
        if shares < threshold:
            raise ValueError("shares must be >= threshold")

        return [
            {
                "index": index,
                "value": secret + index.to_bytes(1, "big"),
                "threshold": threshold,
                "total_shares": shares,
            }
            for index in range(1, shares + 1)
        ]

    @staticmethod
    def reconstruct_secret(shares: Sequence[tuple[int, bytes]]) -> bytes:
        if not shares:
            raise ValueError("shares must be non-empty")

        value = shares[0][1]
        if not isinstance(value, bytes) or len(value) < 2:
            raise ValueError("invalid share value")
        return value[:-1]


def _derive_dkg_secret(parties: Sequence[Party], threshold: int) -> bytes:
    descriptor = "|".join(f"{party.party_id}@{party.endpoint}" for party in parties)
    digest_input = f"{descriptor}|threshold={threshold}".encode("utf-8")
    return hashlib.sha256(digest_input).digest()


class _DeterministicDKGBackend:
    @staticmethod
    def distributed_key_generation(parties: list[Party], threshold: int) -> dict[str, Any]:
        session_secret = _derive_dkg_secret(parties, threshold)
        raw_shares = _DeterministicShamirBackend.split_secret(session_secret, threshold, len(parties))
        normalized_parties = [{"party_id": party.party_id, "endpoint": party.endpoint} for party in parties]

        return {
            "session_id": f"dkg-session-{threshold}-of-{len(parties)}",
            "public_key": hashlib.sha256(session_secret + b"|public").digest(),
            "parties": normalized_parties,
            "key_shares": raw_shares,
            "metadata": {"backend": "deterministic-test-dkg"},
            "vss_enabled": True,
        }


@pytest.fixture
def streaming_paths(tmp_path: Path) -> dict[str, Path]:
    return {
        "input": tmp_path / "large_input_100mb.bin",
        "encrypted": tmp_path / "large_input_100mb.bin.enc",
        "decrypted_dir": tmp_path / "decrypted",
        "key_db": tmp_path / "streaming_keys.db",
    }


@pytest.fixture
def docker_compose_orchestrator() -> Iterator[dict[str, Any]]:
    context: dict[str, Any] = {
        "enabled": False,
        "reason": "docker-compose orchestration disabled",
        "services": [],
        "project_name": None,
    }

    if not _env_flag("KEYCRYPT_ENABLE_DOCKER_COMPOSE_TESTS"):
        yield context
        return

    available, reason = _check_docker_compose_availability()
    if not available:
        pytest.skip(reason)

    services = _compose_services_from_env(default=("postgres", "redis"))
    project_name = f"keycrypt-e2e-{os.getpid()}-{int(time.time())}"
    command_prefix = [
        "docker",
        "compose",
        "-f",
        str(DOCKER_COMPOSE_FILE),
        "-p",
        project_name,
    ]

    try:
        _run_command([*command_prefix, "up", "-d", *services], timeout_seconds=300.0)
        _wait_for_running_services(command_prefix, services, timeout_seconds=180.0)

        context = {
            "enabled": True,
            "reason": "services started",
            "services": list(services),
            "project_name": project_name,
        }
        yield context
    finally:
        _run_command([*command_prefix, "down", "-v"], timeout_seconds=240.0, check=False)


@pytest.mark.asyncio
async def test_encrypt_decrypt_large_file_streaming(
    streaming_paths: dict[str, Path],
    record_property: pytest.RecordProperty,
) -> None:
    _write_pattern_file(streaming_paths["input"], HUNDRED_MB)
    original_hash = _sha256_file(streaming_paths["input"])

    key_provider = AsyncLocalKeyProvider(
        db_path=streaming_paths["key_db"],
        kek=b"S" * 32,
    )

    associated_data = b"integration-streaming-100mb"
    crypto_provider = _AsyncDelegatingProvider(ClassicalCryptoProvider("aes-gcm"))

    try:
        encrypt_config = EncryptConfig(
            crypto_provider=crypto_provider,
            key_provider=key_provider,
            output_dir=streaming_paths["encrypted"].parent,
            chunk_size=16 * 1024 * 1024,
            queue_maxsize=3,
            transform_workers=1,
            associated_data=associated_data,
        )

        encrypt_stats = await encrypt_large_file_streaming(
            streaming_paths["input"],
            streaming_paths["encrypted"],
            encrypt_config,
        )

        decrypt_config = DecryptConfig(
            crypto_provider=crypto_provider,
            key_provider=key_provider,
            output_dir=streaming_paths["decrypted_dir"],
            key_id=encrypt_stats.key_id,
            associated_data=associated_data,
            overwrite=True,
        )
        decrypted_path = await decrypt_file_async(streaming_paths["encrypted"], decrypt_config)
    finally:
        await key_provider.aclose()

    decrypted_hash = _sha256_file(decrypted_path)
    throughput_mb_s = encrypt_stats.average_throughput_bps / (1024 * 1024)

    assert encrypt_stats.completed is True
    assert encrypt_stats.bytes_read == HUNDRED_MB
    assert decrypted_hash == original_hash
    assert throughput_mb_s > THROUGHPUT_TARGET_MB_S

    record_property("streaming_input_bytes", HUNDRED_MB)
    record_property("streaming_throughput_mb_s", round(throughput_mb_s, 3))
    record_property("streaming_elapsed_seconds", round(encrypt_stats.elapsed_seconds, 3))


def test_multi_algorithm_encryption_pipeline(record_property: pytest.RecordProperty) -> None:
    plaintext = (b"multi-algorithm-pipeline-block|" * 4096) + b"tail"

    layers: list[tuple[ClassicalCryptoProvider, bytes, bytes]] = [
        (ClassicalCryptoProvider("aes-gcm"), b"A" * 32, b"layer-aes-1"),
        (ClassicalCryptoProvider("chacha20"), b"B" * 32, b"layer-chacha-2"),
        (ClassicalCryptoProvider("aes-gcm"), b"C" * 32, b"layer-aes-3"),
    ]

    encrypted_layers: list[bytes] = []
    current = plaintext
    for provider, key, aad in layers:
        current = provider.encrypt(current, {"key": key, "associated_data": aad})
        encrypted_layers.append(current)

    recovered = encrypted_layers[-1]
    for provider, key, aad in reversed(layers):
        recovered = provider.decrypt(recovered, {"key": key, "associated_data": aad})

    assert recovered == plaintext
    assert len(encrypted_layers) == 3
    assert encrypted_layers[0] != plaintext
    assert encrypted_layers[1] != encrypted_layers[0]
    assert encrypted_layers[2] != encrypted_layers[1]

    record_property("pipeline_plaintext_bytes", len(plaintext))
    record_property("pipeline_final_ciphertext_bytes", len(encrypted_layers[-1]))


def test_key_rotation_with_re_encryption(
    tmp_path: Path,
    record_property: pytest.RecordProperty,
) -> None:
    source = tmp_path / "rotation_source.bin"
    old_key_output = tmp_path / "rotation_old_key_roundtrip.bin"
    new_key_output = tmp_path / "rotation_new_key_roundtrip.bin"

    source.write_bytes(os.urandom(24 * 1024 * 1024))
    original_hash = _sha256_file(source)

    manager = KeyManager(db_path=tmp_path / "rotation_keys.db", kek=b"R" * 32)
    chunker = FileChunker()

    key_record = manager.generate_master_key("KYBER-HYBRID")
    old_key_id = key_record["key_id"]
    old_key = key_record["key"]

    old_chunks = chunker.encrypt_chunks(list(chunker.chunk_file(source)), old_key, max_workers=4)
    chunker.reassemble_file(old_chunks, old_key_output, key=old_key)
    assert _sha256_file(old_key_output) == original_hash

    rotation = manager.rotate_key(old_key_id, "integration_re_encryption")
    new_key_id = rotation["new_key_id"]
    new_key = rotation["new_key"]

    with pytest.raises(KeyRevokedError):
        manager.get_key(old_key_id)

    assert manager.get_key(new_key_id) == new_key

    re_encrypted_chunks = chunker.encrypt_chunks(
        list(chunker.chunk_file(old_key_output)),
        new_key,
        max_workers=4,
    )
    chunker.reassemble_file(re_encrypted_chunks, new_key_output, key=new_key)

    assert _sha256_file(new_key_output) == original_hash
    assert any(old.ciphertext != new.ciphertext for old, new in zip(old_chunks, re_encrypted_chunks, strict=False))

    record_property("rotation_old_key_id", old_key_id)
    record_property("rotation_new_key_id", new_key_id)


def test_distributed_encryption_across_nodes(
    tmp_path: Path,
    docker_compose_orchestrator: dict[str, Any],
    record_property: pytest.RecordProperty,
) -> None:
    parties = [
        Party(party_id=f"node-{index}", endpoint=f"10.0.0.{index}:7443")
        for index in range(1, 6)
    ]

    threshold_provider = ThresholdCryptoProvider(
        shamir_backend=_DeterministicShamirBackend,
        dkg_backend=_DeterministicDKGBackend,
    )

    dkg_result = threshold_provider.distributed_key_generation(parties=parties, threshold=3)
    reconstructed = threshold_provider.reconstruct_key(
        [dkg_result.key_shares[0], dkg_result.key_shares[2], dkg_result.key_shares[4]]
    )
    expected_secret = _derive_dkg_secret(parties, threshold=3)

    source = tmp_path / "distributed_source.bin"
    recovered = tmp_path / "distributed_recovered.bin"
    source.write_bytes(os.urandom(6 * 1024 * 1024))

    chunker = FileChunker()
    encrypted_chunks = chunker.encrypt_chunks(list(chunker.chunk_file(source)), reconstructed, max_workers=4)
    chunker.reassemble_file(encrypted_chunks, recovered, key=reconstructed)

    assert reconstructed == expected_secret
    assert _sha256_file(recovered) == _sha256_file(source)
    assert len(dkg_result.key_shares) == 5
    assert dkg_result.threshold == 3

    record_property("distributed_threshold", dkg_result.threshold)
    record_property("distributed_parties", len(dkg_result.parties))
    record_property("docker_compose_enabled", bool(docker_compose_orchestrator["enabled"]))
    record_property("docker_compose_reason", str(docker_compose_orchestrator["reason"]))


def _env_flag(name: str) -> bool:
    value = os.getenv(name, "")
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _compose_services_from_env(*, default: tuple[str, ...]) -> tuple[str, ...]:
    raw = os.getenv("KEYCRYPT_DOCKER_COMPOSE_SERVICES", "")
    if not raw.strip():
        return default

    services = tuple(token for token in raw.split() if token)
    return services if services else default


def _check_docker_compose_availability() -> tuple[bool, str]:
    if not DOCKER_COMPOSE_FILE.exists():
        return False, f"docker compose file not found: {DOCKER_COMPOSE_FILE}"

    if shutil.which("docker") is None:
        return False, "docker CLI not available in PATH"

    try:
        _run_command(["docker", "compose", "version"], timeout_seconds=20.0)
    except Exception as exc:
        return False, f"docker compose not available: {exc}"

    try:
        _run_command(["docker", "info"], timeout_seconds=20.0)
    except Exception as exc:
        return False, f"docker daemon unreachable: {exc}"

    return True, "docker compose available"


def _wait_for_running_services(
    command_prefix: Sequence[str],
    services: Sequence[str],
    *,
    timeout_seconds: float,
) -> None:
    deadline = time.monotonic() + timeout_seconds

    while time.monotonic() < deadline:
        result = _run_command(
            [*command_prefix, "ps", "--services", "--filter", "status=running"],
            timeout_seconds=30.0,
            check=False,
        )
        running = {line.strip() for line in result.stdout.splitlines() if line.strip()}
        if all(service in running for service in services):
            return
        time.sleep(2.0)

    raise TimeoutError(f"docker compose services did not become healthy in time: {', '.join(services)}")


def _run_command(
    command: Sequence[str],
    *,
    timeout_seconds: float,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        text=True,
        capture_output=True,
        check=check,
        timeout=timeout_seconds,
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_pattern_file(path: Path, size_bytes: int) -> None:
    if size_bytes <= 0:
        raise ValueError("size_bytes must be positive")

    block = hashlib.sha256(b"keycrypt-e2e-streaming-pattern").digest() * 8192
    path.parent.mkdir(parents=True, exist_ok=True)

    remaining = size_bytes
    with path.open("wb") as handle:
        while remaining > 0:
            portion = block if remaining >= len(block) else block[:remaining]
            handle.write(portion)
            remaining -= len(portion)