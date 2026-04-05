"""Unit tests for src.security.secrets_manager.SecretsManager."""

from __future__ import annotations

import base64
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import src.security.secrets_manager as sm_module
from src.security.secrets_manager import (
    EnvironmentSecretBackend,
    FileSecretBackend,
    SecretBackend,
    SecretsManager,
)


class InMemorySecretBackend(SecretBackend):
    """Simple backend used to test manager behavior in isolation."""

    backend_name = "memory-test"

    def __init__(self) -> None:
        self.data: dict[str, str] = {}
        self.secure_wipe_calls = 0

    def store(self, key: str, encrypted_payload: str) -> None:
        self.data[key] = encrypted_payload

    def retrieve(self, key: str) -> str:
        if key not in self.data:
            raise KeyError(key)
        return self.data[key]

    def delete(self, key: str) -> None:
        if key not in self.data:
            raise KeyError(key)
        del self.data[key]

    def secure_wipe(self, key: str) -> None:
        if key not in self.data:
            raise KeyError(key)

        self.secure_wipe_calls += 1
        self.data[key] = "x" * len(self.data[key])
        del self.data[key]


def test_store_retrieve_delete_roundtrip_file_backend(tmp_path: Path) -> None:
    """Secrets should be encrypted at rest and retrievable with matching key."""
    secrets_path = tmp_path / "secrets.json"
    backend = FileSecretBackend(file_path=secrets_path)
    manager = SecretsManager(backend=backend)

    encryption_key = b"K" * 32
    manager.store_secret("db.password", "super-secret-value", encryption_key)

    file_text = secrets_path.read_text(encoding="utf-8")
    assert "super-secret-value" not in file_text

    retrieved = manager.retrieve_secret("db.password", encryption_key)
    assert retrieved == "super-secret-value"

    manager.delete_secret("db.password")
    with pytest.raises(KeyError):
        manager.retrieve_secret("db.password", encryption_key)


def test_retrieve_with_wrong_key_fails(tmp_path: Path) -> None:
    """Decryption should fail when a different key is provided."""
    backend = FileSecretBackend(file_path=tmp_path / "secrets.json")
    manager = SecretsManager(backend=backend)

    manager.store_secret("api.token", "token-v1", b"A" * 32)

    with pytest.raises(ValueError, match="Authentication failed"):
        manager.retrieve_secret("api.token", b"B" * 32)


def test_rotate_secret_uses_env_derived_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Rotate should derive key material from configured environment variable."""
    source_material = b"env-derived-source-material"
    monkeypatch.setenv("TEST_SECRETS_KEY_B64", base64.b64encode(source_material).decode("ascii"))

    backend = FileSecretBackend(file_path=tmp_path / "secrets.json")
    manager = SecretsManager(
        backend=backend,
        encryption_key_env_var="TEST_SECRETS_KEY_B64",
        raw_encryption_key_env_var="TEST_SECRETS_KEY_RAW_UNUSED",
    )

    manager.store_secret("service.auth", "value-v1", source_material)
    manager.rotate_secret("service.auth", "value-v2")

    assert manager.retrieve_secret("service.auth", source_material) == "value-v2"


def test_rotate_secret_uses_hsm_resolver_when_available() -> None:
    """Rotate should prefer HSM resolver key source when configured."""
    source_material = b"hsm-derived-source-material"
    backend = InMemorySecretBackend()
    manager = SecretsManager(
        backend=backend,
        hsm_key_resolver=lambda: source_material,
    )

    manager.store_secret("oauth.client", "old", source_material)
    manager.rotate_secret("oauth.client", "new")

    assert manager.retrieve_secret("oauth.client", source_material) == "new"


def test_delete_secret_invokes_backend_secure_wipe() -> None:
    """Deletion path should call backend secure_wipe for best-effort erasure."""
    backend = InMemorySecretBackend()
    manager = SecretsManager(backend=backend)

    manager.store_secret("cache.key", "value", b"M" * 32)
    manager.delete_secret("cache.key")

    assert backend.secure_wipe_calls == 1
    assert "cache.key" not in backend.data


def test_audit_logging_emitted_for_all_secret_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Store/retrieve/delete should emit structured security audit events."""
    captured: list[dict[str, Any]] = []

    def _capture_event(
        event_type: str,
        *,
        severity: str = "WARNING",
        actor: str = "unknown",
        target: str = "unknown",
        details: str | dict[str, Any] = "",
    ) -> None:
        captured.append(
            {
                "event_type": event_type,
                "severity": severity,
                "actor": actor,
                "target": target,
                "details": details,
            }
        )

    monkeypatch.setattr(sm_module, "log_security_event", _capture_event)

    backend = FileSecretBackend(file_path=tmp_path / "secrets.json")
    manager = SecretsManager(backend=backend)

    encryption_key = b"Q" * 32
    manager.store_secret("service.key", "v1", encryption_key)
    _ = manager.retrieve_secret("service.key", encryption_key)
    manager.delete_secret("service.key")

    actions = [str(item["details"].get("action")) for item in captured]  # type: ignore[union-attr]
    outcomes = [str(item["details"].get("outcome")) for item in captured]  # type: ignore[union-attr]

    assert actions == ["store_secret", "retrieve_secret", "delete_secret"]
    assert outcomes == ["success", "success", "success"]
    assert all(item["event_type"] == "secret_access" for item in captured)


def test_build_backend_supports_file_and_environment() -> None:
    """Backend factory should construct supported local backends."""
    assert isinstance(SecretsManager.build_backend("file"), FileSecretBackend)
    assert isinstance(SecretsManager.build_backend("environment"), EnvironmentSecretBackend)


def test_vault_backend_dependency_error_is_lazy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Vault backend should fail in constructor when hvac is unavailable."""
    monkeypatch.setattr(sm_module, "hvac", None)
    monkeypatch.setattr(sm_module, "_HVAC_IMPORT_ERROR", RuntimeError("missing hvac"))

    with pytest.raises(RuntimeError, match="requires hvac"):
        sm_module.VaultSecretBackend(token="token")


def test_aws_backend_dependency_error_is_lazy(monkeypatch: pytest.MonkeyPatch) -> None:
    """AWS backend should fail in constructor when boto3 is unavailable."""
    monkeypatch.setattr(sm_module, "boto3", None)
    monkeypatch.setattr(sm_module, "_BOTO3_IMPORT_ERROR", RuntimeError("missing boto3"))

    with pytest.raises(RuntimeError, match="requires boto3"):
        sm_module.AWSSecretsManagerBackend()
