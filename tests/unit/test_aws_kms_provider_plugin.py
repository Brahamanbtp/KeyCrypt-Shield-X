"""Unit tests for plugins/official/aws_kms_provider/aws_kms_provider.py."""

from __future__ import annotations

import importlib.util
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.abstractions.key_provider import KeyFilter, KeyGenerationParams


def _load_provider_class():
    plugin_path = Path(__file__).resolve().parents[2] / "plugins/official/aws_kms_provider/aws_kms_provider.py"
    spec = importlib.util.spec_from_file_location("aws_kms_provider_plugin", plugin_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load aws_kms_provider plugin module")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.AWSKMSKeyProvider


class _FakeKMSClient:
    def __init__(self) -> None:
        self.create_key_calls: list[dict[str, Any]] = []
        self.create_alias_calls: list[dict[str, Any]] = []
        self.enable_rotation_calls: list[dict[str, Any]] = []
        self.encrypt_calls: list[dict[str, Any]] = []
        self.decrypt_calls: list[dict[str, Any]] = []
        self.create_grant_calls: list[dict[str, Any]] = []
        self.retire_grant_calls: list[dict[str, Any]] = []

    def create_key(self, **kwargs: Any) -> dict[str, Any]:
        self.create_key_calls.append(dict(kwargs))
        return {
            "KeyMetadata": {
                "KeyId": "kms-key-123",
            }
        }

    def create_alias(self, **kwargs: Any) -> dict[str, Any]:
        self.create_alias_calls.append(dict(kwargs))
        return {}

    def enable_key_rotation(self, **kwargs: Any) -> dict[str, Any]:
        self.enable_rotation_calls.append(dict(kwargs))
        return {}

    def describe_key(self, **kwargs: Any) -> dict[str, Any]:
        key_id = str(kwargs.get("KeyId", ""))
        enabled = key_id != "key-disabled"
        deletion_date = datetime(2030, 1, 1, tzinfo=UTC) if key_id == "key-pending" else None
        return {
            "KeyMetadata": {
                "KeyId": key_id,
                "Arn": f"arn:aws:kms:region:123:key/{key_id}",
                "Enabled": enabled,
                "KeyState": "PendingDeletion" if deletion_date else ("Enabled" if enabled else "Disabled"),
                "KeySpec": "SYMMETRIC_DEFAULT",
                "CreationDate": datetime(2024, 1, 1, tzinfo=UTC),
                "DeletionDate": deletion_date,
                "Origin": "AWS_KMS",
                "KeyManager": "CUSTOMER",
                "KeyUsage": "ENCRYPT_DECRYPT",
            }
        }

    def list_resource_tags(self, **kwargs: Any) -> dict[str, Any]:
        key_id = str(kwargs.get("KeyId", ""))
        if key_id == "key-active":
            return {
                "Tags": [
                    {"TagKey": "env", "TagValue": "prod"},
                    {"TagKey": "team", "TagValue": "security"},
                ]
            }
        return {"Tags": []}

    def list_keys(self, **kwargs: Any) -> dict[str, Any]:
        return {
            "Keys": [
                {"KeyId": "key-active"},
                {"KeyId": "key-disabled"},
            ],
            "Truncated": False,
        }

    def encrypt(self, **kwargs: Any) -> dict[str, Any]:
        self.encrypt_calls.append(dict(kwargs))
        return {
            "CiphertextBlob": b"kms-ciphertext",
        }

    def decrypt(self, **kwargs: Any) -> dict[str, Any]:
        self.decrypt_calls.append(dict(kwargs))
        return {
            "Plaintext": b"kms-plaintext",
        }

    def create_grant(self, **kwargs: Any) -> dict[str, Any]:
        self.create_grant_calls.append(dict(kwargs))
        return {"GrantId": "grant-123"}

    def list_grants(self, **kwargs: Any) -> dict[str, Any]:
        return {
            "Grants": [
                {
                    "GrantId": "grant-123",
                    "GranteePrincipal": kwargs.get("KeyId"),
                }
            ],
            "Truncated": False,
        }

    def retire_grant(self, **kwargs: Any) -> dict[str, Any]:
        self.retire_grant_calls.append(dict(kwargs))
        return {}


def test_generate_key_uses_create_key_and_schedules_rotation() -> None:
    AWSKMSKeyProvider = _load_provider_class()
    fake = _FakeKMSClient()
    provider = AWSKMSKeyProvider(kms_client=fake)

    key_id = provider.generate_key(
        KeyGenerationParams(
            algorithm="AES-256-GCM",
            tags={"alias": "test-key", "env": "prod"},
        )
    )

    assert key_id == "kms-key-123"
    assert len(fake.create_key_calls) == 1
    assert fake.create_key_calls[0]["KeySpec"] == "SYMMETRIC_DEFAULT"
    assert len(fake.create_alias_calls) == 1
    assert fake.create_alias_calls[0]["AliasName"] == "alias/test-key"
    assert len(fake.enable_rotation_calls) >= 1
    assert fake.enable_rotation_calls[-1]["KeyId"] == "kms-key-123"


def test_get_key_wraps_describe_key_response() -> None:
    AWSKMSKeyProvider = _load_provider_class()
    provider = AWSKMSKeyProvider(kms_client=_FakeKMSClient())

    material = provider.get_key("key-active")

    assert material.key_id == "key-active"
    assert material.algorithm == "SYMMETRIC_DEFAULT"
    assert material.material == b""
    assert material.metadata["material_exportable"] is False
    assert material.metadata["key_state"] == "Enabled"


def test_encrypt_and_decrypt_use_kms_api() -> None:
    AWSKMSKeyProvider = _load_provider_class()
    fake = _FakeKMSClient()
    provider = AWSKMSKeyProvider(kms_client=fake, encryption_context={"tenant": "alpha"})

    ciphertext = provider.encrypt("key-active", b"hello")
    plaintext = provider.decrypt("key-active", ciphertext)

    assert ciphertext == b"kms-ciphertext"
    assert plaintext == b"kms-plaintext"
    assert fake.encrypt_calls[0]["EncryptionContext"]["tenant"] == "alpha"
    assert fake.decrypt_calls[0]["EncryptionContext"]["tenant"] == "alpha"


def test_list_keys_applies_key_filter() -> None:
    AWSKMSKeyProvider = _load_provider_class()
    provider = AWSKMSKeyProvider(kms_client=_FakeKMSClient())

    records = provider.list_keys(KeyFilter(active_only=True, tags={"env": "prod"}))

    assert len(records) == 1
    assert records[0].key_id == "key-active"
    assert records[0].status == "active"
    assert records[0].tags["env"] == "prod"


def test_grant_management_for_cross_account_permissions() -> None:
    AWSKMSKeyProvider = _load_provider_class()
    fake = _FakeKMSClient()
    provider = AWSKMSKeyProvider(kms_client=fake)

    grant_id = provider.create_grant_for_account(
        key_id="key-active",
        account_id="123456789012",
        operations=["Decrypt", "Encrypt"],
        name="cross-account-grant",
    )
    listed = provider.list_grants("key-active")
    provider.retire_grant(grant_id=grant_id, key_id="key-active")

    assert grant_id == "grant-123"
    assert len(fake.create_grant_calls) == 1
    assert fake.create_grant_calls[0]["GranteePrincipal"] == "arn:aws:iam::123456789012:root"
    assert len(listed) == 1
    assert len(fake.retire_grant_calls) == 1
    assert fake.retire_grant_calls[0]["GrantId"] == "grant-123"
