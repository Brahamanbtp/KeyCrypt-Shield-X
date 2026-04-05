"""Unit tests for src.observability.audit_event_schema."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import src.observability.audit_event_schema as schema_module
from src.observability.audit_event_schema import (
    AccessEvent,
    AuditEvent,
    ConfigChangeEvent,
    EncryptionEvent,
    KeyRotationEvent,
)


def test_audit_event_requires_core_fields() -> None:
    with pytest.raises(ValidationError):
        AuditEvent(
            event_type="custom",
            actor="alice",
            resource="/keys/1",
            action="read",
            # outcome missing
        )


def test_encryption_event_json_roundtrip() -> None:
    event = EncryptionEvent(
        actor="svc-crypto",
        resource="/keys/production/key-1",
        action="encrypt",
        outcome="success",
        algorithm="AES-256-GCM",
        key_id="key-1",
        data_size=1024,
        duration=0.012,
    )

    payload = event.to_json()
    restored = EncryptionEvent.from_json(payload)

    assert restored.event_type == "encryption"
    assert restored.key_id == "key-1"
    assert restored.data_size == 1024


def test_key_rotation_event_validates_distinct_keys() -> None:
    with pytest.raises(ValidationError, match="must differ"):
        KeyRotationEvent(
            actor="key-manager",
            resource="/kms/keys/master",
            action="rotate",
            outcome="success",
            old_key_id="same-key",
            new_key_id="same-key",
            rotation_reason="schedule",
        )


def test_access_event_denial_reason_validation() -> None:
    with pytest.raises(ValidationError, match="denial_reason is required"):
        AccessEvent(
            actor="alice",
            resource="/keys/prod/k1",
            action="read",
            outcome="deny",
            resource_accessed="/keys/prod/k1",
            access_granted=False,
            denial_reason=None,
        )

    with pytest.raises(ValidationError, match="must be empty"):
        AccessEvent(
            actor="alice",
            resource="/keys/prod/k1",
            action="read",
            outcome="allow",
            resource_accessed="/keys/prod/k1",
            access_granted=True,
            denial_reason="not applicable",
        )


def test_config_change_event_validates_actual_change() -> None:
    with pytest.raises(ValidationError, match="must differ"):
        ConfigChangeEvent(
            actor="admin",
            resource="/config/security",
            action="update",
            outcome="success",
            config_key="token_ttl",
            old_value=3600,
            new_value=3600,
            change_reason="policy-update",
        )


def test_msgpack_serialization_supported_or_explicit_error() -> None:
    event = EncryptionEvent(
        actor="svc",
        resource="/keys/k1",
        action="encrypt",
        outcome="success",
        algorithm="AES-256-GCM",
        key_id="k1",
        data_size=16,
        duration=0.001,
    )

    if schema_module.msgpack is None:
        with pytest.raises(RuntimeError, match="msgpack"):
            event.to_msgpack()
        return

    packed = event.to_msgpack()
    restored = EncryptionEvent.from_msgpack(packed)
    assert restored.algorithm == "AES-256-GCM"
    assert restored.key_id == "k1"


def test_protobuf_serialization_supported_or_explicit_error() -> None:
    event = AccessEvent(
        actor="svc-authz",
        resource="/keys/prod/k1",
        action="authorize",
        outcome="allow",
        resource_accessed="/keys/prod/k1",
        access_granted=True,
    )

    if schema_module.Struct is None:
        with pytest.raises(RuntimeError, match="protobuf"):
            event.to_protobuf()
        return

    blob = event.to_protobuf()
    restored = AccessEvent.from_protobuf(blob)
    assert restored.resource_accessed == "/keys/prod/k1"
    assert restored.access_granted is True
