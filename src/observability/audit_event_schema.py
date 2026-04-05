"""Type-safe audit event schemas and serialization utilities.

The schema is centered on a base audit event and specialized event types for
encryption, key rotation, access checks, and configuration changes.

Serialization formats:
- JSON
- MessagePack (msgpack)
- Protobuf (google.protobuf.Struct)
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

try:  # pragma: no cover - optional dependency boundary
    import msgpack
except Exception as exc:  # pragma: no cover - optional dependency boundary
    msgpack = None  # type: ignore[assignment]
    _MSGPACK_IMPORT_ERROR = exc
else:
    _MSGPACK_IMPORT_ERROR = None

try:  # pragma: no cover - optional dependency boundary
    from google.protobuf.json_format import MessageToDict
    from google.protobuf.struct_pb2 import Struct
except Exception as exc:  # pragma: no cover - optional dependency boundary
    MessageToDict = None  # type: ignore[assignment]
    Struct = None  # type: ignore[assignment]
    _PROTOBUF_IMPORT_ERROR = exc
else:
    _PROTOBUF_IMPORT_ERROR = None


class AuditEvent(BaseModel):
    """Base audit event schema.

    Required fields:
    - timestamp
    - event_id
    - event_type
    - actor
    - resource
    - action
    - outcome
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    event_type: str = Field(min_length=1)
    actor: str = Field(min_length=1)
    resource: str = Field(min_length=1)
    action: str = Field(min_length=1)
    outcome: str = Field(min_length=1)

    @field_validator("event_id", "event_type", "actor", "resource", "action", "outcome")
    @classmethod
    def _validate_non_empty_text(cls, value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("field must be a non-empty string")
        return value.strip()

    def to_payload(self) -> dict[str, Any]:
        """Return canonical JSON-compatible event payload."""
        return self.model_dump(mode="json")

    def to_json(self) -> str:
        """Serialize event as JSON text."""
        return self.model_dump_json()

    def to_msgpack(self) -> bytes:
        """Serialize event as MessagePack bytes.

        Raises:
            RuntimeError: If msgpack dependency is not available.
        """
        if msgpack is None:
            raise RuntimeError("msgpack serialization requires msgpack package") from _MSGPACK_IMPORT_ERROR

        return msgpack.packb(self.to_payload(), use_bin_type=True)

    def to_protobuf(self) -> bytes:
        """Serialize event as protobuf Struct bytes.

        Raises:
            RuntimeError: If protobuf dependency is not available.
        """
        if Struct is None:
            raise RuntimeError("protobuf serialization requires protobuf package") from _PROTOBUF_IMPORT_ERROR

        message = Struct()
        message.update(self.to_payload())
        return message.SerializeToString()

    @classmethod
    def from_json(cls, payload: str) -> "AuditEvent":
        """Deserialize event from JSON text."""
        if not isinstance(payload, str) or not payload.strip():
            raise ValueError("payload must be a non-empty JSON string")
        return cls.model_validate_json(payload)

    @classmethod
    def from_msgpack(cls, payload: bytes) -> "AuditEvent":
        """Deserialize event from MessagePack bytes."""
        if msgpack is None:
            raise RuntimeError("msgpack deserialization requires msgpack package") from _MSGPACK_IMPORT_ERROR
        if not isinstance(payload, (bytes, bytearray)) or not payload:
            raise ValueError("payload must be non-empty msgpack bytes")

        unpacked = msgpack.unpackb(payload, raw=False)
        return cls.model_validate(unpacked)

    @classmethod
    def from_protobuf(cls, payload: bytes) -> "AuditEvent":
        """Deserialize event from protobuf Struct bytes."""
        if Struct is None or MessageToDict is None:
            raise RuntimeError("protobuf deserialization requires protobuf package") from _PROTOBUF_IMPORT_ERROR
        if not isinstance(payload, (bytes, bytearray)) or not payload:
            raise ValueError("payload must be non-empty protobuf bytes")

        message = Struct()
        message.ParseFromString(bytes(payload))
        data = MessageToDict(message, preserving_proto_field_name=True)
        return cls.model_validate(data)


class EncryptionEvent(AuditEvent):
    """Audit event for cryptographic encryption operations."""

    event_type: Literal["encryption"] = "encryption"
    algorithm: str = Field(min_length=1)
    key_id: str = Field(min_length=1)
    data_size: int = Field(ge=0)
    duration: float = Field(ge=0.0)

    @field_validator("algorithm", "key_id")
    @classmethod
    def _validate_non_empty(cls, value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("field must be a non-empty string")
        return value.strip()


class KeyRotationEvent(AuditEvent):
    """Audit event for key rotation lifecycle actions."""

    event_type: Literal["key_rotation"] = "key_rotation"
    old_key_id: str = Field(min_length=1)
    new_key_id: str = Field(min_length=1)
    rotation_reason: str = Field(min_length=1)

    @field_validator("old_key_id", "new_key_id", "rotation_reason")
    @classmethod
    def _validate_non_empty(cls, value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("field must be a non-empty string")
        return value.strip()

    @model_validator(mode="after")
    def _validate_distinct_keys(self) -> "KeyRotationEvent":
        if self.old_key_id == self.new_key_id:
            raise ValueError("old_key_id and new_key_id must differ")
        return self


class AccessEvent(AuditEvent):
    """Audit event for resource access checks and decisions."""

    event_type: Literal["access"] = "access"
    resource_accessed: str = Field(min_length=1)
    access_granted: bool
    denial_reason: str | None = None

    @field_validator("resource_accessed")
    @classmethod
    def _validate_resource_accessed(cls, value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("resource_accessed must be a non-empty string")
        return value.strip()

    @model_validator(mode="after")
    def _validate_denial_reason(self) -> "AccessEvent":
        if self.access_granted and self.denial_reason:
            raise ValueError("denial_reason must be empty when access_granted is true")
        if not self.access_granted:
            if not isinstance(self.denial_reason, str) or not self.denial_reason.strip():
                raise ValueError("denial_reason is required when access_granted is false")
            self.denial_reason = self.denial_reason.strip()
        return self


class ConfigChangeEvent(AuditEvent):
    """Audit event for configuration changes."""

    event_type: Literal["config_change"] = "config_change"
    config_key: str = Field(min_length=1)
    old_value: Any
    new_value: Any
    change_reason: str = Field(min_length=1)

    @field_validator("config_key", "change_reason")
    @classmethod
    def _validate_non_empty(cls, value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("field must be a non-empty string")
        return value.strip()

    @model_validator(mode="after")
    def _validate_changed_value(self) -> "ConfigChangeEvent":
        if self.old_value == self.new_value:
            raise ValueError("old_value and new_value must differ for config changes")
        return self


__all__ = [
    "ValidationError",
    "AuditEvent",
    "EncryptionEvent",
    "KeyRotationEvent",
    "AccessEvent",
    "ConfigChangeEvent",
]
