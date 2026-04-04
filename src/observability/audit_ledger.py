"""Immutable audit ledger using append-only, tamper-evident records.

The ledger stores one JSON record per line and chains records by including the
SHA256 hash of the previous record in each new entry.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping


@dataclass(frozen=True)
class AuditEvent:
    """Domain event persisted in the immutable audit ledger."""

    event_type: str
    details: dict[str, Any] = field(default_factory=dict)
    actor_id: str | None = None
    action: str | None = None
    severity: str = "INFO"
    timestamp: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_payload(self) -> dict[str, Any]:
        payload = {
            "event_type": self.event_type,
            "details": dict(self.details),
            "severity": self.severity,
            "timestamp": float(self.timestamp),
            "metadata": dict(self.metadata),
        }
        if self.actor_id:
            payload["actor_id"] = self.actor_id
        if self.action:
            payload["action"] = self.action
        return payload


class ImmutableAuditLedger:
    """Append-only tamper-evident ledger with hash chaining and signatures."""

    _LEDGER_VERSION = 1
    _GENESIS_PREVIOUS_HASH = "0" * 64
    _SIGNATURE_ALGORITHM = "hmac-sha256"

    def __init__(
        self,
        *,
        ledger_path: str | Path = "audit/immutable_audit_ledger.jsonl",
        signing_key: str | bytes | None = None,
        signer_id: str = "keycrypt-audit-ledger",
    ) -> None:
        self._ledger_path = Path(ledger_path)
        self._signing_key = self._resolve_signing_key(signing_key)
        self._signer_id = signer_id.strip() or "keycrypt-audit-ledger"
        self._lock = threading.RLock()

        self._head_hash = self._GENESIS_PREVIOUS_HASH
        self._next_index = 0

        self._initialize_store()

    def append(self, event: AuditEvent) -> dict[str, Any]:
        """Append an event by hashing, linking to previous record, and signing."""
        if not isinstance(event, AuditEvent):
            raise TypeError("event must be an AuditEvent instance")

        payload = event.to_payload()
        self._validate_event_payload(payload)

        with self._lock:
            previous_event_hash = self._head_hash
            event_hash = self._sha256_dict(payload)

            unsigned_entry: dict[str, Any] = {
                "ledger_version": self._LEDGER_VERSION,
                "index": self._next_index,
                "recorded_at": datetime.now(UTC).isoformat(),
                "previous_event_hash": previous_event_hash,
                "event_hash": event_hash,
                "event": payload,
            }
            entry_hash = self._sha256_dict(unsigned_entry)
            signature = self._sign_entry(
                index=self._next_index,
                previous_event_hash=previous_event_hash,
                event_hash=event_hash,
                entry_hash=entry_hash,
            )

            entry = {
                **unsigned_entry,
                "entry_hash": entry_hash,
                "signature": {
                    "algorithm": self._SIGNATURE_ALGORITHM,
                    "signer_id": self._signer_id,
                    "value": signature,
                },
            }

            self._append_line(entry)
            self._head_hash = entry_hash
            self._next_index += 1
            return entry

    def verify_chain(self) -> bool:
        """Validate hash-chain linkage, event hashes, and entry signatures."""
        with self._lock:
            expected_previous_hash = self._GENESIS_PREVIOUS_HASH
            expected_index = 0

            for entry in self._read_entries():
                if int(entry.get("ledger_version", -1)) != self._LEDGER_VERSION:
                    return False

                index = entry.get("index")
                if not isinstance(index, int) or index != expected_index:
                    return False

                previous_event_hash = entry.get("previous_event_hash")
                if not isinstance(previous_event_hash, str) or previous_event_hash != expected_previous_hash:
                    return False

                event = entry.get("event")
                if not isinstance(event, dict):
                    return False

                stored_event_hash = entry.get("event_hash")
                if not isinstance(stored_event_hash, str):
                    return False
                computed_event_hash = self._sha256_dict(event)
                if not hmac.compare_digest(stored_event_hash, computed_event_hash):
                    return False

                unsigned_entry = self._build_unsigned_entry(entry, event)
                computed_entry_hash = self._sha256_dict(unsigned_entry)
                stored_entry_hash = entry.get("entry_hash")
                if not isinstance(stored_entry_hash, str):
                    return False
                if not hmac.compare_digest(stored_entry_hash, computed_entry_hash):
                    return False

                signature = entry.get("signature")
                if not isinstance(signature, dict):
                    return False

                signature_value = signature.get("value")
                if not isinstance(signature_value, str):
                    return False

                expected_signature = self._sign_entry(
                    index=index,
                    previous_event_hash=previous_event_hash,
                    event_hash=computed_event_hash,
                    entry_hash=computed_entry_hash,
                )
                if not hmac.compare_digest(signature_value, expected_signature):
                    return False

                expected_previous_hash = computed_entry_hash
                expected_index += 1

            return True

    def query(self, filters: dict[str, Any]) -> list[dict[str, Any]]:
        """Search ledger entries by simple equality/range filter expressions."""
        if not isinstance(filters, dict):
            raise TypeError("filters must be a dictionary")

        with self._lock:
            entries = list(self._read_entries())

        if not filters:
            return entries

        matches: list[dict[str, Any]] = []
        for entry in entries:
            if self._matches_filters(entry, filters):
                matches.append(entry)
        return matches

    def _initialize_store(self) -> None:
        self._ledger_path.parent.mkdir(parents=True, exist_ok=True)
        if not self._ledger_path.exists():
            self._ledger_path.touch()
            return

        last_hash = self._GENESIS_PREVIOUS_HASH
        next_index = 0
        for entry in self._read_entries():
            index = entry.get("index")
            entry_hash = entry.get("entry_hash")
            if isinstance(index, int) and isinstance(entry_hash, str):
                next_index = max(next_index, index + 1)
                last_hash = entry_hash

        self._next_index = next_index
        self._head_hash = last_hash

    def _append_line(self, payload: dict[str, Any]) -> None:
        line = self._canonical_json(payload)
        with self._ledger_path.open("a", encoding="utf-8") as handle:
            handle.write(line)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())

    def _read_entries(self):
        with self._ledger_path.open("r", encoding="utf-8") as handle:
            for line_no, raw_line in enumerate(handle, start=1):
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"invalid audit ledger record at line {line_no}") from exc

                if not isinstance(data, dict):
                    raise ValueError(f"invalid audit ledger record type at line {line_no}")
                yield data

    def _matches_filters(self, entry: dict[str, Any], filters: dict[str, Any]) -> bool:
        for key, expected in filters.items():
            value, found = self._resolve_filter_value(entry, key)
            if not found:
                return False
            if not self._value_matches_filter(value, expected):
                return False
        return True

    def _resolve_filter_value(self, entry: dict[str, Any], key: str) -> tuple[Any, bool]:
        if not isinstance(key, str) or not key.strip():
            return None, False

        path = key.strip().split(".")

        if len(path) > 1:
            cursor: Any = entry
            for token in path:
                if not isinstance(cursor, dict) or token not in cursor:
                    return None, False
                cursor = cursor[token]
            return cursor, True

        flat_key = path[0]
        if flat_key in entry:
            return entry[flat_key], True

        event = entry.get("event")
        if isinstance(event, dict):
            if flat_key in event:
                return event[flat_key], True

            details = event.get("details")
            if isinstance(details, dict) and flat_key in details:
                return details[flat_key], True

            metadata = event.get("metadata")
            if isinstance(metadata, dict) and flat_key in metadata:
                return metadata[flat_key], True

        return None, False

    def _value_matches_filter(self, value: Any, expected: Any) -> bool:
        if isinstance(expected, Mapping):
            return self._match_operator_filter(value, expected)

        if isinstance(expected, (list, tuple, set, frozenset)):
            return value in expected

        return value == expected

    def _match_operator_filter(self, value: Any, operators: Mapping[str, Any]) -> bool:
        for op, expected in operators.items():
            if op == "$eq" and value != expected:
                return False
            if op == "$ne" and value == expected:
                return False
            if op == "$gt" and not self._compare(value, expected, lambda a, b: a > b):
                return False
            if op == "$gte" and not self._compare(value, expected, lambda a, b: a >= b):
                return False
            if op == "$lt" and not self._compare(value, expected, lambda a, b: a < b):
                return False
            if op == "$lte" and not self._compare(value, expected, lambda a, b: a <= b):
                return False
            if op == "$contains":
                if isinstance(value, (list, tuple, set, frozenset)):
                    if expected not in value:
                        return False
                elif isinstance(value, str):
                    if str(expected) not in value:
                        return False
                else:
                    return False
        return True

    @staticmethod
    def _compare(value: Any, expected: Any, predicate) -> bool:
        try:
            return bool(predicate(value, expected))
        except Exception:
            return False

    def _build_unsigned_entry(self, entry: dict[str, Any], event: dict[str, Any]) -> dict[str, Any]:
        return {
            "ledger_version": int(entry["ledger_version"]),
            "index": int(entry["index"]),
            "recorded_at": str(entry["recorded_at"]),
            "previous_event_hash": str(entry["previous_event_hash"]),
            "event_hash": str(entry["event_hash"]),
            "event": event,
        }

    def _sign_entry(
        self,
        *,
        index: int,
        previous_event_hash: str,
        event_hash: str,
        entry_hash: str,
    ) -> str:
        payload = {
            "index": int(index),
            "previous_event_hash": previous_event_hash,
            "event_hash": event_hash,
            "entry_hash": entry_hash,
            "signer_id": self._signer_id,
            "algorithm": self._SIGNATURE_ALGORITHM,
        }
        message = self._canonical_json(payload).encode("utf-8")
        return hmac.new(self._signing_key, message, hashlib.sha256).hexdigest()

    @staticmethod
    def _validate_event_payload(payload: dict[str, Any]) -> None:
        event_type = payload.get("event_type")
        if not isinstance(event_type, str) or not event_type.strip():
            raise ValueError("event.event_type must be a non-empty string")

        details = payload.get("details", {})
        if not isinstance(details, dict):
            raise TypeError("event.details must be a dictionary")

        metadata = payload.get("metadata", {})
        if not isinstance(metadata, dict):
            raise TypeError("event.metadata must be a dictionary")

    @staticmethod
    def _sha256_dict(payload: dict[str, Any]) -> str:
        text = ImmutableAuditLedger._canonical_json(payload)
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    @staticmethod
    def _canonical_json(payload: dict[str, Any]) -> str:
        return json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True, default=repr)

    @staticmethod
    def _resolve_signing_key(value: str | bytes | None) -> bytes:
        if isinstance(value, bytes):
            if not value:
                raise ValueError("signing_key bytes cannot be empty")
            return value

        if isinstance(value, str):
            normalized = value.strip()
            if not normalized:
                raise ValueError("signing_key string cannot be empty")
            return normalized.encode("utf-8")

        env_value = os.getenv("KEYCRYPT_AUDIT_SIGNING_KEY")
        if isinstance(env_value, str) and env_value.strip():
            return env_value.strip().encode("utf-8")

        # Development fallback to keep component standalone in minimal setups.
        return b"keycrypt-audit-ledger-dev-key"


__all__ = ["AuditEvent", "ImmutableAuditLedger"]
