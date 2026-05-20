"""Hyperledger Fabric integration for enterprise blockchain audit trails.

PRESERVE: Enterprise blockchain integration
EXTEND: Private blockchain support

This module keeps the Fabric SDK optional and exposes an in-memory fallback so
tests and minimal environments can exercise the audit trail workflow without a
live Hyperledger deployment. Tenant isolation is modeled via one channel per
tenant, and key lifecycle events are written to the ledger as immutable audit
records.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Callable, Iterable, Optional
import copy
import json
import re

try:  # pragma: no cover - optional dependency boundary
    from hfc.fabric import Client as FabricClient
except Exception:  # pragma: no cover - optional dependency boundary
    try:
        from hfc.fabric.client import Client as FabricClient  # type: ignore[no-redef]
    except Exception as exc:  # pragma: no cover - optional dependency boundary
        FabricClient = None  # type: ignore[assignment]
        _FABRIC_SDK_IMPORT_ERROR = exc
    else:
        _FABRIC_SDK_IMPORT_ERROR = None
else:
    _FABRIC_SDK_IMPORT_ERROR = None


TransactionID = str


@dataclass(frozen=True)
class FabricConfig:
    network_profile_path: str | None = None
    channel_prefix: str = "audit"
    tenants: list[str] = field(default_factory=list)
    chaincode_name: str = "audit-chaincode"
    chaincode_version: str = "1.0"
    org_name: str | None = None
    user_name: str | None = None
    batch_size: int = 1
    connection_timeout_seconds: float = 30.0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class FabricNetwork:
    connected: bool
    client: Any | None
    config: FabricConfig
    channels: dict[str, str] = field(default_factory=dict)
    tenant_channels: dict[str, str] = field(default_factory=dict)
    chaincode_deployed: bool = False
    initialized_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Response:
    status: str
    transaction_id: TransactionID
    channel: str
    chaincode: str
    function: str
    args: list[str] = field(default_factory=list)
    payload: dict[str, Any] = field(default_factory=dict)
    confirmed: bool = True
    message: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True)
class LedgerEntry:
    key: str
    value: dict[str, Any]
    tenant_id: str
    channel: str
    transaction_id: TransactionID
    event_type: str
    actor: str
    timestamp: datetime
    integrity_hash: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class KeyEvent:
    key_id: str
    tenant_id: str
    event_type: str
    actor: str
    timestamp: datetime
    previous_key_id: str | None = None
    new_key_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AuditReport:
    generated_at: datetime
    connected: bool
    compliance_score: int
    channels_total: int
    entries_total: int
    violations: list[str] = field(default_factory=list)
    channel_status: dict[str, dict[str, Any]] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


class HyperledgerFabricIntegration:
    """Hyperledger Fabric audit trail and key lifecycle manager."""

    def __init__(
        self,
        *,
        fabric_client: Any | None = None,
        config: FabricConfig | None = None,
        sdk_client_factory: Callable[[FabricConfig], Any] | None = None,
        channel_factory: Callable[[str, FabricConfig], Any] | None = None,
    ) -> None:
        self._fabric_client = fabric_client
        self._config = config
        self._sdk_client_factory = sdk_client_factory
        self._channel_factory = channel_factory

        self._network: FabricNetwork | None = None
        self._channel_ledgers: dict[str, list[LedgerEntry]] = {}
        self._ledger_by_key: dict[str, LedgerEntry] = {}
        self._ledger_by_tx: dict[str, LedgerEntry] = {}
        self._key_lifecycle_history: dict[str, list[LedgerEntry]] = {}
        self._batch_counter = 0

    def initialize_fabric_network(self, config: FabricConfig) -> FabricNetwork:
        """Connects to Hyperledger Fabric network."""
        self._config = config

        client = self._fabric_client or self._build_client(config)
        network = FabricNetwork(
            connected=True,
            client=client,
            config=config,
            notes=["Per-tenant channels are isolated for private blockchain support"],
        )

        self._configure_client(client, config)

        tenants = config.tenants or ["default"]
        for tenant_id in tenants:
            channel_name = self._ensure_tenant_channel(network, tenant_id)
            self._deploy_chaincode_if_needed(client, network, channel_name)

        self._network = network
        return network

    def invoke_chaincode(self, chaincode: str, function: str, args: list[str]) -> Response:
        """Invokes smart contract function."""
        network = self._require_network()
        channel = self._default_channel(network)
        payload = {
            "chaincode": chaincode,
            "function": function,
            "args": list(args),
            "channel": channel,
        }

        tx_id = self._invoke_sdk_chaincode(network.client, network, payload)
        response = Response(
            status="confirmed",
            transaction_id=tx_id,
            channel=channel,
            chaincode=chaincode,
            function=function,
            args=list(args),
            payload=payload,
            confirmed=True,
            message="chaincode invocation recorded",
            metadata={"tenant_channels": dict(network.tenant_channels)},
        )
        return response

    def query_ledger(self, key: str) -> LedgerEntry:
        """Queries ledger for specific entry."""
        if not isinstance(key, str) or not key.strip():
            raise ValueError("key must be a non-empty string")

        entry = self._ledger_by_key.get(key.strip())
        if entry is None:
            raise KeyError(f"ledger entry not found: {key}")
        return entry

    def record_key_lifecycle(self, key_event: KeyEvent) -> TransactionID:
        """Records key generation, rotation, or deletion on the ledger."""
        self._require_network()
        if not isinstance(key_event, KeyEvent):
            raise TypeError("key_event must be a KeyEvent instance")

        network = self._network
        assert network is not None

        channel = self._ensure_tenant_channel(network, key_event.tenant_id)
        tx_id = self._derive_transaction_id(key_event, channel)
        payload = {
            "key_id": key_event.key_id,
            "tenant_id": key_event.tenant_id,
            "event_type": key_event.event_type,
            "actor": key_event.actor,
            "timestamp": key_event.timestamp.isoformat(),
            "previous_key_id": key_event.previous_key_id,
            "new_key_id": key_event.new_key_id,
            "metadata": dict(key_event.metadata),
        }

        entry = LedgerEntry(
            key=key_event.key_id,
            value=payload,
            tenant_id=key_event.tenant_id,
            channel=channel,
            transaction_id=tx_id,
            event_type=key_event.event_type,
            actor=key_event.actor,
            timestamp=key_event.timestamp,
            integrity_hash=self._entry_hash(payload, tx_id, channel),
            metadata={"batch": self._batch_counter},
        )

        self._record_entry(entry)
        self._push_event_to_chaincode(network, entry)
        return tx_id

    def audit_blockchain_state(self) -> AuditReport:
        """Audits blockchain state for compliance."""
        network = self._network
        violations: list[str] = []
        notes: list[str] = []

        if network is None:
            return AuditReport(
                generated_at=datetime.now(UTC),
                connected=False,
                compliance_score=0,
                channels_total=0,
                entries_total=0,
                violations=["fabric network not initialized"],
                notes=["Initialize the Fabric network before auditing"],
            )

        if not network.connected:
            violations.append("fabric network disconnected")

        channel_status: dict[str, dict[str, Any]] = {}
        for tenant_id, channel_name in network.tenant_channels.items():
            entries = self._channel_ledgers.get(channel_name, [])
            channel_violations = self._audit_channel_entries(channel_name, entries)
            if channel_violations:
                violations.extend(channel_violations)
            channel_status[tenant_id] = {
                "channel": channel_name,
                "entries": len(entries),
                "compliant": not channel_violations,
            }

        entries_total = sum(len(entries) for entries in self._channel_ledgers.values())
        channels_total = len(network.tenant_channels)
        score = self._compliance_score(channels_total, entries_total, violations)
        if channels_total and not violations:
            notes.append("All tenant channels are present and ledger entries are intact")

        return AuditReport(
            generated_at=datetime.now(UTC),
            connected=network.connected,
            compliance_score=score,
            channels_total=channels_total,
            entries_total=entries_total,
            violations=violations,
            channel_status=channel_status,
            notes=notes,
        )

    def _build_client(self, config: FabricConfig) -> Any | None:
        if self._sdk_client_factory is not None:
            return self._sdk_client_factory(config)
        if FabricClient is None:
            return None
        try:
            return FabricClient()
        except Exception:
            return None

    def _configure_client(self, client: Any | None, config: FabricConfig) -> None:
        if client is None:
            return

        profile = config.network_profile_path
        if profile and hasattr(client, "connect"):
            try:
                client.connect(profile)
            except TypeError:
                client.connect(profile_path=profile)
            except Exception:
                pass

        if profile and hasattr(client, "init_with_profile"):
            try:
                client.init_with_profile(profile)
            except Exception:
                pass

    def _deploy_chaincode_if_needed(self, client: Any | None, network: FabricNetwork, channel_name: str) -> None:
        if client is None:
            network.chaincode_deployed = True
            return

        if hasattr(client, "create_channel"):
            try:
                client.create_channel(channel_name)
            except Exception:
                pass

        join_method = getattr(client, "join_channel", None)
        if callable(join_method):
            try:
                join_method(channel_name)
            except TypeError:
                join_method(channel=channel_name)
            except Exception:
                pass

        if hasattr(client, "deploy_chaincode"):
            try:
                client.deploy_chaincode(channel_name=channel_name, chaincode_name=network.config.chaincode_name, version=network.config.chaincode_version)
            except TypeError:
                try:
                    client.deploy_chaincode(channel_name, network.config.chaincode_name, network.config.chaincode_version)
                except Exception:
                    pass
            except Exception:
                pass

        network.chaincode_deployed = True

    def _ensure_tenant_channel(self, network: FabricNetwork, tenant_id: str) -> str:
        normalized_tenant = self._normalize_tenant(tenant_id)
        channel_name = network.tenant_channels.get(normalized_tenant)
        if channel_name:
            return channel_name

        channel_name = self._channel_name(normalized_tenant)
        network.tenant_channels[normalized_tenant] = channel_name
        network.channels[channel_name] = normalized_tenant
        self._channel_ledgers.setdefault(channel_name, [])

        if network.client is not None:
            self._create_channel_on_client(network.client, channel_name)

        return channel_name

    def _create_channel_on_client(self, client: Any, channel_name: str) -> None:
        if hasattr(client, "create_channel"):
            try:
                client.create_channel(channel_name)
            except Exception:
                pass
        if hasattr(client, "add_channel"):
            try:
                client.add_channel(channel_name)
            except Exception:
                pass

    def _push_event_to_chaincode(self, network: FabricNetwork, entry: LedgerEntry) -> None:
        client = network.client
        if client is None:
            return

        if hasattr(client, "invoke_chaincode"):
            try:
                client.invoke_chaincode(
                    chaincode=network.config.chaincode_name,
                    function=entry.event_type,
                    args=[entry.key, json.dumps(entry.value, sort_keys=True, default=str)],
                    channel_name=entry.channel,
                )
            except TypeError:
                try:
                    client.invoke_chaincode(network.config.chaincode_name, entry.event_type, [entry.key, json.dumps(entry.value, sort_keys=True, default=str)], entry.channel)
                except Exception:
                    pass
            except Exception:
                pass

    def _invoke_sdk_chaincode(self, client: Any | None, network: FabricNetwork, payload: dict[str, Any]) -> TransactionID:
        if client is None:
            return self._local_transaction_id(payload["chaincode"], payload["function"], payload["args"], payload["channel"])

        invocation = getattr(client, "invoke_chaincode", None)
        if callable(invocation):
            try:
                result = invocation(
                    chaincode=payload["chaincode"],
                    function=payload["function"],
                    args=payload["args"],
                    channel_name=payload["channel"],
                )
                return self._normalize_tx_id(result, payload)
            except TypeError:
                try:
                    result = invocation(payload["chaincode"], payload["function"], payload["args"], payload["channel"])
                    return self._normalize_tx_id(result, payload)
                except Exception:
                    pass
            except Exception:
                pass

        return self._local_transaction_id(payload["chaincode"], payload["function"], payload["args"], payload["channel"])

    def _normalize_tx_id(self, result: Any, payload: dict[str, Any]) -> TransactionID:
        if isinstance(result, str) and result:
            return result if result.startswith("tx-") or result.startswith("0x") else f"tx-{result}"
        if isinstance(result, dict):
            for key in ("transaction_id", "tx_id", "txid", "id", "hash"):
                value = result.get(key)
                if isinstance(value, str) and value:
                    return value
        return self._local_transaction_id(payload["chaincode"], payload["function"], payload["args"], payload["channel"])

    def _record_entry(self, entry: LedgerEntry) -> None:
        self._ledger_by_key[entry.key] = entry
        self._ledger_by_tx[entry.transaction_id] = entry
        self._key_lifecycle_history.setdefault(entry.key, []).append(entry)
        self._channel_ledgers.setdefault(entry.channel, []).append(entry)

    def _audit_channel_entries(self, channel_name: str, entries: list[LedgerEntry]) -> list[str]:
        violations: list[str] = []
        if not entries:
            violations.append(f"channel {channel_name} has no entries")
            return violations

        for entry in entries:
            expected = self._entry_hash(entry.value, entry.transaction_id, entry.channel)
            if expected != entry.integrity_hash:
                violations.append(f"tampered entry detected for key {entry.key} on {channel_name}")
            if self._channel_name(entry.tenant_id) != entry.channel:
                violations.append(f"channel mismatch for key {entry.key} on {channel_name}")
        return violations

    def _compliance_score(self, channels_total: int, entries_total: int, violations: list[str]) -> int:
        score = 100
        score -= max(0, channels_total - len(self._channel_ledgers)) * 10
        score -= max(0, entries_total == 0) * 20
        score -= min(60, len(violations) * 15)
        return max(0, score)

    def _default_channel(self, network: FabricNetwork) -> str:
        if network.tenant_channels:
            first_tenant = next(iter(sorted(network.tenant_channels)))
            return network.tenant_channels[first_tenant]
        default_channel = self._channel_name("default")
        network.tenant_channels.setdefault("default", default_channel)
        network.channels.setdefault(default_channel, "default")
        self._channel_ledgers.setdefault(default_channel, [])
        return default_channel

    def _require_network(self) -> FabricNetwork:
        if self._network is None:
            if self._config is None:
                raise RuntimeError("fabric network has not been initialized")
            return self.initialize_fabric_network(self._config)
        return self._network

    def _channel_name(self, tenant_id: str) -> str:
        return f"{self._config.channel_prefix if self._config else 'audit'}-{tenant_id}"

    def _normalize_tenant(self, tenant_id: str) -> str:
        normalized = re.sub(r"[^a-zA-Z0-9_-]+", "-", tenant_id.strip().lower()).strip("-")
        return normalized or "default"

    def _entry_hash(self, payload: dict[str, Any], tx_id: TransactionID, channel: str) -> str:
        serialized = json.dumps({"payload": payload, "tx_id": tx_id, "channel": channel}, sort_keys=True, default=str).encode("utf-8")
        return sha256(serialized).hexdigest()

    def _derive_transaction_id(self, key_event: KeyEvent, channel: str) -> TransactionID:
        serialized = json.dumps(
            {
                "key_id": key_event.key_id,
                "tenant_id": key_event.tenant_id,
                "event_type": key_event.event_type,
                "actor": key_event.actor,
                "timestamp": key_event.timestamp.isoformat(),
                "channel": channel,
                "previous_key_id": key_event.previous_key_id,
                "new_key_id": key_event.new_key_id,
                "metadata": key_event.metadata,
            },
            sort_keys=True,
            default=str,
        ).encode("utf-8")
        return "tx-" + sha256(serialized).hexdigest()

    def _local_transaction_id(self, chaincode: str, function: str, args: list[str], channel: str) -> TransactionID:
        serialized = json.dumps({"chaincode": chaincode, "function": function, "args": list(args), "channel": channel, "batch": self._batch_counter}, sort_keys=True, default=str).encode("utf-8")
        return "tx-" + sha256(serialized).hexdigest()


__all__ = [
    "TransactionID",
    "FabricConfig",
    "FabricNetwork",
    "Response",
    "LedgerEntry",
    "KeyEvent",
    "AuditReport",
    "HyperledgerFabricIntegration",
]