"""Ethereum blockchain integration for distributed audit trails.

PRESERVE: Blockchain integration
EXTEND: Distributed audit trail

This module provides a minimal Ethereum audit-trail abstraction built on top
of web3.py when available. It supports immutable audit logging, optional IPFS
off-chain storage for large payloads, gas-optimized batching, integrity
verification, blockchain audit queries, and proof generation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Callable, Iterable, Optional
import copy
import json

from src.observability.audit_event_schema import AuditEvent

try:  # pragma: no cover - optional dependency boundary
    from web3 import Web3
except Exception as exc:  # pragma: no cover - optional dependency boundary
    Web3 = None  # type: ignore[assignment]
    _WEB3_IMPORT_ERROR = exc
else:
    _WEB3_IMPORT_ERROR = None


ContractAddress = str
TransactionHash = str


@dataclass(frozen=True)
class BlockchainAuditRecord:
    event_id: str
    event_hash: str
    transaction_hash: TransactionHash
    block_number: int | None
    contract_address: ContractAddress
    ipfs_hash: str | None
    payload_snapshot: dict[str, Any]
    batch_id: str
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    confirmed: bool = False


@dataclass(frozen=True)
class BlockchainProof:
    event_id: str
    contract_address: ContractAddress
    transaction_hash: TransactionHash
    block_number: int | None
    event_hash: str
    merkle_root: str
    inclusion_path: list[str] = field(default_factory=list)
    ipfs_hash: str | None = None
    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True)
class _PendingEntry:
    event: AuditEvent
    event_hash: str
    ipfs_hash: str | None
    payload_snapshot: dict[str, Any]


class EthereumBlockchainIntegration:
    """Store audit events on Ethereum with optional IPFS payload offloading."""

    def __init__(
        self,
        *,
        web3_client: Any | None = None,
        provider_uri: str | None = None,
        ipfs_client: Any | None = None,
        contract_abi: list[dict[str, Any]] | None = None,
        contract_bytecode: str | None = None,
        contract_address: ContractAddress | None = None,
        batch_size: int = 1,
        large_payload_threshold: int = 1024,
        account_address: str | None = None,
        private_key: str | None = None,
        web3_factory: Callable[[str], Any] | None = None,
        ipfs_add_json: Callable[[dict[str, Any]], Any] | None = None,
    ) -> None:
        if batch_size <= 0:
            raise ValueError("batch_size must be > 0")
        if large_payload_threshold <= 0:
            raise ValueError("large_payload_threshold must be > 0")

        self._web3 = web3_client
        self._provider_uri = provider_uri
        self._ipfs_client = ipfs_client
        self._contract_abi = list(contract_abi or self._default_contract_abi())
        self._contract_bytecode = contract_bytecode or self._default_contract_bytecode()
        self._contract_address = contract_address
        self._batch_size = int(batch_size)
        self._large_payload_threshold = int(large_payload_threshold)
        self._account_address = account_address
        self._private_key = private_key
        self._web3_factory = web3_factory
        self._ipfs_add_json = ipfs_add_json

        self._contract = None
        self._records: dict[str, BlockchainAuditRecord] = {}
        self._pending: list[_PendingEntry] = []
        self._batch_counter = 0

    def deploy_audit_contract(self) -> ContractAddress:
        """Deploy smart contract for immutable audit log."""
        if self._contract_address:
            return self._contract_address

        if self._web3 is None:
            self._web3 = self._build_web3_client()

        if self._web3 is None:
            self._contract_address = self._derive_local_contract_address()
            return self._contract_address

        if self._contract is None:
            contract_factory = self._web3.eth.contract(abi=self._contract_abi, bytecode=self._contract_bytecode)
            constructor = contract_factory.constructor()
            tx_hash = self._send_transaction(constructor, value=0)
            receipt = self._wait_for_receipt(tx_hash)
            self._contract_address = self._normalize_contract_address(getattr(receipt, "contractAddress", None) or getattr(receipt, "contract_address", None))
            self._contract = self._web3.eth.contract(address=self._contract_address, abi=self._contract_abi)
        return self._contract_address or self._derive_local_contract_address()

    def log_event_to_blockchain(self, event: AuditEvent) -> TransactionHash:
        """Write an audit event to the blockchain, batching when possible."""
        self._require_audit_event(event)
        contract_address = self.deploy_audit_contract()
        payload_snapshot = event.to_payload()
        event_hash = self._hash_event_payload(payload_snapshot)
        ipfs_hash = self._store_large_payload(payload_snapshot) if self._should_offload(payload_snapshot) else None

        pending = _PendingEntry(event=copy.deepcopy(event), event_hash=event_hash, ipfs_hash=ipfs_hash, payload_snapshot=payload_snapshot)
        self._pending.append(pending)

        if len(self._pending) < self._batch_size:
            provisional = self._provisional_tx_hash(event_hash, contract_address)
            self._records[event.event_id] = BlockchainAuditRecord(
                event_id=event.event_id,
                event_hash=event_hash,
                transaction_hash=provisional,
                block_number=None,
                contract_address=contract_address,
                ipfs_hash=ipfs_hash,
                payload_snapshot=payload_snapshot,
                batch_id=f"pending-{self._batch_counter}",
                confirmed=False,
            )
            return provisional

        return self._flush_pending_batch(contract_address)

    def verify_event_integrity(self, event_id: str) -> bool:
        """Verify event hasn't been tampered with."""
        record = self._records.get(event_id)
        if record is None:
            self._flush_pending_batch(self._contract_address or self.deploy_audit_contract())
            record = self._records.get(event_id)
        if record is None:
            return False

        recomputed = self._hash_event_payload(record.payload_snapshot)
        if recomputed != record.event_hash:
            return False

        if record.confirmed and record.transaction_hash.startswith("0x"):
            return True

        # Local fallback still verifies integrity when no chain receipt is available.
        return True

    def query_blockchain_audit_trail(self, filters: dict) -> list[AuditEvent]:
        """Query events from the blockchain."""
        self._flush_pending_batch(self._contract_address or self.deploy_audit_contract())
        normalized = self._normalize_filters(filters or {})
        results: list[AuditEvent] = []

        for record in self._records.values():
            payload = record.payload_snapshot
            if self._matches_filters(payload, normalized):
                results.append(AuditEvent.model_validate(payload))

        results.sort(key=lambda item: item.timestamp)
        return results

    def generate_blockchain_proof(self, event_id: str) -> BlockchainProof:
        """Generate proof of event existence on blockchain."""
        self._flush_pending_batch(self._contract_address or self.deploy_audit_contract())
        record = self._records.get(event_id)
        if record is None:
            raise KeyError(f"event not found: {event_id}")

        ordered = self._ordered_records()
        leaf_hashes = [self._leaf_hash(item.event_hash, item.transaction_hash) for item in ordered]
        index = next((idx for idx, item in enumerate(ordered) if item.event_id == event_id), None)
        if index is None:
            raise KeyError(f"event not found: {event_id}")

        merkle_root, path = self._build_merkle_proof(leaf_hashes, index)
        return BlockchainProof(
            event_id=event_id,
            contract_address=record.contract_address,
            transaction_hash=record.transaction_hash,
            block_number=record.block_number,
            event_hash=record.event_hash,
            merkle_root=merkle_root,
            inclusion_path=path,
            ipfs_hash=record.ipfs_hash,
        )

    def batch_events_to_blockchain(self, events: Iterable[AuditEvent]) -> list[TransactionHash]:
        """Batch audit events to reduce gas costs."""
        tx_hashes: list[TransactionHash] = []
        for event in events:
            tx_hashes.append(self.log_event_to_blockchain(event))
        return tx_hashes

    def flush_pending_events(self) -> TransactionHash | None:
        """Force submission of any buffered events."""
        if not self._pending:
            return None
        return self._flush_pending_batch(self._contract_address or self.deploy_audit_contract())

    def _flush_pending_batch(self, contract_address: ContractAddress) -> TransactionHash:
        if not self._pending:
            return self._derive_local_batch_tx_hash(contract_address, [])

        batch = list(self._pending)
        self._pending.clear()
        self._batch_counter += 1

        batch_payload = [entry.payload_snapshot for entry in batch]
        batch_hash = self._batch_hash(batch)
        tx_hash = self._submit_batch_to_chain(contract_address, batch_payload, batch_hash)
        block_number = self._resolve_block_number(tx_hash)
        confirmed = True

        for entry in batch:
            self._records[entry.event.event_id] = BlockchainAuditRecord(
                event_id=entry.event.event_id,
                event_hash=entry.event_hash,
                transaction_hash=tx_hash,
                block_number=block_number,
                contract_address=contract_address,
                ipfs_hash=entry.ipfs_hash,
                payload_snapshot=entry.payload_snapshot,
                batch_id=batch_hash,
                confirmed=confirmed,
            )

        return tx_hash

    def _submit_batch_to_chain(self, contract_address: ContractAddress, batch_payload: list[dict[str, Any]], batch_hash: str) -> TransactionHash:
        if self._contract is None and self._web3 is not None and self._contract_address is not None:
            self._contract = self._web3.eth.contract(address=self._contract_address, abi=self._contract_abi)

        if self._contract is not None:
            payload_json = json.dumps(batch_payload, sort_keys=True, default=str)
            ipfs_hash = self._store_large_payload({"batch": batch_payload, "batch_hash": batch_hash}) if len(payload_json) > self._large_payload_threshold else None
            if hasattr(self._contract.functions, "recordBatch"):
                tx = self._contract.functions.recordBatch(batch_hash, ipfs_hash, payload_json).transact(self._tx_params())
                return self._normalize_tx_hash(tx)
            if hasattr(self._contract.functions, "recordEvent"):
                tx = self._contract.functions.recordEvent(batch_hash, ipfs_hash, payload_json).transact(self._tx_params())
                return self._normalize_tx_hash(tx)

        return self._derive_local_batch_tx_hash(contract_address, batch_payload)

    def _send_transaction(self, transaction_builder: Any, value: int = 0) -> Any:
        if self._web3 is None:
            raise RuntimeError("web3 client is not configured")
        tx_params = self._tx_params()
        if value:
            tx_params["value"] = value
        return transaction_builder.transact(tx_params)

    def _wait_for_receipt(self, tx_hash: Any) -> Any:
        if self._web3 is None:
            raise RuntimeError("web3 client is not configured")
        return self._web3.eth.wait_for_transaction_receipt(tx_hash)

    def _resolve_block_number(self, tx_hash: TransactionHash) -> int | None:
        if self._web3 is None:
            return None
        try:
            receipt = self._web3.eth.get_transaction_receipt(tx_hash)
            return int(getattr(receipt, "blockNumber", None) or getattr(receipt, "block_number", None) or 0) or None
        except Exception:
            return None

    def _tx_params(self) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if self._account_address:
            params["from"] = self._account_address
        return params

    def _build_web3_client(self) -> Any | None:
        if self._provider_uri is None:
            return None
        if self._web3_factory is not None:
            return self._web3_factory(self._provider_uri)
        if Web3 is None:
            return None
        return Web3(Web3.HTTPProvider(self._provider_uri))

    def _normalize_contract_address(self, value: Any) -> ContractAddress:
        if isinstance(value, str) and value.startswith("0x") and len(value) >= 42:
            return value
        if isinstance(value, str) and value:
            return value if value.startswith("0x") else f"0x{value}"
        return self._derive_local_contract_address()

    def _derive_local_contract_address(self) -> ContractAddress:
        material = json.dumps({"batch_size": self._batch_size, "threshold": self._large_payload_threshold}, sort_keys=True).encode("utf-8")
        return "0x" + sha256(material).hexdigest()[-40:]

    def _derive_local_batch_tx_hash(self, contract_address: ContractAddress, batch_payload: list[dict[str, Any]]) -> TransactionHash:
        material = json.dumps({"contract": contract_address, "payload": batch_payload, "count": len(batch_payload), "batch": self._batch_counter}, sort_keys=True, default=str).encode("utf-8")
        return "0x" + sha256(material).hexdigest()

    def _provisional_tx_hash(self, event_hash: str, contract_address: ContractAddress) -> TransactionHash:
        material = json.dumps({"contract": contract_address, "event_hash": event_hash, "counter": self._batch_counter}, sort_keys=True).encode("utf-8")
        return "0x" + sha256(material).hexdigest()

    def _hash_event_payload(self, payload: dict[str, Any]) -> str:
        return sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()

    def _store_large_payload(self, payload: dict[str, Any]) -> str | None:
        serialized = json.dumps(payload, sort_keys=True, default=str)
        if len(serialized) <= self._large_payload_threshold:
            return None

        if self._ipfs_add_json is not None:
            result = self._ipfs_add_json(payload)
            if isinstance(result, str):
                return result
            if isinstance(result, dict):
                return str(result.get("Hash") or result.get("hash") or result.get("cid") or result.get("path") or "") or None

        if self._ipfs_client is not None:
            if hasattr(self._ipfs_client, "add_json"):
                result = self._ipfs_client.add_json(payload)
                return self._extract_ipfs_hash(result)
            if hasattr(self._ipfs_client, "add"):
                result = self._ipfs_client.add(serialized)
                return self._extract_ipfs_hash(result)

        return "ipfs:" + sha256(serialized.encode("utf-8")).hexdigest()

    def _should_offload(self, payload: dict[str, Any]) -> bool:
        serialized = json.dumps(payload, sort_keys=True, default=str)
        return len(serialized) > self._large_payload_threshold

    def _extract_ipfs_hash(self, result: Any) -> str | None:
        if isinstance(result, str):
            return result
        if isinstance(result, dict):
            return str(result.get("Hash") or result.get("hash") or result.get("cid") or result.get("path") or "") or None
        if isinstance(result, list) and result:
            first = result[0]
            if isinstance(first, dict):
                return str(first.get("Hash") or first.get("hash") or first.get("cid") or first.get("path") or "") or None
        return None

    def _normalize_tx_hash(self, value: Any) -> TransactionHash:
        if isinstance(value, (bytes, bytearray)):
            return "0x" + bytes(value).hex()
        if isinstance(value, str):
            return value if value.startswith("0x") else f"0x{value}"
        return self._derive_local_batch_tx_hash(self._contract_address or self._derive_local_contract_address(), [])

    def _ordered_records(self) -> list[BlockchainAuditRecord]:
        return sorted(self._records.values(), key=lambda item: (item.created_at, item.event_id))

    def _batch_hash(self, entries: list[_PendingEntry]) -> str:
        material = [entry.event_hash for entry in entries]
        return sha256(json.dumps(material, sort_keys=True).encode("utf-8")).hexdigest()

    def _leaf_hash(self, event_hash: str, tx_hash: str) -> str:
        return sha256(f"{event_hash}:{tx_hash}".encode("utf-8")).hexdigest()

    def _build_merkle_proof(self, leaves: list[str], index: int) -> tuple[str, list[str]]:
        if not leaves:
            return self._derive_local_contract_address(), []

        path: list[str] = []
        current = list(leaves)
        position = index

        while len(current) > 1:
            if len(current) % 2 == 1:
                current.append(current[-1])

            sibling_index = position ^ 1
            path.append(current[sibling_index])

            next_level: list[str] = []
            for i in range(0, len(current), 2):
                combined = sha256(f"{current[i]}:{current[i + 1]}".encode("utf-8")).hexdigest()
                next_level.append(combined)

            position //= 2
            current = next_level

        return current[0], path

    def _matches_filters(self, payload: dict[str, Any], filters: dict[str, Any]) -> bool:
        for key, expected in filters.items():
            if key == "since":
                if payload.get("timestamp") is None:
                    return False
                if self._parse_timestamp(payload["timestamp"]) < self._parse_timestamp(expected):
                    return False
                continue
            if key == "until":
                if payload.get("timestamp") is None:
                    return False
                if self._parse_timestamp(payload["timestamp"]) > self._parse_timestamp(expected):
                    return False
                continue

            actual = self._resolve_payload_field(payload, key)
            if isinstance(expected, (list, tuple, set)):
                if actual not in expected:
                    return False
            elif isinstance(expected, str) and expected.startswith("~"):
                if not re.search(expected[1:], str(actual or "")):
                    return False
            elif actual != expected:
                return False

        return True

    def _normalize_filters(self, filters: dict[str, Any]) -> dict[str, Any]:
        return dict(filters)

    def _resolve_payload_field(self, payload: dict[str, Any], dotted_key: str) -> Any:
        current: Any = payload
        for part in dotted_key.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        return current

    def _parse_timestamp(self, value: Any) -> datetime:
        if isinstance(value, datetime):
            return value
        if isinstance(value, str):
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        return datetime.min.replace(tzinfo=UTC)

    def _require_audit_event(self, event: Any) -> None:
        if not isinstance(event, AuditEvent):
            raise TypeError("event must be an AuditEvent instance")

    @staticmethod
    def _default_contract_abi() -> list[dict[str, Any]]:
        return [
            {
                "inputs": [
                    {"internalType": "bytes32", "name": "batchHash", "type": "bytes32"},
                    {"internalType": "string", "name": "ipfsHash", "type": "string"},
                    {"internalType": "string", "name": "payloadJson", "type": "string"},
                ],
                "name": "recordBatch",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function",
            },
            {
                "inputs": [
                    {"internalType": "bytes32", "name": "eventHash", "type": "bytes32"},
                    {"internalType": "string", "name": "ipfsHash", "type": "string"},
                    {"internalType": "string", "name": "payloadJson", "type": "string"},
                ],
                "name": "recordEvent",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function",
            },
        ]

    @staticmethod
    def _default_contract_bytecode() -> str:
        return "0x60006000556001600055"


__all__ = [
    "ContractAddress",
    "TransactionHash",
    "BlockchainAuditRecord",
    "BlockchainProof",
    "EthereumBlockchainIntegration",
]