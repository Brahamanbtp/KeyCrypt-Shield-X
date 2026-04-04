"""Multi-node orchestration state synchronization with Paxos-lite consensus.

This module preserves the distributed coordination layer by providing a
standalone synchronizer that can merge state across nodes, broadcast updates,
and resolve conflicts with a deterministic default strategy.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
import uuid
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, List, Protocol


@dataclass(frozen=True)
class StateChange:
    """Represents a state delta emitted by a node."""

    key: str
    value: dict[str, Any]
    node_id: str
    timestamp: float = field(default_factory=time.time)
    version: int = 1
    change_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    metadata: dict[str, Any] = field(default_factory=dict)


class SynchronizerPeer(Protocol):
    """Peer RPC contract consumed by StateSynchronizer.

    Implementations are expected to be lightweight wrappers around transport
    adapters (HTTP/gRPC/message bus).
    """

    peer_id: str

    async def prepare(self, proposal_id: int, round_id: str, state_digest: str) -> bool:
        """Promise to consider a proposal round."""

    async def accept(self, proposal_id: int, round_id: str, proposed_state: dict[str, Any]) -> bool:
        """Accept a prepared proposal round."""

    async def notify_state_change(self, change: StateChange) -> None:
        """Apply or queue remote state-change notification."""


class StateSynchronizer:
    """Coordinates state synchronization for multi-node orchestration.

    Consensus mode:
        Paxos-lite two-phase quorum (prepare + accept) with local-node vote.

    Partition tolerance:
        When quorum is not reachable, the synchronizer can operate in degraded
        mode and queue outbound changes for later replay.
    """

    def __init__(
        self,
        *,
        node_id: str,
        peers: Mapping[str, SynchronizerPeer] | None = None,
        merge_strategy: str | Callable[[List[dict[str, Any]]], dict[str, Any]] = "lww",
        rpc_timeout_seconds: float = 0.75,
        partition_tolerance: bool = True,
        max_pending_changes: int = 1024,
    ) -> None:
        if not isinstance(node_id, str) or not node_id.strip():
            raise ValueError("node_id must be a non-empty string")
        if rpc_timeout_seconds <= 0:
            raise ValueError("rpc_timeout_seconds must be > 0")
        if max_pending_changes <= 0:
            raise ValueError("max_pending_changes must be > 0")

        self._node_id = node_id.strip()
        self._peers: dict[str, SynchronizerPeer] = dict(peers or {})
        self._rpc_timeout_seconds = float(rpc_timeout_seconds)
        self._partition_tolerance = bool(partition_tolerance)
        self._pending_changes: deque[StateChange] = deque(maxlen=int(max_pending_changes))

        self._proposal_counter = 0
        self._proposal_lock = asyncio.Lock()

        self._in_partition_mode = False
        self._last_partition_detected_at: float | None = None

        self._custom_merge_strategy: Callable[[List[dict[str, Any]]], dict[str, Any]] | None = None
        self._merge_strategy = "lww"
        self._configure_merge_strategy(merge_strategy)

    async def sync_state(self, local_state: dict[str, Any], remote_states: List[dict[str, Any]]) -> dict[str, Any]:
        """Merge local + remote node states and commit using Paxos-lite quorum."""
        self._validate_state_dict(local_state, "local_state")
        if not isinstance(remote_states, list):
            raise TypeError("remote_states must be a list of dictionaries")

        normalized_remote: list[dict[str, Any]] = []
        for index, item in enumerate(remote_states):
            self._validate_state_dict(item, f"remote_states[{index}]")
            normalized_remote.append(dict(item))

        merged_state = await self.resolve_conflict([dict(local_state), *normalized_remote])
        committed_state = await self._commit_with_consensus(merged_state)

        if not self._in_partition_mode:
            await self._flush_pending_broadcasts()

        return committed_state

    async def broadcast_state_change(self, change: StateChange) -> None:
        """Broadcast state changes to peers with partition-tolerant behavior."""
        if not isinstance(change, StateChange):
            raise TypeError("change must be a StateChange instance")

        if not self._peers:
            return

        acknowledgements = 1 + await self._broadcast_to_peers(change)
        if acknowledgements >= self._quorum_size():
            self._exit_partition_mode()
            return

        self._enter_partition_mode()
        if self._partition_tolerance:
            self._pending_changes.append(change)
            return

        raise RuntimeError("broadcast failed: quorum unavailable and partition_tolerance=False")

    async def resolve_conflict(self, states: List[dict[str, Any]]) -> dict[str, Any]:
        """Resolve conflicting node state using LWW or custom merge strategy."""
        if not isinstance(states, list):
            raise TypeError("states must be a list of dictionaries")
        if not states:
            return {}

        normalized: list[dict[str, Any]] = []
        for index, item in enumerate(states):
            self._validate_state_dict(item, f"states[{index}]")
            normalized.append(dict(item))

        if self._custom_merge_strategy is not None:
            merged = self._custom_merge_strategy(normalized)
            self._validate_state_dict(merged, "custom merge strategy result")
            return dict(merged)

        if self._merge_strategy == "deep_merge":
            return self._merge_deep(normalized)

        return self._merge_last_write_wins(normalized)

    def register_peer(self, peer: SynchronizerPeer) -> None:
        """Register a peer for consensus and broadcast operations."""
        peer_id = self._peer_id(peer)
        self._peers[peer_id] = peer

    def remove_peer(self, peer_id: str) -> None:
        """Remove a peer from synchronization participation."""
        if not isinstance(peer_id, str) or not peer_id.strip():
            raise ValueError("peer_id must be a non-empty string")
        self._peers.pop(peer_id.strip(), None)

    def is_partitioned(self) -> bool:
        """Return whether the synchronizer is currently in partition mode."""
        return self._in_partition_mode

    def pending_change_count(self) -> int:
        """Return number of deferred broadcast changes."""
        return len(self._pending_changes)

    def _configure_merge_strategy(
        self,
        merge_strategy: str | Callable[[List[dict[str, Any]]], dict[str, Any]],
    ) -> None:
        if callable(merge_strategy):
            self._custom_merge_strategy = merge_strategy
            self._merge_strategy = "custom"
            return

        if not isinstance(merge_strategy, str):
            raise TypeError("merge_strategy must be 'lww', 'deep_merge', or a callable")

        normalized = merge_strategy.strip().lower()
        if normalized not in {"lww", "deep_merge"}:
            raise ValueError("merge_strategy must be 'lww' or 'deep_merge' when provided as string")

        self._custom_merge_strategy = None
        self._merge_strategy = normalized

    async def _commit_with_consensus(self, state: dict[str, Any]) -> dict[str, Any]:
        if not self._peers:
            return self._mark_sync_metadata(state=state, quorum_achieved=True, degraded=False)

        proposal_id = await self._next_proposal_id()
        round_id = f"{self._node_id}:{proposal_id}"
        state_digest = self._stable_digest(state)

        prepare_acks = 1 + await self._prepare_phase(
            proposal_id=proposal_id,
            round_id=round_id,
            state_digest=state_digest,
        )
        if prepare_acks < self._quorum_size():
            return self._handle_partitioned_commit(state=state, reason="prepare_quorum_unavailable")

        accept_acks = 1 + await self._accept_phase(
            proposal_id=proposal_id,
            round_id=round_id,
            state=state,
        )
        if accept_acks < self._quorum_size():
            return self._handle_partitioned_commit(state=state, reason="accept_quorum_unavailable")

        self._exit_partition_mode()
        return self._mark_sync_metadata(
            state=state,
            quorum_achieved=True,
            degraded=False,
            proposal_id=proposal_id,
            round_id=round_id,
        )

    def _handle_partitioned_commit(self, *, state: dict[str, Any], reason: str) -> dict[str, Any]:
        self._enter_partition_mode()
        if not self._partition_tolerance:
            raise RuntimeError(f"consensus failure: {reason}")

        return self._mark_sync_metadata(
            state=state,
            quorum_achieved=False,
            degraded=True,
            partition_reason=reason,
        )

    async def _prepare_phase(self, *, proposal_id: int, round_id: str, state_digest: str) -> int:
        tasks = [
            asyncio.create_task(self._peer_prepare(peer, proposal_id, round_id, state_digest))
            for peer in self._peers.values()
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return sum(1 for item in results if item is True)

    async def _accept_phase(self, *, proposal_id: int, round_id: str, state: dict[str, Any]) -> int:
        tasks = [
            asyncio.create_task(self._peer_accept(peer, proposal_id, round_id, state))
            for peer in self._peers.values()
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return sum(1 for item in results if item is True)

    async def _peer_prepare(
        self,
        peer: SynchronizerPeer,
        proposal_id: int,
        round_id: str,
        state_digest: str,
    ) -> bool:
        handler = getattr(peer, "prepare", None)
        if not callable(handler):
            return False

        try:
            accepted = await asyncio.wait_for(
                handler(proposal_id, round_id, state_digest),
                timeout=self._rpc_timeout_seconds,
            )
            return bool(accepted)
        except Exception:
            return False

    async def _peer_accept(
        self,
        peer: SynchronizerPeer,
        proposal_id: int,
        round_id: str,
        state: dict[str, Any],
    ) -> bool:
        handler = getattr(peer, "accept", None)
        if not callable(handler):
            return False

        try:
            accepted = await asyncio.wait_for(
                handler(proposal_id, round_id, dict(state)),
                timeout=self._rpc_timeout_seconds,
            )
            return bool(accepted)
        except Exception:
            return False

    async def _broadcast_to_peers(self, change: StateChange) -> int:
        tasks = [asyncio.create_task(self._notify_peer(peer, change)) for peer in self._peers.values()]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return sum(1 for item in results if item is True)

    async def _notify_peer(self, peer: SynchronizerPeer, change: StateChange) -> bool:
        handler = getattr(peer, "notify_state_change", None)
        if not callable(handler):
            return False

        try:
            await asyncio.wait_for(handler(change), timeout=self._rpc_timeout_seconds)
            return True
        except Exception:
            return False

    async def _flush_pending_broadcasts(self) -> None:
        if not self._pending_changes:
            return

        snapshot = list(self._pending_changes)
        self._pending_changes.clear()

        for change in snapshot:
            try:
                await self.broadcast_state_change(change)
            except Exception:
                self._pending_changes.append(change)

    async def _next_proposal_id(self) -> int:
        async with self._proposal_lock:
            self._proposal_counter += 1
            return self._proposal_counter

    def _merge_last_write_wins(self, states: List[dict[str, Any]]) -> dict[str, Any]:
        merged: dict[str, Any] = {}
        field_timestamps: dict[str, float] = {}

        for state in states:
            state_timestamp = self._state_timestamp(state)
            explicit_field_ts = state.get("_field_timestamps", {})
            if not isinstance(explicit_field_ts, dict):
                explicit_field_ts = {}

            for key, value in state.items():
                if key == "_field_timestamps":
                    continue

                candidate_ts = self._coerce_float(explicit_field_ts.get(key), default=state_timestamp)
                current_ts = field_timestamps.get(key, float("-inf"))

                if candidate_ts >= current_ts:
                    merged[key] = self._safe_copy(value)
                    field_timestamps[key] = candidate_ts

        merged["_field_timestamps"] = {k: float(v) for k, v in field_timestamps.items()}
        merged["_updated_at"] = max(field_timestamps.values()) if field_timestamps else time.time()
        return merged

    def _merge_deep(self, states: List[dict[str, Any]]) -> dict[str, Any]:
        ordered = sorted(states, key=self._state_timestamp)
        merged: dict[str, Any] = {}

        for state in ordered:
            merged = self._deep_merge_values(merged, state)

        merged["_updated_at"] = self._state_timestamp(merged)
        return merged

    def _deep_merge_values(self, base: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
        output: dict[str, Any] = dict(base)

        for key, value in incoming.items():
            if key not in output:
                output[key] = self._safe_copy(value)
                continue

            existing = output[key]
            if isinstance(existing, dict) and isinstance(value, dict):
                output[key] = self._deep_merge_values(existing, value)
            else:
                output[key] = self._safe_copy(value)

        return output

    def _mark_sync_metadata(
        self,
        *,
        state: dict[str, Any],
        quorum_achieved: bool,
        degraded: bool,
        proposal_id: int | None = None,
        round_id: str | None = None,
        partition_reason: str | None = None,
    ) -> dict[str, Any]:
        result = dict(state)
        metadata = result.get("_sync_meta", {})
        if not isinstance(metadata, dict):
            metadata = {}

        metadata.update(
            {
                "node_id": self._node_id,
                "quorum_achieved": bool(quorum_achieved),
                "degraded_consensus": bool(degraded),
                "partition_mode": bool(self._in_partition_mode),
                "peer_count": len(self._peers),
                "updated_at": time.time(),
            }
        )

        if proposal_id is not None:
            metadata["proposal_id"] = int(proposal_id)
        if round_id is not None:
            metadata["round_id"] = round_id
        if partition_reason:
            metadata["partition_reason"] = partition_reason
            metadata["partition_detected_at"] = self._last_partition_detected_at

        result["_sync_meta"] = metadata
        result.setdefault("_updated_at", time.time())
        return result

    def _enter_partition_mode(self) -> None:
        self._in_partition_mode = True
        self._last_partition_detected_at = time.time()

    def _exit_partition_mode(self) -> None:
        self._in_partition_mode = False

    def _quorum_size(self) -> int:
        total_nodes = 1 + len(self._peers)
        return (total_nodes // 2) + 1

    @staticmethod
    def _validate_state_dict(value: dict[str, Any], name: str) -> None:
        if not isinstance(value, dict):
            raise TypeError(f"{name} must be a dictionary")

    @staticmethod
    def _peer_id(peer: SynchronizerPeer) -> str:
        peer_id = getattr(peer, "peer_id", None)
        if not isinstance(peer_id, str) or not peer_id.strip():
            raise ValueError("peer must define non-empty string attribute peer_id")
        return peer_id.strip()

    @staticmethod
    def _state_timestamp(state: Mapping[str, Any]) -> float:
        for key in ("_updated_at", "updated_at", "timestamp", "last_modified"):
            if key in state:
                return StateSynchronizer._coerce_float(state.get(key), default=0.0)
        return 0.0

    @staticmethod
    def _coerce_float(value: Any, *, default: float) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return float(default)

    @staticmethod
    def _safe_copy(value: Any) -> Any:
        if isinstance(value, (dict, list)):
            return json.loads(json.dumps(value, sort_keys=True, default=repr))
        return value

    @staticmethod
    def _stable_digest(state: Mapping[str, Any]) -> str:
        serialized = json.dumps(
            state,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            default=repr,
        )
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


__all__ = ["StateChange", "SynchronizerPeer", "StateSynchronizer"]
