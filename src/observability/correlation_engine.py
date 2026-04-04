"""Cross-system event correlation and causal-chain analysis.

This module provides a standalone event-analysis layer for linking related
events across systems with temporal and identifier-based correlation.
"""

from __future__ import annotations

import hashlib
import itertools
import math
from dataclasses import dataclass, field
from typing import Any

import networkx as nx


Graph = nx.DiGraph


@dataclass(frozen=True)
class Event:
    """Canonical event model for cross-system correlation."""

    event_id: str
    timestamp: float
    event_type: str = "unknown"
    source_system: str = "unknown"
    correlation_id: str | None = None
    trace_id: str | None = None
    user_id: str | None = None
    session_id: str | None = None
    parent_event_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.event_id, str) or not self.event_id.strip():
            raise ValueError("event_id must be a non-empty string")
        if not isinstance(self.timestamp, (int, float)):
            raise TypeError("timestamp must be numeric")

        object.__setattr__(self, "event_id", self.event_id.strip())
        object.__setattr__(self, "event_type", str(self.event_type).strip() or "unknown")
        object.__setattr__(self, "source_system", str(self.source_system).strip() or "unknown")
        object.__setattr__(self, "timestamp", float(self.timestamp))
        object.__setattr__(self, "correlation_id", _normalize_optional(self.correlation_id))
        object.__setattr__(self, "trace_id", _normalize_optional(self.trace_id))
        object.__setattr__(self, "user_id", _normalize_optional(self.user_id))
        object.__setattr__(self, "session_id", _normalize_optional(self.session_id))
        object.__setattr__(self, "parent_event_id", _normalize_optional(self.parent_event_id))

        if not isinstance(self.metadata, dict):
            raise TypeError("metadata must be a dictionary")
        object.__setattr__(self, "metadata", dict(self.metadata))


@dataclass(frozen=True)
class CorrelatedEventGroup:
    """A group of correlated events discovered by identifier + time."""

    group_id: str
    events: list[Event]
    correlation_keys: dict[str, list[str]]
    start_time: float
    end_time: float
    relationship_count: int


@dataclass(frozen=True)
class EventChain:
    """Directed causal chain inferred from correlated events."""

    chain_id: str
    event_ids: list[str]
    events: list[Event]
    confidence: float
    duration_seconds: float
    relationship_count: int


class CorrelationEngine:
    """Correlation engine for grouping, chaining, and visualizing events."""

    def __init__(
        self,
        *,
        temporal_window_seconds: float = 300.0,
        min_causal_score: float = 0.45,
    ) -> None:
        if temporal_window_seconds <= 0:
            raise ValueError("temporal_window_seconds must be > 0")
        if not 0.0 <= min_causal_score <= 1.0:
            raise ValueError("min_causal_score must be in [0, 1]")

        self._temporal_window_seconds = float(temporal_window_seconds)
        self._min_causal_score = float(min_causal_score)

    def correlate_events(self, events: list[Event]) -> list[CorrelatedEventGroup]:
        """Group related events by identifiers and temporal locality."""
        normalized = self._normalize_events(events)
        if not normalized:
            return []

        graph = self._build_correlation_graph(normalized)

        groups: list[CorrelatedEventGroup] = []
        for component in nx.connected_components(graph):
            component_ids = sorted(component)
            component_events = [graph.nodes[event_id]["event"] for event_id in component_ids]
            component_events.sort(key=lambda e: (e.timestamp, e.event_id))

            start_time = component_events[0].timestamp
            end_time = component_events[-1].timestamp
            relationships = graph.subgraph(component_ids).number_of_edges()

            groups.append(
                CorrelatedEventGroup(
                    group_id=self._group_id(component_events),
                    events=component_events,
                    correlation_keys=self._collect_correlation_keys(component_events),
                    start_time=start_time,
                    end_time=end_time,
                    relationship_count=int(relationships),
                )
            )

        groups.sort(key=lambda item: (item.start_time, item.group_id))
        return groups

    def detect_event_chains(self, events: list[Event]) -> list[EventChain]:
        """Detect causal chains where A likely caused B likely caused C."""
        normalized = self._normalize_events(events)
        if len(normalized) < 2:
            return []

        graph = self._build_causal_graph(normalized)
        chains: list[EventChain] = []

        for component in nx.weakly_connected_components(graph):
            subgraph = graph.subgraph(component).copy()
            if subgraph.number_of_nodes() < 2:
                continue

            if not nx.is_directed_acyclic_graph(subgraph):
                subgraph = self._to_acyclic_by_time(subgraph)
                if subgraph.number_of_nodes() < 2:
                    continue

            longest = nx.algorithms.dag_longest_path(subgraph, weight="weight")
            if len(longest) < 2:
                continue

            chain_events = [subgraph.nodes[event_id]["event"] for event_id in longest]
            chain_events.sort(key=lambda event: (event.timestamp, event.event_id))

            edge_weights: list[float] = []
            for left, right in zip(longest, longest[1:]):
                payload = subgraph.get_edge_data(left, right, default={})
                edge_weights.append(float(payload.get("weight", 0.0)))

            confidence = float(sum(edge_weights) / len(edge_weights)) if edge_weights else 0.0
            duration = max(0.0, chain_events[-1].timestamp - chain_events[0].timestamp)

            chains.append(
                EventChain(
                    chain_id=self._chain_id(chain_events),
                    event_ids=[item.event_id for item in chain_events],
                    events=chain_events,
                    confidence=confidence,
                    duration_seconds=duration,
                    relationship_count=max(0, len(chain_events) - 1),
                )
            )

        chains.sort(key=lambda item: (item.events[0].timestamp, -item.confidence, item.chain_id))
        return chains

    def visualize_correlation(self, group: CorrelatedEventGroup) -> Graph:
        """Generate a graph visualization model for one correlated group."""
        if not isinstance(group, CorrelatedEventGroup):
            raise TypeError("group must be a CorrelatedEventGroup instance")

        graph: Graph = nx.DiGraph()
        for event in group.events:
            graph.add_node(
                event.event_id,
                label=event.event_type,
                source_system=event.source_system,
                timestamp=event.timestamp,
                correlation_id=event.correlation_id,
                trace_id=event.trace_id,
                user_id=event.user_id,
                session_id=event.session_id,
            )

        for left, right in itertools.permutations(group.events, 2):
            if left.event_id == right.event_id:
                continue
            if right.timestamp < left.timestamp:
                continue

            reasons = self._shared_reasons(left, right)
            if right.parent_event_id == left.event_id:
                reasons.add("parent")

            if not reasons:
                continue

            if (right.timestamp - left.timestamp) > self._temporal_window_seconds:
                continue

            graph.add_edge(
                left.event_id,
                right.event_id,
                relation=sorted(reasons),
                delta_seconds=max(0.0, right.timestamp - left.timestamp),
            )

        if graph.number_of_nodes() > 0:
            positions = nx.spring_layout(graph, seed=13)
            for node, coords in positions.items():
                graph.nodes[node]["x"] = float(coords[0])
                graph.nodes[node]["y"] = float(coords[1])

        return graph

    def _build_correlation_graph(self, events: list[Event]) -> nx.Graph:
        graph = nx.Graph()
        by_id: dict[str, Event] = {}

        for event in events:
            if event.event_id in by_id:
                raise ValueError(f"duplicate event_id detected: {event.event_id}")
            by_id[event.event_id] = event
            graph.add_node(event.event_id, event=event)

        # Explicit parent linkage is always a strong correlation signal.
        for event in events:
            if event.parent_event_id and event.parent_event_id in by_id:
                self._add_undirected_edge(graph, event.parent_event_id, event.event_id, "parent")

        for key in ("correlation_id", "trace_id", "user_id", "session_id"):
            buckets = self._bucket_by_key(events, key)
            for bucket in buckets.values():
                bucket.sort(key=lambda item: (item.timestamp, item.event_id))
                for idx, left in enumerate(bucket):
                    for right in bucket[idx + 1 :]:
                        delta = abs(right.timestamp - left.timestamp)
                        if delta > self._temporal_window_seconds:
                            break
                        self._add_undirected_edge(graph, left.event_id, right.event_id, key)

        return graph

    def _build_causal_graph(self, events: list[Event]) -> nx.DiGraph:
        graph = nx.DiGraph()
        by_id: dict[str, Event] = {}

        for event in events:
            if event.event_id in by_id:
                raise ValueError(f"duplicate event_id detected: {event.event_id}")
            by_id[event.event_id] = event
            graph.add_node(event.event_id, event=event)

        ordered = sorted(events, key=lambda item: (item.timestamp, item.event_id))

        for event in ordered:
            if event.parent_event_id and event.parent_event_id in by_id:
                parent = by_id[event.parent_event_id]
                if parent.event_id != event.event_id:
                    if (parent.timestamp < event.timestamp) or (
                        math.isclose(parent.timestamp, event.timestamp) and parent.event_id < event.event_id
                    ):
                        graph.add_edge(
                            parent.event_id,
                            event.event_id,
                            weight=1.0,
                            relation="explicit_parent",
                        )

        for idx, left in enumerate(ordered):
            for right in ordered[idx + 1 :]:
                delta = right.timestamp - left.timestamp
                if delta < 0:
                    continue
                if delta > self._temporal_window_seconds:
                    break

                score = self._causal_score(left, right, delta)
                if score < self._min_causal_score:
                    continue

                # Keep strongest edge when both explicit and inferred exist.
                existing = graph.get_edge_data(left.event_id, right.event_id)
                if existing is None or float(existing.get("weight", 0.0)) < score:
                    graph.add_edge(
                        left.event_id,
                        right.event_id,
                        weight=score,
                        relation="inferred_temporal",
                    )

        return graph

    def _causal_score(self, left: Event, right: Event, delta_seconds: float) -> float:
        shared = self._shared_reasons(left, right)
        if not shared:
            return 0.0

        identifier_strength = min(1.0, len(shared) / 4.0)
        proximity = max(0.0, 1.0 - (delta_seconds / self._temporal_window_seconds))

        base = 0.55 * identifier_strength + 0.45 * proximity

        if right.parent_event_id == left.event_id:
            base = min(1.0, base + 0.25)

        return float(base)

    @staticmethod
    def _to_acyclic_by_time(graph: nx.DiGraph) -> nx.DiGraph:
        reduced = nx.DiGraph()
        for node, attrs in graph.nodes(data=True):
            reduced.add_node(node, **attrs)

        for left, right, attrs in graph.edges(data=True):
            left_event = graph.nodes[left].get("event")
            right_event = graph.nodes[right].get("event")
            if left_event is None or right_event is None:
                continue

            if right_event.timestamp > left_event.timestamp:
                reduced.add_edge(left, right, **attrs)
            elif math.isclose(right_event.timestamp, left_event.timestamp) and left < right:
                reduced.add_edge(left, right, **attrs)

        return reduced

    @staticmethod
    def _bucket_by_key(events: list[Event], key: str) -> dict[str, list[Event]]:
        buckets: dict[str, list[Event]] = {}
        for event in events:
            value = getattr(event, key)
            if not value:
                continue
            buckets.setdefault(value, []).append(event)
        return buckets

    @staticmethod
    def _add_undirected_edge(graph: nx.Graph, left: str, right: str, reason: str) -> None:
        if left == right:
            return
        if graph.has_edge(left, right):
            payload = graph[left][right]
            reasons = set(payload.get("reasons", []))
            reasons.add(reason)
            payload["reasons"] = sorted(reasons)
            payload["weight"] = float(len(reasons))
            return

        graph.add_edge(left, right, reasons=[reason], weight=1.0)

    @staticmethod
    def _shared_reasons(left: Event, right: Event) -> set[str]:
        reasons: set[str] = set()
        if left.correlation_id and left.correlation_id == right.correlation_id:
            reasons.add("correlation_id")
        if left.trace_id and left.trace_id == right.trace_id:
            reasons.add("trace_id")
        if left.user_id and left.user_id == right.user_id:
            reasons.add("user_id")
        if left.session_id and left.session_id == right.session_id:
            reasons.add("session_id")
        return reasons

    @staticmethod
    def _collect_correlation_keys(events: list[Event]) -> dict[str, list[str]]:
        keys: dict[str, set[str]] = {
            "correlation_id": set(),
            "trace_id": set(),
            "user_id": set(),
            "session_id": set(),
        }

        for event in events:
            if event.correlation_id:
                keys["correlation_id"].add(event.correlation_id)
            if event.trace_id:
                keys["trace_id"].add(event.trace_id)
            if event.user_id:
                keys["user_id"].add(event.user_id)
            if event.session_id:
                keys["session_id"].add(event.session_id)

        return {
            key: sorted(values)
            for key, values in keys.items()
            if values
        }

    @staticmethod
    def _group_id(events: list[Event]) -> str:
        basis = "|".join(item.event_id for item in events)
        digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]
        return f"group-{digest}"

    @staticmethod
    def _chain_id(events: list[Event]) -> str:
        basis = "|".join(item.event_id for item in events)
        digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]
        return f"chain-{digest}"

    @staticmethod
    def _normalize_events(events: list[Event]) -> list[Event]:
        if not isinstance(events, list):
            raise TypeError("events must be a list")
        for item in events:
            if not isinstance(item, Event):
                raise TypeError("events must contain Event instances")
        return list(events)


def _normalize_optional(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        value = str(value)
    normalized = value.strip()
    return normalized if normalized else None


__all__ = [
    "Graph",
    "Event",
    "CorrelatedEventGroup",
    "EventChain",
    "CorrelationEngine",
]
