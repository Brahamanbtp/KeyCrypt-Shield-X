"""Integrated Information Theory (IIT) utilities for consciousness estimation."""

from __future__ import annotations

from itertools import combinations
from math import log2
from threading import RLock
from typing import Any, Iterable

import networkx as nx

from src.utils.logging import get_logger


logger = get_logger("src.consciousness.integrated_info")


Partition = tuple[frozenset[str], frozenset[str]]


class IntegratedInformationCalculator:
    """Estimate integrated information (Phi) on a networked system state."""

    def __init__(self, graph: nx.Graph | nx.DiGraph | None = None) -> None:
        self.graph: nx.DiGraph = nx.DiGraph()
        if graph is not None:
            self.graph = graph if isinstance(graph, nx.DiGraph) else nx.DiGraph(graph)

        self._state_cache: dict[tuple[tuple[str, float], Partition], float] = {}
        self._partition_cache: dict[tuple[str, ...], list[Partition]] = {}
        self._lock = RLock()

    def compute_phi(
        self,
        system_state: dict[str, Any],
        partition: tuple[Iterable[str], Iterable[str]],
    ) -> float:
        """Compute effective information Phi for a specified partition."""
        normalized = self._normalize_state(system_state)
        part_a, part_b = self._normalize_partition(partition)

        if not part_a or not part_b:
            raise ValueError("partition must contain two non-empty subsets")

        if part_a & part_b:
            raise ValueError("partition subsets must be disjoint")

        if part_a | part_b != frozenset(normalized.keys()):
            raise ValueError("partition must cover all nodes in system_state exactly once")

        state_key = self._state_key(normalized)
        partition_key: Partition = (part_a, part_b)

        with self._lock:
            cached = self._state_cache.get((state_key, partition_key))
            if cached is not None:
                return cached

        cause_effect = self._cause_effect_structure(normalized)
        cross_influence = self._cross_partition_influence(normalized, part_a, part_b)

        local_entropy_a = self._partition_entropy(part_a, cause_effect)
        local_entropy_b = self._partition_entropy(part_b, cause_effect)

        # Effective information rises with boundary influence and internal uncertainty.
        entropy_gain = (local_entropy_a + local_entropy_b) / 2.0
        phi = max(0.0, cross_influence * (1.0 + entropy_gain))

        with self._lock:
            self._state_cache[(state_key, partition_key)] = phi

        logger.debug(
            "phi computed nodes={nodes} partition_sizes=({size_a},{size_b}) phi={phi}",
            nodes=len(normalized),
            size_a=len(part_a),
            size_b=len(part_b),
            phi=phi,
        )
        return phi

    def find_minimum_information_partition(self, system_state: dict[str, Any]) -> dict[str, Any]:
        """Find the minimum information partition (MIP) via exponential search."""
        normalized = self._normalize_state(system_state)
        nodes = tuple(sorted(normalized.keys()))
        if len(nodes) < 2:
            raise ValueError("system_state must contain at least 2 nodes")

        partitions = self._all_bipartitions(nodes)

        best_partition: Partition | None = None
        best_phi: float | None = None
        best_normalized_phi: float | None = None

        for partition in partitions:
            phi = self.compute_phi(normalized, partition)
            size_penalty = min(len(partition[0]), len(partition[1]))
            normalized_phi = phi / max(size_penalty, 1)

            if best_normalized_phi is None or normalized_phi < best_normalized_phi:
                best_partition = partition
                best_phi = phi
                best_normalized_phi = normalized_phi

        assert best_partition is not None
        assert best_phi is not None

        conscious = self.is_conscious(best_phi)
        result = {
            "mip": (sorted(best_partition[0]), sorted(best_partition[1])),
            "phi_value": best_phi,
            "normalized_phi": best_normalized_phi,
            "is_conscious": conscious,
        }

        logger.info(
            "mip identified nodes={nodes} phi={phi} conscious={conscious}",
            nodes=len(nodes),
            phi=best_phi,
            conscious=conscious,
        )
        return result

    def is_conscious(self, phi_value: float, threshold: float = 3.14) -> bool:
        """Determine whether Phi exceeds the consciousness threshold."""
        return float(phi_value) >= float(threshold)

    def _normalize_state(self, system_state: dict[str, Any]) -> dict[str, float]:
        if not isinstance(system_state, dict) or not system_state:
            raise ValueError("system_state must be a non-empty dict")

        normalized: dict[str, float] = {}
        for node, raw_value in system_state.items():
            node_id = str(node)

            if isinstance(raw_value, dict):
                candidate = raw_value.get("activation", raw_value.get("probability", raw_value.get("state", 0.0)))
            else:
                candidate = raw_value

            try:
                value = float(candidate)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"invalid state value for node {node_id}") from exc

            # Clamp to [0, 1] to model activation probability.
            normalized[node_id] = min(1.0, max(0.0, value))

        for node in normalized:
            if node not in self.graph:
                self.graph.add_node(node)

        return normalized

    def _normalize_partition(
        self,
        partition: tuple[Iterable[str], Iterable[str]],
    ) -> Partition:
        if not isinstance(partition, tuple) or len(partition) != 2:
            raise ValueError("partition must be a 2-tuple of iterables")

        part_a = frozenset(str(node) for node in partition[0])
        part_b = frozenset(str(node) for node in partition[1])
        return part_a, part_b

    def _state_key(self, normalized_state: dict[str, float]) -> tuple[tuple[str, float], ...]:
        return tuple((node, round(value, 6)) for node, value in sorted(normalized_state.items()))

    def _all_bipartitions(self, nodes: tuple[str, ...]) -> list[Partition]:
        with self._lock:
            cached = self._partition_cache.get(nodes)
            if cached is not None:
                return cached

        partitions: list[Partition] = []
        node_set = frozenset(nodes)
        total_nodes = len(nodes)

        # Enumerate half the search space to avoid mirrored duplicate partitions.
        for size in range(1, (total_nodes // 2) + 1):
            for subset in combinations(nodes, size):
                part_a = frozenset(subset)
                part_b = node_set - part_a

                if size == total_nodes - size and min(part_a) > min(part_b):
                    continue

                partitions.append((part_a, part_b))

        with self._lock:
            self._partition_cache[nodes] = partitions

        logger.debug("generated partitions nodes={nodes} count={count}", nodes=total_nodes, count=len(partitions))
        return partitions

    def _cause_effect_structure(self, normalized_state: dict[str, float]) -> dict[str, dict[str, float]]:
        structure: dict[str, dict[str, float]] = {}

        for node in normalized_state:
            incoming = 0.0
            outgoing = 0.0

            if node in self.graph:
                for source, _, edge_data in self.graph.in_edges(node, data=True):
                    weight = float(edge_data.get("weight", 1.0))
                    incoming += weight * abs(normalized_state.get(str(source), 0.0) - normalized_state[node])

                for _, target, edge_data in self.graph.out_edges(node, data=True):
                    weight = float(edge_data.get("weight", 1.0))
                    outgoing += weight * abs(normalized_state[node] - normalized_state.get(str(target), 0.0))

            structure[node] = {
                "incoming_influence": incoming,
                "outgoing_influence": outgoing,
                "local_entropy": self._binary_entropy(normalized_state[node]),
            }

        return structure

    def _cross_partition_influence(
        self,
        normalized_state: dict[str, float],
        part_a: frozenset[str],
        part_b: frozenset[str],
    ) -> float:
        cross = 0.0

        for source, target, edge_data in self.graph.edges(data=True):
            source_id = str(source)
            target_id = str(target)

            if source_id not in normalized_state or target_id not in normalized_state:
                continue

            crosses_cut = (source_id in part_a and target_id in part_b) or (
                source_id in part_b and target_id in part_a
            )
            if not crosses_cut:
                continue

            weight = float(edge_data.get("weight", 1.0))
            cross += weight * abs(normalized_state[source_id] - normalized_state[target_id])

        return cross

    def _partition_entropy(
        self,
        partition: frozenset[str],
        cause_effect_structure: dict[str, dict[str, float]],
    ) -> float:
        if not partition:
            return 0.0

        entropy_sum = sum(cause_effect_structure[node]["local_entropy"] for node in partition)
        return entropy_sum / len(partition)

    def _binary_entropy(self, probability: float) -> float:
        p = min(1.0, max(0.0, float(probability)))
        if p in {0.0, 1.0}:
            return 0.0
        return -(p * log2(p) + (1.0 - p) * log2(1.0 - p))


__all__ = ["IntegratedInformationCalculator"]
