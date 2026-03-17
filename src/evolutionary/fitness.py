"""Comprehensive fitness scoring for cryptographic protocol evolution.

Fitness model:
    fitness = (security_score * efficiency_score) / (cost * attack_surface)

The raw ratio is further normalized to [0, 1] with:
    normalized = raw / (1 + raw)

This module is designed to plug into the evolutionary engine as a test suite
callable and emit detailed logs for each component.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.evolutionary.protocol_organism import CryptoProtocolOrganism
from src.utils.logging import get_logger


logger = get_logger("src.evolutionary.fitness")


@dataclass(frozen=True)
class PerformanceBenchmark:
    """Runtime benchmark metrics for protocol performance."""

    throughput_mbps: float
    latency_ms: float


@dataclass(frozen=True)
class ResourceCost:
    """Resource consumption profile for protocol execution."""

    cpu_percent: float
    memory_mb: float
    energy_watts: float


@dataclass(frozen=True)
class FitnessBreakdown:
    """Detailed breakdown of intermediate and final fitness values."""

    security_score: float
    efficiency_score: float
    cost: float
    attack_surface: float
    raw_fitness: float
    normalized_fitness: float


class ProtocolFitnessEvaluator:
    """Evaluator implementing a normalized multi-factor protocol fitness score."""

    _ALGORITHM_STRENGTH = {
        "AES-256-GCM": 0.90,
        "CHACHA20-POLY1305": 0.88,
        "XCHACHA20-POLY1305": 0.90,
        "KYBER-HYBRID": 0.98,
        "KYBER-AES-GCM": 0.96,
        "DILITHIUM-AES-GCM": 0.95,
    }

    def evaluate(
        self,
        organism: CryptoProtocolOrganism,
        *,
        benchmark: PerformanceBenchmark | None = None,
        resources: ResourceCost | None = None,
        attack_surface_points: int | None = None,
    ) -> FitnessBreakdown:
        """Evaluate protocol organism and return detailed score breakdown."""
        if not isinstance(organism, CryptoProtocolOrganism):
            raise TypeError("organism must be a CryptoProtocolOrganism")

        genome = organism.genome

        benchmark = benchmark or self._benchmark_from_genome(genome)
        resources = resources or self._resources_from_genome(genome)
        attack_surface_points = (
            int(attack_surface_points)
            if attack_surface_points is not None
            else int(genome.get("attack_surface_points", 5))
        )

        security_score = self._security_score(genome)
        efficiency_score = self._efficiency_score(benchmark)
        cost = self._cost(resources)
        attack_surface = self._attack_surface(attack_surface_points)

        raw = (security_score * efficiency_score) / max(cost * attack_surface, 1e-12)
        normalized = self._normalize_ratio(raw)

        breakdown = FitnessBreakdown(
            security_score=security_score,
            efficiency_score=efficiency_score,
            cost=cost,
            attack_surface=attack_surface,
            raw_fitness=raw,
            normalized_fitness=normalized,
        )

        logger.info(
            "fitness components | generation={generation} dna={dna} "
            "security={security:.4f} efficiency={efficiency:.4f} cost={cost:.4f} "
            "attack_surface={attack_surface:.4f} raw={raw:.6f} normalized={normalized:.6f}",
            generation=organism.generation,
            dna=organism.dna,
            security=security_score,
            efficiency=efficiency_score,
            cost=cost,
            attack_surface=attack_surface,
            raw=raw,
            normalized=normalized,
        )

        logger.debug(
            "fitness detail | genome={genome} benchmark={benchmark} resources={resources} "
            "attack_surface_points={asp}",
            genome=genome,
            benchmark={
                "throughput_mbps": benchmark.throughput_mbps,
                "latency_ms": benchmark.latency_ms,
            },
            resources={
                "cpu_percent": resources.cpu_percent,
                "memory_mb": resources.memory_mb,
                "energy_watts": resources.energy_watts,
            },
            asp=attack_surface_points,
        )

        return breakdown

    def score(self, organism: CryptoProtocolOrganism) -> float:
        """Return normalized fitness in [0, 1]."""
        result = self.evaluate(organism)
        return result.normalized_fitness

    def _security_score(self, genome: dict[str, Any]) -> float:
        key_size = int(genome.get("key_size", 256))
        algorithm = str(genome.get("algorithm", "AES-256-GCM")).upper().strip()
        rotation_days = int(genome.get("rotation_period", 30))

        # Key sizes >= 1024 are saturated at max contribution for this model.
        key_size_score = self._clip01(key_size / 1024.0)

        algorithm_score = self._ALGORITHM_STRENGTH.get(algorithm, 0.75)

        # More frequent rotation improves score, with diminishing returns.
        rotation_days = max(1, rotation_days)
        rotation_score = 1.0 / (1.0 + (rotation_days / 30.0))
        rotation_score = self._clip01(rotation_score * 2.0)

        security = 0.45 * key_size_score + 0.40 * algorithm_score + 0.15 * rotation_score
        return self._clip01(security)

    def _efficiency_score(self, benchmark: PerformanceBenchmark) -> float:
        throughput = max(0.0, benchmark.throughput_mbps)
        latency = max(0.001, benchmark.latency_ms)

        throughput_score = throughput / (throughput + 1000.0)
        latency_score = 1.0 / (1.0 + (latency / 10.0))

        efficiency = 0.60 * throughput_score + 0.40 * latency_score
        return self._clip01(efficiency)

    def _cost(self, resources: ResourceCost) -> float:
        cpu_n = max(0.0, resources.cpu_percent) / 100.0
        memory_n = max(0.0, resources.memory_mb) / 4096.0
        energy_n = max(0.0, resources.energy_watts) / 500.0

        # Keep denominator positive and stable.
        cost = 0.40 * cpu_n + 0.30 * memory_n + 0.30 * energy_n
        return max(cost, 0.05)

    def _attack_surface(self, points: int) -> float:
        points = max(1, int(points))
        # Normalize points to [0.1, 1.0] where higher means broader attack surface.
        return max(min(points / 20.0, 1.0), 0.1)

    def _benchmark_from_genome(self, genome: dict[str, Any]) -> PerformanceBenchmark:
        return PerformanceBenchmark(
            throughput_mbps=float(genome.get("throughput_mbps", 500.0)),
            latency_ms=float(genome.get("latency_ms", 10.0)),
        )

    def _resources_from_genome(self, genome: dict[str, Any]) -> ResourceCost:
        return ResourceCost(
            cpu_percent=float(genome.get("cpu_percent", 40.0)),
            memory_mb=float(genome.get("memory_mb", 512.0)),
            energy_watts=float(genome.get("energy_watts", 65.0)),
        )

    @staticmethod
    def _normalize_ratio(raw: float) -> float:
        raw = max(raw, 0.0)
        return raw / (1.0 + raw)

    @staticmethod
    def _clip01(value: float) -> float:
        if value < 0.0:
            return 0.0
        if value > 1.0:
            return 1.0
        return value


def comprehensive_fitness(organism: CryptoProtocolOrganism) -> float:
    """Convenience callable for EvolutionEngine test suite integration."""
    evaluator = ProtocolFitnessEvaluator()
    return evaluator.score(organism)


__all__ = [
    "PerformanceBenchmark",
    "ResourceCost",
    "FitnessBreakdown",
    "ProtocolFitnessEvaluator",
    "comprehensive_fitness",
]
