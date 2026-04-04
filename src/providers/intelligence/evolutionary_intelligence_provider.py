"""Evolutionary intelligence provider using compositional wrappers.

This module wraps existing evolutionary components without modifications:
- src/evolutionary/evolution_engine.py
- src/evolutionary/fitness.py
- src/evolutionary/protocol_organism.py
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor, TimeoutError
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence
from uuid import uuid4

from src.evolutionary.evolution_engine import EvolutionConfig, EvolutionEngine
from src.evolutionary.fitness import (
    FitnessBreakdown,
    PerformanceBenchmark,
    ProtocolFitnessEvaluator,
    ResourceCost,
)
from src.evolutionary.protocol_organism import CryptoProtocolOrganism


@dataclass(frozen=True)
class Protocol:
    """Typed protocol descriptor used by the provider boundary."""

    key_size: int
    algorithm: str
    rotation_period: int
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.key_size < 128:
            raise ValueError("key_size must be >= 128")
        if self.rotation_period < 1:
            raise ValueError("rotation_period must be >= 1")
        if not self.algorithm.strip():
            raise ValueError("algorithm must be a non-empty string")

    def to_genome(self) -> dict[str, Any]:
        return {
            "key_size": int(self.key_size),
            "algorithm": str(self.algorithm).strip().upper(),
            "rotation_period": int(self.rotation_period),
            **dict(self.metadata),
        }


@dataclass(frozen=True)
class OptimizationConstraints:
    """Constraints and controls for evolutionary optimization runs."""

    population_size: int = 64
    generations: int = 40
    fitness_target: float = 0.92
    mutation_rate: float = 0.15
    elitism_ratio: float = 0.10
    diversity_ratio: float = 0.10
    tournament_size: int = 3
    convergence_patience: int = 12
    convergence_delta: float = 1e-4
    seed: int | None = None
    baseline_protocol: Protocol | None = None
    parent_lineage_id: str | None = None
    benchmark: PerformanceBenchmark | None = None
    resources: ResourceCost | None = None
    attack_surface_points: int | None = None

    def __post_init__(self) -> None:
        if self.population_size <= 0:
            raise ValueError("population_size must be > 0")
        if self.generations <= 0:
            raise ValueError("generations must be > 0")
        if not 0.0 <= self.fitness_target <= 1.0:
            raise ValueError("fitness_target must be in [0, 1]")
        if not 0.0 <= self.mutation_rate <= 1.0:
            raise ValueError("mutation_rate must be in [0, 1]")
        if not 0.0 <= self.elitism_ratio <= 1.0:
            raise ValueError("elitism_ratio must be in [0, 1]")
        if not 0.0 <= self.diversity_ratio <= 1.0:
            raise ValueError("diversity_ratio must be in [0, 1]")
        if self.tournament_size < 2:
            raise ValueError("tournament_size must be >= 2")
        if self.convergence_patience <= 0:
            raise ValueError("convergence_patience must be > 0")
        if self.convergence_delta < 0:
            raise ValueError("convergence_delta must be >= 0")
        if self.attack_surface_points is not None and self.attack_surface_points <= 0:
            raise ValueError("attack_surface_points must be > 0 when provided")


@dataclass(frozen=True)
class FitnessScore:
    """Fitness score returned by protocol evaluation."""

    value: float
    breakdown: FitnessBreakdown
    rationale: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class OptimizedProtocol:
    """Optimization output from evolutionary search."""

    protocol: Protocol
    fitness: float
    generation: int
    lineage_id: str
    evaluation_time_ms: float
    fitness_history: list[float] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ThreatLandscape:
    """Threat landscape used for adaptive protocol evolution."""

    threat_level: float
    active_threats: Sequence[str] = field(default_factory=tuple)
    attack_surface_points: int = 8
    compliance_requirements: Sequence[str] = field(default_factory=tuple)
    performance_pressure: float = 0.5
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not 0.0 <= float(self.threat_level) <= 1.0:
            raise ValueError("threat_level must be in [0, 1]")
        if self.attack_surface_points <= 0:
            raise ValueError("attack_surface_points must be > 0")
        if not 0.0 <= float(self.performance_pressure) <= 1.0:
            raise ValueError("performance_pressure must be in [0, 1]")


@dataclass(frozen=True)
class AdaptedProtocol:
    """Adaptation result for a threat-driven optimization run."""

    protocol: Protocol
    fitness: float
    lineage_id: str
    adaptation_confidence: float
    mitigated_threats: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class EvolutionHistoryEntry:
    """Lineage record for protocol improvements across optimization runs."""

    lineage_id: str
    parent_lineage_id: str | None
    timestamp: float
    event_type: str
    protocol: Protocol
    fitness: float
    generation: int
    improvement_delta: float
    fitness_history: list[float] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class EvolutionaryIntelligenceProvider:
    """Provider wrapper for evolutionary protocol intelligence."""

    def __init__(self, *, max_background_workers: int = 2) -> None:
        if max_background_workers <= 0:
            raise ValueError("max_background_workers must be > 0")

        self._lock = threading.RLock()
        self._fitness_evaluator = ProtocolFitnessEvaluator()
        self._executor = ThreadPoolExecutor(
            max_workers=max_background_workers,
            thread_name_prefix="evolution-optimizer",
        )

        self._lineage_history: list[EvolutionHistoryEntry] = []
        self._active_jobs: dict[str, Future[OptimizedProtocol]] = {}
        self._latest_protocol: Protocol | None = None
        self._latest_lineage_id: str | None = None

    def optimize_protocol(self, constraints: OptimizationConstraints) -> OptimizedProtocol:
        """Optimize protocol under constraints using EvolutionEngine."""
        if not isinstance(constraints, OptimizationConstraints):
            raise TypeError("constraints must be OptimizationConstraints")

        started = time.perf_counter()
        test_suite = self._build_test_suite(
            benchmark=constraints.benchmark,
            resources=constraints.resources,
            attack_surface_points=constraints.attack_surface_points,
        )

        engine = EvolutionEngine(
            test_suite=test_suite,
            config=EvolutionConfig(
                mutation_rate=constraints.mutation_rate,
                elitism_ratio=constraints.elitism_ratio,
                diversity_ratio=constraints.diversity_ratio,
                tournament_size=constraints.tournament_size,
                convergence_patience=constraints.convergence_patience,
                convergence_delta=constraints.convergence_delta,
            ),
            seed=constraints.seed,
        )

        population = engine.initialize_population(constraints.population_size)
        if constraints.baseline_protocol is not None:
            self._inject_baseline(population, constraints.baseline_protocol, test_suite, seed=constraints.seed)
            engine.population = population

        best = engine.evolve(constraints.generations, constraints.fitness_target)

        lineage_id = self._new_lineage_id(prefix="evo")
        protocol = self._protocol_from_organism(best)
        elapsed_ms = (time.perf_counter() - started) * 1000.0

        optimized = OptimizedProtocol(
            protocol=protocol,
            fitness=self._clamp01(best.fitness),
            generation=int(best.generation),
            lineage_id=lineage_id,
            evaluation_time_ms=elapsed_ms,
            fitness_history=[self._clamp01(value) for value in engine.best_history],
            metadata={
                "population_size": constraints.population_size,
                "generations": constraints.generations,
                "fitness_target": constraints.fitness_target,
                "algorithm": protocol.algorithm,
                "dna": best.dna,
            },
        )

        self._record_optimization_history(optimized, parent_lineage_id=constraints.parent_lineage_id)
        return optimized

    def evaluate_protocol_fitness(self, protocol: Protocol) -> FitnessScore:
        """Evaluate a protocol using comprehensive fitness metrics."""
        if not isinstance(protocol, Protocol):
            raise TypeError("protocol must be Protocol")

        organism = CryptoProtocolOrganism(genome=protocol.to_genome())
        breakdown = self._fitness_evaluator.evaluate(organism)

        rationale = (
            "Fitness computed from normalized security, efficiency, resource cost, "
            "and attack-surface factors."
        )
        return FitnessScore(
            value=self._clamp01(breakdown.normalized_fitness),
            breakdown=breakdown,
            rationale=rationale,
            metadata={
                "provider": "EvolutionaryIntelligenceProvider",
                "raw_fitness": breakdown.raw_fitness,
                "dna": organism.dna,
            },
        )

    def adapt_to_threats(self, threat_landscape: ThreatLandscape) -> AdaptedProtocol:
        """Adapt protocol selection using threat-driven evolutionary optimization."""
        if not isinstance(threat_landscape, ThreatLandscape):
            raise TypeError("threat_landscape must be ThreatLandscape")

        baseline = self._threat_baseline_protocol(threat_landscape)

        mutation_rate = 0.18 + (0.20 * self._clamp01(float(threat_landscape.threat_level)))
        generations = 30 + int(50 * self._clamp01(float(threat_landscape.threat_level)))
        fitness_target = 0.85 + (0.10 * self._clamp01(float(threat_landscape.threat_level)))

        constraints = OptimizationConstraints(
            population_size=72,
            generations=generations,
            fitness_target=self._clamp01(fitness_target),
            mutation_rate=min(0.5, mutation_rate),
            elitism_ratio=0.12,
            diversity_ratio=0.15,
            tournament_size=4,
            baseline_protocol=baseline,
            parent_lineage_id=self._latest_lineage_id,
            attack_surface_points=int(threat_landscape.attack_surface_points),
        )

        optimized = self.optimize_protocol(constraints)

        mitigated = sorted({item.strip().lower() for item in threat_landscape.active_threats if str(item).strip()})
        confidence = self._clamp01((0.65 * optimized.fitness) + (0.35 * float(threat_landscape.threat_level)))

        return AdaptedProtocol(
            protocol=optimized.protocol,
            fitness=optimized.fitness,
            lineage_id=optimized.lineage_id,
            adaptation_confidence=confidence,
            mitigated_threats=mitigated,
            metadata={
                "provider": "EvolutionaryIntelligenceProvider",
                "threat_level": float(threat_landscape.threat_level),
                "active_threat_count": len(mitigated),
                "compliance_requirements": [str(item) for item in threat_landscape.compliance_requirements],
                "performance_pressure": float(threat_landscape.performance_pressure),
                "attack_surface_points": int(threat_landscape.attack_surface_points),
                "optimized_generation": optimized.generation,
            },
        )

    def optimize_protocol_async(self, constraints: OptimizationConstraints) -> str:
        """Run optimization in a background thread and return a job id."""
        if not isinstance(constraints, OptimizationConstraints):
            raise TypeError("constraints must be OptimizationConstraints")

        job_id = uuid4().hex
        future = self._executor.submit(self.optimize_protocol, constraints)

        with self._lock:
            self._active_jobs[job_id] = future

        return job_id

    def get_async_result(self, job_id: str, *, timeout_seconds: float | None = None) -> OptimizedProtocol | None:
        """Return async optimization result when available, else None."""
        if not isinstance(job_id, str) or not job_id.strip():
            raise ValueError("job_id must be non-empty string")

        with self._lock:
            future = self._active_jobs.get(job_id)
        if future is None:
            raise KeyError(f"unknown optimization job_id: {job_id}")

        try:
            if timeout_seconds is None:
                if not future.done():
                    return None
                result = future.result()
            else:
                result = future.result(timeout=max(0.0, float(timeout_seconds)))
        except TimeoutError:
            return None

        if future.done():
            with self._lock:
                self._active_jobs.pop(job_id, None)

        return result

    def cancel_async_optimization(self, job_id: str) -> bool:
        """Cancel an active background optimization job."""
        with self._lock:
            future = self._active_jobs.get(job_id)
            if future is None:
                return False

            cancelled = future.cancel()
            if cancelled:
                self._active_jobs.pop(job_id, None)
            return cancelled

    def list_active_jobs(self) -> list[str]:
        """List currently running optimization job identifiers."""
        with self._lock:
            running: list[str] = []
            stale: list[str] = []
            for job_id, future in self._active_jobs.items():
                if future.done():
                    stale.append(job_id)
                    continue
                running.append(job_id)

            for job_id in stale:
                self._active_jobs.pop(job_id, None)

        running.sort()
        return running

    def get_evolution_history(self, *, lineage_id: str | None = None) -> list[EvolutionHistoryEntry]:
        """Return full or lineage-scoped protocol improvement history."""
        with self._lock:
            if lineage_id is None:
                return list(self._lineage_history)
            return [entry for entry in self._lineage_history if entry.lineage_id == lineage_id]

    def shutdown(self, *, wait: bool = False) -> None:
        """Shutdown background execution resources."""
        self._executor.shutdown(wait=wait, cancel_futures=True)

    def _build_test_suite(
        self,
        *,
        benchmark: PerformanceBenchmark | None,
        resources: ResourceCost | None,
        attack_surface_points: int | None,
    ):
        def _test_suite(organism: CryptoProtocolOrganism) -> float:
            breakdown = self._fitness_evaluator.evaluate(
                organism,
                benchmark=benchmark,
                resources=resources,
                attack_surface_points=attack_surface_points,
            )
            return self._clamp01(breakdown.normalized_fitness)

        return _test_suite

    @staticmethod
    def _inject_baseline(
        population: list[CryptoProtocolOrganism],
        baseline: Protocol,
        test_suite,
        *,
        seed: int | None,
    ) -> None:
        if not population:
            return

        baseline_organism = CryptoProtocolOrganism(
            genome=baseline.to_genome(),
            generation=0,
            rng_seed=seed,
        )
        baseline_organism.evaluate_fitness(test_suite)

        worst_index = min(range(len(population)), key=lambda idx: population[idx].fitness)
        population[worst_index] = baseline_organism

    def _record_optimization_history(
        self,
        optimized: OptimizedProtocol,
        *,
        parent_lineage_id: str | None,
    ) -> None:
        with self._lock:
            previous_fitness = self._lineage_history[-1].fitness if self._lineage_history else 0.0
            improvement = optimized.fitness - previous_fitness

            entry = EvolutionHistoryEntry(
                lineage_id=optimized.lineage_id,
                parent_lineage_id=parent_lineage_id,
                timestamp=time.time(),
                event_type="optimize_protocol",
                protocol=optimized.protocol,
                fitness=optimized.fitness,
                generation=optimized.generation,
                improvement_delta=improvement,
                fitness_history=list(optimized.fitness_history),
                metadata=dict(optimized.metadata),
            )
            self._lineage_history.append(entry)

            self._latest_protocol = optimized.protocol
            self._latest_lineage_id = optimized.lineage_id

            if len(self._lineage_history) > 1024:
                self._lineage_history = self._lineage_history[-1024:]

    def _threat_baseline_protocol(self, landscape: ThreatLandscape) -> Protocol:
        if self._latest_protocol is not None:
            return self._latest_protocol

        requirements = {
            item.strip().lower()
            for item in landscape.compliance_requirements
            if isinstance(item, str) and item.strip()
        }
        threat_level = self._clamp01(float(landscape.threat_level))

        if threat_level >= 0.8 or {"post-quantum", "nist", "fips"}.intersection(requirements):
            return Protocol(key_size=1024, algorithm="KYBER-HYBRID", rotation_period=7)
        if threat_level >= 0.55:
            return Protocol(key_size=512, algorithm="AES-256-GCM", rotation_period=14)
        if float(landscape.performance_pressure) >= 0.7:
            return Protocol(key_size=256, algorithm="CHACHA20-POLY1305", rotation_period=30)
        return Protocol(key_size=256, algorithm="AES-256-GCM", rotation_period=30)

    @staticmethod
    def _protocol_from_organism(organism: CryptoProtocolOrganism) -> Protocol:
        genome = organism.genome
        metadata = {
            key: value
            for key, value in genome.items()
            if key not in {"key_size", "algorithm", "rotation_period"}
        }
        metadata["dna"] = organism.dna
        metadata["generation"] = organism.generation
        return Protocol(
            key_size=int(genome["key_size"]),
            algorithm=str(genome["algorithm"]).upper().strip(),
            rotation_period=int(genome["rotation_period"]),
            metadata=metadata,
        )

    @staticmethod
    def _new_lineage_id(*, prefix: str) -> str:
        return f"{prefix}-{uuid4().hex[:12]}"

    @staticmethod
    def _clamp01(value: float) -> float:
        if value < 0.0:
            return 0.0
        if value > 1.0:
            return 1.0
        return float(value)


__all__ = [
    "Protocol",
    "OptimizationConstraints",
    "OptimizedProtocol",
    "FitnessScore",
    "ThreatLandscape",
    "AdaptedProtocol",
    "EvolutionHistoryEntry",
    "EvolutionaryIntelligenceProvider",
]
