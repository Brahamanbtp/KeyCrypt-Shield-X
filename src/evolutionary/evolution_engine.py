"""Genetic algorithm engine for evolving cryptographic protocols."""

from __future__ import annotations

import random
from dataclasses import dataclass
from statistics import pstdev
from typing import Callable

from src.evolutionary.protocol_organism import CryptoProtocolOrganism, FitnessTest


@dataclass(frozen=True)
class EvolutionConfig:
    mutation_rate: float = 0.15
    elitism_ratio: float = 0.10
    diversity_ratio: float = 0.10
    tournament_size: int = 3
    convergence_patience: int = 12
    convergence_delta: float = 1e-4


class EvolutionEngine:
    """Genetic algorithm for cryptographic protocol evolution.

    Features:
    - Tournament selection with configurable selection pressure
    - Reproduction via crossover + mutation
    - Elitism (top 10% retained by default)
    - Diversity maintenance via random immigrant injection
    - Convergence detection using best-fitness stagnation and low variance
    """

    _ALGORITHM_CHOICES = [
        "AES-256-GCM",
        "CHACHA20-POLY1305",
        "KYBER-HYBRID",
        "XCHACHA20-POLY1305",
    ]

    def __init__(
        self,
        test_suite: FitnessTest | list[FitnessTest],
        *,
        config: EvolutionConfig | None = None,
        seed: int | None = None,
    ) -> None:
        if not callable(test_suite) and not (
            isinstance(test_suite, list) and test_suite and all(callable(t) for t in test_suite)
        ):
            raise ValueError("test_suite must be a callable or non-empty list of callables")

        self.test_suite = test_suite
        self.config = config if config is not None else EvolutionConfig()
        self._rng = random.Random(seed)

        self.population: list[CryptoProtocolOrganism] = []
        self.best_history: list[float] = []

    def initialize_population(self, size: int) -> list[CryptoProtocolOrganism]:
        """Initialize a new random organism population."""
        if size <= 0:
            raise ValueError("size must be a positive integer")

        population: list[CryptoProtocolOrganism] = []
        for _ in range(size):
            organism = CryptoProtocolOrganism(
                genome=self._random_genome(),
                generation=0,
                rng_seed=self._rng.randint(0, 2**31 - 1),
            )
            organism.evaluate_fitness(self.test_suite)
            population.append(organism)

        self.population = population
        return population

    def selection(self, population: list[CryptoProtocolOrganism], selection_pressure: float) -> list[CryptoProtocolOrganism]:
        """Select parents using tournament selection.

        Args:
            population: Current evaluated population.
            selection_pressure: Controls tournament size scaling in [0, 1].

        Returns:
            Parent pool with length equal to input population length.
        """
        if not population:
            raise ValueError("population must not be empty")
        if not 0.0 <= selection_pressure <= 1.0:
            raise ValueError("selection_pressure must be in [0, 1]")

        base = self.config.tournament_size
        tournament_size = max(2, min(len(population), int(round(base + selection_pressure * base))))

        parents: list[CryptoProtocolOrganism] = []
        for _ in range(len(population)):
            tournament = self._rng.sample(population, k=tournament_size)
            winner = max(tournament, key=lambda o: o.fitness)
            parents.append(winner)

        return parents

    def reproduce(
        self,
        parent1: CryptoProtocolOrganism,
        parent2: CryptoProtocolOrganism,
    ) -> CryptoProtocolOrganism:
        """Produce one offspring using crossover followed by mutation."""
        child = parent1.crossover(parent2)
        child.mutate(self.config.mutation_rate)
        child.evaluate_fitness(self.test_suite)
        return child

    def evolve(self, generations: int, fitness_target: float) -> CryptoProtocolOrganism:
        """Run evolution and return best protocol found.

        Stops early when:
        - `fitness_target` is reached, or
        - convergence is detected.
        """
        if generations <= 0:
            raise ValueError("generations must be a positive integer")
        if not self.population:
            raise ValueError("population is empty; call initialize_population(size) first")

        population = self.population
        best = max(population, key=lambda o: o.fitness)

        for gen_idx in range(1, generations + 1):
            ranked = sorted(population, key=lambda o: o.fitness, reverse=True)
            best = ranked[0]
            self.best_history.append(best.fitness)

            if best.fitness >= fitness_target:
                self.population = ranked
                return best

            if self._is_converged(ranked):
                self.population = ranked
                return best

            elite_count = max(1, int(len(population) * self.config.elitism_ratio))
            elites = [self._clone_organism(org, generation=gen_idx) for org in ranked[:elite_count]]

            parents = self.selection(ranked, selection_pressure=0.7)

            next_population: list[CryptoProtocolOrganism] = []
            next_population.extend(elites)

            while len(next_population) < len(population):
                p1 = self._rng.choice(parents)
                p2 = self._rng.choice(parents)
                if p1 is p2 and len(parents) > 1:
                    p2 = self._rng.choice([p for p in parents if p is not p1])

                offspring = self.reproduce(p1, p2)
                offspring.generation = gen_idx
                next_population.append(offspring)

            population = self._maintain_diversity(next_population, generation=gen_idx)

        self.population = sorted(population, key=lambda o: o.fitness, reverse=True)
        return self.population[0]

    def _maintain_diversity(
        self,
        population: list[CryptoProtocolOrganism],
        *,
        generation: int,
    ) -> list[CryptoProtocolOrganism]:
        """Inject random immigrants to reduce genetic collapse."""
        if not population:
            return population

        n_replace = int(len(population) * self.config.diversity_ratio)
        if n_replace <= 0:
            return population

        ranked = sorted(population, key=lambda o: o.fitness, reverse=True)
        survivors = ranked[:-n_replace] if n_replace < len(ranked) else ranked[:1]

        immigrants: list[CryptoProtocolOrganism] = []
        for _ in range(n_replace):
            immigrant = CryptoProtocolOrganism(
                genome=self._random_genome(),
                generation=generation,
                rng_seed=self._rng.randint(0, 2**31 - 1),
            )
            immigrant.evaluate_fitness(self.test_suite)
            immigrants.append(immigrant)

        mixed = survivors + immigrants
        mixed.sort(key=lambda o: o.fitness, reverse=True)
        return mixed[: len(population)]

    def _is_converged(self, ranked_population: list[CryptoProtocolOrganism]) -> bool:
        if len(self.best_history) < self.config.convergence_patience:
            return False

        recent = self.best_history[-self.config.convergence_patience :]
        best_gain = max(recent) - min(recent)
        if best_gain > self.config.convergence_delta:
            return False

        fitness_values = [o.fitness for o in ranked_population]
        variance_proxy = pstdev(fitness_values) if len(fitness_values) > 1 else 0.0
        return variance_proxy <= self.config.convergence_delta

    def _random_genome(self) -> dict[str, object]:
        return {
            "key_size": self._rng.choice([128, 192, 256, 384, 512, 1024]),
            "algorithm": self._rng.choice(self._ALGORITHM_CHOICES),
            "rotation_period": self._rng.choice([7, 14, 30, 60, 90, 180, 365]),
        }

    def _clone_organism(self, organism: CryptoProtocolOrganism, *, generation: int) -> CryptoProtocolOrganism:
        clone = CryptoProtocolOrganism(
            genome=dict(organism.genome),
            fitness=organism.fitness,
            generation=generation,
            rng_seed=self._rng.randint(0, 2**31 - 1),
        )
        return clone


__all__ = ["EvolutionEngine", "EvolutionConfig"]
