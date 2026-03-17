"""Evolvable cryptographic protocol organism model.

This module defines a dataclass-based representation of a protocol candidate
that can mutate, crossover, and be scored by a fitness test suite.
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field
from typing import Any, Callable


Genome = dict[str, Any]
FitnessTest = Callable[["CryptoProtocolOrganism"], float]


_DEFAULT_ALGORITHMS = [
    "AES-256-GCM",
    "CHACHA20-POLY1305",
    "KYBER-HYBRID",
    "XCHACHA20-POLY1305",
]


def _normalize_key_size(value: Any) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("key_size must be an integer") from exc

    if parsed < 128:
        return 128
    if parsed > 8192:
        return 8192
    return parsed


def _normalize_rotation_period(value: Any) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("rotation_period must be an integer") from exc

    if parsed < 1:
        return 1
    if parsed > 3650:
        return 3650
    return parsed


@dataclass
class CryptoProtocolOrganism:
    """Represents an evolvable encryption protocol candidate.

    Attributes:
        genome: Parameter dictionary for protocol configuration.
            Expected keys include:
            - key_size (int)
            - algorithm (str)
            - rotation_period (int)
        fitness: Current fitness score.
        generation: Evolution generation index.
    """

    genome: Genome
    fitness: float = 0.0
    generation: int = 0
    rng_seed: int | None = None
    _rng: random.Random = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._rng = random.Random(self.rng_seed)
        self._validate_and_normalize_genome()

    @property
    def dna(self) -> str:
        """Return DNA-like compact encoding of genome parameters.

        Format:
            K<hex_key_size>-A<algo_hash8>-R<hex_rotation>
        """
        key_size = _normalize_key_size(self.genome.get("key_size", 256))
        algorithm = str(self.genome.get("algorithm", "AES-256-GCM"))
        rotation = _normalize_rotation_period(self.genome.get("rotation_period", 30))

        algo_hash = hashlib.sha256(algorithm.encode("utf-8")).hexdigest()[:8].upper()
        return f"K{key_size:04X}-A{algo_hash}-R{rotation:04X}"

    def mutate(self, mutation_rate: float) -> None:
        """Mutate organism genome in-place.

        Args:
            mutation_rate: Probability in [0, 1] applied per mutable gene.
        """
        if not 0.0 <= mutation_rate <= 1.0:
            raise ValueError("mutation_rate must be between 0 and 1")

        if self._rng.random() < mutation_rate:
            key_size = _normalize_key_size(self.genome["key_size"])
            step = self._rng.choice([-128, -64, 64, 128, 256])
            self.genome["key_size"] = _normalize_key_size(key_size + step)

        if self._rng.random() < mutation_rate:
            current_algorithm = str(self.genome["algorithm"])
            candidates = [a for a in _DEFAULT_ALGORITHMS if a != current_algorithm]
            if not candidates:
                candidates = _DEFAULT_ALGORITHMS
            self.genome["algorithm"] = self._rng.choice(candidates)

        if self._rng.random() < mutation_rate:
            rotation = _normalize_rotation_period(self.genome["rotation_period"])
            step = self._rng.choice([-14, -7, 7, 14, 30])
            self.genome["rotation_period"] = _normalize_rotation_period(rotation + step)

        self._validate_and_normalize_genome()

    def crossover(self, other_organism: "CryptoProtocolOrganism") -> "CryptoProtocolOrganism":
        """Perform single-organism crossover and produce child organism.

        Each gene is chosen from one of the parents with equal probability.
        Child generation increments from the older parent generation.
        """
        if not isinstance(other_organism, CryptoProtocolOrganism):
            raise TypeError("other_organism must be a CryptoProtocolOrganism")

        child_genome: Genome = {}
        for key in {"key_size", "algorithm", "rotation_period"}:
            choose_self = self._rng.random() < 0.5
            child_genome[key] = self.genome[key] if choose_self else other_organism.genome[key]

        return CryptoProtocolOrganism(
            genome=child_genome,
            fitness=0.0,
            generation=max(self.generation, other_organism.generation) + 1,
            rng_seed=self._rng.randint(0, 2**31 - 1),
        )

    def evaluate_fitness(self, test_suite: FitnessTest | list[FitnessTest]) -> float:
        """Evaluate and update fitness using one or multiple test functions.

        Args:
            test_suite: Callable or list of callables receiving this organism and
                returning a numeric score.

        Returns:
            Updated fitness score.
        """
        tests: list[FitnessTest]
        if callable(test_suite):
            tests = [test_suite]
        elif isinstance(test_suite, list) and test_suite and all(callable(t) for t in test_suite):
            tests = test_suite
        else:
            raise ValueError("test_suite must be a callable or non-empty list of callables")

        scores: list[float] = []
        for test in tests:
            score = float(test(self))
            scores.append(score)

        self.fitness = sum(scores) / len(scores)
        return self.fitness

    def _validate_and_normalize_genome(self) -> None:
        required = {"key_size", "algorithm", "rotation_period"}
        missing = required - set(self.genome.keys())
        if missing:
            raise ValueError(f"genome missing required keys: {', '.join(sorted(missing))}")

        self.genome["key_size"] = _normalize_key_size(self.genome["key_size"])
        self.genome["rotation_period"] = _normalize_rotation_period(self.genome["rotation_period"])

        algorithm = str(self.genome["algorithm"]).strip().upper()
        if not algorithm:
            raise ValueError("algorithm must be a non-empty string")
        self.genome["algorithm"] = algorithm

        if self.generation < 0:
            raise ValueError("generation must be >= 0")


__all__ = ["CryptoProtocolOrganism", "Genome", "FitnessTest"]
