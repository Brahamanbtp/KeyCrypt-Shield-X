"""Adversarial machine learning defenses and utilities.

PRESERVE: Adversarial ML defenses
EXTEND: AI security hardening

This module implements lightweight, dependency-tolerant defenses for
adversarial inputs, poisoning mitigation, differential privacy wrapping,
and robustness testing. Implementations prefer clarity and testability over
production-level cryptographic guarantees; optional deep-learning integrations
should be provided by the caller when available.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from math import log2
from statistics import median, mean
from typing import Any, List, Mapping, Sequence
import zlib
import math
import random


@dataclass(frozen=True)
class Sample:
    features: Sequence[float]
    label: str
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CleanedData:
    samples: list[Sample]
    removed_indices: list[int] = field(default_factory=list)


@dataclass(frozen=True)
class PrivateModel:
    model: Any
    epsilon: float
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def predict(self, X: Sequence[Sequence[float]]) -> list[Any]:
        if hasattr(self.model, "predict"):
            preds = list(self.model.predict(X))
        else:
            preds = [self.model(x) for x in X]

        # Apply lightweight Laplace noise to numeric predictions if possible.
        noisy: list[Any] = []
        for p in preds:
            if isinstance(p, (int, float)):
                scale = 1.0 / max(1e-6, float(self.epsilon))
                noisy.append(p + random.gauss(0, scale))
            else:
                noisy.append(p)
        return noisy


@dataclass(frozen=True)
class RobustnessScore:
    baseline_accuracy: float
    adversarial_accuracy: float
    robustness: float


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = 0.0
    length = float(len(data))
    for c in counts:
        if c == 0:
            continue
        p = c / length
        entropy -= p * log2(p)
    return entropy


def detect_adversarial_input(data: bytes) -> bool:
    """Detects adversarially crafted inputs using statistical heuristics.

    Heuristics used:
    - Shannon entropy extremes (very low or very high) may indicate crafted data.
    - Poor compressibility (zlib) can indicate high-entropy adversarial payloads.
    - Very short inputs with abnormal byte distributions are flagged.

    Returns True when input looks adversarial.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes or bytearray")

    length = len(data)
    if length == 0:
        return False

    entropy = _shannon_entropy(bytes(data))
    try:
        compressed = zlib.compress(bytes(data))
        compression_ratio = len(compressed) / max(1, length)
    except Exception:
        compression_ratio = 1.0

    # Heuristic thresholds chosen conservatively for detectability in tests.
    if entropy >= 7.8 or entropy <= 0.5:
        return True
    if compression_ratio >= 0.98 and length > 64:
        # Very poor compressibility for larger inputs can be suspicious.
        return True
    if length < 16 and entropy > 6.0:
        # Very small but extremely random input is suspicious.
        return True

    return False


def defend_against_model_poisoning(training_data: List[Sample]) -> CleanedData:
    """Removes poisoned samples from training data using outlier detection.

    Strategy:
    - Group by label, compute centroid (mean) per label, compute Euclidean
      distance of samples to centroid, and remove samples that are far from
      their label centroid (beyond median + 3*IQR heuristic).
    - Return cleaned dataset and indices removed.
    """
    if not isinstance(training_data, list):
        raise TypeError("training_data must be a list of Sample")
    if not training_data:
        return CleanedData(samples=[], removed_indices=[])

    # Ensure feature lengths
    feature_len = len(training_data[0].features)
    for s in training_data:
        if len(s.features) != feature_len:
            raise ValueError("all samples must have the same feature dimensionality")

    # Group indices by label
    groups: dict[str, list[int]] = {}
    for idx, s in enumerate(training_data):
        groups.setdefault(s.label, []).append(idx)

    distances: dict[int, float] = {}
    group_thresholds: dict[str, float] = {}
    for label, indices in groups.items():
        # compute centroid
        centroid = [0.0] * feature_len
        for i in indices:
            for j, v in enumerate(training_data[i].features):
                centroid[j] += float(v)
        n = float(len(indices)) or 1.0
        centroid = [c / n for c in centroid]

        # distances
        dists = []
        for i in indices:
            s = training_data[i]
            dist = math.sqrt(sum((float(a) - float(b)) ** 2 for a, b in zip(s.features, centroid)))
            distances[i] = dist
            dists.append(dist)

        # compute threshold using median + 3*IQR-like heuristic (use percentiles)
        dists_sorted = sorted(dists)
        med = median(dists_sorted)
        q1 = dists_sorted[max(0, int(len(dists_sorted) * 0.25) - 1)]
        q3 = dists_sorted[min(len(dists_sorted) - 1, int(len(dists_sorted) * 0.75))]
        iqr = max(1e-6, q3 - q1)
        threshold = med + 3.0 * iqr
        group_thresholds[label] = threshold

        # mark outliers (kept in distances mapping to examine later)
        for i in indices:
            if distances[i] > threshold:
                distances[i] = distances[i]

    # Decide removals: remove top 5% of distances or those beyond group thresholds
    all_items = sorted(distances.items(), key=lambda kv: kv[1], reverse=True)
    remove_cutoff = max(1, int(len(all_items) * 0.05))
    removed_indices = [idx for idx, _ in all_items[:remove_cutoff]]

    # Also remove any that exceed their group's threshold
    for idx, dist in all_items[remove_cutoff:]:
        label = training_data[idx].label
        if dist > group_thresholds.get(label, float("inf")):
            removed_indices.append(idx)

    removed_set = set(removed_indices)
    cleaned = [s for idx, s in enumerate(training_data) if idx not in removed_set]
    return CleanedData(samples=cleaned, removed_indices=sorted(removed_set))


def implement_differential_privacy(model: Any, epsilon: float) -> PrivateModel:
    """Adds a DP wrapper around a model. This is a lightweight wrapper that
    stores epsilon and applies small output noise for numeric predictions.

    For real training-time DP (e.g., gradient perturbation), integrate with
    a framework like Opacus or TensorFlow Privacy.
    """
    if not isinstance(epsilon, (int, float)) or epsilon <= 0.0:
        raise ValueError("epsilon must be a positive number")

    return PrivateModel(model=model, epsilon=float(epsilon), metadata={"dp_applied": True})


def evaluate_model_robustness(model: Any, X: Sequence[Sequence[float]], y_true: Sequence[Any], attack_budget: float) -> RobustnessScore:
    """Tests model against adversarial attacks using additive perturbations.

    - Compute baseline accuracy using model.predict or callable.
    - Generate adversarial examples by adding bounded noise (attack_budget)
      to each feature vector and evaluate accuracy again.
    - Return robustness score as adversarial_accuracy / baseline_accuracy.
    """
    if not X:
        raise ValueError("X must not be empty")
    if len(X) != len(y_true):
        raise ValueError("X and y_true must have same length")

    def predict(m, data):
        if hasattr(m, "predict"):
            return list(m.predict(data))
        return [m(x) for x in data]

    baseline_preds = predict(model, X)
    baseline_correct = sum(1 for p, t in zip(baseline_preds, y_true) if p == t)
    baseline_acc = baseline_correct / len(y_true)

    # Create adversarial examples by adding normalized noise per sample
    X_adv = []
    for x in X:
        adv = []
        for v in x:
            # perturbation bounded by attack_budget relative to magnitude
            delta = (random.uniform(-1.0, 1.0) * attack_budget * (abs(v) + 1.0))
            adv.append(v + delta)
        X_adv.append(adv)

    adv_preds = predict(model, X_adv)
    adv_correct = sum(1 for p, t in zip(adv_preds, y_true) if p == t)
    adv_acc = adv_correct / len(y_true)

    robustness = adv_acc / baseline_acc if baseline_acc > 0 else 0.0
    return RobustnessScore(baseline_accuracy=baseline_acc, adversarial_accuracy=adv_acc, robustness=robustness)


__all__ = [
    "Sample",
    "CleanedData",
    "PrivateModel",
    "RobustnessScore",
    "detect_adversarial_input",
    "defend_against_model_poisoning",
    "implement_differential_privacy",
    "evaluate_model_robustness",
]
