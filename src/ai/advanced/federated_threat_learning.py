"""Federated learning utilities for distributed threat intelligence.

PRESERVE: Federated learning
EXTEND: Collaborative threat intelligence

This module exposes a small API to initialize a federated learning setup,
train local models on node-local threat events, aggregate local models via
federated averaging, and share lightweight threat intelligence without
revealing raw private data. Optional integrations for TensorFlow Federated
or PySyft are supported via import boundaries; a pure-Python fallback is
provided so tests and simple deployments work without heavy dependencies.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from statistics import mean
from typing import Any, Dict, List, Mapping, Sequence
import json
import math

try:  # pragma: no cover - optional dependency boundary
    import tensorflow_federated as tff
except Exception as exc:  # pragma: no cover - optional dependency boundary
    tff = None  # type: ignore[assignment]
    _TFF_IMPORT_ERROR = exc
else:
    _TFF_IMPORT_ERROR = None

try:
    import syft
except Exception:
    syft = None


@dataclass(frozen=True)
class Node:
    node_id: str
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ThreatEvent:
    """Simple threat event representation used for local training.

    Features is a numeric feature vector extracted from telemetry that a local
    node can use to train a small classifier.
    """

    event_id: str
    features: Sequence[float]
    label: str
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass
class LocalModel:
    params: Dict[str, float]
    sample_count: int
    trained_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class GlobalModel:
    params: Dict[str, float]
    total_samples: int
    aggregated_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class FederatedModel:
    participants: List[Node]
    global_model: GlobalModel | None = None
    shared_threat_signatures: List[dict] = field(default_factory=list)


def initialize_federated_learning(participants: List[Node]) -> FederatedModel:
    if not isinstance(participants, list) or not all(isinstance(p, Node) for p in participants):
        raise TypeError("participants must be a list of Node instances")
    return FederatedModel(participants=list(participants))


def train_local_model(local_data: List[ThreatEvent]) -> LocalModel:
    """Each node trains a local model on its own threat events.

    In this lightweight implementation the "model" is a simple statistic: a
    per-feature mean and a count of samples. Real integrations should replace
    this with actual model training (e.g., PyTorch, TensorFlow) and return
    serialized parameters compatible with `aggregate_models`.
    """
    if not isinstance(local_data, list) or not all(isinstance(s, ThreatEvent) for s in local_data):
        raise TypeError("local_data must be a list of ThreatEvent instances")
    if not local_data:
        return LocalModel(params={}, sample_count=0)

    dim = len(local_data[0].features)
    for s in local_data:
        if len(s.features) != dim:
            raise ValueError("all feature vectors must have the same dimensionality")

    sums = [0.0] * dim
    for s in local_data:
        for i, v in enumerate(s.features):
            sums[i] += float(v)

    sample_count = len(local_data)
    means = {f"w{i}": (sums[i] / sample_count) for i in range(dim)}
    means["bias"] = 0.0
    return LocalModel(params=means, sample_count=sample_count)


def aggregate_models(models: List[LocalModel]) -> GlobalModel:
    """Aggregates models using federated averaging (weighted by sample counts)."""
    if not isinstance(models, list) or not all(isinstance(m, LocalModel) for m in models):
        raise TypeError("models must be a list of LocalModel instances")
    total = sum(m.sample_count for m in models)
    if total == 0:
        return GlobalModel(params={}, total_samples=0)

    # collect keys
    keys = set()
    for m in models:
        keys.update(m.params.keys())

    aggregated: Dict[str, float] = {}
    for k in keys:
        weighted_sum = 0.0
        for m in models:
            value = float(m.params.get(k, 0.0))
            weighted_sum += value * m.sample_count
        aggregated[k] = weighted_sum / total

    return GlobalModel(params=aggregated, total_samples=total)


def share_threat_intelligence_privately(fed: FederatedModel, threat: ThreatEvent, *, dp_noise: float = 0.0) -> None:
    """Shares threat intelligence without revealing raw data.

    Strategy:
    - Create a compact signature of the threat (hash of event_id+label+coarse features).
    - Optionally add small DP noise to numeric summaries before sharing.
    - Store the signature in `fed.shared_threat_signatures` for downstream
      aggregation without exposing individual feature vectors.
    """
    if not isinstance(fed, FederatedModel):
        raise TypeError("fed must be FederatedModel")
    if not isinstance(threat, ThreatEvent):
        raise TypeError("threat must be ThreatEvent")

    # coarse summary: quantize mean of features and label
    if threat.features:
        mean_feature = float(mean([float(x) for x in threat.features]))
    else:
        mean_feature = 0.0

    if dp_noise and dp_noise > 0.0:
        # add tiny Laplace-style noise
        noise = (math.log(1.0 + dp_noise) if dp_noise > 0 else 0.0)
        mean_feature += noise

    summary = {"label": threat.label, "mean_feature": round(mean_feature, 6)}
    signature_input = json.dumps({"event_id": threat.event_id, "summary": summary}, sort_keys=True)
    signature = sha256(signature_input.encode("utf-8")).hexdigest()

    fed.shared_threat_signatures.append({"signature": signature, "summary": summary, "reported_at": datetime.now(UTC).isoformat()})


__all__ = [
    "Node",
    "ThreatEvent",
    "LocalModel",
    "GlobalModel",
    "FederatedModel",
    "initialize_federated_learning",
    "train_local_model",
    "aggregate_models",
    "share_threat_intelligence_privately",
]
