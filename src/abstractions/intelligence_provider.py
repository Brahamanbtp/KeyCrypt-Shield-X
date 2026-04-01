"""Abstract interface and shared models for intelligent security components.

This module defines a provider-agnostic contract for AI/ML services used in
security decisioning, anomaly detection, and cryptographic algorithm selection.

The goal is to let orchestration layers interact with diverse intelligent
implementations through a stable abstraction while preserving strong type
contracts for inputs and outputs.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence


@dataclass(frozen=True)
class SecurityContext:
    """Normalized security context used for risk prediction.

    Attributes:
        asset_id: Identifier of the protected asset or workflow.
        actor_id: Principal initiating or associated with the operation.
        operation: Operation being performed, such as encrypt, decrypt, or rotate.
        telemetry_features: Numeric feature vector derived from runtime telemetry.
        current_threat_level: Current threat indicator in the range [0.0, 1.0].
        sensitivity: Data sensitivity level in the range [0.0, 1.0].
        metadata: Additional contextual attributes.
    """

    asset_id: str
    actor_id: str
    operation: str
    telemetry_features: Sequence[float] = field(default_factory=tuple)
    current_threat_level: float = 0.0
    sensitivity: float = 0.5
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SecurityEvent:
    """Structured event representation used for anomaly scoring.

    Attributes:
        event_id: Unique event identifier.
        event_type: Event classification, such as authentication or key_management.
        timestamp: UNIX timestamp in seconds.
        source: Event source subsystem.
        features: Numeric feature vector representing event behavior.
        metadata: Additional event attributes.
    """

    event_id: str
    event_type: str
    timestamp: float
    source: str
    features: Sequence[float] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DataProfile:
    """Data characteristics used for algorithm recommendation.

    Attributes:
        data_type: Logical data type, for example file, stream, or message.
        size_bytes: Approximate payload size in bytes.
        latency_budget_ms: Maximum acceptable processing latency in milliseconds.
        confidentiality_level: Confidentiality requirement in [0.0, 1.0].
        integrity_level: Integrity requirement in [0.0, 1.0].
        compliance_tags: Compliance labels such as pci, hipaa, or export_control.
        metadata: Additional profile descriptors.
    """

    data_type: str
    size_bytes: int
    latency_budget_ms: float
    confidentiality_level: float = 0.8
    integrity_level: float = 0.8
    compliance_tags: Sequence[str] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RiskScore:
    """Risk prediction output with value constrained to [0.0, 1.0].

    Attributes:
        value: Risk score where 0.0 is minimal risk and 1.0 is maximal risk.
        confidence: Model confidence for the prediction in [0.0, 1.0].
        rationale: Optional explainability summary.
        metadata: Additional model output details.
    """

    value: float
    confidence: float = 1.0
    rationale: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not 0.0 <= self.value <= 1.0:
            raise ValueError("RiskScore.value must be in range [0.0, 1.0]")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("RiskScore.confidence must be in range [0.0, 1.0]")


@dataclass(frozen=True)
class AnomalyScore:
    """Anomaly detection output with normalized score in [0.0, 1.0].

    Attributes:
        value: Anomaly score where higher values indicate stronger anomalies.
        threshold: Decision threshold used to classify anomalous behavior.
        is_anomalous: Boolean classification derived from score and threshold.
        metadata: Additional model-specific scoring details.
    """

    value: float
    threshold: float = 0.5
    is_anomalous: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not 0.0 <= self.value <= 1.0:
            raise ValueError("AnomalyScore.value must be in range [0.0, 1.0]")
        if not 0.0 <= self.threshold <= 1.0:
            raise ValueError("AnomalyScore.threshold must be in range [0.0, 1.0]")


@dataclass(frozen=True)
class AlgorithmRecommendation:
    """Recommended cryptographic algorithm with supporting rationale.

    Attributes:
        algorithm_name: Recommended algorithm/profile identifier.
        confidence: Recommendation confidence in [0.0, 1.0].
        security_level: Integer security level for policy evaluation.
        rationale: Human-readable explanation for recommendation selection.
        alternatives: Optional ranked alternative algorithm names.
        metadata: Additional provider-specific recommendation details.
    """

    algorithm_name: str
    confidence: float
    security_level: int
    rationale: str
    alternatives: Sequence[str] = field(default_factory=tuple)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.algorithm_name.strip():
            raise ValueError("algorithm_name must be non-empty")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be in range [0.0, 1.0]")
        if self.security_level <= 0:
            raise ValueError("security_level must be positive")


class IntelligenceProvider(ABC):
    """Abstract base class for intelligent security providers.

    Concrete implementations may use classical ML, deep learning, graph models,
    or rule-augmented systems. This interface standardizes integration points
    for orchestration layers while allowing implementation-level flexibility.
    """

    @abstractmethod
    def predict_risk(self, context: SecurityContext) -> RiskScore:
        """Predict normalized risk score for the supplied security context.

        Args:
            context: Security context containing telemetry and policy signals.

        Returns:
            A ``RiskScore`` with ``value`` constrained to [0.0, 1.0].

        Raises:
            ValueError: If context fields are invalid or incomplete.
            RuntimeError: If model inference fails.
        """

    @abstractmethod
    def detect_anomaly(self, event: SecurityEvent) -> AnomalyScore:
        """Score event anomalousness using provider-specific detection logic.

        Args:
            event: Structured security event to evaluate.

        Returns:
            An ``AnomalyScore`` describing anomaly strength and classification.

        Raises:
            ValueError: If event is invalid.
            RuntimeError: If anomaly inference fails.
        """

    @abstractmethod
    def suggest_algorithm(self, data_profile: DataProfile) -> AlgorithmRecommendation:
        """Recommend cryptographic algorithm selection for a data profile.

        Args:
            data_profile: Data characteristics and constraints.

        Returns:
            An ``AlgorithmRecommendation`` tailored to profile constraints.

        Raises:
            ValueError: If profile values are invalid.
            RuntimeError: If recommendation generation fails.
        """
