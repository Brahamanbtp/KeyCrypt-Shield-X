"""AutoML-based algorithm selection for encryption workflows.

PRESERVE: AI algorithm selection
EXTEND: Automated optimization

This module trains a lightweight selector that maps data characteristics to the
best encryption algorithm. It prefers scikit-learn when available and falls
back to a pure-Python centroid model when optional ML dependencies are absent.
The feature surface includes data size, entropy, compression ratio, performance
constraints, hardware capabilities, and threat level.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from math import exp, log1p, sqrt
from statistics import mean
from typing import Any, Mapping, Sequence

from src.abstractions.intelligence_provider import AlgorithmRecommendation, DataProfile

try:  # pragma: no cover - optional dependency boundary
    from sklearn.feature_extraction import DictVectorizer
    from sklearn.tree import DecisionTreeClassifier
except Exception as exc:  # pragma: no cover - optional dependency boundary
    DictVectorizer = None  # type: ignore[assignment]
    DecisionTreeClassifier = None  # type: ignore[assignment]
    _SKLEARN_IMPORT_ERROR = exc
else:
    _SKLEARN_IMPORT_ERROR = None


AlgorithmID = str


@dataclass(frozen=True)
class EncryptionExample:
    """Supervised example for algorithm selection training."""

    data_profile: DataProfile
    algorithm_name: AlgorithmID
    observed_latency_ms: float | None = None
    observed_security_score: float | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PerformanceFeedback:
    """Observed post-deployment performance used for online updates."""

    data_profile: DataProfile
    algorithm_name: AlgorithmID
    actual_latency_ms: float
    actual_security_score: float
    succeeded: bool = True
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ModelMetrics:
    """Aggregate metrics for model evaluation."""

    accuracy: float
    precision_macro: float
    recall_macro: float
    f1_macro: float
    samples: int
    backend: str
    notes: tuple[str, ...] = ()


@dataclass
class AlgorithmSelectionModel:
    """Trained model wrapper returned by the selector."""

    backend: str
    label_names: tuple[str, ...]
    feature_names: tuple[str, ...]
    training_examples: list[EncryptionExample] = field(default_factory=list)
    estimator: Any | None = None
    vectorizer: Any | None = None
    class_centroids: dict[str, dict[str, float]] = field(default_factory=dict)
    class_priors: dict[str, float] = field(default_factory=dict)
    trained_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def predict_proba(self, profile: DataProfile, selector: "AutoMLAlgorithmSelector") -> dict[str, float]:
        """Return normalized probabilities for each algorithm label."""
        features = selector._vectorize_features(selector._extract_features(profile))
        if self.backend == "sklearn" and self.estimator is not None and self.vectorizer is not None:
            vector = self.vectorizer.transform([features])
            probabilities = self.estimator.predict_proba(vector)[0]
            classes = [str(label) for label in self.estimator.classes_]
            return {label: float(probability) for label, probability in zip(classes, probabilities)}

        scores = selector._centroid_scores(features, self.class_centroids, self.class_priors, self.feature_names)
        return selector._softmax(scores)

    def predict(self, profile: DataProfile, selector: "AutoMLAlgorithmSelector") -> tuple[str, float]:
        probabilities = self.predict_proba(profile, selector)
        if not probabilities:
            return selector._default_algorithm(profile), 0.0
        best_label = max(probabilities, key=probabilities.get)
        return best_label, probabilities[best_label]


Model = AlgorithmSelectionModel
Metrics = ModelMetrics


class AutoMLAlgorithmSelector:
    """Automatically learns encryption algorithm selection from examples."""

    def __init__(self, *, default_algorithm: str = "aes-gcm") -> None:
        self._default_algorithm_name = default_algorithm
        self._model: AlgorithmSelectionModel | None = None
        self._training_examples: list[EncryptionExample] = []

    def train_algorithm_selector(self, training_data: list[EncryptionExample]) -> Model:
        """Trains ML model to select optimal algorithm."""
        if not training_data:
            raise ValueError("training_data must not be empty")

        self._training_examples = [self._validate_example(example) for example in training_data]
        labels = tuple(sorted({example.algorithm_name for example in self._training_examples}))
        feature_names = self._feature_names(self._training_examples)

        model = AlgorithmSelectionModel(
            backend="fallback",
            label_names=labels,
            feature_names=feature_names,
            training_examples=list(self._training_examples),
        )

        if self._can_use_sklearn(labels):
            estimator, vectorizer = self._train_sklearn_model(self._training_examples)
            if estimator is not None and vectorizer is not None:
                model.backend = "sklearn"
                model.estimator = estimator
                model.vectorizer = vectorizer
                self._model = model
                return model

        model.class_centroids, model.class_priors = self._build_centroid_model(self._training_examples)
        self._model = model
        return model

    def predict_optimal_algorithm(self, data_profile: DataProfile) -> AlgorithmRecommendation:
        """Predicts best algorithm for given data characteristics."""
        self._validate_profile(data_profile)
        model = self._ensure_model()

        probability_map = model.predict_proba(data_profile, self)
        best_algorithm = max(probability_map, key=probability_map.get)
        confidence = self._clamp01(probability_map.get(best_algorithm, 0.0))

        recommendation = AlgorithmRecommendation(
            algorithm_name=best_algorithm,
            confidence=confidence,
            security_level=self._security_level_for_algorithm(best_algorithm),
            rationale=self._build_rationale(data_profile, best_algorithm, probability_map),
            alternatives=tuple(self._rank_alternatives(best_algorithm, probability_map)),
            metadata={
                "backend": model.backend,
                "model_trained_at": model.trained_at.isoformat(),
                "feature_vector": self._extract_features(data_profile),
                "probabilities": probability_map,
                "training_examples": len(model.training_examples),
            },
        )
        return recommendation

    def evaluate_model_performance(self, test_data: list[EncryptionExample]) -> Metrics:
        """Evaluates prediction accuracy."""
        if not test_data:
            raise ValueError("test_data must not be empty")

        model = self._ensure_model()
        normalized_test = [self._validate_example(example) for example in test_data]
        actual_labels = [example.algorithm_name for example in normalized_test]
        predicted_labels = [model.predict(example.data_profile, self)[0] for example in normalized_test]

        label_set = sorted(set(actual_labels) | set(predicted_labels) | set(model.label_names))
        accuracy = sum(1 for actual, predicted in zip(actual_labels, predicted_labels) if actual == predicted) / len(normalized_test)

        precision_values: list[float] = []
        recall_values: list[float] = []
        f1_values: list[float] = []
        for label in label_set:
            tp = sum(1 for actual, predicted in zip(actual_labels, predicted_labels) if actual == label and predicted == label)
            fp = sum(1 for actual, predicted in zip(actual_labels, predicted_labels) if actual != label and predicted == label)
            fn = sum(1 for actual, predicted in zip(actual_labels, predicted_labels) if actual == label and predicted != label)

            precision = tp / max(tp + fp, 1)
            recall = tp / max(tp + fn, 1)
            f1 = 2 * precision * recall / max(precision + recall, 1e-12)
            precision_values.append(precision)
            recall_values.append(recall)
            f1_values.append(f1)

        return Metrics(
            accuracy=accuracy,
            precision_macro=mean(precision_values) if precision_values else 0.0,
            recall_macro=mean(recall_values) if recall_values else 0.0,
            f1_macro=mean(f1_values) if f1_values else 0.0,
            samples=len(normalized_test),
            backend=model.backend,
            notes=("evaluated against supervised labels",),
        )

    def update_model_online(self, feedback: list[PerformanceFeedback]) -> None:
        """Online learning from actual performance."""
        if not feedback:
            return

        new_examples = [
            EncryptionExample(
                data_profile=item.data_profile,
                algorithm_name=item.algorithm_name,
                observed_latency_ms=item.actual_latency_ms,
                observed_security_score=item.actual_security_score,
                metadata={**dict(item.metadata), "succeeded": item.succeeded},
            )
            for item in feedback
        ]
        self.train_algorithm_selector([*self._training_examples, *new_examples])

    def _ensure_model(self) -> AlgorithmSelectionModel:
        if self._model is None:
            raise RuntimeError("model has not been trained yet")
        return self._model

    def _validate_example(self, example: EncryptionExample) -> EncryptionExample:
        if not isinstance(example, EncryptionExample):
            raise TypeError("training examples must be EncryptionExample instances")
        self._validate_profile(example.data_profile)
        if not isinstance(example.algorithm_name, str) or not example.algorithm_name.strip():
            raise ValueError("algorithm_name must be a non-empty string")
        return example

    def _validate_profile(self, profile: DataProfile) -> None:
        if not isinstance(profile, DataProfile):
            raise TypeError("data_profile must be DataProfile")

    def _can_use_sklearn(self, labels: tuple[str, ...]) -> bool:
        return DictVectorizer is not None and DecisionTreeClassifier is not None and len(labels) >= 2

    def _train_sklearn_model(self, examples: Sequence[EncryptionExample]) -> tuple[Any | None, Any | None]:
        if DictVectorizer is None or DecisionTreeClassifier is None:
            return None, None

        vectorizer = DictVectorizer(sparse=False)
        feature_rows = [self._vectorize_features(self._extract_features(example.data_profile, example)) for example in examples]
        labels = [example.algorithm_name for example in examples]

        matrix = vectorizer.fit_transform(feature_rows)
        estimator = DecisionTreeClassifier(random_state=17, class_weight="balanced")
        estimator.fit(matrix, labels)
        return estimator, vectorizer

    def _build_centroid_model(self, examples: Sequence[EncryptionExample]) -> tuple[dict[str, dict[str, float]], dict[str, float]]:
        centroids: dict[str, dict[str, float]] = {}
        priors: dict[str, float] = {}
        grouped: dict[str, list[dict[str, float]]] = {}
        feature_names = self._feature_names(examples)

        for example in examples:
            grouped.setdefault(example.algorithm_name, []).append(
                self._vectorize_features(self._extract_features(example.data_profile, example))
            )

        total = float(len(examples))
        for label, rows in grouped.items():
            priors[label] = len(rows) / total
            centroid: dict[str, float] = {}
            for feature_name in feature_names:
                values = [float(row.get(feature_name, 0.0)) for row in rows]
                centroid[feature_name] = mean(values) if values else 0.0
            centroids[label] = centroid

        return centroids, priors

    def _feature_names(self, examples: Sequence[EncryptionExample] | None = None) -> tuple[str, ...]:
        if not examples:
            return (
                "size_log10",
                "entropy_normalized",
                "compression_ratio",
                "latency_budget_ms",
                "speed_priority",
                "security_priority",
                "threat_level",
                "confidentiality_level",
                "integrity_level",
                "compression_signal",
                "hardware_aes_ni",
                "hardware_gpu",
                "hardware_avx2",
                "hardware_arm_crypto",
                "compliance_tag_count",
                "quantum_risk_level",
            )

        feature_keys: set[str] = set()
        for example in examples:
            feature_keys.update(self._vectorize_features(self._extract_features(example.data_profile, example)).keys())
        return tuple(sorted(feature_keys))

    def _extract_features(self, profile: DataProfile, example: EncryptionExample | None = None) -> dict[str, Any]:
        metadata = self._combined_metadata(profile, example)
        size_bytes = max(int(profile.size_bytes), 0)
        latency_budget_ms = max(float(profile.latency_budget_ms), 0.0)
        confidentiality = self._clamp01(float(profile.confidentiality_level))
        integrity = self._clamp01(float(profile.integrity_level))

        entropy_raw = self._coerce_float(metadata, ("entropy", "entropy_bits_per_byte", "normalized_entropy"), default=0.0)
        entropy_normalized = self._normalize_entropy(entropy_raw)

        compression_ratio = self._coerce_float(metadata, ("compression_ratio", "compression"), default=1.0)
        compression_ratio = max(compression_ratio, 0.0)

        speed_priority = self._clamp01(
            self._coerce_float(metadata, ("speed_priority", "performance_speed", "latency_sensitivity"), default=self._speed_priority_from_latency(latency_budget_ms))
        )
        security_priority = self._clamp01(
            self._coerce_float(metadata, ("security_priority", "security_bias", "threat_sensitivity"), default=self._security_priority_from_cia(confidentiality, integrity))
        )
        threat_level = self._clamp01(
            self._coerce_float(metadata, ("threat_level", "current_threat_level", "risk_level"), default=0.0)
        )

        data_type = str(profile.data_type or "unknown").strip().lower() or "unknown"
        size_bucket = self._size_bucket(size_bytes)
        quantum_risk_level = self._quantum_risk_level(metadata)
        hardware_flags = self._hardware_flags(metadata)
        compliance_tags = [tag for tag in profile.compliance_tags if isinstance(tag, str) and tag.strip()]

        features: dict[str, Any] = {
            "size_log10": log1p(size_bytes) / 10.0,
            "entropy_normalized": entropy_normalized,
            "compression_ratio": compression_ratio,
            "latency_budget_ms": float(latency_budget_ms),
            "speed_priority": speed_priority,
            "security_priority": security_priority,
            "threat_level": threat_level,
            "confidentiality_level": confidentiality,
            "integrity_level": integrity,
            "compression_signal": self._compression_signal(compression_ratio, size_bytes),
            "data_type": data_type,
            "size_bucket": size_bucket,
            "hardware_aes_ni": hardware_flags["hardware_aes_ni"],
            "hardware_gpu": hardware_flags["hardware_gpu"],
            "hardware_avx2": hardware_flags["hardware_avx2"],
            "hardware_arm_crypto": hardware_flags["hardware_arm_crypto"],
            "compliance_tag_count": len(compliance_tags),
            "quantum_risk_level": quantum_risk_level,
        }
        return features

    def _vectorize_features(self, features: Mapping[str, Any]) -> dict[str, float]:
        vector: dict[str, float] = {}
        for key, value in features.items():
            if isinstance(value, bool):
                vector[key] = 1.0 if value else 0.0
            elif isinstance(value, (int, float)):
                vector[key] = float(value)
            elif isinstance(value, str):
                normalized = value.strip().lower().replace(" ", "-")
                if not normalized:
                    continue
                vector[f"{key}={normalized}"] = 1.0
            elif isinstance(value, Sequence):
                for item in value:
                    if isinstance(item, str):
                        normalized = item.strip().lower().replace(" ", "-")
                        if normalized:
                            vector[f"{key}={normalized}"] = 1.0
        return vector

    def _combined_metadata(self, profile: DataProfile, example: EncryptionExample | None) -> dict[str, Any]:
        combined = dict(profile.metadata)
        if example is not None:
            combined.update(dict(example.metadata))
            if example.observed_latency_ms is not None:
                combined.setdefault("observed_latency_ms", example.observed_latency_ms)
            if example.observed_security_score is not None:
                combined.setdefault("observed_security_score", example.observed_security_score)
        return combined

    def _coerce_float(self, metadata: Mapping[str, Any], keys: Sequence[str], default: float) -> float:
        for key in keys:
            value = metadata.get(key)
            if isinstance(value, (int, float)):
                return float(value)
            if isinstance(value, str):
                try:
                    return float(value.strip())
                except ValueError:
                    continue
        return float(default)

    def _normalize_entropy(self, value: float) -> float:
        if value <= 0.0:
            return 0.0
        if value > 1.0:
            return self._clamp01(value / 8.0)
        return self._clamp01(value)

    def _speed_priority_from_latency(self, latency_budget_ms: float) -> float:
        return self._clamp01(1.0 - min(latency_budget_ms, 500.0) / 500.0)

    def _security_priority_from_cia(self, confidentiality: float, integrity: float) -> float:
        return self._clamp01((confidentiality + integrity) / 2.0)

    def _size_bucket(self, size_bytes: int) -> str:
        if size_bytes < 1024 * 1024:
            return "small"
        if size_bytes < 100 * 1024 * 1024:
            return "medium"
        return "large"

    def _quantum_risk_level(self, metadata: Mapping[str, Any]) -> float:
        quantum_risk = str(metadata.get("quantum_risk", metadata.get("quantum_risk_level", ""))).strip().lower()
        if quantum_risk in {"critical", "high"}:
            return 1.0
        if quantum_risk in {"medium", "moderate"}:
            return 0.5
        if quantum_risk in {"low", "none"}:
            return 0.0
        return self._clamp01(self._coerce_float(metadata, ("quantum_risk_score",), default=0.0))

    def _hardware_flags(self, metadata: Mapping[str, Any]) -> dict[str, bool]:
        raw_hardware = metadata.get("hardware_available", metadata.get("hardware", metadata.get("accelerators", ())))
        tokens: set[str] = set()
        if isinstance(raw_hardware, str):
            tokens.add(raw_hardware)
        elif isinstance(raw_hardware, Mapping):
            tokens.update(str(key) for key, value in raw_hardware.items() if value)
        elif isinstance(raw_hardware, Sequence):
            for item in raw_hardware:
                if isinstance(item, str):
                    tokens.add(item)
                elif isinstance(item, Mapping):
                    tokens.update(str(key) for key, value in item.items() if value)

        normalized = {self._normalize_hardware_token(token) for token in tokens}
        return {
            "hardware_aes_ni": bool({"aes-ni", "aesni", "aes_ni", "aes"}.intersection(normalized)),
            "hardware_gpu": bool({"gpu", "cuda", "nvidia"}.intersection(normalized)),
            "hardware_avx2": bool({"avx2", "avx-2"}.intersection(normalized)),
            "hardware_arm_crypto": bool({"arm-crypto", "arm_crypto", "neon", "armv8-crypto"}.intersection(normalized)),
        }

    def _normalize_hardware_token(self, token: str) -> str:
        return token.strip().lower().replace(" ", "-").replace("_", "-")

    def _compression_signal(self, compression_ratio: float, size_bytes: int) -> float:
        if size_bytes <= 0:
            return 0.0
        if compression_ratio <= 0.0:
            return 1.0
        if compression_ratio >= 1.0:
            return self._clamp01(1.0 / compression_ratio)
        return self._clamp01(1.0 - compression_ratio)

    def _centroid_scores(
        self,
        features: Mapping[str, float],
        centroids: Mapping[str, Mapping[str, float]],
        priors: Mapping[str, float],
        feature_names: Sequence[str],
    ) -> dict[str, float]:
        scores: dict[str, float] = {}
        for label, centroid in centroids.items():
            distance = sqrt(
                sum(
                    (float(features.get(feature_name, 0.0)) - float(centroid.get(feature_name, 0.0))) ** 2
                    for feature_name in feature_names
                )
            )
            scores[label] = (priors.get(label, 0.0) + 1e-6) / (1.0 + distance)
        return scores

    def _softmax(self, scores: Mapping[str, float]) -> dict[str, float]:
        if not scores:
            return {}
        max_score = max(scores.values())
        exps = {label: exp(score - max_score) for label, score in scores.items()}
        total = sum(exps.values()) or 1.0
        return {label: value / total for label, value in exps.items()}

    def _default_algorithm(self, profile: DataProfile) -> str:
        features = self._extract_features(profile)
        if features["quantum_risk_level"] >= 0.75 or features["security_priority"] >= 0.9:
            return "hybrid-kem"
        if features["hardware_aes_ni"] and features["security_priority"] >= 0.7:
            return "aes-gcm"
        if features["speed_priority"] >= 0.8 or features["latency_budget_ms"] <= 10.0:
            return "chacha20"
        return self._default_algorithm_name

    def _build_rationale(
        self,
        profile: DataProfile,
        algorithm_name: str,
        probability_map: Mapping[str, float],
    ) -> str:
        features = self._extract_features(profile)
        reasons: list[str] = []

        if features["quantum_risk_level"] >= 0.75:
            reasons.append("high quantum risk")
        if features["security_priority"] >= 0.85:
            reasons.append("strong security preference")
        if features["speed_priority"] >= 0.75 or features["latency_budget_ms"] <= 15.0:
            reasons.append("tight latency budget")
        if features["hardware_aes_ni"]:
            reasons.append("AES-NI available")
        if features["hardware_gpu"]:
            reasons.append("GPU available")
        if features["compression_signal"] > 0.5:
            reasons.append("compressible payload")

        if not reasons:
            reasons.append("balanced workload characteristics")

        probability = probability_map.get(algorithm_name, 0.0)
        return (
            f"AutoML selector chose {algorithm_name} with probability {probability:.2f} "
            f"based on {', '.join(reasons)}."
        )

    def _rank_alternatives(self, winner: str, probability_map: Mapping[str, float]) -> list[str]:
        return [label for label, _probability in sorted(probability_map.items(), key=lambda item: item[1], reverse=True) if label != winner]

    def _security_level_for_algorithm(self, algorithm_name: str) -> int:
        normalized = algorithm_name.strip().lower()
        if "hybrid" in normalized or "kem" in normalized:
            return 5
        if "gcm" in normalized or "chacha" in normalized:
            return 4
        if normalized:
            return 3
        return 1

    def _clamp01(self, value: float) -> float:
        return max(0.0, min(1.0, float(value)))


__all__ = [
    "AlgorithmID",
    "EncryptionExample",
    "PerformanceFeedback",
    "ModelMetrics",
    "AlgorithmSelectionModel",
    "Model",
    "Metrics",
    "AutoMLAlgorithmSelector",
]