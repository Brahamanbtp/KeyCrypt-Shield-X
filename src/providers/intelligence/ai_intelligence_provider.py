"""AI-backed intelligence provider implementation.

This provider wraps existing modules in src/ai using composition without
modifying upstream model implementations:
- src/ai/risk_predictor.py (LSTM risk predictor)
- src/ai/anomaly_detection.py (autoencoder anomaly detector)

Models are loaded lazily on first use and support version tracking and runtime
update hooks.
"""

from __future__ import annotations

import math
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from src.abstractions.intelligence_provider import (
    AlgorithmRecommendation,
    AnomalyScore,
    DataProfile,
    IntelligenceProvider,
    RiskScore,
    SecurityContext,
    SecurityEvent,
)

try:
    import torch
except Exception as exc:  # pragma: no cover - optional dependency boundary
    torch = None  # type: ignore[assignment]
    _TORCH_IMPORT_ERROR = exc
else:
    _TORCH_IMPORT_ERROR = None

try:
    from src.ai.risk_predictor import RiskPredictor, load_model as load_risk_model
except Exception as exc:  # pragma: no cover - optional dependency boundary
    RiskPredictor = None  # type: ignore[assignment]
    load_risk_model = None  # type: ignore[assignment]
    _RISK_MODEL_IMPORT_ERROR = exc
else:
    _RISK_MODEL_IMPORT_ERROR = None

try:
    from src.ai.anomaly_detection import AnomalyDetector, SecurityAutoencoder
except Exception as exc:  # pragma: no cover - optional dependency boundary
    AnomalyDetector = None  # type: ignore[assignment]
    SecurityAutoencoder = None  # type: ignore[assignment]
    _ANOMALY_MODEL_IMPORT_ERROR = exc
else:
    _ANOMALY_MODEL_IMPORT_ERROR = None


@dataclass(frozen=True)
class _AlgorithmDecision:
    algorithm_name: str
    confidence: float
    security_level: int
    rationale: str
    alternatives: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


class AIIntelligenceProvider(IntelligenceProvider):
    """IntelligenceProvider using composed AI modules from src/ai."""

    def __init__(
        self,
        *,
        risk_model_path: str | Path | None = None,
        anomaly_model_path: str | Path | None = None,
        device: str = "cpu",
        risk_input_size: int = 16,
        risk_sequence_length: int = 8,
        anomaly_input_dim: int = 64,
        default_anomaly_threshold: float = 0.10,
        risk_model_version: str | None = None,
        anomaly_model_version: str | None = None,
    ) -> None:
        if risk_input_size <= 0:
            raise ValueError("risk_input_size must be > 0")
        if risk_sequence_length <= 0:
            raise ValueError("risk_sequence_length must be > 0")
        if anomaly_input_dim <= 0:
            raise ValueError("anomaly_input_dim must be > 0")
        if default_anomaly_threshold <= 0:
            raise ValueError("default_anomaly_threshold must be > 0")

        self._lock = threading.RLock()

        self._device = device
        self._risk_input_size = int(risk_input_size)
        self._risk_sequence_length = int(risk_sequence_length)
        self._anomaly_input_dim = int(anomaly_input_dim)
        self._default_anomaly_threshold = float(default_anomaly_threshold)

        self._risk_model_path = self._normalize_optional_path(risk_model_path)
        self._anomaly_model_path = self._normalize_optional_path(anomaly_model_path)

        self._risk_model: Any | None = None
        self._anomaly_detector: Any | None = None

        self._risk_model_extra: dict[str, Any] = {}
        self._anomaly_model_extra: dict[str, Any] = {}

        self._risk_model_version = self._resolve_initial_version(
            explicit=risk_model_version,
            path=self._risk_model_path,
            fallback="risk-lstm-bootstrap-v1",
            prefix="risk",
        )
        self._anomaly_model_version = self._resolve_initial_version(
            explicit=anomaly_model_version,
            path=self._anomaly_model_path,
            fallback="anomaly-autoencoder-bootstrap-v1",
            prefix="anomaly",
        )

        self._models_updated_at = time.time()

    def predict_risk(self, context: SecurityContext) -> RiskScore:
        """Predict risk score from security context using LSTM inference."""
        if not isinstance(context, SecurityContext):
            raise TypeError("context must be SecurityContext")

        if not self._ai_dependencies_available():
            heuristic_score = self._heuristic_risk(context)
            return RiskScore(
                value=heuristic_score,
                confidence=0.45,
                rationale=(
                    "Fallback risk heuristic used because AI model dependencies "
                    "are unavailable in this runtime."
                ),
                metadata={
                    "provider": "AIIntelligenceProvider",
                    "fallback": True,
                    "model": "risk_predictor_lstm",
                    "model_version": self._risk_model_version,
                    "dependency_errors": self._dependency_error_snapshot(),
                },
            )

        model = self._ensure_risk_model(context)
        tensor = self._build_risk_tensor(context, input_size=int(model.input_size))

        assert torch is not None
        model.eval()
        with torch.no_grad():
            raw_scores, attention = model(tensor)

        model_score = self._clamp01(float(raw_scores.squeeze().item()))
        heuristic_score = self._heuristic_risk(context)

        has_checkpoint = self._risk_model_path is not None
        model_weight = 0.80 if has_checkpoint else 0.55
        blended_score = self._clamp01(model_weight * model_score + (1.0 - model_weight) * heuristic_score)

        confidence = self._attention_confidence(attention=attention, has_checkpoint=has_checkpoint)
        rationale = (
            "Risk predicted via LSTM telemetry model and contextual heuristic blend: "
            f"model={model_score:.3f}, heuristic={heuristic_score:.3f}"
        )

        return RiskScore(
            value=blended_score,
            confidence=confidence,
            rationale=rationale,
            metadata={
                "provider": "AIIntelligenceProvider",
                "model": "risk_predictor_lstm",
                "model_version": self._risk_model_version,
                "model_score": model_score,
                "heuristic_score": heuristic_score,
                "input_size": int(model.input_size),
                "sequence_length": self._risk_sequence_length,
                "model_extra": dict(self._risk_model_extra),
            },
        )

    def detect_anomaly(self, event: SecurityEvent) -> AnomalyScore:
        """Detect event anomalousness using autoencoder reconstruction error."""
        if not isinstance(event, SecurityEvent):
            raise TypeError("event must be SecurityEvent")

        if not self._ai_dependencies_available():
            score = self._fallback_anomaly_score(event)
            threshold = 0.70
            return AnomalyScore(
                value=score,
                threshold=threshold,
                is_anomalous=score >= threshold,
                metadata={
                    "provider": "AIIntelligenceProvider",
                    "fallback": True,
                    "model": "security_autoencoder",
                    "model_version": self._anomaly_model_version,
                    "dependency_errors": self._dependency_error_snapshot(),
                    "event_type": event.event_type,
                    "event_source": event.source,
                },
            )

        detector = self._ensure_anomaly_detector()
        input_dim = int(detector.model.input_dim)
        event_tensor = self._build_anomaly_tensor(event.features, input_dim=input_dim)

        assert torch is not None
        detector.model.eval()
        with torch.no_grad():
            reconstructed, _latent = detector.model(event_tensor)
            reconstruction_error = float(torch.mean((event_tensor - reconstructed) ** 2).item())

        raw_threshold = float(detector.threshold if detector.threshold is not None else self._default_anomaly_threshold)
        is_anomalous = reconstruction_error > raw_threshold

        # Normalize error into [0, 1] while preserving threshold crossing behavior.
        normalized_score = reconstruction_error / (reconstruction_error + max(raw_threshold, 1e-12))

        return AnomalyScore(
            value=self._clamp01(normalized_score),
            threshold=0.5,
            is_anomalous=is_anomalous,
            metadata={
                "provider": "AIIntelligenceProvider",
                "model": "security_autoencoder",
                "model_version": self._anomaly_model_version,
                "reconstruction_error": reconstruction_error,
                "raw_threshold": raw_threshold,
                "input_dim": input_dim,
                "model_extra": dict(self._anomaly_model_extra),
                "event_type": event.event_type,
                "event_source": event.source,
            },
        )

    def suggest_algorithm(self, data_profile: DataProfile) -> AlgorithmRecommendation:
        """Suggest crypto algorithm through a profile-driven decision tree."""
        if not isinstance(data_profile, DataProfile):
            raise TypeError("data_profile must be DataProfile")

        decision = self._algorithm_decision_tree(data_profile)
        return AlgorithmRecommendation(
            algorithm_name=decision.algorithm_name,
            confidence=self._clamp01(decision.confidence),
            security_level=decision.security_level,
            rationale=decision.rationale,
            alternatives=decision.alternatives,
            metadata={
                **decision.metadata,
                "provider": "AIIntelligenceProvider",
                "decision_model": "profile_decision_tree",
                "risk_model_version": self._risk_model_version,
                "anomaly_model_version": self._anomaly_model_version,
            },
        )

    def get_model_versions(self) -> dict[str, str]:
        """Return tracked model versions and last update timestamp."""
        with self._lock:
            return {
                "risk_predictor": self._risk_model_version,
                "anomaly_detector": self._anomaly_model_version,
                "updated_at": str(self._models_updated_at),
            }

    def update_models(
        self,
        *,
        risk_model_path: str | Path | None = None,
        anomaly_model_path: str | Path | None = None,
        risk_version: str | None = None,
        anomaly_version: str | None = None,
        default_anomaly_threshold: float | None = None,
    ) -> dict[str, str]:
        """Update model paths/versions and invalidate lazy-loaded instances."""
        with self._lock:
            if risk_model_path is not None:
                self._risk_model_path = self._normalize_optional_path(risk_model_path)
                self._risk_model = None
                self._risk_model_extra = {}

            if anomaly_model_path is not None:
                self._anomaly_model_path = self._normalize_optional_path(anomaly_model_path)
                self._anomaly_detector = None
                self._anomaly_model_extra = {}

            if risk_version is not None:
                normalized = self._normalize_optional_string(risk_version)
                if normalized is not None:
                    self._risk_model_version = normalized

            if anomaly_version is not None:
                normalized = self._normalize_optional_string(anomaly_version)
                if normalized is not None:
                    self._anomaly_model_version = normalized

            if default_anomaly_threshold is not None:
                if default_anomaly_threshold <= 0:
                    raise ValueError("default_anomaly_threshold must be > 0")
                self._default_anomaly_threshold = float(default_anomaly_threshold)
                if self._anomaly_detector is not None and self._anomaly_detector.threshold is None:
                    self._anomaly_detector.threshold = self._default_anomaly_threshold

            if risk_model_path is not None and risk_version is None and self._risk_model_path is not None:
                self._risk_model_version = self._derive_file_version(self._risk_model_path, prefix="risk")

            if anomaly_model_path is not None and anomaly_version is None and self._anomaly_model_path is not None:
                self._anomaly_model_version = self._derive_file_version(self._anomaly_model_path, prefix="anomaly")

            self._models_updated_at = time.time()
            return self.get_model_versions()

    def _ensure_risk_model(self, context: SecurityContext) -> Any:
        with self._lock:
            if self._risk_model is not None:
                return self._risk_model

            self._ensure_ai_dependencies()

            if self._risk_model_path is not None:
                assert load_risk_model is not None
                model, extra = load_risk_model(self._risk_model_path, device=self._device)
                self._risk_model = model
                self._risk_model_extra = dict(extra) if isinstance(extra, Mapping) else {}

                from_extra = self._normalize_optional_string(self._risk_model_extra.get("model_version"))
                if from_extra is not None:
                    self._risk_model_version = from_extra
                else:
                    self._risk_model_version = self._derive_file_version(self._risk_model_path, prefix="risk")

                self._risk_model.eval()
                return self._risk_model

            inferred_input_size = max(self._risk_input_size, len(context.telemetry_features), 4)

            assert torch is not None
            assert RiskPredictor is not None
            with torch.random.fork_rng():
                torch.manual_seed(17)
                model = RiskPredictor(input_size=inferred_input_size)

            model.to(self._device)
            model.eval()

            self._risk_model = model
            self._risk_model_extra = {"bootstrap": True, "initialized_from": "default-config"}
            if self._risk_model_path is None and "bootstrap" not in self._risk_model_version:
                self._risk_model_version = f"risk-lstm-bootstrap-v1-input{inferred_input_size}"

            return self._risk_model

    def _ensure_anomaly_detector(self) -> Any:
        with self._lock:
            if self._anomaly_detector is not None:
                return self._anomaly_detector

            self._ensure_ai_dependencies()

            if self._anomaly_model_path is not None:
                assert AnomalyDetector is not None
                detector, extra = AnomalyDetector.load(self._anomaly_model_path, device=self._device)
                self._anomaly_detector = detector
                self._anomaly_model_extra = dict(extra) if isinstance(extra, Mapping) else {}

                if self._anomaly_detector.threshold is None:
                    self._anomaly_detector.threshold = self._default_anomaly_threshold

                from_extra = self._normalize_optional_string(self._anomaly_model_extra.get("model_version"))
                if from_extra is not None:
                    self._anomaly_model_version = from_extra
                else:
                    self._anomaly_model_version = self._derive_file_version(
                        self._anomaly_model_path,
                        prefix="anomaly",
                    )

                return self._anomaly_detector

            assert torch is not None
            assert SecurityAutoencoder is not None
            assert AnomalyDetector is not None

            with torch.random.fork_rng():
                torch.manual_seed(29)
                model = SecurityAutoencoder(input_dim=self._anomaly_input_dim)

            detector = AnomalyDetector(model=model)
            detector.threshold = self._default_anomaly_threshold

            self._anomaly_detector = detector
            self._anomaly_model_extra = {"bootstrap": True, "initialized_from": "default-config"}
            if self._anomaly_model_path is None and "bootstrap" not in self._anomaly_model_version:
                self._anomaly_model_version = f"anomaly-autoencoder-bootstrap-v1-input{self._anomaly_input_dim}"

            return self._anomaly_detector

    def _algorithm_decision_tree(self, profile: DataProfile) -> _AlgorithmDecision:
        confidentiality = self._clamp01(float(profile.confidentiality_level))
        integrity = self._clamp01(float(profile.integrity_level))
        size_bytes = max(int(profile.size_bytes), 0)
        latency_budget_ms = max(float(profile.latency_budget_ms), 0.0)
        data_type = profile.data_type.strip().lower()

        tags = {tag.strip().lower() for tag in profile.compliance_tags if isinstance(tag, str) and tag.strip()}

        regulatory_tags = {
            "hipaa",
            "pci",
            "pci-dss",
            "gdpr",
            "nist",
            "nist-800-53",
            "fedramp",
            "fips",
        }
        has_regulatory_tag = bool(tags.intersection(regulatory_tags))

        quantum_risk = str(profile.metadata.get("quantum_risk", "")).strip().lower()
        requires_pqc = (
            confidentiality >= 0.95
            or quantum_risk in {"high", "critical"}
            or "post-quantum" in tags
            or "quantum-resistant" in tags
        )

        # Decision tree root: whether profile requires post-quantum resilience.
        if requires_pqc:
            # Branch: latency-constrained large payloads may favor high-throughput classical AEAD.
            if latency_budget_ms <= 15.0 and size_bytes >= 50 * 1024 * 1024:
                return _AlgorithmDecision(
                    algorithm_name="aes-gcm",
                    confidence=0.78,
                    security_level=4,
                    rationale=(
                        "Profile requests PQC-level posture but strict latency and very large payload "
                        "favor classical AEAD throughput with strong key-rotation controls."
                    ),
                    alternatives=("hybrid-kem", "kyber-768"),
                    metadata={"decision_path": "root:pqc -> latency-large-fallback"},
                )

            return _AlgorithmDecision(
                algorithm_name="hybrid-kem",
                confidence=0.93,
                security_level=5,
                rationale=(
                    "Profile indicates high confidentiality or quantum risk; selecting hybrid "
                    "classical plus PQC encapsulation for defense-in-depth."
                ),
                alternatives=("kyber-768", "aes-gcm"),
                metadata={"decision_path": "root:pqc -> hybrid"},
            )

        # Branch: regulatory and compliance-sensitive data.
        if has_regulatory_tag:
            if data_type in {"stream", "realtime", "transaction-stream"} or latency_budget_ms <= 10.0:
                return _AlgorithmDecision(
                    algorithm_name="chacha20",
                    confidence=0.84,
                    security_level=4,
                    rationale=(
                        "Regulated low-latency workload detected; selecting ChaCha20-Poly1305 profile "
                        "for consistent performance under software-accelerated environments."
                    ),
                    alternatives=("aes-gcm", "hybrid-kem"),
                    metadata={"decision_path": "root:regulated -> low-latency"},
                )

            return _AlgorithmDecision(
                algorithm_name="aes-gcm",
                confidence=0.89,
                security_level=4,
                rationale=(
                    "Regulated workload with balanced constraints; selecting AES-GCM for broad "
                    "compliance acceptance and strong authenticated encryption guarantees."
                ),
                alternatives=("chacha20", "hybrid-kem"),
                metadata={"decision_path": "root:regulated -> balanced"},
            )

        # Branch: high-integrity and confidentiality priorities without explicit regulation.
        if confidentiality >= 0.85 and integrity >= 0.85:
            return _AlgorithmDecision(
                algorithm_name="aes-gcm",
                confidence=0.86,
                security_level=4,
                rationale=(
                    "High confidentiality and integrity requirements indicate authenticated encryption "
                    "with strong hardware acceleration support."
                ),
                alternatives=("chacha20", "hybrid-kem"),
                metadata={"decision_path": "root:high-cia -> aes"},
            )

        # Branch: throughput-focused workloads.
        if size_bytes >= 100 * 1024 * 1024 and latency_budget_ms <= 25.0:
            return _AlgorithmDecision(
                algorithm_name="chacha20",
                confidence=0.79,
                security_level=3,
                rationale=(
                    "Large payload with moderate latency budget favors high-throughput stream-oriented "
                    "AEAD processing."
                ),
                alternatives=("aes-gcm",),
                metadata={"decision_path": "root:throughput -> chacha20"},
            )

        return _AlgorithmDecision(
            algorithm_name="aes-gcm",
            confidence=0.74,
            security_level=3,
            rationale="Default balanced recommendation for mixed workload characteristics.",
            alternatives=("chacha20", "hybrid-kem"),
            metadata={"decision_path": "root:default"},
        )

    def _build_risk_tensor(self, context: SecurityContext, *, input_size: int) -> Any:
        assert torch is not None

        telemetry = self._coerce_float_vector(context.telemetry_features)
        payload_size = self._safe_float(context.metadata.get("payload_size_bytes", 0.0))
        payload_feature = min(math.log10(max(payload_size, 0.0) + 1.0) / 8.0, 1.0)

        profile_features = [
            self._clamp01(float(context.current_threat_level)),
            self._clamp01(float(context.sensitivity)),
            self._clamp01(payload_feature),
            1.0 if str(context.operation).strip().lower() in {"rotate", "decrypt"} else 0.5,
        ]

        flat_features = telemetry + profile_features

        sequence_len = self._risk_sequence_length
        target_length = sequence_len * input_size

        if len(flat_features) < target_length:
            mean_value = sum(flat_features) / len(flat_features) if flat_features else 0.0
            flat_features.extend([mean_value] * (target_length - len(flat_features)))
        elif len(flat_features) > target_length:
            flat_features = flat_features[:target_length]

        rows: list[list[float]] = []
        for start in range(0, target_length, input_size):
            rows.append(flat_features[start : start + input_size])

        return torch.tensor([rows], dtype=torch.float32, device=self._device)

    def _build_anomaly_tensor(self, features: Sequence[float], *, input_dim: int) -> Any:
        assert torch is not None

        vector = self._coerce_float_vector(features)
        if len(vector) < input_dim:
            vector.extend([0.0] * (input_dim - len(vector)))
        elif len(vector) > input_dim:
            vector = vector[:input_dim]

        return torch.tensor([vector], dtype=torch.float32, device=self._device)

    def _heuristic_risk(self, context: SecurityContext) -> float:
        telemetry = self._coerce_float_vector(context.telemetry_features)

        if telemetry:
            magnitude = sum(abs(item) for item in telemetry) / len(telemetry)
            telemetry_signal = self._clamp01(math.tanh(magnitude))
        else:
            telemetry_signal = 0.0

        threat = self._clamp01(float(context.current_threat_level))
        sensitivity = self._clamp01(float(context.sensitivity))

        operation = str(context.operation).strip().lower()
        operation_bias = 0.15 if operation in {"rotate", "decrypt"} else 0.0

        score = (0.45 * threat) + (0.30 * sensitivity) + (0.20 * telemetry_signal) + operation_bias
        return self._clamp01(score)

    def _attention_confidence(self, *, attention: Any, has_checkpoint: bool) -> float:
        if attention is None:
            return 0.70 if has_checkpoint else 0.58

        assert torch is not None

        flattened = attention.detach().float().reshape(-1)
        if flattened.numel() == 0:
            return 0.70 if has_checkpoint else 0.58

        normalized = flattened / max(float(flattened.sum().item()), 1e-12)
        entropy = float(-(normalized * torch.log(normalized + 1e-12)).sum().item())
        max_entropy = math.log(max(int(normalized.numel()), 2))
        focus = 1.0 - min(entropy / max(max_entropy, 1e-12), 1.0)

        base = 0.58 + (0.27 * focus)
        if has_checkpoint:
            base += 0.10

        return self._clamp01(base)

    def _ensure_ai_dependencies(self) -> None:
        if torch is None:
            raise RuntimeError(
                "AIIntelligenceProvider requires torch at inference time"
                f"; import error: {_TORCH_IMPORT_ERROR}"
            )
        if RiskPredictor is None or load_risk_model is None:
            raise RuntimeError(
                "Risk predictor module is unavailable"
                f"; import error: {_RISK_MODEL_IMPORT_ERROR}"
            )
        if AnomalyDetector is None or SecurityAutoencoder is None:
            raise RuntimeError(
                "Anomaly detection module is unavailable"
                f"; import error: {_ANOMALY_MODEL_IMPORT_ERROR}"
            )

    @staticmethod
    def _ai_dependencies_available() -> bool:
        return not (
            torch is None
            or RiskPredictor is None
            or load_risk_model is None
            or AnomalyDetector is None
            or SecurityAutoencoder is None
        )

    @staticmethod
    def _dependency_error_snapshot() -> dict[str, str]:
        return {
            "torch": str(_TORCH_IMPORT_ERROR) if _TORCH_IMPORT_ERROR is not None else "ok",
            "risk_model": (
                str(_RISK_MODEL_IMPORT_ERROR) if _RISK_MODEL_IMPORT_ERROR is not None else "ok"
            ),
            "anomaly_model": (
                str(_ANOMALY_MODEL_IMPORT_ERROR) if _ANOMALY_MODEL_IMPORT_ERROR is not None else "ok"
            ),
        }

    def _fallback_anomaly_score(self, event: SecurityEvent) -> float:
        features = self._coerce_float_vector(event.features)
        if not features:
            return 0.0

        mean_abs = sum(abs(item) for item in features) / len(features)
        variance = sum((item - (sum(features) / len(features))) ** 2 for item in features) / len(features)

        # Keep fallback deterministic and bounded while still reflecting spread.
        raw = (0.65 * math.tanh(mean_abs)) + (0.35 * math.tanh(math.sqrt(max(variance, 0.0))))
        return self._clamp01(raw)

    @staticmethod
    def _normalize_optional_path(path: str | Path | None) -> Path | None:
        if path is None:
            return None

        candidate = Path(path).expanduser().resolve()
        if not candidate.exists() or not candidate.is_file():
            raise FileNotFoundError(f"model file not found: {candidate}")

        return candidate

    @classmethod
    def _resolve_initial_version(
        cls,
        *,
        explicit: str | None,
        path: Path | None,
        fallback: str,
        prefix: str,
    ) -> str:
        normalized = cls._normalize_optional_string(explicit)
        if normalized is not None:
            return normalized
        if path is not None:
            return cls._derive_file_version(path, prefix=prefix)
        return fallback

    @staticmethod
    def _derive_file_version(path: Path, *, prefix: str) -> str:
        stat = path.stat()
        return f"{prefix}:{stat.st_size}:{stat.st_mtime_ns}"

    @staticmethod
    def _normalize_optional_string(value: Any) -> str | None:
        if not isinstance(value, str):
            return None
        normalized = value.strip()
        return normalized if normalized else None

    @staticmethod
    def _coerce_float_vector(values: Sequence[float]) -> list[float]:
        output: list[float] = []
        for item in values:
            if isinstance(item, bool):
                output.append(1.0 if item else 0.0)
                continue
            try:
                output.append(float(item))
            except Exception:
                continue
        return output

    @staticmethod
    def _safe_float(value: Any) -> float:
        try:
            return float(value)
        except Exception:
            return 0.0

    @staticmethod
    def _clamp01(value: float) -> float:
        return max(0.0, min(1.0, float(value)))


__all__ = ["AIIntelligenceProvider"]
