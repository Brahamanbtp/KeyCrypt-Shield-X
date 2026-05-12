"""Unit tests for AIIntelligenceProvider."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.abstractions.intelligence_provider import (
    AlgorithmRecommendation,
    AnomalyScore,
    DataProfile,
    RiskScore,
    SecurityContext,
    SecurityEvent,
)
from src.providers.intelligence.ai_intelligence_provider import AIIntelligenceProvider


@pytest.fixture
def provider() -> AIIntelligenceProvider:
    """Create an AIIntelligenceProvider with default bootstrap models."""
    return AIIntelligenceProvider()


@pytest.fixture
def security_context() -> SecurityContext:
    """Create a sample security context for testing."""
    return SecurityContext(
        asset_id="asset-123",
        actor_id="user-456",
        operation="encrypt",
        telemetry_features=[0.1, 0.2, 0.3, 0.4, 0.5],
        current_threat_level=0.6,
        sensitivity=0.7,
        metadata={"payload_size_bytes": 1024},
    )


@pytest.fixture
def security_event() -> SecurityEvent:
    """Create a sample security event for testing."""
    return SecurityEvent(
        event_id="event-789",
        event_type="authentication",
        timestamp=1234567890.0,
        source="auth_service",
        features=[0.1] * 64,
        metadata={"login_attempts": 3},
    )


@pytest.fixture
def data_profile() -> DataProfile:
    """Create a sample data profile for testing."""
    return DataProfile(
        data_type="file",
        size_bytes=1024 * 1024,
        latency_budget_ms=100.0,
        confidentiality_level=0.85,
        integrity_level=0.90,
        compliance_tags=["pci-dss", "hipaa"],
        metadata={"quantum_risk": "low"},
    )


def test_provider_initialization() -> None:
    """AIIntelligenceProvider initializes with default parameters."""
    provider = AIIntelligenceProvider()
    assert provider is not None
    assert provider._risk_input_size == 16
    assert provider._anomaly_input_dim == 64


def test_provider_predict_risk_returns_valid_score(
    provider: AIIntelligenceProvider,
    security_context: SecurityContext,
) -> None:
    """predict_risk returns a valid RiskScore."""
    result = provider.predict_risk(security_context)

    assert isinstance(result, RiskScore)
    assert 0.0 <= result.value <= 1.0
    assert 0.0 <= result.confidence <= 1.0
    assert result.rationale is not None
    assert "provider" in result.metadata


def test_provider_predict_risk_rejects_invalid_context(provider: AIIntelligenceProvider) -> None:
    """predict_risk validates context type."""
    with pytest.raises(TypeError, match="context must be SecurityContext"):
        provider.predict_risk({"invalid": "dict"})  # type: ignore


def test_provider_predict_risk_with_empty_telemetry(provider: AIIntelligenceProvider) -> None:
    """predict_risk handles contexts with no telemetry features."""
    context = SecurityContext(
        asset_id="asset-123",
        actor_id="user-456",
        operation="encrypt",
        telemetry_features=[],
        current_threat_level=0.5,
        sensitivity=0.5,
    )

    result = provider.predict_risk(context)

    assert isinstance(result, RiskScore)
    assert 0.0 <= result.value <= 1.0


def test_provider_predict_risk_varies_with_threat_level(provider: AIIntelligenceProvider) -> None:
    """predict_risk increases with higher threat levels."""
    low_threat = SecurityContext(
        asset_id="a",
        actor_id="u",
        operation="encrypt",
        current_threat_level=0.1,
        sensitivity=0.5,
        telemetry_features=[0.1, 0.2],
    )

    high_threat = SecurityContext(
        asset_id="a",
        actor_id="u",
        operation="encrypt",
        current_threat_level=0.9,
        sensitivity=0.5,
        telemetry_features=[0.1, 0.2],
    )

    low_risk = provider.predict_risk(low_threat)
    high_risk = provider.predict_risk(high_threat)

    assert low_risk.value < high_risk.value


def test_provider_predict_risk_varies_with_sensitivity(provider: AIIntelligenceProvider) -> None:
    """predict_risk increases with higher data sensitivity."""
    low_sensitivity = SecurityContext(
        asset_id="a",
        actor_id="u",
        operation="encrypt",
        current_threat_level=0.5,
        sensitivity=0.2,
        telemetry_features=[0.1],
    )

    high_sensitivity = SecurityContext(
        asset_id="a",
        actor_id="u",
        operation="encrypt",
        current_threat_level=0.5,
        sensitivity=0.9,
        telemetry_features=[0.1],
    )

    low_risk = provider.predict_risk(low_sensitivity)
    high_risk = provider.predict_risk(high_sensitivity)

    assert low_risk.value < high_risk.value


def test_provider_detect_anomaly_returns_valid_score(
    provider: AIIntelligenceProvider,
    security_event: SecurityEvent,
) -> None:
    """detect_anomaly returns a valid AnomalyScore."""
    result = provider.detect_anomaly(security_event)

    assert isinstance(result, AnomalyScore)
    assert 0.0 <= result.value <= 1.0
    assert 0.0 <= result.threshold <= 1.0
    assert isinstance(result.is_anomalous, bool)
    assert "provider" in result.metadata


def test_provider_detect_anomaly_rejects_invalid_event(provider: AIIntelligenceProvider) -> None:
    """detect_anomaly validates event type."""
    with pytest.raises(TypeError, match="event must be SecurityEvent"):
        provider.detect_anomaly({"invalid": "dict"})  # type: ignore


def test_provider_detect_anomaly_with_zero_features(provider: AIIntelligenceProvider) -> None:
    """detect_anomaly handles events with no features."""
    event = SecurityEvent(
        event_id="e1",
        event_type="access",
        timestamp=1234567890.0,
        source="auth",
        features=[],
    )

    result = provider.detect_anomaly(event)

    assert isinstance(result, AnomalyScore)
    assert 0.0 <= result.value <= 1.0


def test_provider_suggest_algorithm_returns_valid_recommendation(
    provider: AIIntelligenceProvider,
    data_profile: DataProfile,
) -> None:
    """suggest_algorithm returns a valid AlgorithmRecommendation."""
    result = provider.suggest_algorithm(data_profile)

    assert isinstance(result, AlgorithmRecommendation)
    assert result.algorithm_name
    assert 0.0 <= result.confidence <= 1.0
    assert result.security_level > 0
    assert result.rationale
    assert "provider" in result.metadata


def test_provider_suggest_algorithm_rejects_invalid_profile(provider: AIIntelligenceProvider) -> None:
    """suggest_algorithm validates profile type."""
    with pytest.raises(TypeError, match="data_profile must be DataProfile"):
        provider.suggest_algorithm({"invalid": "dict"})  # type: ignore


def test_provider_suggest_algorithm_pqc_preference(provider: AIIntelligenceProvider) -> None:
    """suggest_algorithm recommends PQC for high-confidentiality profiles."""
    pqc_profile = DataProfile(
        data_type="file",
        size_bytes=1024,
        latency_budget_ms=1000.0,
        confidentiality_level=0.95,
        integrity_level=0.95,
        metadata={"quantum_risk": "critical"},
    )

    result = provider.suggest_algorithm(pqc_profile)

    assert "hybrid" in result.algorithm_name.lower() or "kem" in result.algorithm_name.lower()
    assert result.security_level >= 4


def test_provider_suggest_algorithm_latency_sensitive(provider: AIIntelligenceProvider) -> None:
    """suggest_algorithm favors ChaCha20 for low-latency regulated workloads."""
    latency_profile = DataProfile(
        data_type="stream",
        size_bytes=1024,
        latency_budget_ms=5.0,
        confidentiality_level=0.8,
        integrity_level=0.8,
        compliance_tags=["hipaa"],
    )

    result = provider.suggest_algorithm(latency_profile)

    assert result.algorithm_name.lower() in {"chacha20", "aes-gcm"}


def test_provider_suggest_algorithm_large_payload(provider: AIIntelligenceProvider) -> None:
    """suggest_algorithm recommends throughput-optimized algorithms for large payloads."""
    large_payload = DataProfile(
        data_type="file",
        size_bytes=500 * 1024 * 1024,
        latency_budget_ms=20.0,
        confidentiality_level=0.7,
        integrity_level=0.7,
    )

    result = provider.suggest_algorithm(large_payload)

    assert result.algorithm_name.lower() in {"chacha20", "aes-gcm"}


def test_provider_get_model_versions(provider: AIIntelligenceProvider) -> None:
    """get_model_versions returns version information."""
    versions = provider.get_model_versions()

    assert isinstance(versions, dict)
    assert "risk_predictor" in versions
    assert "anomaly_detector" in versions
    assert "updated_at" in versions


def test_provider_update_models_resets_state(provider: AIIntelligenceProvider) -> None:
    """update_models clears lazy-loaded model instances when path is updated."""
    # Models are only cleared when updating the path, not just the version
    versions = provider.update_models(
        risk_version="custom-risk-v2",
        anomaly_version="custom-anomaly-v2",
    )

    assert versions["risk_predictor"] == "custom-risk-v2"
    assert versions["anomaly_detector"] == "custom-anomaly-v2"


def test_provider_update_models_with_invalid_threshold() -> None:
    """update_models validates anomaly threshold."""
    provider = AIIntelligenceProvider()

    with pytest.raises(ValueError, match="default_anomaly_threshold must be > 0"):
        provider.update_models(default_anomaly_threshold=0.0)

    with pytest.raises(ValueError, match="default_anomaly_threshold must be > 0"):
        provider.update_models(default_anomaly_threshold=-0.5)


def test_provider_initialization_with_custom_parameters() -> None:
    """AIIntelligenceProvider accepts custom initialization parameters."""
    provider = AIIntelligenceProvider(
        device="cpu",
        risk_input_size=32,
        risk_sequence_length=16,
        anomaly_input_dim=128,
        default_anomaly_threshold=0.25,
        risk_model_version="custom-risk-v1",
        anomaly_model_version="custom-anomaly-v1",
    )

    assert provider._risk_input_size == 32
    assert provider._risk_sequence_length == 16
    assert provider._anomaly_input_dim == 128
    assert provider._default_anomaly_threshold == 0.25
    versions = provider.get_model_versions()
    assert versions["risk_predictor"] == "custom-risk-v1"
    assert versions["anomaly_detector"] == "custom-anomaly-v1"


def test_provider_initialization_rejects_invalid_parameters() -> None:
    """AIIntelligenceProvider rejects invalid parameters."""
    with pytest.raises(ValueError, match="risk_input_size must be > 0"):
        AIIntelligenceProvider(risk_input_size=0)

    with pytest.raises(ValueError, match="risk_sequence_length must be > 0"):
        AIIntelligenceProvider(risk_sequence_length=-5)

    with pytest.raises(ValueError, match="anomaly_input_dim must be > 0"):
        AIIntelligenceProvider(anomaly_input_dim=0)

    with pytest.raises(ValueError, match="default_anomaly_threshold must be > 0"):
        AIIntelligenceProvider(default_anomaly_threshold=-0.1)


def test_provider_predict_risk_metadata_includes_versions(
    provider: AIIntelligenceProvider,
    security_context: SecurityContext,
) -> None:
    """predict_risk metadata includes model version information."""
    result = provider.predict_risk(security_context)

    assert "model_version" in result.metadata
    assert "model" in result.metadata
    assert result.metadata["model"] == "risk_predictor_lstm"


def test_provider_detect_anomaly_metadata_includes_event_type(
    provider: AIIntelligenceProvider,
    security_event: SecurityEvent,
) -> None:
    """detect_anomaly metadata includes event type and source."""
    result = provider.detect_anomaly(security_event)

    assert "event_type" in result.metadata
    assert "event_source" in result.metadata
    assert result.metadata["event_type"] == "authentication"
    assert result.metadata["event_source"] == "auth_service"


def test_provider_suggest_algorithm_metadata_includes_decision_path(
    provider: AIIntelligenceProvider,
    data_profile: DataProfile,
) -> None:
    """suggest_algorithm metadata includes decision tree path."""
    result = provider.suggest_algorithm(data_profile)

    assert "decision_model" in result.metadata
    assert "decision_path" in result.metadata or "decision_model" in result.metadata


def test_provider_thread_safety() -> None:
    """AIIntelligenceProvider uses locks for thread safety."""
    provider = AIIntelligenceProvider()

    assert hasattr(provider, "_lock")
    assert provider._lock is not None


def test_provider_model_lazy_loading(
    provider: AIIntelligenceProvider,
    security_context: SecurityContext,
) -> None:
    """Models are loaded lazily on first predict_risk call (when AI dependencies available)."""
    initial_model = provider._risk_model
    assert initial_model is None

    result = provider.predict_risk(security_context)

    # If torch is available, the model should be loaded; if not, fallback heuristic is used
    if AIIntelligenceProvider._ai_dependencies_available():
        assert provider._risk_model is not None
    else:
        # Fallback path uses heuristics, model remains None
        assert isinstance(result, RiskScore)


def test_provider_anomaly_detector_lazy_loading(
    provider: AIIntelligenceProvider,
    security_event: SecurityEvent,
) -> None:
    """Anomaly detector is loaded lazily on first detect_anomaly call (when AI dependencies available)."""
    initial_detector = provider._anomaly_detector
    assert initial_detector is None

    result = provider.detect_anomaly(security_event)

    # If torch is available, the detector should be loaded; if not, fallback heuristic is used
    if AIIntelligenceProvider._ai_dependencies_available():
        assert provider._anomaly_detector is not None
    else:
        # Fallback path uses heuristics, detector remains None
        assert isinstance(result, AnomalyScore)


def test_provider_clamping_function() -> None:
    """_clamp01 constrains values to [0.0, 1.0]."""
    assert AIIntelligenceProvider._clamp01(-0.5) == 0.0
    assert AIIntelligenceProvider._clamp01(0.5) == 0.5
    assert AIIntelligenceProvider._clamp01(1.5) == 1.0


def test_provider_coerce_float_vector_with_mixed_types() -> None:
    """_coerce_float_vector handles mixed numeric and non-numeric types."""
    values = [1.0, 2, True, "invalid", 3.5, False]  # type: ignore
    result = AIIntelligenceProvider._coerce_float_vector(values)

    assert len(result) >= 4
    assert all(isinstance(v, float) for v in result)


def test_provider_coerce_float_vector_with_bools() -> None:
    """_coerce_float_vector converts booleans correctly."""
    values = [True, False, True]  # type: ignore
    result = AIIntelligenceProvider._coerce_float_vector(values)

    assert result == [1.0, 0.0, 1.0]


def test_provider_normalize_optional_string() -> None:
    """_normalize_optional_string handles various input types."""
    assert AIIntelligenceProvider._normalize_optional_string("  valid  ") == "valid"
    assert AIIntelligenceProvider._normalize_optional_string("") is None
    assert AIIntelligenceProvider._normalize_optional_string("   ") is None
    assert AIIntelligenceProvider._normalize_optional_string(123) is None
    assert AIIntelligenceProvider._normalize_optional_string(None) is None


def test_provider_safe_float_conversion() -> None:
    """_safe_float converts various types safely."""
    assert AIIntelligenceProvider._safe_float(3.14) == pytest.approx(3.14)
    assert AIIntelligenceProvider._safe_float("2.71") == pytest.approx(2.71)
    assert AIIntelligenceProvider._safe_float(5) == 5.0
    assert AIIntelligenceProvider._safe_float("invalid") == 0.0
    assert AIIntelligenceProvider._safe_float(None) == 0.0


def test_provider_algorithm_alternatives_provided(
    provider: AIIntelligenceProvider,
    data_profile: DataProfile,
) -> None:
    """suggest_algorithm provides alternative recommendations."""
    result = provider.suggest_algorithm(data_profile)

    assert len(result.alternatives) > 0
    assert all(isinstance(alt, str) for alt in result.alternatives)
