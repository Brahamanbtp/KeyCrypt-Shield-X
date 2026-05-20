import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.abstractions.intelligence_provider import DataProfile
from src.ai.advanced.automl_algorithm_selection import (
    AutoMLAlgorithmSelector,
    EncryptionExample,
    PerformanceFeedback,
)


def _aes_profile() -> DataProfile:
    return DataProfile(
        data_type="file",
        size_bytes=8 * 1024 * 1024,
        latency_budget_ms=120.0,
        confidentiality_level=0.82,
        integrity_level=0.88,
        metadata={
            "entropy": 0.83,
            "compression_ratio": 1.35,
            "hardware_available": ["aes-ni"],
            "threat_level": 0.3,
        },
    )


def _chacha_profile() -> DataProfile:
    return DataProfile(
        data_type="stream",
        size_bytes=2 * 1024 * 1024,
        latency_budget_ms=8.0,
        confidentiality_level=0.68,
        integrity_level=0.7,
        metadata={
            "entropy": 0.4,
            "compression_ratio": 0.9,
            "hardware_available": ["gpu"],
            "threat_level": 0.2,
        },
    )


def _hybrid_profile() -> DataProfile:
    return DataProfile(
        data_type="archive",
        size_bytes=250 * 1024 * 1024,
        latency_budget_ms=50.0,
        confidentiality_level=0.97,
        integrity_level=0.95,
        metadata={
            "entropy": 0.92,
            "compression_ratio": 1.05,
            "hardware_available": ["aes-ni"],
            "threat_level": 0.95,
            "quantum_risk": "critical",
        },
    )


def test_train_predict_and_evaluate_algorithm_selector() -> None:
    selector = AutoMLAlgorithmSelector()
    training_data = [
        EncryptionExample(data_profile=_aes_profile(), algorithm_name="aes-gcm"),
        EncryptionExample(data_profile=_chacha_profile(), algorithm_name="chacha20"),
        EncryptionExample(data_profile=_hybrid_profile(), algorithm_name="hybrid-kem"),
    ]

    model = selector.train_algorithm_selector(training_data)

    assert model.training_examples == training_data
    assert model.label_names == ("aes-gcm", "chacha20", "hybrid-kem")

    recommendation = selector.predict_optimal_algorithm(_aes_profile())
    assert recommendation.algorithm_name == "aes-gcm"
    assert 0.0 <= recommendation.confidence <= 1.0
    assert recommendation.security_level == 4
    assert recommendation.rationale

    metrics = selector.evaluate_model_performance(training_data)
    assert metrics.samples == 3
    assert metrics.accuracy == 1.0
    assert 0.0 <= metrics.f1_macro <= 1.0
    assert metrics.backend in {"sklearn", "fallback"}


def test_online_update_retrains_selector() -> None:
    selector = AutoMLAlgorithmSelector()
    initial_training = [
        EncryptionExample(data_profile=_chacha_profile(), algorithm_name="chacha20"),
        EncryptionExample(data_profile=_chacha_profile(), algorithm_name="chacha20"),
    ]
    selector.train_algorithm_selector(initial_training)

    before_update = selector.predict_optimal_algorithm(_aes_profile())
    assert before_update.algorithm_name == "chacha20"

    selector.update_model_online(
        [
            PerformanceFeedback(
                data_profile=_aes_profile(),
                algorithm_name="aes-gcm",
                actual_latency_ms=18.0,
                actual_security_score=0.92,
            )
        ]
    )

    after_update = selector.predict_optimal_algorithm(_aes_profile())
    assert after_update.algorithm_name == "aes-gcm"
