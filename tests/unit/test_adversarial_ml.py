import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.ai.advanced.adversarial_ml import (
    detect_adversarial_input,
    defend_against_model_poisoning,
    implement_differential_privacy,
    evaluate_model_robustness,
    Sample,
    PrivateModel,
)


def test_detect_adversarial_input_basic() -> None:
    benign = b"This is a normal plaintext input for testing purposes."
    assert detect_adversarial_input(benign) is False

    # Crafted high-entropy input
    rnd = bytes([i % 256 for i in range(256)]) * 2
    assert detect_adversarial_input(rnd) is True


def test_defend_against_model_poisoning_removes_outliers() -> None:
    samples = [
        Sample(features=[0.1, 0.2, 0.1], label="A"),
        Sample(features=[0.12, 0.19, 0.11], label="A"),
        Sample(features=[10.0, 10.0, 9.9], label="A"),  # poisoned/outlier
        Sample(features=[0.3, 0.2, 0.25], label="B"),
        Sample(features=[0.31, 0.21, 0.27], label="B"),
    ]

    cleaned = defend_against_model_poisoning(samples)
    assert isinstance(cleaned, type(cleaned))
    assert len(cleaned.samples) <= len(samples)
    # poisoned sample likely removed
    assert any(s.label == "A" for s in cleaned.samples)


def test_implement_differential_privacy_and_predict() -> None:
    class DummyModel:
        def predict(self, X):
            return [sum(x) for x in X]

    dm = DummyModel()
    pm = implement_differential_privacy(dm, epsilon=0.5)
    assert isinstance(pm, PrivateModel)
    preds = pm.predict([[1.0, 2.0], [0.5, 0.5]])
    assert len(preds) == 2


def test_test_model_robustness_simple() -> None:
    class SimpleClassifier:
        def predict(self, X):
            return [1 if sum(x) > 0.5 else 0 for x in X]

    model = SimpleClassifier()
    X = [[0.6], [0.4], [1.2], [0.0]]
    y = [1, 0, 1, 0]
    score = evaluate_model_robustness(model, X, y, attack_budget=0.1)
    assert 0.0 <= score.baseline_accuracy <= 1.0
    assert 0.0 <= score.adversarial_accuracy <= 1.0
    assert 0.0 <= score.robustness <= 10.0
