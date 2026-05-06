import hashlib
import pytest
from src.security.federated_computation import (
    FederatedComputationFramework,
    EncryptedData,
    Model,
    Query,
)


def test_aggregate_encrypted_statistics():
    framework = FederatedComputationFramework()
    encrypted_data = [
        EncryptedData(data_id="d1", ciphertext=b"cipher1", party_id="p1"),
        EncryptedData(data_id="d2", ciphertext=b"cipher2", party_id="p2"),
    ]
    stats = framework.aggregate_encrypted_statistics(encrypted_data)
    assert stats.stat_id is not None
    assert stats.count == 2
    assert set(stats.parties_contributed) == {"p1", "p2"}
    assert stats.encrypted_result is not None


def test_federated_average_models():
    framework = FederatedComputationFramework()
    models = [
        Model(model_id="m1", party_id="p1", weights={"w1": 1.0, "w2": 2.0}),
        Model(model_id="m2", party_id="p2", weights={"w1": 3.0, "w2": 4.0}),
    ]
    avg_model = framework.federated_average(models)
    assert avg_model.party_id == "coordinator"
    assert avg_model.weights["w1"] == 2.0  # (1.0 + 3.0) / 2
    assert avg_model.weights["w2"] == 3.0  # (2.0 + 4.0) / 2
    assert avg_model.version == 2


def test_differential_privacy_noise():
    framework = FederatedComputationFramework()
    epsilon = 0.5
    sensitivity = 1.0
    # Generate multiple noise samples and verify reasonable scale
    noises = [framework.differential_privacy_noise(epsilon, sensitivity) for _ in range(100)]
    # noise_scale = sensitivity / epsilon = 1.0 / 0.5 = 2.0
    # check that noise values are reasonable (not all the same, within expected scale)
    assert len(set(noises)) > 1  # should have variety
    avg_noise = sum(abs(n) for n in noises) / len(noises)
    # average absolute Laplace noise is roughly scale = 2.0, so avg should be around 2.0
    assert avg_noise > 0.5 and avg_noise < 5.0


def test_verify_privacy_budget():
    framework = FederatedComputationFramework()
    queries = [Query(query_id="q1", query_type="mean", epsilon_cost=0.3), Query(query_id="q2", query_type="sum", epsilon_cost=0.4)]
    assert framework.verify_privacy_budget(queries, 1.0) is True
    assert framework.verify_privacy_budget(queries, 0.6) is False


def test_execute_query_with_privacy():
    framework = FederatedComputationFramework()
    budget = framework.create_privacy_budget("budget1", total_epsilon=1.0)
    q1 = Query(query_id="q1", query_type="mean", epsilon_cost=0.4)
    q2 = Query(query_id="q2", query_type="sum", epsilon_cost=0.7)
    assert framework.execute_query_with_privacy(q1, budget) is True
    assert q1.executed is True
    assert budget.consumed_epsilon == 0.4
    assert framework.execute_query_with_privacy(q2, budget) is False  # would exceed budget
    assert q2.executed is False


def test_privacy_budget_creation_and_status():
    framework = FederatedComputationFramework()
    budget = framework.create_privacy_budget("budget2", total_epsilon=2.0)
    status = framework.get_privacy_budget_status("budget2")
    assert status is not None
    assert status["total_epsilon"] == 2.0
    assert status["consumed_epsilon"] == 0.0
    assert status["remaining_epsilon"] == 2.0
    assert status["queries_executed"] == 0


def test_estimate_privacy_cost():
    framework = FederatedComputationFramework()
    # test with reasonable parameters
    cost = framework.estimate_privacy_cost(query_type="histogram", data_size=1000, sensitivity=1.0, target_error=0.1)
    assert cost > 0


def test_aggregate_encrypted_statistics_empty_raises():
    framework = FederatedComputationFramework()
    with pytest.raises(ValueError):
        framework.aggregate_encrypted_statistics([])


def test_federated_average_empty_raises():
    framework = FederatedComputationFramework()
    with pytest.raises(ValueError):
        framework.federated_average([])


def test_differential_privacy_noise_invalid_epsilon_raises():
    framework = FederatedComputationFramework()
    with pytest.raises(ValueError):
        framework.differential_privacy_noise(epsilon=-0.5, sensitivity=1.0)


def test_privacy_budget_multiple_queries():
    framework = FederatedComputationFramework()
    budget = framework.create_privacy_budget("budget3", total_epsilon=2.0)
    queries = [Query(query_id=f"q{i}", query_type="analysis", epsilon_cost=0.7) for i in range(3)]
    # execute first two
    assert framework.execute_query_with_privacy(queries[0], budget) is True
    assert framework.execute_query_with_privacy(queries[1], budget) is True
    # third would exceed: 1.4 + 0.7 = 2.1 > 2.0
    assert framework.execute_query_with_privacy(queries[2], budget) is False
    assert budget.consumed_epsilon == 1.4
