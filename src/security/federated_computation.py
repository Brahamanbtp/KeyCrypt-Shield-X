from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
import math
import random
import hashlib
import json


@dataclass
class EncryptedData:
    data_id: str
    ciphertext: bytes
    party_id: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AggregateStats:
    stat_id: str
    encrypted_result: Optional[bytes]
    count: int
    parties_contributed: List[str]
    privacy_budget_used: float


@dataclass
class Model:
    model_id: str
    party_id: str
    weights: Dict[str, float]
    version: int = 1


@dataclass
class Query:
    query_id: str
    query_type: str
    epsilon_cost: float
    executed: bool = False


@dataclass
class PrivacyBudget:
    budget_id: str
    total_epsilon: float
    consumed_epsilon: float
    queries_executed: List[str] = field(default_factory=list)


class FederatedComputationFramework:
    """Privacy-preserving federated computation framework.

    Supports:
    - Aggregate statistics on encrypted data (homomorphic encryption)
    - Federated learning (model averaging)
    - Differential privacy with calibrated noise
    - Privacy budget tracking

    For production: integrate with actual homomorphic encryption library (HElib, SEAL),
    real federated learning frameworks (Flower, TensorFlow Federated), and rigorous
    differential privacy implementations (PyDP, Opacus).
    """

    def __init__(self):
        self._privacy_budgets: Dict[str, PrivacyBudget] = {}
        self._query_history: List[Query] = []
        self._aggregate_cache: Dict[str, AggregateStats] = {}

    def aggregate_encrypted_statistics(self, encrypted_data: List[EncryptedData]) -> AggregateStats:
        """Aggregate statistics from encrypted data without decryption.

        In production: uses homomorphic encryption to compute sum/mean/variance
        on encrypted payloads.
        For now: simulates aggregation by combining ciphertexts and computing
        deterministic aggregated result.
        """
        if not encrypted_data:
            raise ValueError("No encrypted data provided")

        stat_id = hashlib.sha256(json.dumps([d.data_id for d in encrypted_data]).encode()).hexdigest()[:16]
        parties = list(set(d.party_id for d in encrypted_data))

        # Simulate homomorphic aggregation: XOR ciphertexts (toy operation)
        combined_ciphertext = b""
        for data in encrypted_data:
            for i, byte in enumerate(data.ciphertext):
                if i < len(combined_ciphertext):
                    combined_ciphertext = (combined_ciphertext[:i] + 
                                         bytes([combined_ciphertext[i] ^ byte]) + 
                                         combined_ciphertext[i+1:])
                else:
                    combined_ciphertext += bytes([byte])

        # Simulate encrypted result (hash-based)
        encrypted_result = hashlib.sha256(combined_ciphertext).digest()

        stats = AggregateStats(
            stat_id=stat_id,
            encrypted_result=encrypted_result,
            count=len(encrypted_data),
            parties_contributed=parties,
            privacy_budget_used=0.1,
        )
        self._aggregate_cache[stat_id] = stats
        return stats

    def federated_average(self, models: List[Model]) -> Model:
        """Compute federated average of models from multiple parties.

        Averaging is done on model weights; for neural networks, this is typically
        done parameter-by-parameter.
        """
        if not models:
            raise ValueError("No models provided for averaging")

        # determine common weight keys
        common_keys = set(models[0].weights.keys())
        for model in models[1:]:
            common_keys &= set(model.weights.keys())

        # average weights across parties
        averaged_weights: Dict[str, float] = {}
        for key in common_keys:
            weight_sum = sum(model.weights[key] for model in models)
            averaged_weights[key] = weight_sum / len(models)

        # create new averaged model
        parties = [m.party_id for m in models]
        model_id = hashlib.sha256(json.dumps(parties).encode()).hexdigest()[:16]
        avg_model = Model(
            model_id=model_id,
            party_id="coordinator",
            weights=averaged_weights,
            version=max(m.version for m in models) + 1,
        )
        return avg_model

    def differential_privacy_noise(self, epsilon: float, sensitivity: float) -> float:
        """Generate calibrated Laplace noise for differential privacy.

        Noise scale = sensitivity / epsilon
        Drawn from Laplace distribution with location=0 and scale=noise_scale.
        """
        if epsilon <= 0:
            raise ValueError("Epsilon must be positive")
        if sensitivity < 0:
            raise ValueError("Sensitivity must be non-negative")

        noise_scale = sensitivity / epsilon
        # Laplace distribution: draw from Exp(1/scale)
        u = random.random()
        # Laplace: sign * scale * ln(1 - 2*|u - 0.5|)
        laplace_noise = noise_scale * math.log(1 - 2 * abs(u - 0.5))
        return laplace_noise

    def verify_privacy_budget(self, queries: List[Query], epsilon_budget: float) -> bool:
        """Verify that executing queries doesn't exceed privacy budget.

        Returns True if total epsilon cost of queries <= budget.
        Uses simple composition: total_epsilon = sum(epsilon_i).
        For production: use advanced composition or Renyi DP for tighter bounds.
        """
        total_epsilon_cost = sum(q.epsilon_cost for q in queries)
        return total_epsilon_cost <= epsilon_budget

    def execute_query_with_privacy(self, query: Query, privacy_budget: PrivacyBudget) -> bool:
        """Execute a query if it fits within the privacy budget.

        Returns True if query executed, False if it would exceed budget.
        """
        if privacy_budget.consumed_epsilon + query.epsilon_cost > privacy_budget.total_epsilon:
            return False

        privacy_budget.consumed_epsilon += query.epsilon_cost
        privacy_budget.queries_executed.append(query.query_id)
        query.executed = True
        self._query_history.append(query)
        return True

    def estimate_privacy_cost(self, query_type: str, data_size: int, sensitivity: float, target_error: float) -> float:
        """Estimate privacy cost (epsilon) for a query.

        Rule of thumb: epsilon ≈ sensitivity / target_error
        Adjusted for data size and query type.
        """
        base_epsilon = sensitivity / target_error if target_error > 0 else 1.0
        # scale up for larger data (more queries possible)
        data_factor = math.log(data_size + 1) / 10.0
        return base_epsilon * (1 + data_factor)

    def create_privacy_budget(self, budget_id: str, total_epsilon: float) -> PrivacyBudget:
        """Create a new privacy budget for a session/user."""
        budget = PrivacyBudget(budget_id=budget_id, total_epsilon=total_epsilon, consumed_epsilon=0.0)
        self._privacy_budgets[budget_id] = budget
        return budget

    def get_privacy_budget_status(self, budget_id: str) -> Optional[Dict[str, Any]]:
        """Get the current status of a privacy budget."""
        budget = self._privacy_budgets.get(budget_id)
        if budget is None:
            return None
        return {
            "budget_id": budget.budget_id,
            "total_epsilon": budget.total_epsilon,
            "consumed_epsilon": budget.consumed_epsilon,
            "remaining_epsilon": budget.total_epsilon - budget.consumed_epsilon,
            "queries_executed": len(budget.queries_executed),
        }


__all__ = [
    "FederatedComputationFramework",
    "EncryptedData",
    "AggregateStats",
    "Model",
    "Query",
    "PrivacyBudget",
]
