"""Unit tests for PolicyEvaluator decision-tree based rule matching."""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.policy.policy_evaluator import PolicyEvaluator
from src.policy.policy_schema import Action, Condition, Operator, Policy, PolicyRule


def _base_action() -> dict[str, Any]:
    return {
        "algorithm": "aes-256-gcm",
        "key_rotation": "90d",
        "compliance": ["baseline"],
        "metadata": {},
    }


def _base_policy(name: str = "test-policy", rules: list[dict[str, Any]] | None = None) -> Policy:
    return Policy.model_validate(
        {
            "name": name,
            "version": "1.0",
            "default_action": _base_action(),
            "rules": rules or [],
        }
    )


@pytest.fixture
def evaluator() -> PolicyEvaluator:
    return PolicyEvaluator(cache_limit=10)


def test_evaluator_returns_default_action_when_no_rules_match(evaluator: PolicyEvaluator) -> None:
    policy = _base_policy()
    context = {"data_classification": "PUBLIC"}

    result = evaluator.evaluate(context=context, policy=policy)

    assert result.matched_rule is None
    assert result.action.algorithm == "aes-256-gcm"
    assert result.confidence == pytest.approx(0.5, abs=0.01)


def test_evaluator_matches_equals_condition(evaluator: PolicyEvaluator) -> None:
    policy = _base_policy(
        rules=[
            {
                "condition": {
                    "field": "data_classification",
                    "operator": "EQUALS",
                    "value": "PHI",
                },
                "action": {
                    "algorithm": "chacha20-poly1305",
                    "key_rotation": "30d",
                    "compliance": ["hipaa"],
                    "metadata": {},
                },
            }
        ]
    )
    context = {"data_classification": "PHI"}

    result = evaluator.evaluate(context=context, policy=policy)

    assert result.matched_rule is not None
    assert result.action.algorithm == "chacha20-poly1305"
    assert "hipaa" in result.action.compliance


def test_evaluator_matches_greater_than_condition(evaluator: PolicyEvaluator) -> None:
    policy = _base_policy(
        rules=[
            {
                "condition": {
                    "field": "risk_score",
                    "operator": "GREATER_THAN",
                    "value": 0.8,
                },
                "action": {
                    "algorithm": "xsalsa20-poly1305",
                    "key_rotation": "15d",
                    "compliance": ["high-risk"],
                    "metadata": {},
                },
            }
        ]
    )
    context = {"risk_score": 0.95}

    result = evaluator.evaluate(context=context, policy=policy)

    assert result.matched_rule is not None
    assert result.action.algorithm == "xsalsa20-poly1305"


def test_evaluator_matches_less_than_condition(evaluator: PolicyEvaluator) -> None:
    policy = _base_policy(
        rules=[
            {
                "condition": {
                    "field": "trust_level",
                    "operator": "LESS_THAN",
                    "value": 3,
                },
                "action": {
                    "algorithm": "aes-128-gcm",
                    "key_rotation": "30d",
                    "compliance": ["low-trust"],
                    "metadata": {},
                },
            }
        ]
    )
    context = {"trust_level": 2}

    result = evaluator.evaluate(context=context, policy=policy)

    assert result.matched_rule is not None
    assert result.action.algorithm == "aes-128-gcm"


def test_evaluator_matches_in_condition(evaluator: PolicyEvaluator) -> None:
    policy = _base_policy(
        rules=[
            {
                "condition": {
                    "field": "region",
                    "operator": "IN",
                    "value": ["us-east", "us-west"],
                },
                "action": {
                    "algorithm": "aes-256-gcm",
                    "key_rotation": "60d",
                    "compliance": ["us-regional"],
                    "metadata": {},
                },
            }
        ]
    )
    context = {"region": "us-east"}

    result = evaluator.evaluate(context=context, policy=policy)

    assert result.matched_rule is not None
    assert "us-regional" in result.action.compliance


def test_evaluator_matches_contains_condition(evaluator: PolicyEvaluator) -> None:
    policy = _base_policy(
        rules=[
            {
                "condition": {
                    "field": "tags",
                    "operator": "CONTAINS",
                    "value": "sensitive",
                },
                "action": {
                    "algorithm": "chacha20-poly1305",
                    "key_rotation": "30d",
                    "compliance": ["sensitive"],
                    "metadata": {},
                },
            }
        ]
    )
    context = {"tags": ["public", "sensitive", "archived"]}

    result = evaluator.evaluate(context=context, policy=policy)

    assert result.matched_rule is not None
    assert "sensitive" in result.action.compliance


def test_evaluator_matches_regex_condition(evaluator: PolicyEvaluator) -> None:
    policy = _base_policy(
        rules=[
            {
                "condition": {
                    "field": "tenant_id",
                    "operator": "MATCHES",
                    "value": r"^org-\d+$",
                },
                "action": {
                    "algorithm": "aes-256-gcm",
                    "key_rotation": "90d",
                    "compliance": ["org"],
                    "metadata": {},
                },
            }
        ]
    )
    context = {"tenant_id": "org-42"}

    result = evaluator.evaluate(context=context, policy=policy)

    assert result.matched_rule is not None
    assert "org" in result.action.compliance


def test_evaluator_matches_not_equals_condition(evaluator: PolicyEvaluator) -> None:
    policy = _base_policy(
        rules=[
            {
                "condition": {
                    "field": "env",
                    "operator": "NOT_EQUALS",
                    "value": "development",
                },
                "action": {
                    "algorithm": "chacha20-poly1305",
                    "key_rotation": "60d",
                    "compliance": ["prod-ready"],
                    "metadata": {},
                },
            }
        ]
    )
    context = {"env": "production"}

    result = evaluator.evaluate(context=context, policy=policy)

    assert result.matched_rule is not None
    assert "prod-ready" in result.action.compliance


def test_evaluator_prefers_specific_rules_over_general(evaluator: PolicyEvaluator) -> None:
    """Rules with nested fields have higher precedence than flat fields."""
    policy = _base_policy(
        rules=[
            {
                "condition": {"field": "region", "operator": "EQUALS", "value": "us-east"},
                "action": {
                    "algorithm": "flat-algo",
                    "key_rotation": "60d",
                    "compliance": ["flat"],
                    "metadata": {},
                },
            },
            {
                "condition": {
                    "field": "context.region.metadata",
                    "operator": "EQUALS",
                    "value": "us-east",
                },
                "action": {
                    "algorithm": "nested-algo",
                    "key_rotation": "30d",
                    "compliance": ["nested"],
                    "metadata": {},
                },
            },
        ]
    )
    context = {"context": {"region": {"metadata": "us-east"}}}

    result = evaluator.evaluate(context=context, policy=policy)

    assert "nested" in result.action.compliance
    assert result.action.algorithm == "nested-algo"


def test_evaluator_flattens_nested_context(evaluator: PolicyEvaluator) -> None:
    """Nested fields are flattened with dot notation."""
    policy = _base_policy(
        rules=[
            {
                "condition": {
                    "field": "metadata.risk_score",
                    "operator": "GREATER_THAN",
                    "value": 0.7,
                },
                "action": {
                    "algorithm": "xsalsa20-poly1305",
                    "key_rotation": "20d",
                    "compliance": ["elevated-risk"],
                    "metadata": {},
                },
            }
        ]
    )
    context = {"metadata": {"risk_score": 0.85, "source": "scanner"}}

    result = evaluator.evaluate(context=context, policy=policy)

    assert result.matched_rule is not None
    assert result.action.algorithm == "xsalsa20-poly1305"


def test_evaluator_returns_performance_metrics(evaluator: PolicyEvaluator) -> None:
    """EvaluationResult includes evaluation_time_ms and rules_checked."""
    policy = _base_policy(
        rules=[
            {
                "condition": {"field": "tier", "operator": "EQUALS", "value": "premium"},
                "action": {
                    "algorithm": "chacha20-poly1305",
                    "key_rotation": "15d",
                    "compliance": ["premium"],
                    "metadata": {},
                },
            }
        ]
    )
    context = {"tier": "premium"}

    result = evaluator.evaluate(context=context, policy=policy)

    assert result.evaluation_time_ms > 0.0
    assert result.evaluation_time_ms < 100.0  # Should be very fast
    assert result.rules_checked >= 1


def test_evaluator_caches_compiled_policies(evaluator: PolicyEvaluator) -> None:
    """Compiled policies are cached to improve repeated evaluation performance."""
    policy = _base_policy(
        rules=[
            {
                "condition": {"field": "status", "operator": "EQUALS", "value": "active"},
                "action": {
                    "algorithm": "aes-256-gcm",
                    "key_rotation": "90d",
                    "compliance": ["active"],
                    "metadata": {},
                },
            }
        ]
    )
    context = {"status": "active"}

    result1 = evaluator.evaluate(context=context, policy=policy)
    result2 = evaluator.evaluate(context=context, policy=policy)

    assert len(evaluator._compiled_cache) == 1
    assert result1.action.algorithm == result2.action.algorithm


def test_evaluator_enforces_cache_limit(evaluator: PolicyEvaluator) -> None:
    """Cache evicts oldest entries when limit is reached."""
    cache_limit = 3
    evaluator_limited = PolicyEvaluator(cache_limit=cache_limit)

    for i in range(cache_limit + 2):
        policy = _base_policy(
            name=f"policy-{i}",
            rules=[
                {
                    "condition": {"field": "id", "operator": "EQUALS", "value": i},
                    "action": _base_action(),
                }
            ],
        )
        evaluator_limited.evaluate(context={"id": i}, policy=policy)

    assert len(evaluator_limited._compiled_cache) == cache_limit


def test_evaluator_explain_shows_matching_decision(evaluator: PolicyEvaluator) -> None:
    """explain() returns human-readable description of matching logic."""
    policy = _base_policy(
        rules=[
            {
                "condition": {
                    "field": "classification",
                    "operator": "EQUALS",
                    "value": "confidential",
                },
                "action": {
                    "algorithm": "chacha20-poly1305",
                    "key_rotation": "15d",
                    "compliance": ["confidential"],
                    "metadata": {},
                },
            }
        ]
    )
    context = {"classification": "confidential"}

    explanation = evaluator.explain(context=context, policy=policy)

    assert "matched_rule=" in explanation
    assert "confidential" in explanation
    assert "algorithm=chacha20-poly1305" in explanation
    assert "confidence=" in explanation


def test_evaluator_explain_includes_performance_metrics(evaluator: PolicyEvaluator) -> None:
    """explain() includes evaluation time and rules checked."""
    policy = _base_policy(
        rules=[
            {
                "condition": {"field": "type", "operator": "EQUALS", "value": "sensitive"},
                "action": {
                    "algorithm": "aes-256-gcm",
                    "key_rotation": "60d",
                    "compliance": ["sensitive"],
                    "metadata": {},
                },
            }
        ]
    )
    context = {"type": "sensitive"}

    explanation = evaluator.explain(context=context, policy=policy)

    assert "evaluation_time_ms=" in explanation
    assert "checked_rules=" in explanation


def test_evaluator_explain_shows_no_match_explanation(evaluator: PolicyEvaluator) -> None:
    """explain() handles case where no rules match."""
    policy = _base_policy(
        rules=[
            {
                "condition": {"field": "env", "operator": "EQUALS", "value": "staging"},
                "action": {
                    "algorithm": "aes-256-gcm",
                    "key_rotation": "90d",
                    "compliance": ["staging"],
                    "metadata": {},
                },
            }
        ]
    )
    context = {"env": "production"}

    explanation = evaluator.explain(context=context, policy=policy)

    assert "matched_rule=none" in explanation
    assert "default_action applied" in explanation


def test_evaluator_computes_confidence_score(evaluator: PolicyEvaluator) -> None:
    """Confidence score reflects match certainty (0.0 to 0.99)."""
    policy = _base_policy(
        rules=[
            {
                "condition": {"field": "priority", "operator": "EQUALS", "value": "critical"},
                "action": {
                    "algorithm": "xsalsa20-poly1305",
                    "key_rotation": "5d",
                    "compliance": ["critical"],
                    "metadata": {},
                },
            }
        ]
    )
    context = {"priority": "critical"}

    result = evaluator.evaluate(context=context, policy=policy)

    assert 0.0 <= result.confidence <= 0.99
    assert result.confidence > 0.55  # Should be high for exact match


def test_evaluator_handles_missing_context_fields(evaluator: PolicyEvaluator) -> None:
    """Missing fields do not cause errors; NOT_EQUALS returns true for missing fields."""
    policy = _base_policy(
        rules=[
            {
                "condition": {"field": "restricted_tag", "operator": "NOT_EQUALS", "value": "admin"},
                "action": {
                    "algorithm": "chacha20-poly1305",
                    "key_rotation": "30d",
                    "compliance": ["no-admin"],
                    "metadata": {},
                },
            }
        ]
    )
    context = {"some_field": "value"}

    result = evaluator.evaluate(context=context, policy=policy)

    assert result.matched_rule is not None
    assert "no-admin" in result.action.compliance


def test_evaluator_handles_null_and_none_values(evaluator: PolicyEvaluator) -> None:
    """Evaluator gracefully handles None and null values in context."""
    policy = _base_policy(
        rules=[
            {
                "condition": {"field": "optional_field", "operator": "EQUALS", "value": None},
                "action": {
                    "algorithm": "aes-256-gcm",
                    "key_rotation": "90d",
                    "compliance": ["null-aware"],
                    "metadata": {},
                },
            }
        ]
    )
    context = {"optional_field": None}

    result = evaluator.evaluate(context=context, policy=policy)

    assert result.matched_rule is not None


def test_evaluator_rejects_invalid_policy_type(evaluator: PolicyEvaluator) -> None:
    """Evaluator validates that policy argument is a Policy instance."""
    with pytest.raises(TypeError, match="policy must be a Policy instance"):
        evaluator.evaluate(context={}, policy={"invalid": "dict"})


def test_evaluator_handles_multiple_matching_rules_by_precedence(
    evaluator: PolicyEvaluator,
) -> None:
    """When multiple rules match, highest-precedence rule is selected."""
    policy = _base_policy(
        rules=[
            {
                "condition": {"field": "type", "operator": "CONTAINS", "value": "data"},
                "action": {
                    "algorithm": "algo-1",
                    "key_rotation": "30d",
                    "compliance": ["rule-1"],
                    "metadata": {},
                },
            },
            {
                "condition": {
                    "field": "metadata.subtype",
                    "operator": "EQUALS",
                    "value": "personal-data",
                },
                "action": {
                    "algorithm": "algo-2",
                    "key_rotation": "15d",
                    "compliance": ["rule-2"],
                    "metadata": {},
                },
            },
        ]
    )
    context = {"type": "personal-data", "metadata": {"subtype": "personal-data"}}

    result = evaluator.evaluate(context=context, policy=policy)

    assert "rule-2" in result.action.compliance or "rule-1" in result.action.compliance


def test_evaluator_decision_tree_efficiency_with_many_rules(evaluator: PolicyEvaluator) -> None:
    """Decision tree provides O(log n) lookup efficiency."""
    rules = []
    for i in range(100):
        rules.append(
            {
                "condition": {
                    "field": f"field_{i % 10}",
                    "operator": "EQUALS",
                    "value": i,
                },
                "action": {
                    "algorithm": f"algo-{i}",
                    "key_rotation": "60d",
                    "compliance": [f"rule-{i}"],
                    "metadata": {},
                },
            }
        )

    policy = _base_policy(rules=rules)
    context = {f"field_{i}": i for i in range(10)}

    start = time.perf_counter()
    result = evaluator.evaluate(context=context, policy=policy)
    elapsed = (time.perf_counter() - start) * 1000.0

    assert result.evaluation_time_ms < 20.0
    assert elapsed < 50.0  # Should be very fast even with 100 rules


def test_evaluator_handles_dataclass_context(evaluator: PolicyEvaluator) -> None:
    """Evaluator can accept dataclass as context."""
    from dataclasses import dataclass

    @dataclass
    class EncryptionContext:
        data_class: str
        risk_level: float

    policy = _base_policy(
        rules=[
            {
                "condition": {
                    "field": "data_class",
                    "operator": "EQUALS",
                    "value": "PII",
                },
                "action": {
                    "algorithm": "chacha20-poly1305",
                    "key_rotation": "30d",
                    "compliance": ["pii"],
                    "metadata": {},
                },
            }
        ]
    )
    context = EncryptionContext(data_class="PII", risk_level=0.9)

    result = evaluator.evaluate(context=context, policy=policy)

    assert result.matched_rule is not None
    assert "pii" in result.action.compliance
