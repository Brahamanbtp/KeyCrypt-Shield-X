"""Unit tests for policy compilation and evaluation components."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Callable

import pytest
import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from src.policy.compliance_policies import HIPAA_POLICY
from src.policy.policy_compiler import PolicyCompiler
from src.policy.policy_evaluator import PolicyEvaluator
from src.policy.policy_schema import Policy
from src.policy.rule_engine import RuleEngine


@pytest.fixture
def yaml_policy_factory(tmp_path: Path) -> Callable[[dict[str, Any], str], Path]:
    def _factory(payload: dict[str, Any], filename: str = "policy.yaml") -> Path:
        path = tmp_path / filename
        path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
        return path

    return _factory


@pytest.fixture
def compiler() -> PolicyCompiler:
    return PolicyCompiler()


@pytest.fixture
def rule_engine() -> RuleEngine:
    return RuleEngine()


@pytest.fixture
def policy_evaluator() -> PolicyEvaluator:
    return PolicyEvaluator()


def test_policy_compiler_parses_yaml_correctly(
    yaml_policy_factory: Callable[[dict[str, Any], str], Path],
    compiler: PolicyCompiler,
) -> None:
    policy_payload = {
        "name": "compiler-parse",
        "default_decision": {
            "algorithm": "aes-128-gcm",
            "key_rotation": "180d",
            "compliance_tags": ["baseline"],
        },
        "rules": [
            {
                "when": {
                    "data_classification": "PHI",
                    "region": {"in": ["us-east", "us-west"]},
                },
                "decision": {
                    "algorithm": "aes-256-gcm",
                    "key_rotation": "90d",
                    "compliance_tags": ["hipaa"],
                },
            },
            {
                "if": {
                    "risk_score": {"gt": 0.8},
                },
                "then": {
                    "algorithm": "chacha20-poly1305",
                    "key_rotation": "30d",
                },
            },
        ],
    }

    yaml_path = yaml_policy_factory(policy_payload, "compiler-parse.yaml")
    compiled = compiler.compile(yaml_path)

    assert compiled.name == "compiler-parse"
    assert compiled.default_decision["algorithm"] == "aes-128-gcm"
    assert len(compiled.rules) == 2
    assert compiled.rules[0].specificity >= compiled.rules[1].specificity

    decision = compiled.evaluate(
        {
            "data_classification": "PHI",
            "region": "us-east",
            "risk_score": 0.2,
        }
    )

    assert decision["algorithm"] == "aes-256-gcm"
    assert decision["key_rotation"] == "90d"
    assert "hipaa" in decision["compliance_tags"]


def test_rule_engine_matches_conditions_accurately(
    yaml_policy_factory: Callable[[dict[str, Any], str], Path],
    compiler: PolicyCompiler,
    rule_engine: RuleEngine,
) -> None:
    policy_payload = {
        "name": "rule-engine-match",
        "default_decision": {
            "algorithm": "aes-128-gcm",
            "key_rotation": "180d",
            "compliance_tags": ["default"],
        },
        "rules": [
            {
                "when": {
                    "tenant": {"regex": "^hospital-"},
                    "risk_score": {"gte": 70},
                    "regions": {"contains": "us-east"},
                },
                "decision": {
                    "algorithm": "aes-256-gcm",
                    "key_rotation": "90d",
                    "compliance_tags": ["matched"],
                },
            }
        ],
    }

    yaml_path = yaml_policy_factory(policy_payload, "rule-engine-match.yaml")
    compiled = compiler.compile(yaml_path)

    matched_context = {
        "tenant": "hospital-main",
        "risk_score": 72,
        "regions": ["us-east", "us-west"],
    }
    unmatched_context = {
        "tenant": "retail-main",
        "risk_score": 20,
        "regions": ["eu-central"],
    }

    matched_action = rule_engine.evaluate(matched_context, compiled)
    unmatched_action = rule_engine.evaluate(unmatched_context, compiled)

    assert matched_action.algorithm == "aes-256-gcm"
    assert matched_action.key_rotation == "90d"
    assert matched_action.compliance_tags == ["matched"]

    assert unmatched_action.algorithm == "aes-128-gcm"
    assert unmatched_action.key_rotation == "180d"


def test_policy_evaluator_selects_correct_action(policy_evaluator: PolicyEvaluator) -> None:
    policy = Policy.model_validate(
        {
            "name": "runtime-policy",
            "version": "1.0",
            "default_action": {
                "algorithm": "aes-128-gcm",
                "key_rotation": "180d",
                "compliance": ["baseline"],
            },
            "rules": [
                {
                    "condition": {
                        "field": "metadata.risk_score",
                        "operator": "GREATER_THAN",
                        "value": 0.8,
                    },
                    "action": {
                        "algorithm": "chacha20-poly1305",
                        "key_rotation": "30d",
                        "compliance": ["high-risk"],
                    },
                }
            ],
        }
    )

    result = policy_evaluator.evaluate(
        context={
            "metadata": {
                "risk_score": 0.95,
                "data_classification": "INTERNAL",
            }
        },
        policy=policy,
    )

    assert result.matched_rule is not None
    assert result.action.algorithm == "chacha20-poly1305"
    assert result.action.key_rotation == "30d"
    assert "high-risk" in result.action.compliance
    assert result.rules_checked >= 1


def test_compliance_policies_enforce_requirements(
    yaml_policy_factory: Callable[[dict[str, Any], str], Path],
    compiler: PolicyCompiler,
    rule_engine: RuleEngine,
) -> None:
    hipaa_for_compiler = {
        "name": HIPAA_POLICY["name"],
        "default_decision": HIPAA_POLICY["default_action"],
        "rules": [
            {
                "when": dict(HIPAA_POLICY["rules"][0]["match"]),
                "decision": dict(HIPAA_POLICY["rules"][0]["action"]),
            }
        ],
    }

    yaml_path = yaml_policy_factory(hipaa_for_compiler, "hipaa.yaml")
    compiled = compiler.compile(yaml_path)

    action = rule_engine.evaluate(
        context={"data_classification": "PHI"},
        rules=compiled,
    )

    assert "256" in action.algorithm
    assert action.key_rotation == "90d"


def test_policy_precedence_specific_before_general(
    yaml_policy_factory: Callable[[dict[str, Any], str], Path],
    compiler: PolicyCompiler,
    rule_engine: RuleEngine,
) -> None:
    policy_payload = {
        "name": "precedence-policy",
        "default_decision": {
            "algorithm": "aes-128-gcm",
            "key_rotation": "180d",
            "compliance_tags": ["default"],
        },
        "rules": [
            {
                "when": {
                    "data_classification": {"exists": True},
                },
                "decision": {
                    "algorithm": "aes-192-gcm",
                    "key_rotation": "120d",
                    "compliance_tags": ["general"],
                },
            },
            {
                "when": {
                    "data_classification": "PHI",
                    "region": "us-east",
                },
                "decision": {
                    "algorithm": "aes-256-gcm",
                    "key_rotation": "90d",
                    "compliance_tags": ["specific"],
                },
            },
        ],
    }

    yaml_path = yaml_policy_factory(policy_payload, "precedence.yaml")
    compiled = compiler.compile(yaml_path)
    action = rule_engine.evaluate(
        context={
            "data_classification": "PHI",
            "region": "us-east",
        },
        rules=compiled,
    )

    assert action.algorithm == "aes-256-gcm"
    assert action.key_rotation == "90d"
    assert action.compliance_tags == ["specific"]


def test_policy_edge_cases_empty_policy_and_conflicting_rules(
    yaml_policy_factory: Callable[[dict[str, Any], str], Path],
    compiler: PolicyCompiler,
    rule_engine: RuleEngine,
) -> None:
    empty_policy = {
        "name": "empty-policy",
        "default_decision": {
            "algorithm": "aes-128-gcm",
            "key_rotation": "365d",
            "compliance_tags": ["empty"],
        },
        "rules": [],
    }

    empty_yaml = yaml_policy_factory(empty_policy, "empty.yaml")
    compiled_empty = compiler.compile(empty_yaml)
    empty_action = rule_engine.evaluate({"any": "value"}, compiled_empty)

    assert empty_action.algorithm == "aes-128-gcm"
    assert empty_action.key_rotation == "365d"

    conflicting_policy = {
        "name": "conflicting-policy",
        "default_decision": {
            "algorithm": "aes-128-gcm",
            "key_rotation": "180d",
            "compliance_tags": ["default"],
        },
        "rules": [
            {
                "when": {"tenant": "acme"},
                "decision": {
                    "algorithm": "aes-256-gcm",
                    "key_rotation": "90d",
                    "compliance_tags": ["first"],
                },
            },
            {
                "when": {"tenant": "acme"},
                "decision": {
                    "algorithm": "chacha20-poly1305",
                    "key_rotation": "30d",
                    "compliance_tags": ["second"],
                },
            },
        ],
    }

    conflicting_yaml = yaml_policy_factory(conflicting_policy, "conflicting.yaml")
    compiled_conflicting = compiler.compile(conflicting_yaml)
    conflicting_action = rule_engine.evaluate({"tenant": "acme"}, compiled_conflicting)

    # Conflicting rules with equal specificity preserve first-defined precedence.
    assert conflicting_action.algorithm == "aes-256-gcm"
    assert conflicting_action.key_rotation == "90d"
    assert conflicting_action.compliance_tags == ["first"]
