"""Unit tests for policy schema validation and versioning."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.policy.policy_schema import (
    Action,
    Condition,
    Operator,
    Policy,
    PolicySchemaDocumentV1,
    PolicySchemaVersion,
    parse_policy_document,
    validate_action,
    validate_condition,
)


def _policy_payload(schema_version: object) -> dict[str, object]:
    return {
        "schema_version": schema_version,
        "policy": {
            "name": "demo-policy",
            "version": "1.0",
            "default_action": {
                "algorithm": "aes-256-gcm",
                "key_rotation": "90d",
                "compliance": ["baseline"],
                "metadata": {"source": "unit-test"},
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
                        "metadata": {},
                    },
                }
            ],
        },
    }


def test_parse_policy_document_accepts_numeric_schema_version() -> None:
    document = parse_policy_document(_policy_payload(1))

    assert document.schema_version == PolicySchemaVersion.V1
    assert document.policy.name == "demo-policy"
    assert document.policy.rules[0].condition.operator == Operator.GREATER_THAN


def test_parse_policy_document_accepts_canonical_schema_version() -> None:
    document = parse_policy_document(_policy_payload("2.0"))

    assert document.schema_version == PolicySchemaVersion.V2
    assert document.policy.default_action.algorithm == "aes-256-gcm"


def test_policy_schema_document_normalizes_version_on_direct_validation() -> None:
    document = PolicySchemaDocumentV1.model_validate(_policy_payload("v1"))

    assert document.schema_version == PolicySchemaVersion.V1


def test_condition_and_action_validation_helpers_return_true_for_valid_values() -> None:
    condition = Condition(field="metadata.risk_score", operator=Operator.GREATER_THAN, value=0.8)
    action = Action(
        algorithm="aes-256-gcm",
        key_rotation="90d",
        compliance=["baseline", "baseline"],
        metadata={},
    )

    assert validate_condition(condition) is True
    assert validate_action(action) is True
    assert action.compliance == ["baseline"]


def test_policy_model_requires_non_empty_names() -> None:
    with pytest.raises(ValueError):
        Policy.model_validate(
            {
                "name": " ",
                "version": "1.0",
                "default_action": {
                    "algorithm": "aes-256-gcm",
                    "key_rotation": "90d",
                    "compliance": [],
                    "metadata": {},
                },
                "rules": [],
            }
        )
