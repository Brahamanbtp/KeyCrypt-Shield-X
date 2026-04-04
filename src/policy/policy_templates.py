"""Ready-to-use policy templates for common compliance and security profiles."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from src.policy.policy_schema import Action, Condition, Operator, Policy, PolicyRule


HEALTHCARE_POLICY = Policy(
    name="Healthcare HIPAA Baseline",
    version="1.0",
    rules=[
        PolicyRule(
            condition=Condition(
                field="data_classification",
                operator=Operator.EQUALS,
                value="PHI",
            ),
            action=Action(
                algorithm="aes-256-gcm",
                key_rotation="30d",
                compliance=["hipaa", "healthcare", "phi"],
                metadata={
                    "audit": {"immutable_logs": True, "retention_days": 2555},
                    "access_control": "least-privilege",
                },
            ),
        ),
        PolicyRule(
            condition=Condition(
                field="metadata.treatment_context",
                operator=Operator.EQUALS,
                value=True,
            ),
            action=Action(
                algorithm="aes-256-gcm",
                key_rotation="15d",
                compliance=["hipaa", "minimum-necessary"],
                metadata={"dual_authorization": True},
            ),
        ),
    ],
    default_action=Action(
        algorithm="aes-256-gcm",
        key_rotation="60d",
        compliance=["hipaa"],
        metadata={"audit": {"enabled": True}, "integrity": "sha256"},
    ),
)


FINANCIAL_POLICY = Policy(
    name="Financial PCI-DSS Baseline",
    version="1.0",
    rules=[
        PolicyRule(
            condition=Condition(
                field="contains_cardholder_data",
                operator=Operator.EQUALS,
                value=True,
            ),
            action=Action(
                algorithm="aes-256-gcm",
                key_rotation="30d",
                compliance=["pci-dss", "financial", "pan-data"],
                metadata={"tokenization": True, "hsm_required": True},
            ),
        ),
        PolicyRule(
            condition=Condition(
                field="payment_flow",
                operator=Operator.IN,
                value=["card-present", "card-not-present"],
            ),
            action=Action(
                algorithm="aes-256-gcm",
                key_rotation="14d",
                compliance=["pci-dss", "transaction-security"],
                metadata={"mfa_for_key_ops": True},
            ),
        ),
        PolicyRule(
            condition=Condition(
                field="metadata.transaction_amount",
                operator=Operator.GREATER_THAN,
                value=100000,
            ),
            action=Action(
                algorithm="aes-256-gcm",
                key_rotation="7d",
                compliance=["pci-dss", "fraud-monitoring"],
                metadata={"enhanced_audit": True},
            ),
        ),
    ],
    default_action=Action(
        algorithm="aes-256-gcm",
        key_rotation="45d",
        compliance=["pci-dss"],
        metadata={"tokenization": True},
    ),
)


GOVERNMENT_POLICY = Policy(
    name="Government NIST 800-53 Baseline",
    version="1.0",
    rules=[
        PolicyRule(
            condition=Condition(
                field="classification",
                operator=Operator.IN,
                value=["SECRET", "TOP_SECRET"],
            ),
            action=Action(
                algorithm="aes-256-gcm",
                key_rotation="7d",
                compliance=["nist-800-53", "fedramp-high"],
                metadata={"fips_mode": True, "continuous_monitoring": True},
            ),
        ),
        PolicyRule(
            condition=Condition(
                field="threat_level",
                operator=Operator.GREATER_THAN,
                value=0.8,
            ),
            action=Action(
                algorithm="aes-256-gcm",
                key_rotation="3d",
                compliance=["nist-800-53", "incident-response"],
                metadata={"requires_manual_review": True},
            ),
        ),
    ],
    default_action=Action(
        algorithm="aes-256-gcm",
        key_rotation="30d",
        compliance=["nist-800-53"],
        metadata={"fips_mode": True},
    ),
)


GDPR_POLICY = Policy(
    name="EU GDPR Baseline",
    version="1.0",
    rules=[
        PolicyRule(
            condition=Condition(
                field="contains_personal_data",
                operator=Operator.EQUALS,
                value=True,
            ),
            action=Action(
                algorithm="aes-256-gcm",
                key_rotation="30d",
                compliance=["gdpr", "pii", "privacy"],
                metadata={
                    "deletion": {
                        "crypto_erasure": True,
                        "retention_days": 30,
                        "secure_delete_workflow": True,
                    }
                },
            ),
        ),
        PolicyRule(
            condition=Condition(
                field="region",
                operator=Operator.EQUALS,
                value="EU",
            ),
            action=Action(
                algorithm="aes-256-gcm",
                key_rotation="21d",
                compliance=["gdpr", "data-sovereignty"],
                metadata={"data_residency": "eu-only"},
            ),
        ),
        PolicyRule(
            condition=Condition(
                field="metadata.right_to_erasure_request",
                operator=Operator.EQUALS,
                value=True,
            ),
            action=Action(
                algorithm="aes-256-gcm",
                key_rotation="1d",
                compliance=["gdpr", "right-to-erasure"],
                metadata={
                    "deletion": {
                        "crypto_erasure": True,
                        "retention_days": 0,
                        "priority": "immediate",
                    }
                },
            ),
        ),
    ],
    default_action=Action(
        algorithm="aes-256-gcm",
        key_rotation="45d",
        compliance=["gdpr"],
        metadata={
            "deletion": {
                "crypto_erasure": True,
                "retention_days": 90,
                "secure_delete_workflow": True,
            }
        },
    ),
)


HIGH_SECURITY_POLICY = Policy(
    name="High Security Maximum Protection",
    version="1.0",
    rules=[
        PolicyRule(
            condition=Condition(
                field="threat_level",
                operator=Operator.GREATER_THAN,
                value=0.7,
            ),
            action=Action(
                algorithm="hybrid-kyber1024-aes-256-gcm",
                key_rotation="1d",
                compliance=["nist-800-53", "cisa-zero-trust", "fips-140-3"],
                metadata={"hsm_required": True, "pqc_enabled": True, "multi_region_backup": True},
            ),
        ),
        PolicyRule(
            condition=Condition(
                field="data_classification",
                operator=Operator.IN,
                value=["secret", "top_secret", "restricted"],
            ),
            action=Action(
                algorithm="hybrid-kyber1024-aes-256-gcm",
                key_rotation="12h",
                compliance=["high-assurance", "mission-critical"],
                metadata={"split_key_custody": True, "tamper_evident_logs": True},
            ),
        ),
        PolicyRule(
            condition=Condition(
                field="metadata.quantum_risk",
                operator=Operator.MATCHES,
                value="^(high|critical)$",
            ),
            action=Action(
                algorithm="hybrid-kyber1024-aes-256-gcm",
                key_rotation="6h",
                compliance=["post-quantum", "forward-secrecy"],
                metadata={"pqc_priority": "max", "forced_reencrypt": True},
            ),
        ),
    ],
    default_action=Action(
        algorithm="hybrid-kyber1024-aes-256-gcm",
        key_rotation="3d",
        compliance=["high-security", "post-quantum"],
        metadata={"hsm_required": True, "pqc_enabled": True},
    ),
)


def customize_template(template: Policy, overrides: dict[str, Any]) -> Policy:
    """Return a customized policy without mutating the original template.

    The override mapping is recursively merged into the template payload.
    Non-mapping values replace the existing values, while mappings are merged.
    """
    if not isinstance(template, Policy):
        raise TypeError("template must be a Policy instance")
    if not isinstance(overrides, dict):
        raise TypeError("overrides must be a dict")

    base_payload = template.model_dump(mode="python", by_alias=False, exclude_none=False)
    merged = _deep_merge(base_payload, overrides)
    return Policy.model_validate(merged)


def _deep_merge(base: Mapping[str, Any], overrides: Mapping[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, override_value in overrides.items():
        existing = merged.get(key)
        if isinstance(existing, Mapping) and isinstance(override_value, Mapping):
            merged[key] = _deep_merge(existing, override_value)
        else:
            merged[key] = override_value
    return merged


__all__ = [
    "HEALTHCARE_POLICY",
    "FINANCIAL_POLICY",
    "GOVERNMENT_POLICY",
    "GDPR_POLICY",
    "HIGH_SECURITY_POLICY",
    "customize_template",
]
