"""Unit tests for policy templates and customization."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.policy.policy_schema import Policy
from src.policy.policy_templates import (
    FINANCIAL_POLICY,
    GDPR_POLICY,
    GOVERNMENT_POLICY,
    HEALTHCARE_POLICY,
    HIGH_SECURITY_POLICY,
    customize_template,
)


def test_healthcare_policy_is_valid_policy() -> None:
    """Healthcare template is a valid Policy instance."""
    assert isinstance(HEALTHCARE_POLICY, Policy)
    assert HEALTHCARE_POLICY.name == "Healthcare HIPAA Baseline"
    assert HEALTHCARE_POLICY.version == "1.0"


def test_healthcare_policy_has_hipaa_compliance_tags() -> None:
    """Healthcare policy includes HIPAA compliance markers."""
    assert "hipaa" in HEALTHCARE_POLICY.default_action.compliance
    assert HEALTHCARE_POLICY.default_action.algorithm == "aes-256-gcm"
    assert HEALTHCARE_POLICY.default_action.key_rotation == "60d"


def test_healthcare_policy_phi_rule_exists() -> None:
    """Healthcare policy has specific PHI data protection rule."""
    phi_rules = [
        rule
        for rule in HEALTHCARE_POLICY.rules
        if rule.condition.field == "data_classification"
    ]
    assert len(phi_rules) > 0
    assert "phi" in phi_rules[0].action.compliance


def test_healthcare_policy_enforces_shorter_rotation_for_phi() -> None:
    """PHI data requires more frequent key rotation than default."""
    phi_rule = [
        rule
        for rule in HEALTHCARE_POLICY.rules
        if "phi" in rule.action.compliance
    ][0]
    assert phi_rule.action.key_rotation == "30d"
    assert HEALTHCARE_POLICY.default_action.key_rotation == "60d"


def test_financial_policy_is_valid_policy() -> None:
    """Financial template is a valid Policy instance."""
    assert isinstance(FINANCIAL_POLICY, Policy)
    assert FINANCIAL_POLICY.name == "Financial PCI-DSS Baseline"
    assert FINANCIAL_POLICY.version == "1.0"


def test_financial_policy_has_pci_dss_compliance_tags() -> None:
    """Financial policy includes PCI-DSS compliance markers."""
    assert "pci-dss" in FINANCIAL_POLICY.default_action.compliance
    assert FINANCIAL_POLICY.default_action.algorithm == "aes-256-gcm"


def test_financial_policy_cardholder_data_requires_hsm() -> None:
    """Cardholder data protection requires HSM."""
    chd_rules = [
        rule
        for rule in FINANCIAL_POLICY.rules
        if rule.condition.field == "contains_cardholder_data"
    ]
    assert len(chd_rules) > 0
    assert chd_rules[0].action.metadata.get("hsm_required") is True


def test_financial_policy_large_transactions_require_frequent_rotation() -> None:
    """Large transactions (>$100k) require more frequent key rotation."""
    large_tx_rules = [
        rule
        for rule in FINANCIAL_POLICY.rules
        if rule.condition.field == "metadata.transaction_amount"
    ]
    assert len(large_tx_rules) > 0
    assert large_tx_rules[0].action.key_rotation == "7d"


def test_government_policy_is_valid_policy() -> None:
    """Government template is a valid Policy instance."""
    assert isinstance(GOVERNMENT_POLICY, Policy)
    assert GOVERNMENT_POLICY.name == "Government NIST 800-53 Baseline"
    assert GOVERNMENT_POLICY.version == "1.0"


def test_government_policy_has_nist_compliance_tags() -> None:
    """Government policy includes NIST 800-53 compliance markers."""
    assert "nist-800-53" in GOVERNMENT_POLICY.default_action.compliance
    assert GOVERNMENT_POLICY.default_action.metadata.get("fips_mode") is True


def test_government_policy_classified_data_requires_frequent_rotation() -> None:
    """Classified data requires frequent key rotation."""
    secret_rules = [
        rule
        for rule in GOVERNMENT_POLICY.rules
        if rule.condition.field == "classification"
    ]
    assert len(secret_rules) > 0
    assert secret_rules[0].action.key_rotation == "7d"
    assert "fedramp-high" in secret_rules[0].action.compliance


def test_government_policy_high_threat_requires_very_short_rotation() -> None:
    """High threat level requires very frequent key rotation."""
    threat_rules = [
        rule
        for rule in GOVERNMENT_POLICY.rules
        if rule.condition.field == "threat_level"
    ]
    assert len(threat_rules) > 0
    assert threat_rules[0].action.key_rotation == "3d"


def test_gdpr_policy_is_valid_policy() -> None:
    """GDPR template is a valid Policy instance."""
    assert isinstance(GDPR_POLICY, Policy)
    assert GDPR_POLICY.name == "EU GDPR Baseline"
    assert GDPR_POLICY.version == "1.0"


def test_gdpr_policy_has_gdpr_compliance_tags() -> None:
    """GDPR policy includes GDPR compliance markers."""
    assert "gdpr" in GDPR_POLICY.default_action.compliance
    assert GDPR_POLICY.default_action.algorithm == "aes-256-gcm"


def test_gdpr_policy_personal_data_includes_deletion_settings() -> None:
    """Personal data protection includes crypto erasure settings."""
    pii_rules = [
        rule
        for rule in GDPR_POLICY.rules
        if rule.condition.field == "contains_personal_data"
    ]
    assert len(pii_rules) > 0
    deletion_config = pii_rules[0].action.metadata.get("deletion", {})
    assert deletion_config.get("crypto_erasure") is True
    assert deletion_config.get("retention_days") == 30


def test_gdpr_policy_right_to_erasure_immediate() -> None:
    """Right-to-erasure requests trigger immediate deletion."""
    erasure_rules = [
        rule
        for rule in GDPR_POLICY.rules
        if rule.condition.field == "metadata.right_to_erasure_request"
    ]
    assert len(erasure_rules) > 0
    deletion_config = erasure_rules[0].action.metadata.get("deletion", {})
    assert deletion_config.get("priority") == "immediate"
    assert deletion_config.get("retention_days") == 0


def test_gdpr_policy_eu_data_residency() -> None:
    """EU data requires data residency constraints."""
    eu_rules = [
        rule
        for rule in GDPR_POLICY.rules
        if rule.condition.field == "region"
    ]
    assert len(eu_rules) > 0
    assert eu_rules[0].action.metadata.get("data_residency") == "eu-only"


def test_high_security_policy_is_valid_policy() -> None:
    """High-security template is a valid Policy instance."""
    assert isinstance(HIGH_SECURITY_POLICY, Policy)
    assert HIGH_SECURITY_POLICY.name == "High Security Maximum Protection"
    assert HIGH_SECURITY_POLICY.version == "1.0"


def test_high_security_policy_uses_post_quantum_algorithms() -> None:
    """High-security policy uses hybrid post-quantum algorithms."""
    assert "hybrid-kyber1024-aes-256-gcm" in HIGH_SECURITY_POLICY.default_action.algorithm
    for rule in HIGH_SECURITY_POLICY.rules:
        assert "hybrid-kyber1024-aes-256-gcm" in rule.action.algorithm


def test_high_security_policy_requires_hsm() -> None:
    """High-security policy requires HSM for key operations."""
    assert HIGH_SECURITY_POLICY.default_action.metadata.get("hsm_required") is True
    assert HIGH_SECURITY_POLICY.default_action.metadata.get("pqc_enabled") is True


def test_high_security_policy_short_key_rotation() -> None:
    """High-security policy enforces short key rotation periods."""
    assert HIGH_SECURITY_POLICY.default_action.key_rotation == "3d"
    for rule in HIGH_SECURITY_POLICY.rules:
        assert rule.action.key_rotation in ["1d", "12h", "6h", "3d"]


def test_high_security_policy_threat_level_rotation() -> None:
    """High threat levels require very frequent rotation."""
    threat_rules = [
        rule
        for rule in HIGH_SECURITY_POLICY.rules
        if rule.condition.field == "threat_level"
    ]
    assert len(threat_rules) > 0
    assert threat_rules[0].action.key_rotation == "1d"


def test_high_security_policy_quantum_risk_rotation() -> None:
    """Quantum risk triggers most aggressive rotation schedule."""
    quantum_rules = [
        rule
        for rule in HIGH_SECURITY_POLICY.rules
        if rule.condition.field == "metadata.quantum_risk"
    ]
    assert len(quantum_rules) > 0
    assert quantum_rules[0].action.key_rotation == "6h"
    assert quantum_rules[0].action.metadata.get("pqc_priority") == "max"


def test_customize_template_basic_override() -> None:
    """customize_template() applies overrides to template."""
    custom = customize_template(
        HEALTHCARE_POLICY,
        {"default_action": {"key_rotation": "14d"}},
    )

    assert custom.default_action.key_rotation == "14d"
    assert custom.default_action.algorithm == "aes-256-gcm"


def test_customize_template_preserves_original() -> None:
    """customize_template() does not mutate the original template."""
    original_rotation = HEALTHCARE_POLICY.default_action.key_rotation
    customize_template(
        HEALTHCARE_POLICY,
        {"default_action": {"key_rotation": "999d"}},
    )

    assert HEALTHCARE_POLICY.default_action.key_rotation == original_rotation


def test_customize_template_deep_merge() -> None:
    """customize_template() recursively merges override values."""
    custom = customize_template(
        FINANCIAL_POLICY,
        {
            "default_action": {
                "metadata": {"custom_field": "custom_value"},
            }
        },
    )

    assert custom.default_action.metadata.get("tokenization") is True
    assert custom.default_action.metadata.get("custom_field") == "custom_value"


def test_customize_template_override_compliance_tags() -> None:
    """customize_template() can override compliance tags."""
    custom = customize_template(
        HEALTHCARE_POLICY,
        {"default_action": {"compliance": ["custom-tag", "another-tag"]}},
    )

    assert custom.default_action.compliance == ["custom-tag", "another-tag"]


def test_customize_template_returns_valid_policy() -> None:
    """customize_template() returns a valid Policy instance."""
    custom = customize_template(
        GOVERNMENT_POLICY,
        {"name": "Custom Government Policy"},
    )

    assert isinstance(custom, Policy)
    assert custom.name == "Custom Government Policy"
    assert custom.version == GOVERNMENT_POLICY.version


def test_customize_template_rejects_non_policy_template() -> None:
    """customize_template() validates template type."""
    with pytest.raises(TypeError, match="template must be a Policy instance"):
        customize_template({"invalid": "dict"}, {})


def test_customize_template_rejects_non_dict_overrides() -> None:
    """customize_template() validates overrides type."""
    with pytest.raises(TypeError, match="overrides must be a dict"):
        customize_template(HEALTHCARE_POLICY, "invalid")


def test_customize_template_multiple_overrides() -> None:
    """customize_template() applies multiple independent overrides."""
    custom = customize_template(
        HIGH_SECURITY_POLICY,
        {
            "name": "Custom High Security",
            "default_action": {"key_rotation": "1d"},
            "version": "2.0",
        },
    )

    assert custom.name == "Custom High Security"
    assert custom.version == "2.0"
    assert custom.default_action.key_rotation == "1d"


def test_templates_have_unique_names() -> None:
    """Each template has a unique, descriptive name."""
    templates = [
        HEALTHCARE_POLICY,
        FINANCIAL_POLICY,
        GOVERNMENT_POLICY,
        GDPR_POLICY,
        HIGH_SECURITY_POLICY,
    ]
    names = [t.name for t in templates]
    assert len(names) == len(set(names))


def test_templates_have_rules() -> None:
    """Each template defines at least one policy rule."""
    templates = [
        HEALTHCARE_POLICY,
        FINANCIAL_POLICY,
        GOVERNMENT_POLICY,
        GDPR_POLICY,
        HIGH_SECURITY_POLICY,
    ]
    for template in templates:
        assert len(template.rules) > 0


def test_templates_are_valid_policies() -> None:
    """All templates are valid Policy instances."""
    templates = [
        HEALTHCARE_POLICY,
        FINANCIAL_POLICY,
        GOVERNMENT_POLICY,
        GDPR_POLICY,
        HIGH_SECURITY_POLICY,
    ]
    for template in templates:
        assert isinstance(template, Policy)
        assert template.name
        assert template.version
        assert template.default_action is not None


def test_templates_rule_conditions_are_well_formed() -> None:
    """All template rules have well-formed conditions."""
    templates = [
        HEALTHCARE_POLICY,
        FINANCIAL_POLICY,
        GOVERNMENT_POLICY,
        GDPR_POLICY,
        HIGH_SECURITY_POLICY,
    ]
    for template in templates:
        for rule in template.rules:
            assert rule.condition.field
            assert rule.condition.operator
            assert rule.condition.value is not None


def test_customize_template_preserves_rule_count() -> None:
    """customize_template() preserves the number of rules."""
    original_count = len(HEALTHCARE_POLICY.rules)
    custom = customize_template(HEALTHCARE_POLICY, {"name": "Custom"})
    assert len(custom.rules) == original_count


def test_customize_template_with_new_compliance_adds_to_metadata() -> None:
    """customize_template() can add new metadata fields."""
    custom = customize_template(
        GDPR_POLICY,
        {
            "default_action": {
                "metadata": {
                    "custom_audit": {"enabled": True, "level": "verbose"}
                }
            }
        },
    )

    assert custom.default_action.metadata.get("custom_audit") == {
        "enabled": True,
        "level": "verbose",
    }
    assert "deletion" in custom.default_action.metadata


def test_financial_policy_includes_payment_flow_rules() -> None:
    """Financial policy handles different payment flow types."""
    payment_rules = [
        rule
        for rule in FINANCIAL_POLICY.rules
        if rule.condition.field == "payment_flow"
    ]
    assert len(payment_rules) > 0
    assert payment_rules[0].condition.value == ["card-present", "card-not-present"]
