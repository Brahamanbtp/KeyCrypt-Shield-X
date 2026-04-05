"""Unit tests for src.observability.compliance_validator."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.observability.compliance_validator import (
    ComplianceValidator,
    ComplianceViolationError,
    Operation,
)


def _baseline_operation() -> Operation:
    return Operation(
        actor="svc-crypto",
        action="encrypt",
        resource="/patients/records/42",
        encryption_enabled=True,
        encryption_strength_bits=256,
        key_rotation_days=30,
        audit_logging_enabled=True,
        deletion_capability=True,
        consent_obtained=True,
        data_minimization_enabled=True,
        contains_cardholder_data=True,
        cardholder_data_encrypted=True,
        keys_protected=True,
        access_restricted=True,
    )


def test_validate_hipaa_compliance_success() -> None:
    validator = ComplianceValidator()

    result = validator.validate_hipaa_compliance(_baseline_operation())

    assert result.compliant is True
    assert result.violations == []
    assert result.recommendations == []


def test_validate_hipaa_compliance_reports_violations_and_recommendations() -> None:
    validator = ComplianceValidator()
    operation = _baseline_operation().model_copy(
        update={
            "encryption_enabled": False,
            "encryption_strength_bits": 128,
            "key_rotation_days": 180,
            "audit_logging_enabled": False,
        }
    )

    result = validator.validate_hipaa_compliance(operation)

    assert result.compliant is False
    assert any("encryption" in item.lower() for item in result.violations)
    assert any("256-bit" in item for item in result.violations)
    assert any("rotation" in item.lower() for item in result.violations)
    assert any("audit logging" in item.lower() for item in result.violations)
    assert len(result.recommendations) >= 3


def test_validate_gdpr_compliance_checks_required_controls() -> None:
    validator = ComplianceValidator()
    operation = _baseline_operation().model_copy(
        update={
            "encryption_strength_bits": 64,
            "deletion_capability": False,
            "consent_obtained": False,
            "data_minimization_enabled": False,
        }
    )

    result = validator.validate_gdpr_compliance(operation)

    assert result.compliant is False
    assert any("gdpr" in item.lower() for item in result.violations)
    assert any("deletion" in item.lower() for item in result.violations)
    assert any("consent" in item.lower() for item in result.violations)
    assert any("minimization" in item.lower() for item in result.violations)


def test_validate_pci_dss_compliance_checks_encryption_keys_and_access() -> None:
    validator = ComplianceValidator()
    operation = _baseline_operation().model_copy(
        update={
            "cardholder_data_encrypted": False,
            "keys_protected": False,
            "access_restricted": False,
        }
    )

    result = validator.validate_pci_dss_compliance(operation)

    assert result.compliant is False
    assert any("cardholder data" in item.lower() for item in result.violations)
    assert any("keys" in item.lower() for item in result.violations)
    assert any("access" in item.lower() for item in result.violations)


def test_validate_pre_operation_blocks_non_compliant_operation() -> None:
    validator = ComplianceValidator(block_non_compliant_operations=True)
    operation = _baseline_operation().model_copy(
        update={
            "audit_logging_enabled": False,
        }
    )

    with pytest.raises(ComplianceViolationError) as exc_info:
        validator.validate_pre_operation(operation, ["hipaa"])

    assert exc_info.value.result.compliant is False
    assert any("audit logging" in item.lower() for item in exc_info.value.result.violations)


def test_validate_pre_operation_can_run_in_observe_mode() -> None:
    validator = ComplianceValidator(block_non_compliant_operations=False)
    operation = _baseline_operation().model_copy(
        update={
            "deletion_capability": False,
            "consent_obtained": False,
        }
    )

    result = validator.validate_operation_realtime(operation, ["gdpr", "hipaa"])

    assert result.compliant is False
    assert len(result.violations) >= 2
    assert len(result.recommendations) >= 2
