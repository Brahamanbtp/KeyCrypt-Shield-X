"""Unit tests for src/compliance/hipaa_compliance.py."""

from __future__ import annotations

import importlib.util
import sys
from datetime import date, timedelta
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


def _load_module():
    module_path = PROJECT_ROOT / "src/compliance/hipaa_compliance.py"
    spec = importlib.util.spec_from_file_location("hipaa_compliance_module", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load hipaa_compliance module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_validate_hipaa_encryption_accepts_aes_256_equivalent() -> None:
    module = _load_module()
    framework = module.HIPAAComplianceFramework()

    assert framework.validate_hipaa_encryption("AES-256-GCM", 256) is True
    assert framework.validate_hipaa_encryption("AES-128-GCM", 128) is False


def test_validate_hipaa_key_rotation_enforces_90_day_window() -> None:
    module = _load_module()
    framework = module.HIPAAComplianceFramework()

    assert framework.validate_hipaa_key_rotation(30) is True
    assert framework.validate_hipaa_key_rotation(120) is False


def test_validate_hipaa_access_controls_require_role_and_audit_logging() -> None:
    module = _load_module()
    framework = module.HIPAAComplianceFramework()

    user = module.User(user_id="user-1", role="clinician")
    resource = module.Resource(resource_id="phi-record")
    bad_user = module.User(user_id="user-2", role="guest")

    assert framework.validate_hipaa_access_controls(user, resource) is True
    assert framework.validate_hipaa_access_controls(bad_user, resource) is False


def test_generate_hipaa_compliance_report_includes_baa_and_breach_notifications() -> None:
    module = _load_module()
    framework = module.HIPAAComplianceFramework(
        covered_entity_name="Northwind Hospital",
        business_associate_name="KeyCrypt Shield",
    )

    good_user = module.User(user_id="user-1", role="clinician")
    bad_user = module.User(user_id="user-2", role="guest")
    resource = module.Resource(resource_id="phi-record")

    assert framework.validate_hipaa_encryption("aes-256-gcm", 256) is True
    assert framework.validate_hipaa_key_rotation(45) is True
    assert framework.validate_hipaa_access_controls(good_user, resource) is True
    assert framework.validate_hipaa_access_controls(bad_user, resource) is False

    today = date.today()
    report = framework.generate_hipaa_compliance_report(today - timedelta(days=1), today)

    assert report.requirement_version == module.HIPAA_REQUIREMENT_VERSION
    assert report.compliant is False
    assert len(report.breach_notifications) >= 1
    assert "Business Associate Agreement" in report.baa_template
    assert "Northwind Hospital" in report.baa_template
    assert "KeyCrypt Shield" in report.baa_template
    assert any(entry["event_type"] == "access_control_validation" for entry in report.access_control_checks)