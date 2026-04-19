"""Unit tests for tools/config_validator.py."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def _load_config_validator_module():
    module_path = Path(__file__).resolve().parents[2] / "tools/config_validator.py"
    spec = importlib.util.spec_from_file_location("config_validator_tool", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load config_validator module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_validate_yaml_config_accepts_valid_document(tmp_path: Path) -> None:
    module = _load_config_validator_module()

    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        """
environment: development
default_algorithm: HYBRID
log_level: INFO
api:
  host: 127.0.0.1
  port: 9000
security:
  require_mfa: true
  allow_plaintext_keys: false
  key_rotation_days: 60
  audit_logging: true
""".strip()
        + "\n",
        encoding="utf-8",
    )

    result = module.validate_yaml_config(config_path)

    assert result.valid is True
    assert result.errors == ()


def test_validate_yaml_config_reports_schema_errors_with_examples(tmp_path: Path) -> None:
    module = _load_config_validator_module()

    config_path = tmp_path / "invalid-config.yaml"
    config_path.write_text(
        """
environment: prod
default_algorithm: AES
log_level: TRACE
api:
  host: ""
  port: 70000
""".strip()
        + "\n",
        encoding="utf-8",
    )

    result = module.validate_yaml_config(config_path)

    assert result.valid is False
    assert any(issue.path == "$.environment" for issue in result.errors)
    assert any(issue.path == "$.log_level" for issue in result.errors)
    assert all("environment:" in issue.example for issue in result.errors)


def test_validate_policy_file_accepts_valid_policy(tmp_path: Path) -> None:
    module = _load_config_validator_module()

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
schema_version: "1.0"
policy:
  name: risk-policy
  version: "1.0.0"
  rules:
    - condition:
        field: request.risk_score
        operator: GREATER_THAN
        value: 0.9
      action:
        algorithm: HYBRID
        key_rotation: 30d
        compliance: [soc2]
  default_action:
    algorithm: AES
    key_rotation: 90d
    compliance: [pci]
""".strip()
        + "\n",
        encoding="utf-8",
    )

    result = module.validate_policy_file(policy_path)

    assert result.valid is True
    assert result.errors == ()


def test_validate_policy_file_rejects_invalid_condition_operator(tmp_path: Path) -> None:
    module = _load_config_validator_module()

    policy_path = tmp_path / "bad-policy.yaml"
    policy_path.write_text(
        """
schema_version: "1.0"
policy:
  name: bad-policy
  version: "1.0.0"
  rules:
    - condition:
        field: request.risk_score
        operator: UNKNOWN
        value: 0.9
      action:
        algorithm: HYBRID
        key_rotation: 30d
  default_action:
    algorithm: AES
    key_rotation: 90d
""".strip()
        + "\n",
        encoding="utf-8",
    )

    result = module.validate_policy_file(policy_path)

    assert result.valid is False
    assert any(issue.path == "$.policy.rules[0].condition.operator" for issue in result.errors)
    assert all("schema_version:" in issue.example for issue in result.errors)


def test_validate_plugin_manifest_accepts_valid_manifest(tmp_path: Path) -> None:
    module = _load_config_validator_module()

    manifest_path = tmp_path / "plugin.yaml"
    manifest_path.write_text(
        """
name: example-plugin
version: 1.0.0
api_version: v1
author: Test Author
provides:
  - interface: src.abstractions.key_provider.KeyProvider
    implementation: plugins.example_provider.ExampleProvider
dependencies:
  - requests
security:
  permissions:
    - keys:read
  signature: ""
""".strip()
        + "\n",
        encoding="utf-8",
    )

    result = module.validate_plugin_manifest(manifest_path)

    assert result.valid is True
    assert result.errors == ()


def test_validate_plugin_manifest_reports_schema_errors_with_examples(tmp_path: Path) -> None:
    module = _load_config_validator_module()

    manifest_path = tmp_path / "invalid-plugin.yaml"
    manifest_path.write_text(
        """
name: example-plugin
version: one.two
api_version: v1
author: Test Author
provides:
  - interface: src.abstractions.key_provider.KeyProvider
security:
  permissions:
    - keys:read
""".strip()
        + "\n",
        encoding="utf-8",
    )

    result = module.validate_plugin_manifest(manifest_path)

    assert result.valid is False
    assert any(issue.path == "$.version" for issue in result.errors)
    assert any(issue.path == "$.provides[0]" for issue in result.errors)
    assert all("provides:" in issue.example for issue in result.errors)


def test_validate_plugin_manifest_warns_on_duplicate_dependencies(tmp_path: Path) -> None:
    module = _load_config_validator_module()

    manifest_path = tmp_path / "duplicate-deps-plugin.yaml"
    manifest_path.write_text(
        """
name: duplicate-plugin
version: 1.2.3
api_version: v1
author: Test Author
provides:
  - interface: src.abstractions.storage_provider.StorageProvider
    implementation: plugins.storage_provider.ExampleStorageProvider
dependencies:
  - Requests
  - requests
security:
  permissions:
    - storage:read
""".strip()
        + "\n",
        encoding="utf-8",
    )

    result = module.validate_plugin_manifest(manifest_path)

    assert result.valid is True
    assert any("duplicate entries" in warning for warning in result.warnings)


def test_suggest_config_improvements_highlights_security_gaps() -> None:
    module = _load_config_validator_module()

    suggestions = module.suggest_config_improvements(
        {
            "environment": "production",
            "default_algorithm": "AES",
            "log_level": "DEBUG",
            "api": {
                "host": "0.0.0.0",
                "port": 443,
                "tls_enabled": False,
            },
            "security": {
                "require_mfa": False,
                "allow_plaintext_keys": True,
                "key_rotation_days": 365,
                "audit_logging": False,
            },
        }
    )

    titles = {item.title for item in suggestions}
    severities = {item.severity for item in suggestions}

    assert "Enable TLS" in titles
    assert "Disable Plaintext Key Handling" in titles
    assert "Require MFA for Sensitive Operations" in titles
    assert "Enable Audit Logging" in titles
    assert "high" in severities
