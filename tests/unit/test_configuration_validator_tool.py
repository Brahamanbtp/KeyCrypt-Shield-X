"""Unit tests for tools/configuration_validator.py."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def _load_configuration_validator_module():
    module_path = Path(__file__).resolve().parents[2] / "tools/configuration_validator.py"
    spec = importlib.util.spec_from_file_location("configuration_validator_tool", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load configuration_validator module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_validate_yaml_config_accepts_valid_document(tmp_path: Path) -> None:
    module = _load_configuration_validator_module()

    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        """
environment: production
default_algorithm: HYBRID
log_level: INFO
api:
  host: 127.0.0.1
  port: 8443
  tls_enabled: true
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
    assert result.missing_fields == ()


def test_validate_yaml_config_reports_missing_fields(tmp_path: Path) -> None:
    module = _load_configuration_validator_module()

    config_path = tmp_path / "invalid.yaml"
    config_path.write_text(
        """
environment: production
api:
  host: 0.0.0.0
""".strip()
        + "\n",
        encoding="utf-8",
    )

    result = module.validate_yaml_config(config_path)

    assert result.valid is False
    assert any(item.path == "$.default_algorithm" for item in result.missing_fields)
    assert any(item.path == "$.log_level" for item in result.missing_fields)


def test_check_required_fields_reports_nested_missing_fields() -> None:
    module = _load_configuration_validator_module()

    config = {"environment": "development", "api": {"host": "127.0.0.1"}}

    missing = module.check_required_fields(config, module.DEFAULT_CONFIG_SCHEMA)

    assert any(item.path == "$.default_algorithm" for item in missing)
    assert any(item.path == "$.api.port" for item in missing)


def test_validate_environment_variables_reports_missing(monkeypatch) -> None:
    module = _load_configuration_validator_module()

    monkeypatch.delenv("KEYCRYPT_TEST_API_KEY", raising=False)
    monkeypatch.setenv("KEYCRYPT_TEST_PRESENT", "value")

    missing = module.validate_environment_variables(
        ["KEYCRYPT_TEST_API_KEY", "KEYCRYPT_TEST_PRESENT"]
    )

    assert missing == ["KEYCRYPT_TEST_API_KEY"]


def test_suggest_config_improvements_flags_insecure_settings() -> None:
    module = _load_configuration_validator_module()

    suggestions = module.suggest_config_improvements(
        {
            "environment": "production",
            "log_level": "DEBUG",
            "api": {"host": "0.0.0.0", "tls_enabled": False},
            "security": {
                "require_mfa": False,
                "allow_plaintext_keys": True,
                "audit_logging": False,
                "key_rotation_days": 120,
            },
        }
    )

    titles = {item.title for item in suggestions}
    assert "Enable TLS" in titles
    assert "Reduce production log verbosity" in titles
    assert "Disable plaintext key handling" in titles


def test_auto_fix_config_generates_valid_yaml(tmp_path: Path) -> None:
    module = _load_configuration_validator_module()

    config_path = tmp_path / "broken.yaml"
    config_path.write_text("environment: production\n", encoding="utf-8")

    fixed_path = module.auto_fix_config(config_path)

    assert fixed_path.exists()
    result = module.validate_yaml_config(fixed_path)
    assert result.valid is True