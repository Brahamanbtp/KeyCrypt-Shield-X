"""Unit tests for src.registry.plugin_validator."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.registry.plugin_validator import PluginValidator


def _safe_plugin_code() -> str:
    return """
from __future__ import annotations

class Plugin:
    def self_test(self) -> bool:
        import math
        return math.sqrt(16) == 4
""".strip()


def _manifest_payload(*, name: str, api_version: str, permissions: list[str], dependencies: list[str]) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "name": name,
        "version": "1.0.0",
        "api_version": api_version,
        "author": "unit-tests",
        "provides": [],
        "dependencies": list(dependencies),
        "security": {
            "permissions": list(permissions),
            "signature": "",
        },
    }
    return payload


def _manifest_signature(payload: dict[str, Any]) -> str:
    canonical = {
        "name": payload["name"],
        "version": payload["version"],
        "api_version": payload["api_version"],
        "author": payload["author"],
        "provides": list(payload.get("provides", [])),
        "dependencies": list(payload.get("dependencies", [])),
        "security": {
            "permissions": list(payload.get("security", {}).get("permissions", [])),
        },
    }
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _write_plugin(
    tmp_path: Path,
    *,
    plugin_name: str,
    api_version: str = "0.1.0",
    permissions: list[str] | None = None,
    dependencies: list[str] | None = None,
    plugin_code: str | None = None,
) -> Path:
    plugin_root = tmp_path / plugin_name.replace("-", "_")
    plugin_root.mkdir(parents=True, exist_ok=True)

    source = plugin_code if plugin_code is not None else _safe_plugin_code()
    (plugin_root / "plugin.py").write_text(source, encoding="utf-8")

    manifest = _manifest_payload(
        name=plugin_name,
        api_version=api_version,
        permissions=permissions or ["registry:read"],
        dependencies=dependencies or ["cryptography>=44.0.0"],
    )
    manifest["security"]["signature"] = _manifest_signature(manifest)

    (plugin_root / "plugin.yaml").write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
    return plugin_root


def test_validate_plugin_success_with_multilayer_checks(tmp_path: Path) -> None:
    plugin_root = _write_plugin(tmp_path, plugin_name="validator-safe-plugin")

    validator = PluginValidator(
        require_code_signing=True,
        malware_scanning_enabled=False,
        system_api_version="0.1.0",
    )

    result = validator.validate_plugin(plugin_root)

    assert result.is_valid is True
    assert result.manifest_valid is True
    assert result.signature_valid is True
    assert result.dependency_safe is True
    assert result.api_compliant is True
    assert result.permissions_ok is True
    assert result.malware_scan.clean is True
    assert result.sandbox_result is not None and result.sandbox_result.passed is True
    assert len(result.checklist) >= 8


def test_validate_plugin_flags_api_and_permission_violations(tmp_path: Path) -> None:
    plugin_root = _write_plugin(
        tmp_path,
        plugin_name="validator-policy-violations",
        api_version="2.0.0",
        permissions=["*", "system:admin"],
    )

    validator = PluginValidator(
        require_code_signing=True,
        malware_scanning_enabled=False,
        system_api_version="0.1.0",
    )

    result = validator.validate_plugin(plugin_root)

    assert result.is_valid is False
    assert result.api_compliant is False
    assert result.permissions_ok is False
    assert any("api" in issue.lower() for issue in result.issues)
    assert any("permissions" in issue.lower() for issue in result.issues)


def test_scan_for_vulnerabilities_detects_common_risks() -> None:
    validator = PluginValidator(malware_scanning_enabled=False)

    code = """
import subprocess

password = "supersecret123"
eval("1 + 1")
subprocess.run("echo hello", shell=True)
"""

    findings = validator.scan_for_vulnerabilities(code)

    assert any(item.code == "PV-CODE-001" for item in findings)
    assert any(item.code == "PV-CODE-002" for item in findings)
    assert any(item.code == "PV-SECRET-001" for item in findings)
    assert any(item.severity in {"HIGH", "CRITICAL"} for item in findings)


def test_check_permissions_rejects_excessive_request() -> None:
    class _DummyPlugin:
        pass

    validator = PluginValidator(malware_scanning_enabled=False, max_requested_permissions=2)

    assert validator.check_permissions(_DummyPlugin(), ["registry:read", "crypto:encrypt"]) is True
    assert validator.check_permissions(_DummyPlugin(), ["registry:read", "*"]) is False
    assert validator.check_permissions(_DummyPlugin(), ["registry:read", "crypto:encrypt", "keys:read"]) is False


def test_sandbox_test_reports_policy_violation() -> None:
    class _UnsafePlugin:
        def self_test(self) -> bool:
            import os

            return bool(os.getcwd())

    validator = PluginValidator(malware_scanning_enabled=False)
    result = validator.sandbox_test(_UnsafePlugin())

    assert result.passed is False
    assert any("sandbox" in item.lower() or "whitelist" in item.lower() for item in result.violations)


def test_validate_plugin_malware_scan_integration_handles_missing_engine(tmp_path: Path) -> None:
    plugin_root = _write_plugin(tmp_path, plugin_name="validator-malware-engine-missing")

    validator = PluginValidator(
        require_code_signing=True,
        malware_scanning_enabled=True,
        malware_scan_required=True,
        malware_scan_command=("definitely-not-a-real-clamav-binary",),
    )

    result = validator.validate_plugin(plugin_root)

    assert result.is_valid is False
    assert result.malware_scan.clean is False
    assert any("malware" in issue.lower() for issue in result.issues)
