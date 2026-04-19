#!/usr/bin/env python3
"""Configuration validation tool for YAML configs, policies, and plugin manifests.

This module validates structured files with jsonschema and performs additional
semantic checks using project-native models where available.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, List, Mapping

import yaml


_VALID_YAML_CONFIG_EXAMPLE = """environment: production
default_algorithm: HYBRID
log_level: INFO
api:
  host: 127.0.0.1
  port: 8000
  tls_enabled: true
security:
  require_mfa: true
  allow_plaintext_keys: false
  key_rotation_days: 90
  audit_logging: true
"""


_VALID_POLICY_EXAMPLE = """schema_version: "1.0"
policy:
  name: default-policy
  version: "1.0.0"
  rules:
    - condition:
        field: request.risk_score
        operator: GREATER_THAN
        value: 0.8
      action:
        algorithm: HYBRID
        key_rotation: 30d
        compliance: [pci, soc2]
  default_action:
    algorithm: AES
    key_rotation: 90d
    compliance: [soc2]
"""


_VALID_PLUGIN_MANIFEST_EXAMPLE = """name: keycrypt-example-plugin
version: 1.0.0
api_version: v1
author: Plugin Developer
description: Example manifest
provides:
  - interface: src.abstractions.key_provider.KeyProvider
    implementation: plugins.example.provider.ExampleProvider
dependencies:
  - requests
security:
  permissions:
    - keys:read
    - keys:rotate
  signature: ""
"""


_YAML_CONFIG_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "required": ["environment", "default_algorithm", "log_level", "api"],
    "properties": {
        "environment": {
            "type": "string",
            "enum": ["development", "staging", "production"],
        },
        "default_algorithm": {
            "type": "string",
            "enum": ["AES", "QUANTUM", "HYBRID"],
        },
        "log_level": {
            "type": "string",
            "enum": ["DEBUG", "INFO", "WARNING", "ERROR"],
        },
        "api": {
            "type": "object",
            "required": ["host", "port"],
            "properties": {
                "host": {"type": "string", "minLength": 1},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "tls_enabled": {"type": "boolean"},
            },
            "additionalProperties": True,
        },
        "security": {
            "type": "object",
            "properties": {
                "require_mfa": {"type": "boolean"},
                "allow_plaintext_keys": {"type": "boolean"},
                "key_rotation_days": {"type": "integer", "minimum": 1, "maximum": 365},
                "audit_logging": {"type": "boolean"},
                "min_password_length": {"type": "integer", "minimum": 12, "maximum": 256},
            },
            "additionalProperties": True,
        },
    },
    "additionalProperties": True,
}


_POLICY_CONDITION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["field", "operator", "value"],
    "properties": {
        "field": {"type": "string", "minLength": 1},
        "operator": {
            "type": "string",
            "enum": [
                "EQUALS",
                "NOT_EQUALS",
                "GREATER_THAN",
                "LESS_THAN",
                "CONTAINS",
                "IN",
                "MATCHES",
            ],
        },
        "value": {},
    },
    "additionalProperties": False,
}


_POLICY_ACTION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["algorithm", "key_rotation"],
    "properties": {
        "algorithm": {"type": "string", "minLength": 1},
        "key_rotation": {
            "type": "string",
            "pattern": "^\\d+[dhmwDHM W]$".replace(" ", ""),
        },
        "compliance": {
            "type": "array",
            "items": {"type": "string", "minLength": 1},
        },
        "metadata": {"type": "object"},
    },
    "additionalProperties": True,
}


_POLICY_RULE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "condition": _POLICY_CONDITION_SCHEMA,
        "match": _POLICY_CONDITION_SCHEMA,
        "when": _POLICY_CONDITION_SCHEMA,
        "if": _POLICY_CONDITION_SCHEMA,
        "action": _POLICY_ACTION_SCHEMA,
        "decision": _POLICY_ACTION_SCHEMA,
        "then": _POLICY_ACTION_SCHEMA,
    },
    "anyOf": [
        {"required": ["condition"]},
        {"required": ["match"]},
        {"required": ["when"]},
        {"required": ["if"]},
    ],
    "allOf": [
        {
            "anyOf": [
                {"required": ["action"]},
                {"required": ["decision"]},
                {"required": ["then"]},
            ]
        }
    ],
    "additionalProperties": True,
}


_POLICY_FILE_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "required": ["policy"],
    "properties": {
        "schema_version": {
            "type": "string",
            "enum": ["1.0", "2.0"],
        },
        "policy": {
            "type": "object",
            "required": ["name", "version"],
            "properties": {
                "name": {"type": "string", "minLength": 1},
                "version": {"type": "string", "minLength": 1},
                "rules": {
                    "type": "array",
                    "items": _POLICY_RULE_SCHEMA,
                },
                "default_action": _POLICY_ACTION_SCHEMA,
                "default_decision": _POLICY_ACTION_SCHEMA,
                "default": _POLICY_ACTION_SCHEMA,
            },
            "anyOf": [
                {"required": ["default_action"]},
                {"required": ["default_decision"]},
                {"required": ["default"]},
            ],
            "additionalProperties": True,
        },
    },
    "additionalProperties": True,
}


_PLUGIN_MANIFEST_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "required": ["name", "version", "api_version", "author", "provides", "security"],
    "properties": {
        "name": {"type": "string", "minLength": 1},
        "version": {
            "type": "string",
            "pattern": r"^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9._-]+)?$",
        },
        "api_version": {
            "type": "string",
            "pattern": r"^v\d+(?:\.\d+)?$",
        },
        "author": {"type": "string", "minLength": 1},
        "description": {"type": "string"},
        "provides": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "required": ["interface", "implementation"],
                "properties": {
                    "interface": {
                        "type": "string",
                        "pattern": r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$",
                    },
                    "implementation": {
                        "type": "string",
                        "pattern": r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$",
                    },
                },
                "additionalProperties": True,
            },
        },
        "dependencies": {
            "type": "array",
            "items": {"type": "string", "minLength": 1},
        },
        "configuration": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["name", "type", "required", "description"],
                "properties": {
                    "name": {"type": "string", "minLength": 1},
                    "type": {"type": "string", "minLength": 1},
                    "required": {"type": "boolean"},
                    "default": {},
                    "description": {"type": "string", "minLength": 1},
                },
                "additionalProperties": True,
            },
        },
        "security": {
            "type": "object",
            "required": ["permissions"],
            "properties": {
                "permissions": {
                    "type": "array",
                    "items": {"type": "string", "minLength": 1},
                },
                "signature": {"type": "string"},
            },
            "additionalProperties": True,
        },
    },
    "additionalProperties": True,
}


@dataclass(frozen=True)
class ValidationIssue:
    """Structured validation issue with actionable context."""

    path: str
    message: str
    example: str


@dataclass(frozen=True)
class ValidationResult:
    """Validation result for one config artifact."""

    valid: bool
    errors: tuple[ValidationIssue, ...] = tuple()
    warnings: tuple[str, ...] = tuple()


@dataclass(frozen=True)
class Suggestion:
    """Config quality recommendation."""

    title: str
    severity: str
    rationale: str
    recommendation: str


def _jsonschema_validator(schema: Mapping[str, Any]) -> Any:
    try:
        from jsonschema import Draft202012Validator
    except ModuleNotFoundError as exc:
        raise RuntimeError("jsonschema is required. Install with: pip install jsonschema") from exc

    return Draft202012Validator(schema)


def _path_string(parts: Iterable[Any]) -> str:
    path = "$"
    for part in parts:
        if isinstance(part, int):
            path += f"[{part}]"
        else:
            key = str(part)
            if key:
                path += f".{key}"
    return path


def _result(errors: list[ValidationIssue], warnings: list[str]) -> ValidationResult:
    return ValidationResult(
        valid=len(errors) == 0,
        errors=tuple(errors),
        warnings=tuple(warnings),
    )


def _load_yaml_mapping(path: Path) -> tuple[dict[str, Any] | None, list[ValidationIssue]]:
    issues: list[ValidationIssue] = []
    resolved = Path(path).expanduser().resolve()

    if not resolved.exists() or not resolved.is_file():
        issues.append(
            ValidationIssue(
                path="$",
                message=f"file not found: {resolved}",
                example="Create the file and provide a valid YAML mapping document.",
            )
        )
        return None, issues

    try:
        payload = yaml.safe_load(resolved.read_text(encoding="utf-8"))
    except Exception as exc:
        issues.append(
            ValidationIssue(
                path="$",
                message=f"failed to parse YAML: {exc}",
                example="Ensure the document is valid YAML with proper indentation.",
            )
        )
        return None, issues

    if not isinstance(payload, dict):
        issues.append(
            ValidationIssue(
                path="$",
                message="YAML root must be a mapping/object",
                example="name: value",
            )
        )
        return None, issues

    return payload, issues


def _validate_schema(
    payload: Mapping[str, Any],
    schema: Mapping[str, Any],
    *,
    example: str,
) -> list[ValidationIssue]:
    validator = _jsonschema_validator(schema)
    issues: list[ValidationIssue] = []

    for error in sorted(validator.iter_errors(payload), key=lambda item: list(item.path)):
        issues.append(
            ValidationIssue(
                path=_path_string(error.path),
                message=error.message,
                example=example,
            )
        )

    return issues


def _yaml_semantic_warnings(config: Mapping[str, Any]) -> list[str]:
    warnings: list[str] = []
    environment = str(config.get("environment", "")).lower()
    log_level = str(config.get("log_level", "")).upper()
    api = config.get("api", {}) if isinstance(config.get("api"), Mapping) else {}
    security = (
        config.get("security", {}) if isinstance(config.get("security"), Mapping) else {}
    )

    if environment == "production" and log_level == "DEBUG":
        warnings.append(
            "Production config uses DEBUG logging; prefer INFO or WARNING to reduce sensitive log exposure."
        )

    if str(api.get("host", "")).strip() == "0.0.0.0":
        warnings.append(
            "API host is 0.0.0.0; prefer a restricted interface or network policy in sensitive deployments."
        )

    if api.get("tls_enabled") is False:
        warnings.append("TLS is disabled for API endpoint; enable TLS for transport security.")

    rotation_days = security.get("key_rotation_days")
    if isinstance(rotation_days, int) and rotation_days > 180:
        warnings.append(
            "Key rotation period exceeds 180 days; consider a shorter rotation interval."
        )

    if security.get("allow_plaintext_keys") is True:
        warnings.append(
            "allow_plaintext_keys is true; disable plaintext key handling for stronger key protection."
        )

    if security.get("audit_logging") is False:
        warnings.append("audit_logging is disabled; enable audit logging for traceability.")

    return warnings


def validate_yaml_config(config_path: Path) -> ValidationResult:
    """Validate a YAML configuration file against schema and semantic checks."""
    payload, load_issues = _load_yaml_mapping(Path(config_path))
    if payload is None:
        return _result(load_issues, [])

    errors = list(load_issues)
    errors.extend(
        _validate_schema(payload, _YAML_CONFIG_SCHEMA, example=_VALID_YAML_CONFIG_EXAMPLE)
    )

    warnings = _yaml_semantic_warnings(payload)
    return _result(errors, warnings)


def _policy_semantic_issues(payload: Mapping[str, Any]) -> list[ValidationIssue]:
    from src.policy.policy_schema import parse_policy_document

    issues: list[ValidationIssue] = []
    try:
        document = parse_policy_document(payload)
    except Exception as exc:
        issues.append(
            ValidationIssue(
                path="$.policy",
                message=f"policy semantic validation failed: {exc}",
                example=_VALID_POLICY_EXAMPLE,
            )
        )
        return issues

    # Detect exact duplicate rules, which indicate likely policy quality issues.
    seen: set[str] = set()
    for index, rule in enumerate(document.policy.rules):
        signature = json.dumps(
            {
                "condition": rule.condition.model_dump(mode="json"),
                "action": rule.action.model_dump(mode="json"),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        if signature in seen:
            issues.append(
                ValidationIssue(
                    path=f"$.policy.rules[{index}]",
                    message="duplicate rule detected with identical condition and action",
                    example=_VALID_POLICY_EXAMPLE,
                )
            )
        seen.add(signature)

    return issues


def validate_policy_file(policy_path: Path) -> ValidationResult:
    """Validate policy file syntax and semantics."""
    payload, load_issues = _load_yaml_mapping(Path(policy_path))
    if payload is None:
        return _result(load_issues, [])

    errors = list(load_issues)
    errors.extend(_validate_schema(payload, _POLICY_FILE_SCHEMA, example=_VALID_POLICY_EXAMPLE))

    if not errors:
        errors.extend(_policy_semantic_issues(payload))

    warnings: list[str] = []
    policy = payload.get("policy")
    if isinstance(policy, Mapping):
        rules = policy.get("rules")
        if isinstance(rules, list) and len(rules) == 0:
            warnings.append(
                "Policy has no explicit rules; only default_action/default_decision will be applied."
            )

    return _result(errors, warnings)


_SEMVER_PATTERN = re.compile(r"^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9._-]+)?$")


def _plugin_manifest_semantic_issues(payload: Mapping[str, Any], manifest_path: Path) -> tuple[list[ValidationIssue], list[str]]:
    from src.registry.plugin_manifest import PluginManifest

    errors: list[ValidationIssue] = []
    warnings: list[str] = []

    try:
        manifest = PluginManifest.from_yaml(manifest_path)
    except Exception as exc:
        errors.append(
            ValidationIssue(
                path="$",
                message=f"plugin manifest semantic validation failed: {exc}",
                example=_VALID_PLUGIN_MANIFEST_EXAMPLE,
            )
        )
        return errors, warnings

    if _SEMVER_PATTERN.fullmatch(manifest.version) is None:
        errors.append(
            ValidationIssue(
                path="$.version",
                message="version must follow semantic versioning, for example 1.2.3",
                example=_VALID_PLUGIN_MANIFEST_EXAMPLE,
            )
        )

    dependency_set = {item.lower() for item in manifest.dependencies}
    if len(dependency_set) != len(manifest.dependencies):
        warnings.append("dependencies contains duplicate entries; deduplicate for clarity.")

    if not manifest.security.permissions:
        warnings.append(
            "security.permissions is empty; define least-privilege permissions for plugin runtime."
        )

    return errors, warnings


def validate_plugin_manifest(manifest_path: Path) -> ValidationResult:
    """Validate plugin manifest YAML against schema and semantic constraints."""
    payload, load_issues = _load_yaml_mapping(Path(manifest_path))
    if payload is None:
        return _result(load_issues, [])

    errors = list(load_issues)
    errors.extend(
        _validate_schema(payload, _PLUGIN_MANIFEST_SCHEMA, example=_VALID_PLUGIN_MANIFEST_EXAMPLE)
    )

    warnings: list[str] = []
    if not errors:
        semantic_errors, semantic_warnings = _plugin_manifest_semantic_issues(payload, Path(manifest_path))
        errors.extend(semantic_errors)
        warnings.extend(semantic_warnings)

    return _result(errors, warnings)


def suggest_config_improvements(config: dict) -> List[Suggestion]:
    """Suggest security and quality improvements for configuration payloads."""
    suggestions: list[Suggestion] = []

    if not isinstance(config, dict):
        return [
            Suggestion(
                title="Use Mapping-Based Config",
                severity="high",
                rationale="Validation and policy tooling expects a mapping/object configuration.",
                recommendation="Represent configuration as a dictionary-like structure before analysis.",
            )
        ]

    environment = str(config.get("environment", "")).lower()
    log_level = str(config.get("log_level", "")).upper()
    api = config.get("api", {}) if isinstance(config.get("api"), Mapping) else {}
    security = (
        config.get("security", {}) if isinstance(config.get("security"), Mapping) else {}
    )

    if environment == "production" and log_level == "DEBUG":
        suggestions.append(
            Suggestion(
                title="Reduce Production Verbosity",
                severity="medium",
                rationale="Debug logs in production can expose operationally sensitive details.",
                recommendation="Set log_level to INFO or WARNING in production deployments.",
            )
        )

    if api.get("tls_enabled") is False:
        suggestions.append(
            Suggestion(
                title="Enable TLS",
                severity="high",
                rationale="Disabling TLS increases risk of credential interception and data leakage.",
                recommendation="Enable TLS termination and enforce HTTPS-only client access.",
            )
        )

    if str(api.get("host", "")).strip() == "0.0.0.0" and environment == "production":
        suggestions.append(
            Suggestion(
                title="Restrict Network Bind Address",
                severity="medium",
                rationale="Binding on all interfaces can unintentionally expose services.",
                recommendation="Bind API host to a trusted interface and enforce ingress controls.",
            )
        )

    if security.get("allow_plaintext_keys") is True:
        suggestions.append(
            Suggestion(
                title="Disable Plaintext Key Handling",
                severity="high",
                rationale="Plaintext key storage/handling increases key compromise risk.",
                recommendation="Set security.allow_plaintext_keys to false and use wrapped/encrypted key material.",
            )
        )

    if security.get("require_mfa") is False or "require_mfa" not in security:
        suggestions.append(
            Suggestion(
                title="Require MFA for Sensitive Operations",
                severity="medium",
                rationale="MFA reduces account takeover and privilege abuse risk.",
                recommendation="Set security.require_mfa to true for administrative actions.",
            )
        )

    rotation_days = security.get("key_rotation_days")
    if isinstance(rotation_days, int) and rotation_days > 90:
        suggestions.append(
            Suggestion(
                title="Shorten Key Rotation Interval",
                severity="medium",
                rationale="Long-lived keys increase blast radius if compromised.",
                recommendation="Use key_rotation_days of 90 or less for stronger cryptographic hygiene.",
            )
        )

    if security.get("audit_logging") is False or "audit_logging" not in security:
        suggestions.append(
            Suggestion(
                title="Enable Audit Logging",
                severity="medium",
                rationale="Audit logs are essential for forensic analysis and compliance evidence.",
                recommendation="Set security.audit_logging to true and ship logs to immutable storage.",
            )
        )

    algorithm = str(config.get("default_algorithm", "")).upper()
    if algorithm == "AES":
        suggestions.append(
            Suggestion(
                title="Evaluate Hybrid Algorithm Default",
                severity="low",
                rationale="Hybrid profiles can improve future-readiness for post-quantum migration.",
                recommendation="Consider HYBRID as default_algorithm where compliance and performance allow.",
            )
        )

    return suggestions


__all__ = [
    "Suggestion",
    "ValidationIssue",
    "ValidationResult",
    "suggest_config_improvements",
    "validate_plugin_manifest",
    "validate_policy_file",
    "validate_yaml_config",
]
