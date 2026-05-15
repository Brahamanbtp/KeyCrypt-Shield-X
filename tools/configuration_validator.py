#!/usr/bin/env python3
"""Configuration validation tooling for YAML config management.

This module validates YAML configuration files against JSON Schema, checks for
missing required fields, audits environment variables, suggests improvements,
and can auto-fix invalid configs by filling sensible defaults.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

import yaml


DEFAULT_CONFIG_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "required": ["environment", "default_algorithm", "log_level", "api"],
    "properties": {
        "environment": {
            "type": "string",
            "enum": ["development", "staging", "production"],
            "default": "development",
        },
        "default_algorithm": {
            "type": "string",
            "enum": ["AES", "QUANTUM", "HYBRID"],
            "default": "HYBRID",
        },
        "log_level": {
            "type": "string",
            "enum": ["DEBUG", "INFO", "WARNING", "ERROR"],
            "default": "INFO",
        },
        "api": {
            "type": "object",
            "required": ["host", "port"],
            "properties": {
                "host": {"type": "string", "minLength": 1, "default": "127.0.0.1"},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535, "default": 8000},
                "tls_enabled": {"type": "boolean", "default": True},
            },
            "additionalProperties": True,
            "default": {},
        },
        "security": {
            "type": "object",
            "properties": {
                "require_mfa": {"type": "boolean", "default": True},
                "allow_plaintext_keys": {"type": "boolean", "default": False},
                "key_rotation_days": {"type": "integer", "minimum": 1, "maximum": 365, "default": 90},
                "audit_logging": {"type": "boolean", "default": True},
                "min_password_length": {"type": "integer", "minimum": 12, "maximum": 256, "default": 14},
            },
            "additionalProperties": True,
            "default": {},
        },
        "observability": {
            "type": "object",
            "properties": {
                "metrics_enabled": {"type": "boolean", "default": True},
                "tracing_enabled": {"type": "boolean", "default": True},
            },
            "additionalProperties": True,
            "default": {},
        },
    },
    "additionalProperties": True,
}


@dataclass(frozen=True)
class MissingField:
    """A missing configuration field discovered during validation."""

    path: str
    message: str
    suggested_value: Any | None = None


@dataclass(frozen=True)
class Suggestion:
    """A configuration improvement recommendation."""

    title: str
    severity: str
    rationale: str
    recommendation: str


@dataclass(frozen=True)
class ValidationResult:
    """Validation output for a YAML configuration file."""

    valid: bool
    errors: tuple[str, ...] = field(default_factory=tuple)
    warnings: tuple[str, ...] = field(default_factory=tuple)
    missing_fields: tuple[MissingField, ...] = field(default_factory=tuple)


def _load_yaml_mapping(config_path: Path) -> dict[str, Any]:
    resolved = Path(config_path).expanduser().resolve()
    if not resolved.exists() or not resolved.is_file():
        raise FileNotFoundError(f"configuration file not found: {resolved}")

    try:
        payload = yaml.safe_load(resolved.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"failed to parse YAML: {exc}") from exc

    if not isinstance(payload, dict):
        raise ValueError("YAML root must be a mapping/object")

    return payload


def _jsonschema_validator(schema: Mapping[str, Any]):
    try:
        from jsonschema import Draft202012Validator
    except ModuleNotFoundError as exc:  # pragma: no cover - dependency guard
        raise RuntimeError("jsonschema is required. Install with: pip install jsonschema") from exc

    return Draft202012Validator(schema)


def _json_pointer(parts: Iterable[Any]) -> str:
    path = "$"
    for part in parts:
        if isinstance(part, int):
            path += f"[{part}]"
        else:
            key = str(part)
            if key:
                path += f".{key}"
    return path


def _schema_required_properties(schema: Mapping[str, Any]) -> set[str]:
    required = schema.get("required")
    if isinstance(required, list):
        return {str(item) for item in required}
    return set()


def _schema_properties(schema: Mapping[str, Any]) -> Mapping[str, Any]:
    properties = schema.get("properties")
    if isinstance(properties, Mapping):
        return properties
    return {}


def _merge_schema_defaults(config: Any, schema: Mapping[str, Any]) -> Any:
    if not isinstance(schema, Mapping):
        return config

    if config is None:
        config = {}

    schema_type = schema.get("type")
    if schema_type == "object":
        if not isinstance(config, dict):
            config = {}

        merged = dict(config)
        for key, property_schema in _schema_properties(schema).items():
            if key in merged:
                merged[key] = _merge_schema_defaults(merged[key], property_schema)
                continue

            if isinstance(property_schema, Mapping):
                if "default" in property_schema:
                    default_value = property_schema["default"]
                    merged[key] = _merge_schema_defaults(default_value, property_schema)
                elif property_schema.get("type") == "object":
                    merged[key] = _merge_schema_defaults({}, property_schema)
                elif property_schema.get("type") == "array":
                    merged[key] = []

        return merged

    if schema_type == "array" and isinstance(config, list):
        item_schema = schema.get("items")
        if isinstance(item_schema, Mapping):
            return [_merge_schema_defaults(item, item_schema) for item in config]
        return config

    return config


def _validate_schema(payload: Mapping[str, Any], schema: Mapping[str, Any]) -> list[str]:
    validator = _jsonschema_validator(schema)
    errors: list[str] = []
    for error in sorted(validator.iter_errors(payload), key=lambda item: list(item.path)):
        errors.append(f"{_json_pointer(error.path)}: {error.message}")
    return errors


def check_required_fields(config: dict, schema: dict) -> list[MissingField]:
    """Identify required fields missing from a config payload."""
    missing: list[MissingField] = []

    def _walk(current_config: Any, current_schema: Mapping[str, Any], path: str) -> None:
        if not isinstance(current_schema, Mapping):
            return

        required = _schema_required_properties(current_schema)
        properties = _schema_properties(current_schema)

        if current_schema.get("type") == "object":
            if not isinstance(current_config, Mapping):
                current_config = {}

            for name in required:
                child_path = f"{path}.{name}" if path != "$" else f"$.{name}"
                if name not in current_config:
                    prop_schema = properties.get(name, {})
                    missing.append(
                        MissingField(
                            path=child_path,
                            message=f"missing required field: {name}",
                            suggested_value=prop_schema.get("default") if isinstance(prop_schema, Mapping) else None,
                        )
                    )

            for name, prop_schema in properties.items():
                if name in current_config:
                    child_config = current_config[name]
                    child_path = f"{path}.{name}" if path != "$" else f"$.{name}"
                    _walk(child_config, prop_schema, child_path)

        elif current_schema.get("type") == "array":
            item_schema = current_schema.get("items")
            if isinstance(current_config, list) and isinstance(item_schema, Mapping):
                for index, item in enumerate(current_config):
                    _walk(item, item_schema, f"{path}[{index}]")

    _walk(config, schema, "$")
    return missing


def validate_environment_variables(required_vars: list[str]) -> list[str]:
    """Return missing environment variables from the required list."""
    return [name for name in required_vars if not os.getenv(name)]


def suggest_config_improvements(config: dict) -> list[Suggestion]:
    """Suggest config hardening and operational improvements."""
    if not isinstance(config, dict):
        return [
            Suggestion(
                title="Use a mapping config",
                severity="high",
                rationale="The validator expects a mapping/object configuration structure.",
                recommendation="Load or convert configuration into a dictionary before validation.",
            )
        ]

    suggestions: list[Suggestion] = []
    environment = str(config.get("environment", "")).lower()
    log_level = str(config.get("log_level", "")).upper()
    api = config.get("api", {}) if isinstance(config.get("api"), Mapping) else {}
    security = config.get("security", {}) if isinstance(config.get("security"), Mapping) else {}

    if environment == "production" and log_level == "DEBUG":
        suggestions.append(
            Suggestion(
                title="Reduce production log verbosity",
                severity="medium",
                rationale="DEBUG logs may expose secrets or internal operational details.",
                recommendation="Use INFO or WARNING in production environments.",
            )
        )

    if api.get("tls_enabled") is False:
        suggestions.append(
            Suggestion(
                title="Enable TLS",
                severity="high",
                rationale="Plaintext transport increases credential and data exposure risk.",
                recommendation="Enable TLS termination for the API endpoint.",
            )
        )

    if str(api.get("host", "")).strip() == "0.0.0.0" and environment == "production":
        suggestions.append(
            Suggestion(
                title="Restrict API bind address",
                severity="medium",
                rationale="Binding to all interfaces can expose the service unnecessarily.",
                recommendation="Bind to a trusted interface and enforce ingress controls.",
            )
        )

    if security.get("require_mfa") is False or "require_mfa" not in security:
        suggestions.append(
            Suggestion(
                title="Require MFA",
                severity="medium",
                rationale="MFA reduces account takeover risk for administrative operations.",
                recommendation="Set security.require_mfa to true.",
            )
        )

    if security.get("allow_plaintext_keys") is True:
        suggestions.append(
            Suggestion(
                title="Disable plaintext key handling",
                severity="high",
                rationale="Plaintext key handling materially increases compromise risk.",
                recommendation="Set security.allow_plaintext_keys to false and use encrypted or wrapped keys.",
            )
        )

    if security.get("audit_logging") is False or "audit_logging" not in security:
        suggestions.append(
            Suggestion(
                title="Enable audit logging",
                severity="medium",
                rationale="Audit logs help with forensic review and compliance evidence.",
                recommendation="Set security.audit_logging to true and retain logs in immutable storage.",
            )
        )

    rotation_days = security.get("key_rotation_days")
    if isinstance(rotation_days, int) and rotation_days > 90:
        suggestions.append(
            Suggestion(
                title="Shorten key rotation",
                severity="medium",
                rationale="Long-lived keys increase blast radius if compromised.",
                recommendation="Use key_rotation_days of 90 or less.",
            )
        )

    return suggestions


def _default_config() -> dict[str, Any]:
    return {
        "environment": "development",
        "default_algorithm": "HYBRID",
        "log_level": "INFO",
        "api": {"host": "127.0.0.1", "port": 8000, "tls_enabled": True},
        "security": {
            "require_mfa": True,
            "allow_plaintext_keys": False,
            "key_rotation_days": 90,
            "audit_logging": True,
            "min_password_length": 14,
        },
        "observability": {"metrics_enabled": True, "tracing_enabled": True},
    }


def auto_fix_config(config_path: Path, output_path: Path | None = None) -> Path:
    """Generate a valid config file from an invalid YAML config.

    Missing keys are filled from schema defaults and hardened with sane values.
    """
    resolved = Path(config_path).expanduser().resolve()
    try:
        payload = _load_yaml_mapping(resolved)
    except Exception:
        payload = {}

    merged = _merge_schema_defaults(payload, DEFAULT_CONFIG_SCHEMA)
    if not isinstance(merged, dict):
        merged = {}

    fixed = _default_config()
    fixed.update({key: value for key, value in merged.items() if key in fixed})

    api = fixed.setdefault("api", {})
    if isinstance(merged.get("api"), Mapping):
        api.update({key: value for key, value in merged["api"].items() if key in {"host", "port", "tls_enabled"}})

    security = fixed.setdefault("security", {})
    if isinstance(merged.get("security"), Mapping):
        security.update({key: value for key, value in merged["security"].items() if key in security})

    observability = fixed.setdefault("observability", {})
    if isinstance(merged.get("observability"), Mapping):
        observability.update(
            {key: value for key, value in merged["observability"].items() if key in observability}
        )

    target = (
        Path(output_path).expanduser().resolve()
        if output_path is not None
        else resolved.with_suffix(".fixed.yaml")
    )
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(yaml.safe_dump(fixed, sort_keys=False), encoding="utf-8")
    return target


def validate_yaml_config(config_path: Path) -> ValidationResult:
    """Validate a YAML config against JSON Schema and report improvements."""
    try:
        payload = _load_yaml_mapping(config_path)
    except Exception as exc:
        return ValidationResult(valid=False, errors=(str(exc),))

    schema_errors = _validate_schema(payload, DEFAULT_CONFIG_SCHEMA)
    missing = tuple(check_required_fields(payload, DEFAULT_CONFIG_SCHEMA))
    warnings = tuple(_suggestion_to_warning(item) for item in suggest_config_improvements(payload))
    warnings = tuple(item for item in warnings if item)

    return ValidationResult(
        valid=not schema_errors and not missing,
        errors=tuple(schema_errors),
        warnings=warnings,
        missing_fields=missing,
    )


def _suggestion_to_warning(item: Suggestion) -> str:
    return f"{item.title}: {item.recommendation}"


__all__ = [
    "MissingField",
    "Suggestion",
    "ValidationResult",
    "DEFAULT_CONFIG_SCHEMA",
    "auto_fix_config",
    "check_required_fields",
    "suggest_config_improvements",
    "validate_environment_variables",
    "validate_yaml_config",
]