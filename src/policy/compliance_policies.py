"""Pre-built compliance policy templates.

This module provides reference policy dictionaries for common compliance
frameworks and a dependency-free YAML export helper.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Mapping


HIPAA_POLICY: dict[str, Any] = {
    "name": "HIPAA",
    "description": "Healthcare privacy and security policy baseline.",
    "rules": [
        {
            "match": {"data_classification": "PHI"},
            "action": {
                "algorithm": "aes-256-gcm",
                "key_rotation": "90d",
                "compliance_tags": ["hipaa", "healthcare", "phi"],
            },
        }
    ],
    "default_action": {
        "algorithm": "aes-256-gcm",
        "key_rotation": "180d",
        "compliance_tags": ["hipaa"],
    },
}


GDPR_POLICY: dict[str, Any] = {
    "name": "GDPR",
    "description": "EU personal data protection policy baseline.",
    "rules": [
        {
            "match": {"contains_personal_data": True},
            "action": {
                "algorithm": "aes-256-gcm",
                "key_rotation": "60d",
                "compliance_tags": ["gdpr", "pii", "privacy"],
            },
        },
        {
            "match": {"region": "EU"},
            "action": {
                "algorithm": "aes-256-gcm",
                "key_rotation": "45d",
                "compliance_tags": ["gdpr", "data-sovereignty"],
            },
        },
    ],
    "default_action": {
        "algorithm": "aes-256-gcm",
        "key_rotation": "120d",
        "compliance_tags": ["gdpr"],
    },
}


SOC2_POLICY: dict[str, Any] = {
    "name": "SOC2",
    "description": "SOC 2 trust services criteria policy baseline.",
    "rules": [
        {
            "match": {"service_tier": "production"},
            "action": {
                "algorithm": "aes-256-gcm",
                "key_rotation": "90d",
                "compliance_tags": ["soc2", "security", "availability"],
            },
        },
        {
            "match": {"contains_customer_data": True},
            "action": {
                "algorithm": "aes-256-gcm",
                "key_rotation": "60d",
                "compliance_tags": ["soc2", "confidentiality"],
            },
        },
    ],
    "default_action": {
        "algorithm": "aes-256-gcm",
        "key_rotation": "180d",
        "compliance_tags": ["soc2"],
    },
}


NIST_POLICY: dict[str, Any] = {
    "name": "NIST",
    "description": "NIST-aligned cryptographic control policy baseline.",
    "rules": [
        {
            "match": {"classification": "top_secret"},
            "action": {
                "algorithm": "aes-256-gcm",
                "key_rotation": "30d",
                "compliance_tags": ["nist", "high-assurance"],
            },
        },
        {
            "match": {"classification": "secret"},
            "action": {
                "algorithm": "aes-256-gcm",
                "key_rotation": "60d",
                "compliance_tags": ["nist", "moderate-assurance"],
            },
        },
    ],
    "default_action": {
        "algorithm": "aes-256-gcm",
        "key_rotation": "90d",
        "compliance_tags": ["nist"],
    },
}


COMPLIANCE_POLICIES: dict[str, dict[str, Any]] = {
    "hipaa": HIPAA_POLICY,
    "gdpr": GDPR_POLICY,
    "soc2": SOC2_POLICY,
    "nist": NIST_POLICY,
}


def to_yaml(
    output_dir: str | Path,
    policies: Mapping[str, Mapping[str, Any]] | None = None,
) -> list[Path]:
    """Export compliance policy templates to YAML files.

    Args:
        output_dir: Destination directory for YAML policy files.
        policies: Optional explicit policy mapping to export.
            Defaults to `COMPLIANCE_POLICIES`.

    Returns:
        List of written YAML file paths.
    """
    target_dir = Path(output_dir)
    target_dir.mkdir(parents=True, exist_ok=True)

    selected = policies if policies is not None else COMPLIANCE_POLICIES
    if not isinstance(selected, Mapping):
        raise TypeError("policies must be a mapping when provided")

    written: list[Path] = []
    for name, policy in selected.items():
        if not isinstance(name, str) or not name.strip():
            raise ValueError("policy names must be non-empty strings")
        if not isinstance(policy, Mapping):
            raise TypeError(f"policy '{name}' must be a mapping")

        filename = f"{_slug(name)}.yaml"
        yaml_text = _dump_yaml(dict(policy))

        path = target_dir / filename
        path.write_text(yaml_text, encoding="utf-8")
        written.append(path)

    return written


def _dump_yaml(value: Any) -> str:
    lines: list[str] = []
    _emit_yaml(value, lines, indent=0)
    return "\n".join(lines) + "\n"


def _emit_yaml(value: Any, lines: list[str], indent: int) -> None:
    prefix = " " * indent

    if isinstance(value, Mapping):
        if not value:
            lines.append(f"{prefix}{{}}")
            return

        for key, item in value.items():
            key_text = _scalar_to_yaml(str(key))
            if _is_scalar(item):
                lines.append(f"{prefix}{key_text}: {_scalar_to_yaml(item)}")
            else:
                lines.append(f"{prefix}{key_text}:")
                _emit_yaml(item, lines, indent + 2)
        return

    if isinstance(value, list):
        if not value:
            lines.append(f"{prefix}[]")
            return

        for item in value:
            if _is_scalar(item):
                lines.append(f"{prefix}- {_scalar_to_yaml(item)}")
            else:
                lines.append(f"{prefix}-")
                _emit_yaml(item, lines, indent + 2)
        return

    lines.append(f"{prefix}{_scalar_to_yaml(value)}")


def _is_scalar(value: Any) -> bool:
    return value is None or isinstance(value, (str, int, float, bool))


def _scalar_to_yaml(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if value.is_integer():
            return str(int(value))
        return str(value)

    text = str(value)
    if text == "":
        return "''"

    if _is_plain_yaml_string(text):
        return text

    escaped = text.replace("'", "''")
    return f"'{escaped}'"


def _is_plain_yaml_string(text: str) -> bool:
    if text.lower() in {"null", "true", "false", "yes", "no", "on", "off", "~"}:
        return False

    if text[0] in {"-", "?", ":", "#", "&", "*", "!", "|", ">", "@", "`", " ", "\t"}:
        return False

    if text[-1] in {" ", "\t"}:
        return False

    return re.fullmatch(r"[A-Za-z0-9_./:-]+", text) is not None


def _slug(name: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9]+", "-", name.strip().lower()).strip("-")
    return cleaned or "policy"


__all__: list[str] = [
    "HIPAA_POLICY",
    "GDPR_POLICY",
    "SOC2_POLICY",
    "NIST_POLICY",
    "COMPLIANCE_POLICIES",
    "to_yaml",
]