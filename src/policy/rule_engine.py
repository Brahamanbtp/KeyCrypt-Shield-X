"""Rule evaluation utilities for encryption policy decisions.

This module provides a lightweight rule engine used by orchestration policy
components to transform context signals into policy decision overrides.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field, is_dataclass
from typing import Any, Iterator, TYPE_CHECKING

from src.policy.policy_compiler import CompiledPolicy

if TYPE_CHECKING:
    from src.orchestration.encryption_orchestrator import EncryptionContext


@dataclass(frozen=True)
class Action(Mapping[str, Any]):
    """Executable policy action returned by `RuleEngine.evaluate`.

    This dataclass also exposes mapping-like compatibility keys so existing
    consumers that expect dictionary-style access continue to work.
    """

    algorithm: str
    key_rotation: str
    compliance_tags: list[str] = field(default_factory=list)

    def as_mapping(self) -> dict[str, Any]:
        """Return action as a normalized mapping with compatibility aliases."""
        return {
            "algorithm": self.algorithm,
            "selected_algorithm": self.algorithm,
            "key_rotation": self.key_rotation,
            "key_rotation_schedule": self.key_rotation,
            "compliance_tags": list(self.compliance_tags),
        }

    def __getitem__(self, key: str) -> Any:
        return self.as_mapping()[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.as_mapping())

    def __len__(self) -> int:
        return len(self.as_mapping())

    def get(self, key: str, default: Any = None) -> Any:
        return self.as_mapping().get(key, default)


class RuleEngine:
    """Evaluate compiled and legacy policy rules against runtime context.

    Preferred input type:
    - `CompiledPolicy` from `src.policy.policy_compiler`

    Backward compatibility:
    - Also supports legacy policy-like objects with `.rules` and default fields.
    """

    def evaluate(self, context: EncryptionContext, rules: CompiledPolicy | Any = None, **kwargs: Any) -> Action:
        """Evaluate policy rules and return executable `Action`.

        Rule precedence: explicit rule decision values override defaults.

        Args:
            context: Runtime encryption context.
            rules: CompiledPolicy (preferred) or legacy policy-like object.
            **kwargs: Compatibility support for `policy=<legacy_policy>`.

        Returns:
            Action dataclass containing algorithm, key rotation schedule,
            and compliance tags.
        """
        if rules is None:
            rules = kwargs.get("policy")
        if rules is None:
            raise ValueError("rules or policy must be provided")

        context_map = self._context_to_mapping(context)

        if isinstance(rules, CompiledPolicy):
            return self._evaluate_compiled(context_map, rules)

        return self._evaluate_legacy(context_map, rules)

    def _evaluate_compiled(self, context_map: Mapping[str, Any], compiled: CompiledPolicy) -> Action:
        defaults = dict(compiled.default_decision)

        algorithm = self._coerce_non_empty_string(
            defaults.get("algorithm", defaults.get("selected_algorithm")),
            fallback="aes-gcm",
        )
        key_rotation = self._coerce_non_empty_string(
            defaults.get("key_rotation", defaults.get("key_rotation_schedule")),
            fallback="90d",
        )
        compliance_tags = self._coerce_tag_list(defaults.get("compliance_tags", []))

        for rule in compiled.rules:
            if not rule.matches(context_map):
                continue

            decision = dict(rule.then)

            algorithm = self._coerce_non_empty_string(
                decision.get("algorithm", decision.get("selected_algorithm", algorithm)),
                fallback=algorithm,
            )
            key_rotation = self._coerce_non_empty_string(
                decision.get("key_rotation", decision.get("key_rotation_schedule", key_rotation)),
                fallback=key_rotation,
            )
            if "compliance_tags" in decision:
                compliance_tags = self._coerce_tag_list(decision.get("compliance_tags", compliance_tags))

            break

        return Action(
            algorithm=algorithm,
            key_rotation=key_rotation,
            compliance_tags=compliance_tags,
        )

    def _evaluate_legacy(self, context_map: Mapping[str, Any], policy: Any) -> Action:
        default_algorithm = self._coerce_non_empty_string(
            getattr(policy, "default_algorithm", None),
            fallback="aes-gcm",
        )
        default_rotation = self._coerce_non_empty_string(
            getattr(policy, "key_rotation_schedule", None),
            fallback="90d",
        )
        default_tags = self._coerce_tag_list(getattr(policy, "compliance_tags", []))

        selected_algorithm = default_algorithm
        selected_rotation = default_rotation
        selected_tags = list(default_tags)

        legacy_rules = getattr(policy, "rules", [])
        if isinstance(legacy_rules, list):
            for rule in legacy_rules:
                if not isinstance(rule, Mapping):
                    continue

                when = rule.get("when", rule.get("if", {}))
                decision = rule.get("decision", rule.get("then", {}))
                if not isinstance(when, Mapping) or not isinstance(decision, Mapping):
                    continue

                if not self._matches(when, context_map):
                    continue

                # Explicit rule values take precedence over defaults.
                selected_algorithm = self._coerce_non_empty_string(
                    decision.get("selected_algorithm", decision.get("algorithm", selected_algorithm)),
                    fallback=selected_algorithm,
                )
                selected_rotation = self._coerce_non_empty_string(
                    decision.get("key_rotation_schedule", decision.get("key_rotation", selected_rotation)),
                    fallback=selected_rotation,
                )
                if "compliance_tags" in decision:
                    selected_tags = self._coerce_tag_list(decision.get("compliance_tags", selected_tags))

                break

        return Action(
            algorithm=selected_algorithm,
            key_rotation=selected_rotation,
            compliance_tags=selected_tags,
        )

    def _matches(self, conditions: Mapping[str, Any], context_map: Mapping[str, Any]) -> bool:
        for field, expected in conditions.items():
            actual, exists = self._resolve_field(context_map, field)
            if not self._match_value(actual, expected, exists):
                return False
        return True

    def _match_value(self, actual: Any, expected: Any, exists: bool) -> bool:
        if isinstance(expected, Mapping):
            for operator, operand in expected.items():
                if not self._apply_operator(operator, actual, operand, exists):
                    return False
            return True
        if not exists:
            return False
        return actual == expected

    @staticmethod
    def _apply_operator(operator: str, actual: Any, operand: Any, exists: bool) -> bool:
        op = str(operator).lower()
        try:
            if op == "eq":
                return exists and actual == operand
            if op == "neq":
                return (not exists) or actual != operand
            if op == "gt":
                return exists and actual > operand
            if op == "gte":
                return exists and actual >= operand
            if op == "lt":
                return exists and actual < operand
            if op == "lte":
                return exists and actual <= operand
            if op == "in":
                return exists and isinstance(operand, (list, tuple, set)) and actual in operand
            if op == "not_in":
                return (not exists) or (isinstance(operand, (list, tuple, set)) and actual not in operand)
            if op == "contains":
                return exists and hasattr(actual, "__contains__") and operand in actual
            if op == "starts_with":
                return exists and str(actual).startswith(str(operand))
            if op == "ends_with":
                return exists and str(actual).endswith(str(operand))
            if op == "exists":
                return exists is bool(operand)
            if op == "regex":
                return exists and re.search(str(operand), str(actual)) is not None
            if op == "between":
                if not exists or not isinstance(operand, (list, tuple)) or len(operand) != 2:
                    return False
                lower, upper = operand
                return lower <= actual <= upper
        except Exception:
            return False

        return False

    @staticmethod
    def _resolve_field(context_map: Mapping[str, Any], field_path: Any) -> tuple[Any, bool]:
        if not isinstance(field_path, str) or not field_path:
            return None, False

        current: Any = context_map
        for token in field_path.split("."):
            if isinstance(current, Mapping):
                if token not in current:
                    return None, False
                current = current[token]
                continue

            if hasattr(current, token):
                current = getattr(current, token)
                continue

            return None, False

        return current, True

    @staticmethod
    def _context_to_mapping(context: Any) -> dict[str, Any]:
        if isinstance(context, Mapping):
            payload = dict(context)
        elif is_dataclass(context):
            payload = asdict(context)
        else:
            payload = dict(vars(context))

        metadata = payload.get("metadata")
        if isinstance(metadata, Mapping):
            for key, value in metadata.items():
                payload.setdefault(str(key), value)

        return payload

    @staticmethod
    def _coerce_non_empty_string(value: Any, fallback: str) -> str:
        if isinstance(value, str) and value.strip():
            return value.strip()
        return fallback

    @staticmethod
    def _coerce_tag_list(value: Any) -> list[str]:
        if not isinstance(value, list):
            return []

        tags: list[str] = []
        seen: set[str] = set()
        for item in value:
            if not isinstance(item, str):
                continue
            normalized = item.strip()
            if not normalized:
                continue
            lowered = normalized.lower()
            if lowered in seen:
                continue
            seen.add(lowered)
            tags.append(normalized)

        return tags


__all__ = [
    "Action",
    "RuleEngine",
]
