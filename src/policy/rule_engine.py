"""Rule evaluation utilities for encryption policy decisions.

This module provides a lightweight rule engine used by orchestration policy
components to transform context signals into policy decision overrides.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, is_dataclass
from typing import Any


class RuleEngine:
    """Evaluate policy rules against runtime context.

    Expected policy shape:
    - policy.rules: list of rule mappings
      - when: mapping of condition predicates
      - decision: mapping of output overrides
    """

    def evaluate(self, context: Any, policy: Any) -> dict[str, Any]:
        """Evaluate first matching rule and return decision overrides."""
        context_map = self._context_to_mapping(context)
        rules = getattr(policy, "rules", [])
        if not isinstance(rules, list):
            return {}

        for rule in rules:
            if not isinstance(rule, Mapping):
                continue
            when = rule.get("when", {})
            decision = rule.get("decision", {})
            if not isinstance(when, Mapping) or not isinstance(decision, Mapping):
                continue

            if self._matches(when, context_map):
                return dict(decision)

        return {}

    def _matches(self, conditions: Mapping[str, Any], context_map: Mapping[str, Any]) -> bool:
        for field, expected in conditions.items():
            actual = context_map.get(field)
            if not self._match_value(actual, expected):
                return False
        return True

    def _match_value(self, actual: Any, expected: Any) -> bool:
        if isinstance(expected, Mapping):
            for operator, operand in expected.items():
                if not self._apply_operator(operator, actual, operand):
                    return False
            return True
        return actual == expected

    @staticmethod
    def _apply_operator(operator: str, actual: Any, operand: Any) -> bool:
        op = str(operator).lower()
        if op == "eq":
            return actual == operand
        if op == "neq":
            return actual != operand
        if op == "gt":
            return actual is not None and actual > operand
        if op == "gte":
            return actual is not None and actual >= operand
        if op == "lt":
            return actual is not None and actual < operand
        if op == "lte":
            return actual is not None and actual <= operand
        if op == "in":
            return isinstance(operand, (list, tuple, set)) and actual in operand
        if op == "not_in":
            return isinstance(operand, (list, tuple, set)) and actual not in operand
        if op == "contains":
            return hasattr(actual, "__contains__") and operand in actual
        return False

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


__all__ = ["RuleEngine"]
