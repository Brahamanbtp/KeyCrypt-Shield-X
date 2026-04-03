"""Policy compiler for YAML-based decision rules.

This module compiles declarative YAML policies into executable rule trees with
optimized rule ordering (most specific first).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field, is_dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class CompiledRule:
    """Executable rule with precomputed specificity score."""

    index: int
    when: dict[str, Any]
    then: dict[str, Any]
    specificity: float

    def matches(self, context_map: Mapping[str, Any]) -> bool:
        """Return True when all rule predicates match context."""
        for field, expected in self.when.items():
            actual, exists = _resolve_field(context_map, field)
            if not _match_expected(actual, expected, exists):
                return False
        return True


@dataclass
class _DecisionNode:
    """Internal if-then decision-tree node."""

    rule: CompiledRule
    else_node: _DecisionNode | None = None

    def evaluate(self, context_map: Mapping[str, Any]) -> dict[str, Any] | None:
        """Evaluate this rule and fallback chain."""
        if self.rule.matches(context_map):
            return dict(self.rule.then)

        if self.else_node is None:
            return None

        return self.else_node.evaluate(context_map)


@dataclass(frozen=True)
class CompiledPolicy:
    """Compiled policy with executable evaluate(context) method."""

    name: str
    default_decision: dict[str, Any]
    rules: list[CompiledRule] = field(default_factory=list)
    _decision_tree: _DecisionNode | None = field(default=None, repr=False, compare=False)

    def evaluate(self, context: Any) -> dict[str, Any]:
        """Evaluate runtime context and return a policy decision mapping.

        Evaluation strategy:
        - Start with `default_decision`.
        - Evaluate decision tree (if-then chain) in specificity order.
        - Merge first matching rule decision into defaults.
        """
        context_map = _context_to_mapping(context)
        decision = dict(self.default_decision)

        if self._decision_tree is None:
            return decision

        matched = self._decision_tree.evaluate(context_map)
        if matched is None:
            return decision

        return _merge_decisions(decision, matched)


class PolicyCompiler:
    """Compile YAML policy files into optimized executable policies."""

    def compile(self, yaml_path: Path) -> CompiledPolicy:
        """Compile a YAML policy file into a `CompiledPolicy`.

        Args:
            yaml_path: Path to a YAML file containing policy rules.

        Returns:
            CompiledPolicy with executable `evaluate(context)`.
        """
        if not isinstance(yaml_path, Path):
            raise TypeError("yaml_path must be a pathlib.Path")

        path = yaml_path.expanduser().resolve()
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(f"policy YAML file not found: {path}")

        raw_payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(raw_payload, Mapping):
            raise ValueError("policy root must be a mapping")

        payload = dict(raw_payload)
        name = str(payload.get("name", path.stem)).strip() or path.stem

        default_decision = payload.get("default_decision", payload.get("default", {}))
        if default_decision is None:
            default_decision = {}
        if not isinstance(default_decision, Mapping):
            raise ValueError("default_decision/default must be a mapping")

        rules_payload = payload.get("rules", [])
        if rules_payload is None:
            rules_payload = []
        if not isinstance(rules_payload, list):
            raise ValueError("rules must be a list")

        compiled_rules: list[CompiledRule] = []
        for index, raw_rule in enumerate(rules_payload):
            if not isinstance(raw_rule, Mapping):
                raise ValueError(f"rules[{index}] must be a mapping")

            when = raw_rule.get("when", raw_rule.get("if", {}))
            then = raw_rule.get("decision", raw_rule.get("then", {}))

            if when is None:
                when = {}
            if then is None:
                then = {}

            if not isinstance(when, Mapping):
                raise ValueError(f"rules[{index}].when/if must be a mapping")
            if not isinstance(then, Mapping):
                raise ValueError(f"rules[{index}].decision/then must be a mapping")

            compiled_rules.append(
                CompiledRule(
                    index=index,
                    when=dict(when),
                    then=dict(then),
                    specificity=_specificity_score(when),
                )
            )

        compiled_rules.sort(key=lambda rule: (-rule.specificity, rule.index))

        decision_tree = self._build_decision_tree(compiled_rules)
        return CompiledPolicy(
            name=name,
            default_decision=dict(default_decision),
            rules=compiled_rules,
            _decision_tree=decision_tree,
        )

    @staticmethod
    def _build_decision_tree(rules: list[CompiledRule]) -> _DecisionNode | None:
        if not rules:
            return None

        root: _DecisionNode | None = None
        current: _DecisionNode | None = None

        for rule in rules:
            node = _DecisionNode(rule=rule)
            if root is None:
                root = node
                current = node
                continue

            assert current is not None
            current.else_node = node
            current = node

        return root


def _specificity_score(conditions: Mapping[str, Any]) -> float:
    """Compute rule specificity score for ordering optimization.

    Higher score means the rule is likely more specific and should be evaluated
    earlier.
    """
    score = 0.0

    for field, expected in conditions.items():
        score += 1.0

        if isinstance(field, str) and field:
            # Reward nested field constraints (e.g. metadata.classification).
            score += field.count(".") * 0.15

        if isinstance(expected, Mapping):
            for operator, operand in expected.items():
                op = str(operator).lower()
                if op in {"eq", "neq", "exists", "regex", "starts_with", "ends_with"}:
                    score += 0.9
                elif op in {"gt", "gte", "lt", "lte", "between"}:
                    score += 1.1
                elif op in {"in", "not_in", "contains"}:
                    sequence_size = len(operand) if isinstance(operand, (list, tuple, set)) else 1
                    score += 0.7 + min(1.0, 1.0 / max(1, sequence_size))
                else:
                    score += 0.4
        else:
            score += 0.6

    return score


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


def _match_expected(actual: Any, expected: Any, exists: bool) -> bool:
    if isinstance(expected, Mapping):
        for operator, operand in expected.items():
            if not _apply_operator(str(operator), actual, operand, exists):
                return False
        return True

    if not exists:
        return False
    return actual == expected


def _apply_operator(operator: str, actual: Any, operand: Any, exists: bool) -> bool:
    op = operator.lower()

    try:
        if op == "eq":
            return exists and actual == operand
        if op == "neq":
            return not exists or actual != operand
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


def _merge_decisions(base: Mapping[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        current = merged.get(key)

        if isinstance(current, list) and isinstance(value, list):
            seen = {repr(item) for item in current}
            combined = list(current)
            for item in value:
                marker = repr(item)
                if marker in seen:
                    continue
                seen.add(marker)
                combined.append(item)
            merged[key] = combined
            continue

        if isinstance(current, Mapping) and isinstance(value, Mapping):
            merged[key] = {**dict(current), **dict(value)}
            continue

        merged[key] = value

    return merged


__all__: list[str] = [
    "CompiledRule",
    "CompiledPolicy",
    "PolicyCompiler",
]