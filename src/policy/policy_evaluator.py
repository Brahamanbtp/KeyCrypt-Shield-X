"""Efficient policy evaluation with decision-tree based rule routing.

This module evaluates typed policy rules against runtime encryption context
using a balanced field-index decision tree. The evaluator prioritizes specific
rules over general rules and exposes explainability and performance metrics.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from bisect import bisect_left, bisect_right
from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field, is_dataclass
from typing import TYPE_CHECKING, Any

from src.policy.policy_schema import Action, Operator, Policy, PolicyRule

if TYPE_CHECKING:
    from src.orchestration.encryption_orchestrator import EncryptionContext


@dataclass(frozen=True)
class EvaluationResult:
    """Result returned by policy evaluation."""

    matched_rule: PolicyRule | None
    action: Action
    confidence: float
    evaluation_time_ms: float
    rules_checked: int


@dataclass(frozen=True)
class _IndexedRule:
    rule: PolicyRule
    index: int
    precedence: float
    operand_key: str
    numeric_operand: float | None = None
    compiled_regex: re.Pattern[str] | None = None


@dataclass(frozen=True)
class _CandidateMatch:
    indexed_rule: _IndexedRule
    reason: str


@dataclass(frozen=True)
class _RuleTrace:
    rule_index: int
    field_name: str
    operator: Operator
    expected: Any
    actual: Any
    matched: bool
    reason: str
    precedence: float


@dataclass
class _FieldIndex:
    field_name: str
    equals_rules: dict[str, list[_IndexedRule]] = field(default_factory=dict)
    in_rules: dict[str, list[_IndexedRule]] = field(default_factory=dict)
    gt_thresholds: list[float] = field(default_factory=list)
    gt_prefix_best: list[_IndexedRule] = field(default_factory=list)
    lt_thresholds: list[float] = field(default_factory=list)
    lt_suffix_best: list[_IndexedRule] = field(default_factory=list)
    contains_rules: list[_IndexedRule] = field(default_factory=list)
    matches_rules: list[_IndexedRule] = field(default_factory=list)
    not_equals_rules: list[_IndexedRule] = field(default_factory=list)
    not_equals_best_any: _IndexedRule | None = None
    not_equals_best_excluding: dict[str, _IndexedRule | None] = field(default_factory=dict)


@dataclass
class _DecisionNode:
    field_name: str
    field_index: _FieldIndex
    left: _DecisionNode | None = None
    right: _DecisionNode | None = None


@dataclass(frozen=True)
class _CompiledPolicy:
    key: str
    root: _DecisionNode | None
    field_indexes: dict[str, _FieldIndex]
    not_equals_fields: tuple[str, ...]
    max_precedence: float


@dataclass(frozen=True)
class _EvaluationDiagnostics:
    traces: tuple[_RuleTrace, ...]
    matches: tuple[_CandidateMatch, ...]
    routed_fields: tuple[str, ...]


class PolicyEvaluator:
    """Evaluate policy rules using a field-routed decision tree.

    Evaluation flow:
    1. Compile policy rules into a balanced decision tree keyed by `condition.field`.
    2. Route each context field through O(log n) tree lookup.
    3. Evaluate only candidate rules from relevant field/operator buckets.
    4. Select highest-precedence matching rule; fallback to `default_action`.
    """

    _OPERATOR_WEIGHTS: dict[Operator, float] = {
        Operator.MATCHES: 1.45,
        Operator.IN: 1.35,
        Operator.CONTAINS: 1.20,
        Operator.GREATER_THAN: 1.15,
        Operator.LESS_THAN: 1.15,
        Operator.EQUALS: 1.00,
        Operator.NOT_EQUALS: 0.75,
    }

    def __init__(self, *, cache_limit: int = 128) -> None:
        if cache_limit <= 0:
            raise ValueError("cache_limit must be > 0")

        self._cache_limit = int(cache_limit)
        self._compiled_cache: OrderedDict[str, _CompiledPolicy] = OrderedDict()

    def evaluate(self, context: EncryptionContext, policy: Policy) -> EvaluationResult:
        """Evaluate context against policy and return the selected action."""
        result, _ = self._evaluate_with_diagnostics(context=context, policy=policy, capture_trace=False)
        return result

    def explain(self, context: EncryptionContext, policy: Policy) -> str:
        """Return human-readable explanation of rule matching decisions."""
        result, diagnostics = self._evaluate_with_diagnostics(
            context=context,
            policy=policy,
            capture_trace=True,
        )

        lines: list[str] = []
        lines.append(f"policy={policy.name} version={policy.version}")
        lines.append(
            "decision_tree=balanced-field-index "
            f"routed_fields={len(diagnostics.routed_fields)} checked_rules={result.rules_checked}"
        )
        lines.append(
            "result="
            f"algorithm={result.action.algorithm}, key_rotation={result.action.key_rotation}, "
            f"confidence={result.confidence:.3f}, evaluation_time_ms={result.evaluation_time_ms:.3f}"
        )

        if result.matched_rule is None:
            lines.append("matched_rule=none (default_action applied)")
        else:
            condition = result.matched_rule.condition
            lines.append(
                "matched_rule="
                f"field={condition.field} operator={condition.operator.value} value={condition.value!r}"
            )

        if diagnostics.matches:
            lines.append("matched_candidates:")
            ordered = sorted(
                diagnostics.matches,
                key=lambda item: (-item.indexed_rule.precedence, item.indexed_rule.index),
            )
            for candidate in ordered[:10]:
                cond = candidate.indexed_rule.rule.condition
                lines.append(
                    f"  - rule[{candidate.indexed_rule.index}] "
                    f"{cond.field} {cond.operator.value} {cond.value!r}: {candidate.reason}"
                )

        if diagnostics.traces:
            lines.append("checked_rules:")
            for trace in diagnostics.traces[:15]:
                verdict = "match" if trace.matched else "no-match"
                lines.append(
                    f"  - rule[{trace.rule_index}] {trace.field_name} {trace.operator.value} "
                    f"expected={trace.expected!r} actual={trace.actual!r} => {verdict} ({trace.reason})"
                )

        return "\n".join(lines)

    def _evaluate_with_diagnostics(
        self,
        *,
        context: EncryptionContext,
        policy: Policy,
        capture_trace: bool,
    ) -> tuple[EvaluationResult, _EvaluationDiagnostics | None]:
        if not isinstance(policy, Policy):
            raise TypeError("policy must be a Policy instance")

        started = time.perf_counter()

        compiled = self._get_compiled_policy(policy)
        context_map = self._context_to_mapping(context)
        flat_context = self._flatten_context(context_map)

        traces: list[_RuleTrace] = []
        matches: list[_CandidateMatch] = []
        routed_fields: list[str] = []
        rules_checked = 0

        for field_name, actual in flat_context.items():
            field_index = self._lookup_field_index(compiled.root, field_name)
            if field_index is None:
                continue

            routed_fields.append(field_name)
            rules_checked += self._evaluate_field_candidates(
                field_index=field_index,
                actual=actual,
                exists=True,
                traces=traces,
                matches=matches,
                capture_trace=capture_trace,
            )

        for field_name in compiled.not_equals_fields:
            if field_name in flat_context:
                continue

            field_index = compiled.field_indexes[field_name]
            candidate = field_index.not_equals_best_any
            if candidate is None:
                continue

            rules_checked += self._evaluate_candidate(
                candidate,
                actual=None,
                exists=False,
                traces=traces,
                matches=matches,
                capture_trace=capture_trace,
            )

        ordered_matches = sorted(
            matches,
            key=lambda item: (-item.indexed_rule.precedence, item.indexed_rule.index),
        )

        selected = ordered_matches[0] if ordered_matches else None
        matched_rule = selected.indexed_rule.rule if selected is not None else None
        selected_action = matched_rule.action if matched_rule is not None else policy.default_action

        second = ordered_matches[1] if len(ordered_matches) > 1 else None
        confidence = self._compute_confidence(selected, second, compiled.max_precedence)

        elapsed_ms = (time.perf_counter() - started) * 1000.0
        result = EvaluationResult(
            matched_rule=matched_rule,
            action=selected_action,
            confidence=confidence,
            evaluation_time_ms=elapsed_ms,
            rules_checked=rules_checked,
        )

        if not capture_trace:
            return result, None

        diagnostics = _EvaluationDiagnostics(
            traces=tuple(traces),
            matches=tuple(ordered_matches),
            routed_fields=tuple(routed_fields),
        )
        return result, diagnostics

    def _evaluate_field_candidates(
        self,
        *,
        field_index: _FieldIndex,
        actual: Any,
        exists: bool,
        traces: list[_RuleTrace],
        matches: list[_CandidateMatch],
        capture_trace: bool,
    ) -> int:
        checked = 0
        operand_key = self._canonical_key(actual)

        equals_bucket = field_index.equals_rules.get(operand_key)
        if equals_bucket:
            checked += self._evaluate_candidate(
                equals_bucket[0],
                actual=actual,
                exists=exists,
                traces=traces,
                matches=matches,
                capture_trace=capture_trace,
            )

        in_bucket = field_index.in_rules.get(operand_key)
        if in_bucket:
            checked += self._evaluate_candidate(
                in_bucket[0],
                actual=actual,
                exists=exists,
                traces=traces,
                matches=matches,
                capture_trace=capture_trace,
            )

        if isinstance(actual, (int, float)) and not isinstance(actual, bool):
            numeric_actual = float(actual)

            if field_index.gt_thresholds:
                gt_index = bisect_left(field_index.gt_thresholds, numeric_actual) - 1
                if gt_index >= 0:
                    checked += self._evaluate_candidate(
                        field_index.gt_prefix_best[gt_index],
                        actual=actual,
                        exists=exists,
                        traces=traces,
                        matches=matches,
                        capture_trace=capture_trace,
                    )

            if field_index.lt_thresholds:
                lt_index = bisect_right(field_index.lt_thresholds, numeric_actual)
                if lt_index < len(field_index.lt_suffix_best):
                    checked += self._evaluate_candidate(
                        field_index.lt_suffix_best[lt_index],
                        actual=actual,
                        exists=exists,
                        traces=traces,
                        matches=matches,
                        capture_trace=capture_trace,
                    )

        for candidate in field_index.contains_rules:
            checked += self._evaluate_candidate(
                candidate,
                actual=actual,
                exists=exists,
                traces=traces,
                matches=matches,
                capture_trace=capture_trace,
            )
            if matches and matches[-1].indexed_rule is candidate:
                break

        for candidate in field_index.matches_rules:
            checked += self._evaluate_candidate(
                candidate,
                actual=actual,
                exists=exists,
                traces=traces,
                matches=matches,
                capture_trace=capture_trace,
            )
            if matches and matches[-1].indexed_rule is candidate:
                break

        if field_index.not_equals_best_any is not None:
            candidate = field_index.not_equals_best_excluding.get(
                operand_key,
                field_index.not_equals_best_any,
            )
            if candidate is not None:
                checked += self._evaluate_candidate(
                    candidate,
                    actual=actual,
                    exists=exists,
                    traces=traces,
                    matches=matches,
                    capture_trace=capture_trace,
                )

        return checked

    def _evaluate_candidate(
        self,
        indexed_rule: _IndexedRule,
        *,
        actual: Any,
        exists: bool,
        traces: list[_RuleTrace],
        matches: list[_CandidateMatch],
        capture_trace: bool,
    ) -> int:
        matched, reason = self._match_indexed_rule(indexed_rule, actual=actual, exists=exists)
        if matched:
            matches.append(_CandidateMatch(indexed_rule=indexed_rule, reason=reason))

        if capture_trace:
            condition = indexed_rule.rule.condition
            traces.append(
                _RuleTrace(
                    rule_index=indexed_rule.index,
                    field_name=condition.field,
                    operator=condition.operator,
                    expected=condition.value,
                    actual=actual,
                    matched=matched,
                    reason=reason,
                    precedence=indexed_rule.precedence,
                )
            )

        return 1

    @staticmethod
    def _match_indexed_rule(indexed_rule: _IndexedRule, *, actual: Any, exists: bool) -> tuple[bool, str]:
        condition = indexed_rule.rule.condition
        operator = condition.operator
        expected = condition.value

        if operator is Operator.EQUALS:
            if not exists:
                return False, "field does not exist"
            return actual == expected, "actual equals expected" if actual == expected else "values differ"

        if operator is Operator.NOT_EQUALS:
            if not exists:
                return True, "field missing, NOT_EQUALS considered true"
            matched = actual != expected
            return matched, "values differ" if matched else "actual equals excluded value"

        if operator is Operator.GREATER_THAN:
            if not exists:
                return False, "field does not exist"
            if isinstance(actual, bool) or not isinstance(actual, (int, float)):
                return False, "actual value is not numeric"
            matched = float(actual) > float(expected)
            return matched, "actual is greater than threshold" if matched else "actual is not greater"

        if operator is Operator.LESS_THAN:
            if not exists:
                return False, "field does not exist"
            if isinstance(actual, bool) or not isinstance(actual, (int, float)):
                return False, "actual value is not numeric"
            matched = float(actual) < float(expected)
            return matched, "actual is less than threshold" if matched else "actual is not less"

        if operator is Operator.CONTAINS:
            if not exists:
                return False, "field does not exist"
            try:
                matched = expected in actual
            except Exception:
                return False, "actual value is not container-compatible"
            return matched, "container includes expected value" if matched else "container does not include value"

        if operator is Operator.IN:
            if not exists:
                return False, "field does not exist"
            try:
                matched = actual in expected
            except Exception:
                return False, "IN operand is not iterable"
            return matched, "actual found in expected set" if matched else "actual missing from expected set"

        if operator is Operator.MATCHES:
            if not exists:
                return False, "field does not exist"
            pattern = indexed_rule.compiled_regex
            if pattern is None:
                return False, "regex pattern is unavailable"
            matched = pattern.search(str(actual)) is not None
            return matched, "regex matched actual value" if matched else "regex did not match"

        return False, f"unsupported operator: {operator.value}"

    def _get_compiled_policy(self, policy: Policy) -> _CompiledPolicy:
        policy_key = self._policy_key(policy)
        cached = self._compiled_cache.get(policy_key)
        if cached is not None:
            self._compiled_cache.move_to_end(policy_key)
            return cached

        compiled = self._compile_policy(policy, key=policy_key)
        self._compiled_cache[policy_key] = compiled
        self._compiled_cache.move_to_end(policy_key)

        while len(self._compiled_cache) > self._cache_limit:
            self._compiled_cache.popitem(last=False)

        return compiled

    def _compile_policy(self, policy: Policy, *, key: str) -> _CompiledPolicy:
        indexed_rules: list[_IndexedRule] = []
        max_precedence = 1.0

        for index, rule in enumerate(policy.rules):
            precedence = self._rule_precedence(rule)
            max_precedence = max(max_precedence, precedence)

            numeric_operand: float | None = None
            if rule.condition.operator in {Operator.GREATER_THAN, Operator.LESS_THAN}:
                numeric_operand = float(rule.condition.value)

            compiled_regex: re.Pattern[str] | None = None
            if rule.condition.operator is Operator.MATCHES:
                compiled_regex = re.compile(str(rule.condition.value))

            indexed_rules.append(
                _IndexedRule(
                    rule=rule,
                    index=index,
                    precedence=precedence,
                    operand_key=self._canonical_key(rule.condition.value),
                    numeric_operand=numeric_operand,
                    compiled_regex=compiled_regex,
                )
            )

        indexed_rules.sort(key=lambda item: (-item.precedence, item.index))

        by_field: dict[str, list[_IndexedRule]] = {}
        for indexed in indexed_rules:
            by_field.setdefault(indexed.rule.condition.field, []).append(indexed)

        field_indexes: dict[str, _FieldIndex] = {}
        not_equals_fields: list[str] = []

        for field_name, rules in by_field.items():
            field_index = self._build_field_index(field_name, rules)
            field_indexes[field_name] = field_index
            if field_index.not_equals_best_any is not None:
                not_equals_fields.append(field_name)

        tree_items = sorted(field_indexes.items(), key=lambda item: item[0])
        root = self._build_decision_tree(tree_items)

        return _CompiledPolicy(
            key=key,
            root=root,
            field_indexes=field_indexes,
            not_equals_fields=tuple(sorted(not_equals_fields)),
            max_precedence=max_precedence,
        )

    def _build_field_index(self, field_name: str, rules: list[_IndexedRule]) -> _FieldIndex:
        field_index = _FieldIndex(field_name=field_name)

        gt_by_threshold: dict[float, _IndexedRule] = {}
        lt_by_threshold: dict[float, _IndexedRule] = {}
        not_equals_best_per_operand: dict[str, _IndexedRule] = {}

        for indexed in rules:
            condition = indexed.rule.condition
            operator = condition.operator

            if operator is Operator.EQUALS:
                field_index.equals_rules.setdefault(indexed.operand_key, []).append(indexed)
                continue

            if operator is Operator.IN:
                values = condition.value
                if isinstance(values, (list, tuple, set)):
                    for item in values:
                        item_key = self._canonical_key(item)
                        bucket = field_index.in_rules.setdefault(item_key, [])
                        bucket.append(indexed)
                continue

            if operator is Operator.GREATER_THAN and indexed.numeric_operand is not None:
                current = gt_by_threshold.get(indexed.numeric_operand)
                if current is None or self._is_better(indexed, current):
                    gt_by_threshold[indexed.numeric_operand] = indexed
                continue

            if operator is Operator.LESS_THAN and indexed.numeric_operand is not None:
                current = lt_by_threshold.get(indexed.numeric_operand)
                if current is None or self._is_better(indexed, current):
                    lt_by_threshold[indexed.numeric_operand] = indexed
                continue

            if operator is Operator.CONTAINS:
                field_index.contains_rules.append(indexed)
                continue

            if operator is Operator.MATCHES:
                field_index.matches_rules.append(indexed)
                continue

            if operator is Operator.NOT_EQUALS:
                field_index.not_equals_rules.append(indexed)
                current = not_equals_best_per_operand.get(indexed.operand_key)
                if current is None or self._is_better(indexed, current):
                    not_equals_best_per_operand[indexed.operand_key] = indexed

        for bucket in field_index.equals_rules.values():
            bucket.sort(key=lambda item: (-item.precedence, item.index))

        for bucket in field_index.in_rules.values():
            bucket.sort(key=lambda item: (-item.precedence, item.index))

        field_index.contains_rules.sort(key=lambda item: (-item.precedence, item.index))
        field_index.matches_rules.sort(key=lambda item: (-item.precedence, item.index))
        field_index.not_equals_rules.sort(key=lambda item: (-item.precedence, item.index))

        if gt_by_threshold:
            sorted_gt = sorted(gt_by_threshold.items(), key=lambda item: item[0])
            field_index.gt_thresholds = [threshold for threshold, _ in sorted_gt]
            field_index.gt_prefix_best = []
            best: _IndexedRule | None = None
            for _, candidate in sorted_gt:
                if best is None or self._is_better(candidate, best):
                    best = candidate
                field_index.gt_prefix_best.append(best)

        if lt_by_threshold:
            sorted_lt = sorted(lt_by_threshold.items(), key=lambda item: item[0])
            field_index.lt_thresholds = [threshold for threshold, _ in sorted_lt]
            size = len(sorted_lt)
            field_index.lt_suffix_best = [sorted_lt[-1][1]] * size
            best = sorted_lt[-1][1]
            for offset in range(size - 1, -1, -1):
                candidate = sorted_lt[offset][1]
                if self._is_better(candidate, best):
                    best = candidate
                field_index.lt_suffix_best[offset] = best

        if field_index.not_equals_rules:
            field_index.not_equals_best_any = field_index.not_equals_rules[0]

            grouped_best = sorted(
                not_equals_best_per_operand.values(),
                key=lambda item: (-item.precedence, item.index),
            )

            exclusions: dict[str, _IndexedRule | None] = {}
            for operand_key in not_equals_best_per_operand:
                replacement: _IndexedRule | None = None
                for candidate in grouped_best:
                    if candidate.operand_key != operand_key:
                        replacement = candidate
                        break
                exclusions[operand_key] = replacement
            field_index.not_equals_best_excluding = exclusions

        return field_index

    @classmethod
    def _is_better(cls, left: _IndexedRule, right: _IndexedRule) -> bool:
        if left.precedence != right.precedence:
            return left.precedence > right.precedence
        return left.index < right.index

    def _build_decision_tree(self, items: list[tuple[str, _FieldIndex]]) -> _DecisionNode | None:
        if not items:
            return None

        midpoint = len(items) // 2
        field_name, field_index = items[midpoint]
        return _DecisionNode(
            field_name=field_name,
            field_index=field_index,
            left=self._build_decision_tree(items[:midpoint]),
            right=self._build_decision_tree(items[midpoint + 1 :]),
        )

    @staticmethod
    def _lookup_field_index(root: _DecisionNode | None, field_name: str) -> _FieldIndex | None:
        node = root
        while node is not None:
            if field_name == node.field_name:
                return node.field_index
            if field_name < node.field_name:
                node = node.left
            else:
                node = node.right
        return None

    @classmethod
    def _rule_precedence(cls, rule: PolicyRule) -> float:
        condition = rule.condition

        base = 1.0
        operator_weight = cls._OPERATOR_WEIGHTS.get(condition.operator, 1.0)
        depth_weight = 0.25 * condition.field.count(".")

        value_weight = 0.0
        if condition.operator is Operator.IN and isinstance(condition.value, (list, tuple, set)):
            value_weight = 1.0 / max(1.0, float(len(condition.value)))
        elif condition.operator is Operator.MATCHES and isinstance(condition.value, str):
            value_weight = min(0.8, len(condition.value) / 64.0)
        elif condition.operator in {Operator.GREATER_THAN, Operator.LESS_THAN}:
            value_weight = 0.15
        elif condition.operator is Operator.EQUALS:
            value_weight = 0.2

        return base + operator_weight + depth_weight + value_weight

    @staticmethod
    def _compute_confidence(
        best: _CandidateMatch | None,
        second: _CandidateMatch | None,
        max_precedence: float,
    ) -> float:
        if best is None:
            return 0.5

        best_score = best.indexed_rule.precedence
        normalized_best = min(1.0, best_score / max(1.0, max_precedence))

        if second is None:
            separation = 1.0
        else:
            delta = max(0.0, best_score - second.indexed_rule.precedence)
            separation = min(1.0, delta / max(1.0, best_score))

        confidence = 0.55 + (0.35 * normalized_best) + (0.10 * separation)
        return max(0.0, min(0.99, confidence))

    @staticmethod
    def _context_to_mapping(context: Any) -> dict[str, Any]:
        if isinstance(context, Mapping):
            payload = dict(context)
        elif is_dataclass(context):
            payload = asdict(context)
        elif hasattr(context, "model_dump") and callable(getattr(context, "model_dump")):
            payload = dict(context.model_dump())
        else:
            payload = dict(vars(context))

        metadata = payload.get("metadata")
        if isinstance(metadata, Mapping):
            for key, value in metadata.items():
                payload.setdefault(str(key), value)

        return payload

    @classmethod
    def _flatten_context(cls, payload: Mapping[str, Any]) -> dict[str, Any]:
        flattened: dict[str, Any] = {}

        def _walk(value: Any, prefix: str) -> None:
            if prefix:
                flattened[prefix] = value

            if isinstance(value, Mapping):
                for key, item in value.items():
                    key_text = str(key)
                    child = f"{prefix}.{key_text}" if prefix else key_text
                    _walk(item, child)

        _walk(payload, "")
        return flattened

    @staticmethod
    def _policy_key(policy: Policy) -> str:
        payload = policy.model_dump(mode="json", by_alias=False, exclude_none=False)
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        return f"{policy.name}:{policy.version}:{digest}"

    @staticmethod
    def _canonical_key(value: Any) -> str:
        try:
            encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        except Exception:
            encoded = repr(value)
        return f"{type(value).__name__}:{encoded}"


__all__ = [
    "EvaluationResult",
    "PolicyEvaluator",
]
