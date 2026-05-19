"""Policy compliance checking and enforcement validation.

PRESERVE: Policy compliance checking
EXTEND: Policy enforcement validation

Provides policy-aware compliance checks, violation discovery, update
suggestions, effectiveness scoring, and policy version tracking.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import UTC, datetime
from typing import Any, Mapping, Optional
import copy
import hashlib
import json
import re

from src.governance.incident_response import Incident
from src.policy.policy_evaluator import PolicyEvaluator
from src.policy.policy_schema import Action, Policy, PolicyRule


APPROVED_ALGORITHMS = {
    "aes-256-gcm",
    "aes-192-gcm",
    "aes-128-gcm",
    "chacha20-poly1305",
    "xchacha20-poly1305",
}

ACCESS_TAGS = {"least-privilege", "rbac", "access-control", "least_privilege"}
LOGGING_TAGS = {"audit-logging", "logging", "all-events-logged", "audit"}


@dataclass(frozen=True)
class Violation:
    policy_name: str
    policy_version: str
    category: str
    severity: str
    message: str
    expected: Any
    actual: Any
    control: str
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendation: str | None = None


@dataclass(frozen=True)
class ComplianceCheck:
    policy_name: str
    policy_version: str
    compliant: bool
    score: int
    checked_at: datetime
    violations: list[Violation] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    version_record_id: str = ""


@dataclass(frozen=True)
class Effectiveness:
    policy_name: str
    policy_version: str
    score: int
    incidents_total: int
    incidents_prevented: int
    incidents_missed: int
    notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class PolicyVersionRecord:
    policy_name: str
    policy_version: str
    policy_hash: str
    recorded_at: datetime
    change_summary: str


class PolicyComplianceChecker:
    """Validate policies against a system state and incident history."""

    def __init__(self, *, policy_evaluator: PolicyEvaluator | None = None) -> None:
        self._policy_evaluator = policy_evaluator or PolicyEvaluator()
        self._history: dict[str, list[PolicyVersionRecord]] = {}
        self._last_check: dict[str, ComplianceCheck] = {}

    def check_policy_compliance(self, policy: Policy, system_state: dict) -> ComplianceCheck:
        """Verify system complies with policy."""
        self._require_policy(policy)
        state = self._normalize_state(system_state)
        action, active_rule = self._effective_action(policy, state)

        violations: list[Violation] = []
        violations.extend(self._encryption_violations(policy, action, state, active_rule))
        violations.extend(self._key_rotation_violations(policy, action, state, active_rule))
        violations.extend(self._access_control_violations(policy, action, state, active_rule))
        violations.extend(self._logging_violations(policy, action, state, active_rule))

        score = self._score_from_violations(violations)
        check = ComplianceCheck(
            policy_name=policy.name,
            policy_version=policy.version,
            compliant=len(violations) == 0,
            score=score,
            checked_at=datetime.now(UTC),
            violations=violations,
            notes=self._check_notes(policy, state, violations),
            version_record_id=self._record_policy_version(policy, "compliance-check"),
        )
        self._last_check[policy.name.lower()] = check
        return check

    def identify_policy_violations(self, policy: Policy) -> list[Violation]:
        """List all current violations in the policy definition itself."""
        self._require_policy(policy)
        violations: list[Violation] = []

        all_actions = [policy.default_action] + [rule.action for rule in policy.rules]
        for index, action in enumerate(all_actions):
            label = "default_action" if index == 0 else f"rule[{index}]"
            if action.algorithm.lower() not in APPROVED_ALGORITHMS:
                violations.append(
                    self._violation(
                        policy,
                        category="encryption",
                        severity="high",
                        control=f"{label}.algorithm",
                        message=f"Policy uses non-approved encryption algorithm: {action.algorithm}",
                        expected=sorted(APPROVED_ALGORITHMS),
                        actual=action.algorithm,
                        recommendation="Switch to an approved algorithm such as AES-256-GCM or ChaCha20-Poly1305.",
                    )
                )

            rotation_days = self._parse_duration_days(action.key_rotation)
            if rotation_days is None:
                violations.append(
                    self._violation(
                        policy,
                        category="key_rotation",
                        severity="medium",
                        control=f"{label}.key_rotation",
                        message=f"Policy key rotation schedule is invalid: {action.key_rotation}",
                        expected="duration like 90d",
                        actual=action.key_rotation,
                        recommendation="Use a valid key rotation schedule such as 90d or 60d.",
                    )
                )
            elif rotation_days > 365:
                violations.append(
                    self._violation(
                        policy,
                        category="key_rotation",
                        severity="medium",
                        control=f"{label}.key_rotation",
                        message=f"Policy key rotation schedule is too long: {action.key_rotation}",
                        expected="<= 365 days",
                        actual=action.key_rotation,
                        recommendation="Reduce the key rotation schedule to at most one year.",
                    )
                )

            if not self._has_access_control_requirement(action):
                violations.append(
                    self._violation(
                        policy,
                        category="access_control",
                        severity="medium",
                        control=f"{label}.metadata.access_control",
                        message="Policy does not define least-privilege access control requirements.",
                        expected=True,
                        actual=False,
                        recommendation="Add access control metadata requiring least privilege or RBAC enforcement.",
                    )
                )

            if not self._has_logging_requirement(action):
                violations.append(
                    self._violation(
                        policy,
                        category="logging",
                        severity="medium",
                        control=f"{label}.metadata.logging",
                        message="Policy does not define logging requirements for required events.",
                        expected=True,
                        actual=False,
                        recommendation="Add logging metadata requiring immutable logging of all required events.",
                    )
                )

        if not policy.rules:
            violations.append(
                self._violation(
                    policy,
                    category="policy_structure",
                    severity="low",
                    control="rules",
                    message="Policy has no rules and relies entirely on the default action.",
                    expected="at least one rule",
                    actual=0,
                    recommendation="Add specific rules for common policy contexts to reduce ambiguity.",
                )
            )

        self._record_policy_version(policy, "policy-definition-review")
        return violations

    def suggest_policy_updates(self, current_policy: Policy, new_requirements: list[str]) -> Policy:
        """Suggest policy changes to meet new requirements."""
        self._require_policy(current_policy)
        normalized_requirements = [item.strip().lower() for item in new_requirements if str(item).strip()]

        policy_data = current_policy.model_dump(mode="python")
        updated_default = self._update_action(copy.deepcopy(policy_data["default_action"]), normalized_requirements)

        updated_rules: list[dict[str, Any]] = []
        for rule in policy_data["rules"]:
            updated_rule = copy.deepcopy(rule)
            updated_rule["action"] = self._update_action(updated_rule["action"], normalized_requirements)
            updated_rules.append(updated_rule)

        policy_data["default_action"] = updated_default
        policy_data["rules"] = updated_rules
        policy_data["version"] = self._bump_version(current_policy.version)

        updated_policy = Policy.model_validate(policy_data)
        self._record_policy_version(
            updated_policy,
            f"suggested updates for requirements: {', '.join(normalized_requirements) or 'none'}",
        )
        return updated_policy

    def validate_policy_effectiveness(self, policy: Policy, incidents: list[Incident]) -> Effectiveness:
        """Assesses if policy prevents incidents."""
        self._require_policy(policy)
        if not incidents:
            return Effectiveness(
                policy_name=policy.name,
                policy_version=policy.version,
                score=100,
                incidents_total=0,
                incidents_prevented=0,
                incidents_missed=0,
                notes=["No incidents supplied"],
            )

        prevented = 0
        missed = 0
        notes: list[str] = []

        for incident in incidents:
            context = self._incident_context(incident)
            check = self.check_policy_compliance(policy, context)
            if check.compliant:
                missed += 1
                notes.append(f"Incident {incident.id} occurred despite policy compliance")
            else:
                prevented += 1
                notes.append(f"Incident {incident.id} would have violated policy controls")

        score = int(round((prevented / len(incidents)) * 100))
        return Effectiveness(
            policy_name=policy.name,
            policy_version=policy.version,
            score=score,
            incidents_total=len(incidents),
            incidents_prevented=prevented,
            incidents_missed=missed,
            notes=notes,
        )

    def get_policy_version_history(self, policy_name: str) -> list[PolicyVersionRecord]:
        return list(self._history.get(policy_name.lower(), []))

    def _encryption_violations(
        self,
        policy: Policy,
        action: Action,
        state: Mapping[str, Any],
        active_rule: PolicyRule | None,
    ) -> list[Violation]:
        actual_algorithm = self._system_algorithm(state)
        violations: list[Violation] = []

        if actual_algorithm is None:
            violations.append(
                self._violation(
                    policy,
                    category="encryption",
                    severity="high",
                    control="encryption.algorithm",
                    message="System does not declare an encryption algorithm.",
                    expected=action.algorithm,
                    actual=None,
                    recommendation="Declare and enforce an approved encryption algorithm.",
                )
            )
        elif actual_algorithm.lower() not in APPROVED_ALGORITHMS:
            violations.append(
                self._violation(
                    policy,
                    category="encryption",
                    severity="critical",
                    control="encryption.algorithm",
                    message=f"System uses non-approved encryption algorithm: {actual_algorithm}",
                    expected=sorted(APPROVED_ALGORITHMS),
                    actual=actual_algorithm,
                    recommendation="Migrate to an approved algorithm and update the policy baseline.",
                )
            )
        elif actual_algorithm.lower() != action.algorithm.lower():
            violations.append(
                self._violation(
                    policy,
                    category="encryption",
                    severity="medium",
                    control="encryption.algorithm",
                    message="System encryption algorithm does not match the active policy action.",
                    expected=action.algorithm,
                    actual=actual_algorithm,
                    recommendation="Align system encryption settings with the active policy action.",
                    evidence={"active_rule": self._rule_label(active_rule)},
                )
            )

        actual_rotation = self._system_key_rotation_days(state)
        expected_rotation = self._parse_duration_days(action.key_rotation)
        if expected_rotation is not None:
            if actual_rotation is None:
                violations.append(
                    self._violation(
                        policy,
                        category="key_rotation",
                        severity="high",
                        control="encryption.key_rotation",
                        message="System does not declare a key rotation schedule.",
                        expected=action.key_rotation,
                        actual=None,
                        recommendation="Declare a key rotation schedule that matches the policy.",
                    )
                )
            elif actual_rotation > expected_rotation:
                violations.append(
                    self._violation(
                        policy,
                        category="key_rotation",
                        severity="high",
                        control="encryption.key_rotation",
                        message="System key rotation exceeds policy schedule.",
                        expected=action.key_rotation,
                        actual=f"{actual_rotation}d",
                        recommendation="Reduce the rotation interval to the policy maximum.",
                    )
                )

        return violations

    def _key_rotation_violations(
        self,
        policy: Policy,
        action: Action,
        state: Mapping[str, Any],
        active_rule: PolicyRule | None,
    ) -> list[Violation]:
        if active_rule is None:
            return []

        # Any explicit rule metadata demanding tighter rotation should be honored.
        rule_rotation = self._rotation_from_metadata(active_rule.action.metadata)
        if rule_rotation is None:
            return []

        actual_rotation = self._system_key_rotation_days(state)
        if actual_rotation is None:
            return [
                self._violation(
                    policy,
                    category="key_rotation",
                    severity="high",
                    control="encryption.key_rotation",
                    message="System does not declare a key rotation schedule required by the active policy rule.",
                    expected=f"{rule_rotation}d",
                    actual=None,
                    recommendation="Configure the required key rotation schedule.",
                    evidence={"active_rule": self._rule_label(active_rule)},
                )
            ]

        if actual_rotation > rule_rotation:
            return [
                self._violation(
                    policy,
                    category="key_rotation",
                    severity="high",
                    control="encryption.key_rotation",
                    message="System key rotation exceeds the active policy rule requirement.",
                    expected=f"{rule_rotation}d",
                    actual=f"{actual_rotation}d",
                    recommendation="Reduce the rotation interval to meet the rule requirement.",
                    evidence={"active_rule": self._rule_label(active_rule)},
                )
            ]

        return []

    def _access_control_violations(
        self,
        policy: Policy,
        action: Action,
        state: Mapping[str, Any],
        active_rule: PolicyRule | None,
    ) -> list[Violation]:
        access_state = self._access_state(state)
        required = self._policy_requires_access_control(action, active_rule)
        if not required:
            return []

        if not access_state.get("least_privilege", False):
            return [
                self._violation(
                    policy,
                    category="access_control",
                    severity="high",
                    control="access_controls.least_privilege",
                    message="System does not enforce least-privilege access control.",
                    expected=True,
                    actual=access_state.get("least_privilege", False),
                    recommendation="Enable least-privilege access rules and review role assignments.",
                    evidence={"access_controls": access_state},
                )
            ]

        return []

    def _logging_violations(
        self,
        policy: Policy,
        action: Action,
        state: Mapping[str, Any],
        active_rule: PolicyRule | None,
    ) -> list[Violation]:
        logging_state = self._logging_state(state)
        required = self._policy_requires_logging(action, active_rule)
        if not required:
            return []

        if not logging_state.get("all_required_events_logged", False):
            return [
                self._violation(
                    policy,
                    category="logging",
                    severity="high",
                    control="logging.all_required_events_logged",
                    message="System does not log all required security events.",
                    expected=True,
                    actual=logging_state.get("all_required_events_logged", False),
                    recommendation="Enable immutable logging for all required events and verify coverage.",
                    evidence={"logging": logging_state},
                )
            ]

        return []

    def _effective_action(self, policy: Policy, system_state: Mapping[str, Any]) -> tuple[Action, PolicyRule | None]:
        evaluation = self._policy_evaluator.evaluate(context=system_state, policy=policy)
        if evaluation.matched_rule is not None:
            return evaluation.action, evaluation.matched_rule

        return policy.default_action, None

    def _check_notes(self, policy: Policy, state: Mapping[str, Any], violations: list[Violation]) -> list[str]:
        notes = [f"policy={policy.name} version={policy.version}"]
        if violations:
            notes.append(f"violations={len(violations)}")
        if state:
            notes.append(f"state_keys={len(state)}")
        return notes

    def _update_action(self, action_payload: dict[str, Any], requirements: list[str]) -> dict[str, Any]:
        action = Action.model_validate(action_payload)
        metadata = dict(action.metadata)
        compliance = list(action.compliance)

        if any("encryption" in item or "algorithm" in item for item in requirements):
            action = action.model_copy(update={"algorithm": "aes-256-gcm"})
            metadata.setdefault("encryption", {})["approved_algorithms"] = sorted(APPROVED_ALGORITHMS)
        if any("rotation" in item or "key" in item for item in requirements):
            action = action.model_copy(update={"key_rotation": self._strongest_rotation(action.key_rotation, requirements)})
            metadata.setdefault("key_management", {})["rotation_policy"] = action.key_rotation
        if any("least privilege" in item or "rbac" in item or "access" in item for item in requirements):
            metadata.setdefault("access_control", {})["least_privilege"] = True
            if not any(tag.lower() == "least-privilege" for tag in compliance):
                compliance.append("least-privilege")
        if any("logging" in item or "audit" in item for item in requirements):
            metadata.setdefault("logging", {})["all_required_events_logged"] = True
            if not any(tag.lower() == "audit-logging" for tag in compliance):
                compliance.append("audit-logging")

        return action.model_copy(update={"metadata": metadata, "compliance": compliance}).model_dump(mode="python")

    def _strongest_rotation(self, current_rotation: str, requirements: list[str]) -> str:
        current_days = self._parse_duration_days(current_rotation) or 365
        target_days = current_days
        for item in requirements:
            match = re.search(r"(\d+)\s*d", item)
            if match:
                target_days = min(target_days, int(match.group(1)))
            elif "60" in item:
                target_days = min(target_days, 60)
            elif "30" in item:
                target_days = min(target_days, 30)

        return f"{max(1, target_days)}d"

    def _score_from_violations(self, violations: list[Violation]) -> int:
        if not violations:
            return 100

        penalties = 0
        for violation in violations:
            penalties += {
                "critical": 25,
                "high": 20,
                "medium": 10,
                "low": 5,
            }.get(violation.severity.lower(), 8)

        return max(0, 100 - min(100, penalties))

    def _incident_context(self, incident: Incident) -> dict[str, Any]:
        context = dict(incident.indicators or {})
        context.setdefault("incident_type", incident.incident_type)
        context.setdefault("severity", incident.severity)
        context.setdefault("detected_at", incident.detected_at.isoformat())
        return context

    def _violation(
        self,
        policy: Policy,
        *,
        category: str,
        severity: str,
        control: str,
        message: str,
        expected: Any,
        actual: Any,
        recommendation: str,
        evidence: Optional[dict[str, Any]] = None,
    ) -> Violation:
        return Violation(
            policy_name=policy.name,
            policy_version=policy.version,
            category=category,
            severity=severity,
            message=message,
            expected=expected,
            actual=actual,
            control=control,
            evidence=dict(evidence or {}),
            recommendation=recommendation,
        )

    def _record_policy_version(self, policy: Policy, change_summary: str) -> str:
        record = PolicyVersionRecord(
            policy_name=policy.name,
            policy_version=policy.version,
            policy_hash=self._policy_hash(policy),
            recorded_at=datetime.now(UTC),
            change_summary=change_summary,
        )
        history = self._history.setdefault(policy.name.lower(), [])
        if not history or history[-1].policy_hash != record.policy_hash:
            history.append(record)
        return record.policy_hash

    def _policy_hash(self, policy: Policy) -> str:
        payload = policy.model_dump(mode="python")
        serialized = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(serialized).hexdigest()

    def _bump_version(self, version: str) -> str:
        parts = version.split(".")
        if len(parts) == 1:
            try:
                return f"{int(parts[0]) + 1}.0"
            except Exception:
                return f"{version}.1"

        try:
            major = int(parts[0])
            minor = int(parts[1])
        except Exception:
            return f"{version}.1"
        return f"{major}.{minor + 1}"

    def _require_policy(self, policy: Policy) -> None:
        if not isinstance(policy, Policy):
            raise TypeError("policy must be a Policy instance")

    def _normalize_state(self, system_state: dict) -> dict[str, Any]:
        return copy.deepcopy(system_state) if isinstance(system_state, dict) else {}

    def _system_algorithm(self, state: Mapping[str, Any]) -> Optional[str]:
        for key in ("algorithm", "selected_algorithm", "encryption_algorithm"):
            value = state.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()

        encryption = state.get("encryption")
        if isinstance(encryption, Mapping):
            for key in ("algorithm", "selected_algorithm"):
                value = encryption.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()

        return None

    def _system_key_rotation_days(self, state: Mapping[str, Any]) -> Optional[int]:
        for key in ("key_rotation_days", "key_rotation"):
            value = state.get(key)
            parsed = self._parse_duration_days(value)
            if parsed is not None:
                return parsed

        encryption = state.get("encryption")
        if isinstance(encryption, Mapping):
            for key in ("key_rotation_days", "key_rotation"):
                parsed = self._parse_duration_days(encryption.get(key))
                if parsed is not None:
                    return parsed

        return None

    def _rotation_from_metadata(self, metadata: Mapping[str, Any]) -> Optional[int]:
        if not isinstance(metadata, Mapping):
            return None
        key_management = metadata.get("key_management")
        if isinstance(key_management, Mapping):
            return self._parse_duration_days(key_management.get("rotation_policy"))
        return None

    def _access_state(self, state: Mapping[str, Any]) -> dict[str, Any]:
        access = state.get("access_controls") or state.get("access_control") or {}
        if isinstance(access, Mapping):
            return dict(access)
        return {"least_privilege": bool(access)}

    def _logging_state(self, state: Mapping[str, Any]) -> dict[str, Any]:
        logging_state = state.get("logging") or state.get("audit_logging") or {}
        if isinstance(logging_state, Mapping):
            return dict(logging_state)
        return {"all_required_events_logged": bool(logging_state)}

    def _policy_requires_access_control(self, action: Action, active_rule: PolicyRule | None) -> bool:
        if self._has_access_control_requirement(action):
            return True
        if active_rule is not None and self._has_access_control_requirement(active_rule.action):
            return True
        return True

    def _policy_requires_logging(self, action: Action, active_rule: PolicyRule | None) -> bool:
        if self._has_logging_requirement(action):
            return True
        if active_rule is not None and self._has_logging_requirement(active_rule.action):
            return True
        return True

    def _has_access_control_requirement(self, action: Action) -> bool:
        metadata = action.metadata if isinstance(action.metadata, Mapping) else {}
        access_metadata = metadata.get("access_control") if isinstance(metadata, Mapping) else None
        if isinstance(access_metadata, Mapping) and bool(access_metadata.get("least_privilege", False)):
            return True
        lower_tags = {tag.lower() for tag in action.compliance}
        return bool(lower_tags & ACCESS_TAGS)

    def _has_logging_requirement(self, action: Action) -> bool:
        metadata = action.metadata if isinstance(action.metadata, Mapping) else {}
        logging_metadata = metadata.get("logging") if isinstance(metadata, Mapping) else None
        if isinstance(logging_metadata, Mapping) and bool(logging_metadata.get("all_required_events_logged", False)):
            return True
        lower_tags = {tag.lower() for tag in action.compliance}
        return bool(lower_tags & LOGGING_TAGS)

    def _parse_duration_days(self, value: Any) -> Optional[int]:
        if value is None:
            return None
        if isinstance(value, int):
            return max(0, value)
        if isinstance(value, str):
            text = value.strip().lower()
            match = re.fullmatch(r"(\d+)([dhmw])", text)
            if not match:
                return None
            amount = int(match.group(1))
            unit = match.group(2)
            if unit == "d":
                return amount
            if unit == "h":
                return max(0, amount // 24)
            if unit == "w":
                return amount * 7
            if unit == "m":
                return max(1, amount // 1440)
        return None

    def _rule_label(self, rule: PolicyRule | None) -> str:
        if rule is None:
            return "default_action"
        return f"rule:{rule.condition.field}:{rule.condition.operator.value}"


__all__ = [
    "Violation",
    "ComplianceCheck",
    "Effectiveness",
    "PolicyVersionRecord",
    "PolicyComplianceChecker",
]