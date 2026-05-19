"""Role-based and attribute-based access control policies.

PRESERVE: Access governance
EXTEND: Authorization policy management

Provides RBAC role assignment, permission grants, ABAC rule evaluation, and
decision auditing for governance and authorization workflows.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional


class Role(str, Enum):
    VIEWER = "Viewer"
    OPERATOR = "Operator"
    KEY_MANAGER = "Key Manager"
    SECURITY_ADMIN = "Security Admin"
    AUDITOR = "Auditor"
    SUPER_ADMIN = "Super Admin"


@dataclass
class AccessDecision:
    timestamp: datetime
    user_id: str
    resource: str
    action: str
    allowed: bool
    reason: str
    role: Optional[str] = None


@dataclass
class AccessAuditReport:
    generated_at: datetime
    total_decisions: int
    granted: int
    denied: int
    decisions: List[AccessDecision] = field(default_factory=list)


@dataclass
class ABACRule:
    resource: str
    action: str
    condition: Callable[[Dict[str, Any], Dict[str, Any]], bool]
    description: Optional[str] = None


class AccessControlManager:
    """In-memory RBAC + ABAC authorization manager."""

    def __init__(self) -> None:
        self._user_roles: Dict[str, List[str]] = {}
        self._role_permissions: Dict[str, Dict[str, List[str]]] = {}
        self._user_attributes: Dict[str, Dict[str, Any]] = {}
        self._resource_attributes: Dict[str, Dict[str, Any]] = {}
        self._abac_rules: List[ABACRule] = []
        self._audit_log: List[AccessDecision] = []
        self._seed_default_roles()

    def _seed_default_roles(self) -> None:
        self._role_permissions = {
            Role.VIEWER.value: {
                "encrypted_data_metadata": ["read"],
            },
            Role.OPERATOR.value: {
                "encrypted_data": ["encrypt", "decrypt", "read"],
            },
            Role.KEY_MANAGER.value: {
                "keys": ["generate", "rotate", "delete", "read"],
            },
            Role.SECURITY_ADMIN.value: {
                "security_policy": ["configure", "read", "update"],
            },
            Role.AUDITOR.value: {
                "audit_logs": ["read"],
            },
            Role.SUPER_ADMIN.value: {
                "*": ["*"],
            },
        }

        # Baseline ABAC rules for fine-grained control.
        self._abac_rules = [
            ABACRule(
                resource="encrypted_data",
                action="decrypt",
                condition=lambda user, resource: bool(user.get("mfa_enabled")) and user.get("clearance", 0) >= resource.get("classification_level", 0),
                description="Require MFA and sufficient clearance for decrypt operations.",
            ),
            ABACRule(
                resource="keys",
                action="rotate",
                condition=lambda user, resource: user.get("department") == "security" or user.get("role") == Role.KEY_MANAGER.value,
                description="Restrict key rotation to security staff and key managers.",
            ),
            ABACRule(
                resource="audit_logs",
                action="read",
                condition=lambda user, resource: user.get("role") in {Role.AUDITOR.value, Role.SUPER_ADMIN.value},
                description="Audit log read access is limited to auditors and super admins.",
            ),
        ]

    def assign_role(self, user_id: str, role: str) -> None:
        if role not in self._role_permissions:
            raise ValueError(f"Unknown role: {role}")
        roles = self._user_roles.setdefault(user_id, [])
        if role not in roles:
            roles.append(role)

        attrs = self._user_attributes.setdefault(user_id, {})
        attrs["role"] = role

    def grant_permission(self, role: str, resource: str, actions: List[str]) -> None:
        if role not in self._role_permissions:
            self._role_permissions[role] = {}
        permissions = self._role_permissions[role].setdefault(resource, [])
        for action in actions:
            if action not in permissions:
                permissions.append(action)

    def set_user_attributes(self, user_id: str, attributes: Dict[str, Any]) -> None:
        current = self._user_attributes.setdefault(user_id, {})
        current.update(attributes)

    def set_resource_attributes(self, resource: str, attributes: Dict[str, Any]) -> None:
        current = self._resource_attributes.setdefault(resource, {})
        current.update(attributes)

    def add_abac_rule(
        self,
        resource: str,
        action: str,
        condition: Callable[[Dict[str, Any], Dict[str, Any]], bool],
        description: Optional[str] = None,
    ) -> None:
        self._abac_rules.append(ABACRule(resource=resource, action=action, condition=condition, description=description))

    def check_permission(self, user_id: str, resource: str, action: str) -> bool:
        user_attrs = dict(self._user_attributes.get(user_id, {}))
        resource_attrs = dict(self._resource_attributes.get(resource, {}))
        roles = list(self._user_roles.get(user_id, []))

        if not roles:
            self._record_decision(user_id, resource, action, False, "no roles assigned")
            return False

        user_attrs.setdefault("roles", roles)

        # RBAC evaluation: role permission grant first
        for role in roles:
            permissions = self._role_permissions.get(role, {})
            if self._action_allowed_by_rbac(permissions, resource, action):
                if self._abac_allows(user_attrs, resource_attrs, resource, action, role):
                    self._record_decision(user_id, resource, action, True, "granted by RBAC and ABAC", role)
                    return True
                self._record_decision(user_id, resource, action, False, "ABAC denied", role)
                return False

        self._record_decision(user_id, resource, action, False, "RBAC denied")
        return False

    def audit_access_decisions(self) -> AccessAuditReport:
        granted = sum(1 for d in self._audit_log if d.allowed)
        denied = len(self._audit_log) - granted
        return AccessAuditReport(
            generated_at=datetime.utcnow(),
            total_decisions=len(self._audit_log),
            granted=granted,
            denied=denied,
            decisions=list(self._audit_log),
        )

    def _action_allowed_by_rbac(self, permissions: Dict[str, List[str]], resource: str, action: str) -> bool:
        if "*" in permissions and "*" in permissions["*"]:
            return True
        if resource in permissions and action in permissions[resource]:
            return True
        if "*" in permissions and action in permissions["*"]:
            return True
        return False

    def _abac_allows(
        self,
        user_attrs: Dict[str, Any],
        resource_attrs: Dict[str, Any],
        resource: str,
        action: str,
        role: str,
    ) -> bool:
        # Role-driven privilege always passes when Super Admin is explicitly present.
        if role == Role.SUPER_ADMIN.value:
            return True

        for rule in self._abac_rules:
            if rule.resource == resource and rule.action == action:
                if not rule.condition(user_attrs, resource_attrs):
                    return False

        # Fine-grained constraints can be supplied in resource attributes.
        required_tags = set(resource_attrs.get("required_tags", []))
        user_tags = set(user_attrs.get("tags", []))
        if required_tags and not required_tags.issubset(user_tags):
            return False

        return True

    def _record_decision(
        self,
        user_id: str,
        resource: str,
        action: str,
        allowed: bool,
        reason: str,
        role: Optional[str] = None,
    ) -> None:
        self._audit_log.append(
            AccessDecision(
                timestamp=datetime.utcnow(),
                user_id=user_id,
                resource=resource,
                action=action,
                allowed=allowed,
                reason=reason,
                role=role,
            )
        )


_DEFAULT_MANAGER = AccessControlManager()


def assign_role(user_id: str, role: str) -> None:
    _DEFAULT_MANAGER.assign_role(user_id, role)


def grant_permission(role: str, resource: str, actions: List[str]) -> None:
    _DEFAULT_MANAGER.grant_permission(role, resource, actions)


def check_permission(user_id: str, resource: str, action: str) -> bool:
    return _DEFAULT_MANAGER.check_permission(user_id, resource, action)


def audit_access_decisions() -> AccessAuditReport:
    return _DEFAULT_MANAGER.audit_access_decisions()


def set_user_attributes(user_id: str, attributes: Dict[str, Any]) -> None:
    _DEFAULT_MANAGER.set_user_attributes(user_id, attributes)


def set_resource_attributes(resource: str, attributes: Dict[str, Any]) -> None:
    _DEFAULT_MANAGER.set_resource_attributes(resource, attributes)


def add_abac_rule(
    resource: str,
    action: str,
    condition: Callable[[Dict[str, Any], Dict[str, Any]], bool],
    description: Optional[str] = None,
) -> None:
    _DEFAULT_MANAGER.add_abac_rule(resource, action, condition, description)


__all__ = [
    "Role",
    "AccessDecision",
    "AccessAuditReport",
    "ABACRule",
    "AccessControlManager",
    "assign_role",
    "grant_permission",
    "check_permission",
    "audit_access_decisions",
    "set_user_attributes",
    "set_resource_attributes",
    "add_abac_rule",
]
