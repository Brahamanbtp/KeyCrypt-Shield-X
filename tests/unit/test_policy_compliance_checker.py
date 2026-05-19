import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.governance.incident_response import Incident
from src.governance.policy_compliance_checker import PolicyComplianceChecker
from src.policy.policy_schema import Policy


def build_policy() -> Policy:
    return Policy.model_validate(
        {
            "name": "baseline-policy",
            "version": "1.0",
            "default_action": {
                "algorithm": "aes-256-gcm",
                "key_rotation": "90d",
                "compliance": ["least-privilege", "audit-logging"],
                "metadata": {
                    "access_control": {"least_privilege": True},
                    "logging": {"all_required_events_logged": True},
                },
            },
            "rules": [
                {
                    "condition": {"field": "data_classification", "operator": "EQUALS", "value": "PHI"},
                    "action": {
                        "algorithm": "aes-256-gcm",
                        "key_rotation": "60d",
                        "compliance": ["hipaa", "least-privilege", "audit-logging"],
                        "metadata": {
                            "access_control": {"least_privilege": True},
                            "logging": {"all_required_events_logged": True},
                            "key_management": {"rotation_policy": "60d"},
                        },
                    },
                }
            ],
        }
    )


def test_check_policy_compliance_and_version_history():
    checker = PolicyComplianceChecker()
    policy = build_policy()

    check = checker.check_policy_compliance(
        policy,
        {
            "data_classification": "PHI",
            "algorithm": "aes-256-gcm",
            "key_rotation_days": 30,
            "access_controls": {"least_privilege": True},
            "logging": {"all_required_events_logged": True},
        },
    )

    assert check.compliant is True
    assert check.score == 100
    assert check.violations == []
    assert checker.get_policy_version_history("baseline-policy")


def test_identify_policy_violations_and_suggest_updates():
    checker = PolicyComplianceChecker()
    weak_policy = Policy.model_validate(
        {
            "name": "weak-policy",
            "version": "1.0",
            "default_action": {
                "algorithm": "des",
                "key_rotation": "400d",
                "compliance": [],
                "metadata": {},
            },
            "rules": [],
        }
    )

    violations = checker.identify_policy_violations(weak_policy)
    assert any(v.category == "encryption" for v in violations)
    assert any(v.category == "key_rotation" for v in violations)
    assert any(v.category == "access_control" for v in violations)
    assert any(v.category == "logging" for v in violations)

    updated = checker.suggest_policy_updates(
        weak_policy,
        ["Use approved encryption algorithms", "Rotate keys every 60 days", "least privilege", "audit logging"],
    )

    assert updated.version != weak_policy.version
    assert updated.default_action.algorithm == "aes-256-gcm"
    assert updated.default_action.key_rotation == "60d"
    assert "least-privilege" in [tag.lower() for tag in updated.default_action.compliance]


def test_validate_policy_effectiveness_against_incidents():
    checker = PolicyComplianceChecker()
    policy = build_policy()

    incidents = [
        Incident(
            id="INC-1",
            incident_type="data breach",
            description="breach caused by weak encryption",
            severity="high",
            detected_at=__import__("datetime").datetime.utcnow(),
            indicators={
                "data_classification": "PHI",
                "algorithm": "des",
                "key_rotation_days": 180,
                "access_controls": {"least_privilege": False},
                "logging": {"all_required_events_logged": False},
            },
        ),
        Incident(
            id="INC-2",
            incident_type="unauthorized access",
            description="access despite policy",
            severity="medium",
            detected_at=__import__("datetime").datetime.utcnow(),
            indicators={
                "data_classification": "PUBLIC",
                "algorithm": "aes-256-gcm",
                "key_rotation_days": 30,
                "access_controls": {"least_privilege": True},
                "logging": {"all_required_events_logged": True},
            },
        ),
    ]

    effectiveness = checker.validate_policy_effectiveness(policy, incidents)

    assert effectiveness.incidents_total == 2
    assert effectiveness.incidents_prevented >= 1
    assert 0 <= effectiveness.score <= 100