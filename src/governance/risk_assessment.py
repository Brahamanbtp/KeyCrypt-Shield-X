"""Automated risk assessment framework.

PRESERVE: Risk management framework
EXTEND: Automated risk assessment

Provides encryption-risk assessment, residual risk calculation, a risk register,
mitigation recommendations, prioritization, and a simple heat map visualization.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import logging

LOG = logging.getLogger(__name__)


@dataclass
class Control:
    name: str
    effectiveness: float  # 0.0 to 1.0
    description: Optional[str] = None


@dataclass
class Mitigation:
    control: str
    description: str
    expected_risk_reduction: float  # 0.0 to 1.0


@dataclass
class DataProfile:
    data_id: str
    sensitivity: int  # 1-5
    threat_landscape: int  # 1-5
    controls: List[Control] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Risk:
    risk_id: str
    title: str
    likelihood: int  # 1-5
    impact: int  # 1-5
    description: str
    mitigations: List[Mitigation] = field(default_factory=list)
    residual_risk: Optional[float] = None

    @property
    def score(self) -> int:
        return self.likelihood * self.impact


@dataclass
class RiskAssessment:
    assessed_at: datetime
    data_profile: DataProfile
    inherent_risk: float
    residual_risk: float
    risks: List[Risk]
    notes: List[str] = field(default_factory=list)


@dataclass
class RiskRegister:
    generated_at: datetime
    risks: List[Risk]
    summary: Dict[str, Any]
    heat_map: List[List[int]] = field(default_factory=list)


def _clamp_score(value: float) -> float:
    return max(0.0, min(25.0, value))


def _normalize_rating(value: Any, default: int = 1) -> int:
    try:
        rating = int(value)
    except Exception:
        return default
    return max(1, min(5, rating))


def calculate_residual_risk(inherent_risk: float, controls: List[Control]) -> float:
    """Calculate residual risk after applying security controls.

    Control effectiveness is combined multiplicatively to preserve diminishing
    returns. The result is constrained to the 0-25 risk-score range.
    """
    remaining = float(inherent_risk)
    for control in controls:
        effectiveness = max(0.0, min(1.0, control.effectiveness))
        remaining *= (1.0 - effectiveness)
    return _clamp_score(remaining)


def recommend_mitigations(risk: Risk) -> List[Mitigation]:
    """Suggest mitigations that would reduce the given risk."""
    recommendations: List[Mitigation] = []

    if risk.likelihood >= 4:
        recommendations.append(
            Mitigation(
                control="monitoring_and_alerting",
                description="Increase continuous monitoring, alerting, and anomaly detection.",
                expected_risk_reduction=0.20,
            )
        )
    if risk.impact >= 4:
        recommendations.append(
            Mitigation(
                control="strong_encryption",
                description="Apply stronger encryption, tighter key management, and access restrictions.",
                expected_risk_reduction=0.25,
            )
        )
    if risk.score >= 16:
        recommendations.append(
            Mitigation(
                control="segmentation_and_least_privilege",
                description="Segment the data path and reduce exposed privileges to shrink blast radius.",
                expected_risk_reduction=0.30,
            )
        )
    if not recommendations:
        recommendations.append(
            Mitigation(
                control="periodic_review",
                description="Review the risk periodically and validate existing controls remain effective.",
                expected_risk_reduction=0.10,
            )
        )
    return recommendations


def assess_encryption_risk(data_profile: DataProfile) -> RiskAssessment:
    """Evaluate encryption risk based on sensitivity, threat landscape, and controls."""
    sensitivity = _normalize_rating(data_profile.sensitivity, default=1)
    threat = _normalize_rating(data_profile.threat_landscape, default=1)

    inherent_risk = float(sensitivity * threat)
    residual_risk = calculate_residual_risk(inherent_risk, data_profile.controls)

    title = f"Encryption risk for {data_profile.data_id}"
    risk = Risk(
        risk_id=f"risk-{data_profile.data_id}",
        title=title,
        likelihood=threat,
        impact=sensitivity,
        description="Risk arising from data sensitivity, external threat exposure, and current controls.",
        mitigations=[],
        residual_risk=residual_risk,
    )
    risk.mitigations = recommend_mitigations(risk)

    notes = []
    if sensitivity >= 4:
        notes.append("High-sensitivity data profile detected")
    if threat >= 4:
        notes.append("Threat landscape indicates elevated exposure")
    if not data_profile.controls:
        notes.append("No compensating controls provided")

    return RiskAssessment(
        assessed_at=datetime.utcnow(),
        data_profile=data_profile,
        inherent_risk=_clamp_score(inherent_risk),
        residual_risk=residual_risk,
        risks=[risk],
        notes=notes,
    )


def prioritize_risks(risks: List[Risk]) -> List[Risk]:
    """Sort risks by severity × likelihood, highest first."""
    return sorted(risks, key=lambda item: (item.score, item.impact, item.likelihood), reverse=True)


def generate_risk_register() -> RiskRegister:
    """Document identified risks with scores, mitigations, and summary metrics."""
    sample_risks = [
        Risk(
            risk_id="risk-encryption-key-exposure",
            title="Key exposure",
            likelihood=4,
            impact=5,
            description="Encryption keys are not adequately protected or rotated.",
        ),
        Risk(
            risk_id="risk-weak-transit-encryption",
            title="Weak transit encryption",
            likelihood=3,
            impact=4,
            description="Data in transit may traverse channels without strong TLS enforcement.",
        ),
        Risk(
            risk_id="risk-unmonitored-access",
            title="Unmonitored access",
            likelihood=4,
            impact=3,
            description="Access events are not being tracked and monitored consistently.",
        ),
    ]

    prioritized = prioritize_risks(sample_risks)
    for risk in prioritized:
        risk.mitigations = recommend_mitigations(risk)

    heat_map = risk_heat_map_matrix(prioritized)
    summary = {
        "risk_count": len(prioritized),
        "highest_score": max((risk.score for risk in prioritized), default=0),
        "average_score": sum(risk.score for risk in prioritized) / len(prioritized) if prioritized else 0.0,
        "generated_by": "automated",
    }

    return RiskRegister(
        generated_at=datetime.utcnow(),
        risks=prioritized,
        summary=summary,
        heat_map=heat_map,
    )


def risk_heat_map_matrix(risks: Sequence[Risk]) -> List[List[int]]:
    """Build a 5x5 heat map matrix where cells count risk occurrences."""
    matrix = [[0 for _ in range(5)] for _ in range(5)]
    for risk in risks:
        likelihood_idx = max(1, min(5, risk.likelihood)) - 1
        impact_idx = max(1, min(5, risk.impact)) - 1
        matrix[impact_idx][likelihood_idx] += 1
    return matrix


def render_risk_heat_map(risks: Sequence[Risk]) -> str:
    """Render a text-based heat map visualization for environments without plotting libraries."""
    matrix = risk_heat_map_matrix(risks)
    header = ["    L1", "L2", "L3", "L4", "L5"]
    lines = ["Risk Heat Map (rows=impact, cols=likelihood)", "        " + " ".join(header[1:])]
    for impact in range(5, 0, -1):
        row = matrix[impact - 1]
        cells = " ".join(f"{value:>3}" for value in row)
        lines.append(f"I{impact}  {cells}")
    return "\n".join(lines)


def plot_risk_heat_map(risks: Sequence[Risk]):
    """Return a matplotlib figure when matplotlib is available, otherwise None."""
    try:
        import matplotlib.pyplot as plt  # type: ignore
    except Exception:
        return None

    matrix = risk_heat_map_matrix(risks)
    fig, ax = plt.subplots(figsize=(6, 5))
    ax.imshow(matrix, cmap="YlOrRd", origin="lower")
    ax.set_xticks(range(5))
    ax.set_yticks(range(5))
    ax.set_xticklabels(["1", "2", "3", "4", "5"])
    ax.set_yticklabels(["1", "2", "3", "4", "5"])
    ax.set_xlabel("Likelihood")
    ax.set_ylabel("Impact")
    ax.set_title("Risk Heat Map")

    for y, row in enumerate(matrix):
        for x, value in enumerate(row):
            ax.text(x, y, str(value), ha="center", va="center", color="black")

    fig.tight_layout()
    return fig


_DEFAULT_RISK_REGISTER = generate_risk_register()


__all__ = [
    "Control",
    "Mitigation",
    "DataProfile",
    "Risk",
    "RiskAssessment",
    "RiskRegister",
    "assess_encryption_risk",
    "calculate_residual_risk",
    "generate_risk_register",
    "prioritize_risks",
    "recommend_mitigations",
    "risk_heat_map_matrix",
    "render_risk_heat_map",
    "plot_risk_heat_map",
]
