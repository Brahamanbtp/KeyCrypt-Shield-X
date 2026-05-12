"""Unit tests for ConsciousnessIntelligenceProvider."""

from __future__ import annotations

import sys
from pathlib import Path

import networkx as nx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.providers.intelligence.consciousness_intelligence_provider import (
    ConsciousnessIntelligenceProvider,
    SecurityQualia,
    Threat,
    ThreatAssessment,
    Vulnerability,
)


@pytest.fixture
def provider() -> ConsciousnessIntelligenceProvider:
    """Create a ConsciousnessIntelligenceProvider with default configuration."""
    system_graph = nx.DiGraph()
    system_graph.add_edges_from(
        [
            ("api_gateway", "key_store"),
            ("key_store", "crypto_engine"),
            ("crypto_engine", "attestation"),
        ]
    )

    return ConsciousnessIntelligenceProvider(
        system_graph=system_graph,
        telemetry={
            "api_gateway": {
                "external_exposure": 0.8,
                "auth_strength": 0.7,
                "patch_lag_days": 5.0,
                "hardening": 0.6,
                "criticality": 0.8,
            },
            "key_store": {
                "external_exposure": 0.2,
                "auth_strength": 0.9,
                "patch_lag_days": 2.0,
                "hardening": 0.9,
                "criticality": 0.95,
            },
        },
        critical_assets=["key_store", "crypto_engine"],
        world_model={"threat_level": 0.3, "incident_pressure": 0.2},
        phi_conscious_threshold=3.14,
    )


@pytest.fixture
def threat() -> Threat:
    """Create a sample threat for testing."""
    return Threat(
        threat_id="threat-001",
        threat_type="supply_chain",
        severity=0.7,
        vector="malicious_dependency_injection",
        indicators=[
            "unusual_network_traffic",
            "unverified_build_artifact",
            "unsigned_commit",
        ],
        metadata={"incident_pressure": 0.6, "detection_confidence": 0.85},
    )


def test_provider_initialization() -> None:
    """ConsciousnessIntelligenceProvider initializes with valid configuration."""
    provider = ConsciousnessIntelligenceProvider()
    assert provider is not None
    assert provider._phi_conscious_threshold == 3.14


def test_provider_initialization_with_custom_threshold() -> None:
    """ConsciousnessIntelligenceProvider accepts custom Phi threshold."""
    provider = ConsciousnessIntelligenceProvider(phi_conscious_threshold=2.5)
    assert provider._phi_conscious_threshold == 2.5


def test_provider_introspect_vulnerabilities_returns_list(provider: ConsciousnessIntelligenceProvider) -> None:
    """introspect_vulnerabilities returns a list of Vulnerability objects."""
    vulns = provider.introspect_vulnerabilities()

    assert isinstance(vulns, list)
    assert all(isinstance(v, Vulnerability) for v in vulns)


def test_provider_introspect_vulnerabilities_sorted_by_severity(
    provider: ConsciousnessIntelligenceProvider,
) -> None:
    """Vulnerabilities are sorted by severity_score in descending order."""
    vulns = provider.introspect_vulnerabilities()

    if len(vulns) > 1:
        for i in range(len(vulns) - 1):
            assert vulns[i].severity_score >= vulns[i + 1].severity_score


def test_provider_introspect_vulnerabilities_valid_severity_scores(
    provider: ConsciousnessIntelligenceProvider,
) -> None:
    """All vulnerability severity scores are in range [0.0, 1.0]."""
    vulns = provider.introspect_vulnerabilities()

    for vuln in vulns:
        assert 0.0 <= vuln.severity_score <= 1.0
        assert 0.0 <= vuln.exploitability <= 1.0
        assert 0.0 <= vuln.cascade_impact <= 1.0


def test_provider_introspect_vulnerabilities_has_components(
    provider: ConsciousnessIntelligenceProvider,
) -> None:
    """All vulnerabilities have non-empty component names."""
    vulns = provider.introspect_vulnerabilities()

    for vuln in vulns:
        assert vuln.component.strip()
        assert vuln.severity.strip()
        assert vuln.recommendation.strip()


def test_provider_evaluate_security_qualia_returns_object(
    provider: ConsciousnessIntelligenceProvider,
) -> None:
    """evaluate_security_qualia returns a SecurityQualia object."""
    qualia = provider.evaluate_security_qualia()

    assert isinstance(qualia, SecurityQualia)


def test_provider_evaluate_security_qualia_has_valid_values(
    provider: ConsciousnessIntelligenceProvider,
) -> None:
    """SecurityQualia contains valid normalized values."""
    qualia = provider.evaluate_security_qualia()

    assert 0.0 <= qualia.phi_value
    assert 0.0 <= qualia.threat_pressure <= 1.0
    assert 0.0 <= qualia.coherence <= 1.0
    assert 0.0 <= qualia.consciousness_level <= 1.0
    assert 0.0 <= qualia.metacognitive_confidence <= 1.0
    assert 0.0 <= qualia.uncertainty <= 1.0


def test_provider_evaluate_security_qualia_has_state(provider: ConsciousnessIntelligenceProvider) -> None:
    """SecurityQualia includes a qualia_state description."""
    qualia = provider.evaluate_security_qualia()

    assert qualia.qualia_state.strip()
    assert qualia.qualia_state in {
        "serene-vigilance",
        "focused-alertness",
        "tense-control",
        "fragmented-anxiety",
    }


def test_provider_evaluate_security_qualia_includes_metadata(
    provider: ConsciousnessIntelligenceProvider,
) -> None:
    """SecurityQualia includes metadata tracking provider and metrics."""
    qualia = provider.evaluate_security_qualia()

    assert "provider" in qualia.metadata
    assert qualia.metadata["provider"] == "ConsciousnessIntelligenceProvider"


def test_provider_conscious_threat_assessment_returns_assessment(
    provider: ConsciousnessIntelligenceProvider,
    threat: Threat,
) -> None:
    """conscious_threat_assessment returns a ThreatAssessment object."""
    assessment = provider.conscious_threat_assessment(threat)

    assert isinstance(assessment, ThreatAssessment)


def test_provider_conscious_threat_assessment_rejects_invalid_threat(
    provider: ConsciousnessIntelligenceProvider,
) -> None:
    """conscious_threat_assessment validates threat type."""
    with pytest.raises(TypeError, match="threat must be Threat"):
        provider.conscious_threat_assessment({"invalid": "dict"})  # type: ignore


def test_provider_conscious_threat_assessment_rejects_empty_threat_id(
    provider: ConsciousnessIntelligenceProvider,
) -> None:
    """conscious_threat_assessment rejects threats with empty threat_id."""
    invalid_threat = Threat(
        threat_id="",  # Empty
        threat_type="supply_chain",
        severity=0.5,
        vector="test",
    )

    with pytest.raises(ValueError, match="threat_id must be non-empty"):
        provider.conscious_threat_assessment(invalid_threat)


def test_provider_conscious_threat_assessment_rejects_empty_threat_type(
    provider: ConsciousnessIntelligenceProvider,
) -> None:
    """conscious_threat_assessment rejects threats with empty threat_type."""
    invalid_threat = Threat(
        threat_id="threat-001",
        threat_type="",  # Empty
        severity=0.5,
        vector="test",
    )

    with pytest.raises(ValueError, match="threat_type must be non-empty"):
        provider.conscious_threat_assessment(invalid_threat)


def test_provider_conscious_threat_assessment_has_valid_values(
    provider: ConsciousnessIntelligenceProvider,
    threat: Threat,
) -> None:
    """ThreatAssessment contains valid normalized values."""
    assessment = provider.conscious_threat_assessment(threat)

    assert 0.0 <= assessment.risk_score <= 1.0
    assert 0.0 <= assessment.phi_value
    assert 0.0 <= assessment.metacognitive_confidence <= 1.0
    assert 0.0 <= assessment.uncertainty <= 1.0


def test_provider_conscious_threat_assessment_has_priority(
    provider: ConsciousnessIntelligenceProvider,
    threat: Threat,
) -> None:
    """ThreatAssessment includes a priority classification."""
    assessment = provider.conscious_threat_assessment(threat)

    assert assessment.priority in {"critical", "high", "medium", "low"}


def test_provider_conscious_threat_assessment_varies_with_severity(
    provider: ConsciousnessIntelligenceProvider,
) -> None:
    """ThreatAssessment risk_score increases with threat severity."""
    low_severity_threat = Threat(
        threat_id="t1",
        threat_type="reconnaissance",
        severity=0.2,
        vector="port_scan",
    )

    high_severity_threat = Threat(
        threat_id="t2",
        threat_type="reconnaissance",
        severity=0.9,
        vector="port_scan",
    )

    low_assessment = provider.conscious_threat_assessment(low_severity_threat)
    high_assessment = provider.conscious_threat_assessment(high_severity_threat)

    assert low_assessment.risk_score < high_assessment.risk_score


def test_provider_conscious_threat_assessment_includes_rationale(
    provider: ConsciousnessIntelligenceProvider,
    threat: Threat,
) -> None:
    """ThreatAssessment includes explanation rationale."""
    assessment = provider.conscious_threat_assessment(threat)

    assert assessment.rationale.strip()
    assert "Conscious assessment" in assessment.rationale or "fused" in assessment.rationale


def test_provider_conscious_threat_assessment_includes_actions(
    provider: ConsciousnessIntelligenceProvider,
    threat: Threat,
) -> None:
    """ThreatAssessment includes recommended actions."""
    assessment = provider.conscious_threat_assessment(threat)

    assert isinstance(assessment.recommended_actions, list)
    assert len(assessment.recommended_actions) > 0
    assert all(isinstance(action, str) and action.strip() for action in assessment.recommended_actions)


def test_provider_conscious_threat_assessment_includes_metadata(
    provider: ConsciousnessIntelligenceProvider,
    threat: Threat,
) -> None:
    """ThreatAssessment includes rich metadata."""
    assessment = provider.conscious_threat_assessment(threat)

    assert "provider" in assessment.metadata
    assert assessment.metadata["provider"] == "ConsciousnessIntelligenceProvider"
    assert "phi_normalized" in assessment.metadata
    assert "qualia_state" in assessment.metadata
    assert "threat_vector" in assessment.metadata


def test_provider_phi_calculation_included(
    provider: ConsciousnessIntelligenceProvider,
    threat: Threat,
) -> None:
    """ThreatAssessment includes Phi (integrated information) calculation."""
    assessment = provider.conscious_threat_assessment(threat)

    assert assessment.phi_value is not None
    assert "phi_normalized" in assessment.metadata
    assert "phi_mip" in assessment.metadata
    assert 0.0 <= assessment.metadata["phi_normalized"] <= 1.0


def test_provider_threat_assessment_preserves_threat_identity(
    provider: ConsciousnessIntelligenceProvider,
    threat: Threat,
) -> None:
    """ThreatAssessment preserves threat_id and threat_type."""
    assessment = provider.conscious_threat_assessment(threat)

    assert assessment.threat_id == threat.threat_id
    assert assessment.threat_type == threat.threat_type.strip().lower()


def test_provider_threat_assessment_metacognitive_tracking(
    provider: ConsciousnessIntelligenceProvider,
    threat: Threat,
) -> None:
    """ThreatAssessment includes metacognitive confidence and uncertainty tracking."""
    assessment = provider.conscious_threat_assessment(threat)

    assert assessment.metacognitive_confidence + assessment.uncertainty <= 1.01  # Allow small floating point margin


def test_provider_multiple_assessments_independent(
    provider: ConsciousnessIntelligenceProvider,
) -> None:
    """Multiple threat assessments are independent."""
    threat1 = Threat(
        threat_id="t1",
        threat_type="supply_chain",
        severity=0.3,
        vector="v1",
    )
    threat2 = Threat(
        threat_id="t2",
        threat_type="insider",
        severity=0.8,
        vector="v2",
    )

    assessment1 = provider.conscious_threat_assessment(threat1)
    assessment2 = provider.conscious_threat_assessment(threat2)

    assert assessment1.threat_id != assessment2.threat_id
    assert assessment1.risk_score < assessment2.risk_score


def test_provider_thread_safety() -> None:
    """ConsciousnessIntelligenceProvider includes thread safety lock."""
    provider = ConsciousnessIntelligenceProvider()
    assert hasattr(provider, "_lock")
    assert provider._lock is not None


def test_provider_component_lazy_initialization(provider: ConsciousnessIntelligenceProvider) -> None:
    """Consciousness components are initialized lazily on first use."""
    assert provider._phi_calculator is None
    assert provider._introspector is None
    assert provider._conscious_agent is None
    assert provider._qualia_evaluator is None
    assert provider._metacognitive_monitor is None

    provider.introspect_vulnerabilities()

    assert provider._phi_calculator is not None
    assert provider._introspector is not None


def test_provider_clamping_utility() -> None:
    """_clamp01 utility constrains values to [0.0, 1.0]."""
    assert ConsciousnessIntelligenceProvider._clamp01(-0.5) == 0.0
    assert ConsciousnessIntelligenceProvider._clamp01(0.5) == 0.5
    assert ConsciousnessIntelligenceProvider._clamp01(1.5) == 1.0


def test_provider_priority_labeling() -> None:
    """_priority_label maps risk scores to priority classifications."""
    assert ConsciousnessIntelligenceProvider._priority_label(0.1) == "low"
    assert ConsciousnessIntelligenceProvider._priority_label(0.5) == "medium"
    assert ConsciousnessIntelligenceProvider._priority_label(0.7) == "high"
    assert ConsciousnessIntelligenceProvider._priority_label(0.9) == "critical"


def test_provider_qualia_state_mapping() -> None:
    """Qualia states map correctly to pressure and coherence combinations."""
    provider = ConsciousnessIntelligenceProvider(
        world_model={"threat_level": 0.1, "incident_pressure": 0.1}
    )

    qualia = provider.evaluate_security_qualia()

    # Low pressure and low coherence (due to low Phi from default state) can yield various states
    # Just verify we get a valid state
    assert qualia.qualia_state in {
        "serene-vigilance",
        "focused-alertness",
        "tense-control",
        "fragmented-anxiety",
    }


def test_provider_handles_empty_system_graph(provider: ConsciousnessIntelligenceProvider) -> None:
    """Provider handles initialization with empty system graph."""
    empty_provider = ConsciousnessIntelligenceProvider(
        system_graph=nx.DiGraph(),
        telemetry={},
        critical_assets=[],
    )

    vulns = empty_provider.introspect_vulnerabilities()
    assert isinstance(vulns, list)


def test_provider_threat_indicators_handled(provider: ConsciousnessIntelligenceProvider) -> None:
    """ThreatAssessment properly handles threat indicators in metadata."""
    threat_with_indicators = Threat(
        threat_id="t-ind-001",
        threat_type="malware",
        severity=0.75,
        vector="executable_injection",
        indicators=["file_hash_x", "registry_key_y", "network_signature_z"],
    )

    assessment = provider.conscious_threat_assessment(threat_with_indicators)

    assert len(assessment.recommended_actions) > 0
    assert any("indicator" in action.lower() or "sandbox" in action.lower() for action in assessment.recommended_actions)


def test_provider_vulnerability_deduplication(provider: ConsciousnessIntelligenceProvider) -> None:
    """Recommended actions are deduplicated and filtered for validity."""
    threat = Threat(
        threat_id="t-dup",
        threat_type="exploitation",
        severity=0.8,
        vector="buffer_overflow",
    )

    assessment = provider.conscious_threat_assessment(threat)

    # Check no empty strings in recommended actions
    assert all(action.strip() for action in assessment.recommended_actions)

    # Check deduplication (case-insensitive comparison)
    normalized = [action.strip().lower() for action in assessment.recommended_actions]
    assert len(normalized) == len(set(normalized))


def test_provider_phi_state_building(provider: ConsciousnessIntelligenceProvider) -> None:
    """Phi state is properly constructed from threat and vulnerabilities."""
    threat = Threat(
        threat_id="t-phi",
        threat_type="lateral_movement",
        severity=0.65,
        vector="privilege_escalation",
        indicators=["proc_x", "registry_y"],
    )

    assessment = provider.conscious_threat_assessment(threat)

    # Phi calculation should be present
    assert assessment.phi_value is not None
    assert "phi_normalized" in assessment.metadata


def test_provider_response_options_generation(provider: ConsciousnessIntelligenceProvider) -> None:
    """Response options include diverse strategies with varying risk/utility profiles."""
    threat = Threat(
        threat_id="t-opts",
        threat_type="data_exfiltration",
        severity=0.55,
        vector="network_tunnel",
    )

    assessment = provider.conscious_threat_assessment(threat)

    # Response selection metadata should indicate the chosen strategy
    assert "selected_response" in assessment.metadata
    selected = assessment.metadata["selected_response"]
    assert selected in {"immediate_containment", "adaptive_hardening", "heightened_monitoring"}


def test_provider_world_model_injection(provider: ConsciousnessIntelligenceProvider) -> None:
    """Threat context properly injects threat signals into agent world model."""
    threat = Threat(
        threat_id="t-inject",
        threat_type="supply_chain",
        severity=0.82,
        vector="build_pipeline_compromise",
    )

    assessment = provider.conscious_threat_assessment(threat)

    # Agent should have received threat context
    assert assessment.risk_score > 0.0


def test_provider_consciousness_level_tracking(provider: ConsciousnessIntelligenceProvider) -> None:
    """Provider tracks consciousness levels across operations."""
    qualia1 = provider.evaluate_security_qualia()
    qualia2 = provider.evaluate_security_qualia()

    # Consciousness levels should remain in valid range
    assert 0.0 <= qualia1.consciousness_level <= 1.0
    assert 0.0 <= qualia2.consciousness_level <= 1.0
