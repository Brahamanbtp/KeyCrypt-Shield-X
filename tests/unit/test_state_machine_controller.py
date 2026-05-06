"""Comprehensive tests for StateMachineController state transition logic."""

from __future__ import annotations

import pytest
from unittest.mock import Mock, MagicMock, call

from src.orchestration.state_machine_controller import (
    StateMachineController,
    SecurityMetrics,
    SecurityState,
)
from src.monitoring.security_events import SecurityEventLogger


@pytest.fixture
def mock_event_logger():
    """Create a mock SecurityEventLogger."""
    logger = Mock(spec=SecurityEventLogger)
    logger.log_security_state_change = Mock(return_value={})
    return logger


@pytest.fixture
def controller(mock_event_logger):
    """Create a StateMachineController with mock logger."""
    return StateMachineController(
        initial_state=SecurityState.NORMAL,
        event_logger=mock_event_logger,
        hysteresis_count=3,
    )


class TestTransitionRules:
    """Test each transition rule independently."""

    def test_transition_low_to_normal_when_risk_exceeds_threshold(self, mock_event_logger):
        """LOW -> NORMAL when risk_score > 0.3."""
        controller = StateMachineController(
            initial_state=SecurityState.LOW,
            event_logger=mock_event_logger,
            hysteresis_count=1,  # No hysteresis for basic test
        )

        # Below threshold - no transition
        metrics = SecurityMetrics(risk_score=0.25)
        result = controller.evaluate_state_transition(SecurityState.LOW, metrics)
        assert result == SecurityState.LOW

        # Above threshold - should transition
        metrics = SecurityMetrics(risk_score=0.35)
        result = controller.evaluate_state_transition(SecurityState.LOW, metrics)
        assert result == SecurityState.NORMAL
        mock_event_logger.log_security_state_change.assert_called()

    def test_transition_normal_to_elevated_by_risk_score(self, mock_event_logger):
        """NORMAL -> ELEVATED when risk_score > 0.6."""
        controller = StateMachineController(
            initial_state=SecurityState.NORMAL,
            event_logger=mock_event_logger,
            hysteresis_count=1,
        )

        # Below threshold - no transition
        metrics = SecurityMetrics(risk_score=0.55)
        result = controller.evaluate_state_transition(SecurityState.NORMAL, metrics)
        assert result == SecurityState.NORMAL

        # Above threshold - should transition
        metrics = SecurityMetrics(risk_score=0.65)
        result = controller.evaluate_state_transition(SecurityState.NORMAL, metrics)
        assert result == SecurityState.ELEVATED

    def test_transition_normal_to_elevated_by_failed_auth(self, mock_event_logger):
        """NORMAL -> ELEVATED when failed_auth > 10."""
        controller = StateMachineController(
            initial_state=SecurityState.NORMAL,
            event_logger=mock_event_logger,
            hysteresis_count=1,
        )

        # Below threshold - no transition
        metrics = SecurityMetrics(risk_score=0.1, failed_auth=8)
        result = controller.evaluate_state_transition(SecurityState.NORMAL, metrics)
        assert result == SecurityState.NORMAL

        # Above threshold - should transition
        metrics = SecurityMetrics(risk_score=0.1, failed_auth=15)
        result = controller.evaluate_state_transition(SecurityState.NORMAL, metrics)
        assert result == SecurityState.ELEVATED

    def test_transition_elevated_to_critical_by_risk_score(self, mock_event_logger):
        """ELEVATED -> CRITICAL when risk_score > 0.8."""
        controller = StateMachineController(
            initial_state=SecurityState.ELEVATED,
            event_logger=mock_event_logger,
            hysteresis_count=1,
        )

        # Below threshold - no transition
        metrics = SecurityMetrics(risk_score=0.75)
        result = controller.evaluate_state_transition(SecurityState.ELEVATED, metrics)
        assert result == SecurityState.ELEVATED

        # Above threshold - should transition
        metrics = SecurityMetrics(risk_score=0.85)
        result = controller.evaluate_state_transition(SecurityState.ELEVATED, metrics)
        assert result == SecurityState.CRITICAL

    def test_transition_elevated_to_critical_by_active_attack(self, mock_event_logger):
        """ELEVATED -> CRITICAL when active_attack detected."""
        controller = StateMachineController(
            initial_state=SecurityState.ELEVATED,
            event_logger=mock_event_logger,
            hysteresis_count=1,
        )

        # No active attack - no transition
        metrics = SecurityMetrics(risk_score=0.5, active_attack=False)
        result = controller.evaluate_state_transition(SecurityState.ELEVATED, metrics)
        assert result == SecurityState.ELEVATED

        # Active attack detected - should transition
        metrics = SecurityMetrics(risk_score=0.5, active_attack=True)
        result = controller.evaluate_state_transition(SecurityState.ELEVATED, metrics)
        assert result == SecurityState.CRITICAL

    def test_transition_critical_to_lockdown_by_imminent_breach(self, mock_event_logger):
        """CRITICAL -> LOCKDOWN when imminent_breach detected."""
        controller = StateMachineController(
            initial_state=SecurityState.CRITICAL,
            event_logger=mock_event_logger,
            hysteresis_count=1,
        )

        # No imminent breach - no transition
        metrics = SecurityMetrics(risk_score=0.9, imminent_breach=False)
        result = controller.evaluate_state_transition(SecurityState.CRITICAL, metrics)
        assert result == SecurityState.CRITICAL

        # Imminent breach detected - should transition
        metrics = SecurityMetrics(risk_score=0.9, imminent_breach=True)
        result = controller.evaluate_state_transition(SecurityState.CRITICAL, metrics)
        assert result == SecurityState.LOCKDOWN

    def test_transition_critical_to_lockdown_by_manual_trigger(self, mock_event_logger):
        """CRITICAL -> LOCKDOWN when manual_trigger is set."""
        controller = StateMachineController(
            initial_state=SecurityState.CRITICAL,
            event_logger=mock_event_logger,
            hysteresis_count=1,
        )

        # No manual trigger - no transition
        metrics = SecurityMetrics(risk_score=0.9, manual_trigger=False)
        result = controller.evaluate_state_transition(SecurityState.CRITICAL, metrics)
        assert result == SecurityState.CRITICAL

        # Manual trigger - should transition
        metrics = SecurityMetrics(risk_score=0.9, manual_trigger=True)
        result = controller.evaluate_state_transition(SecurityState.CRITICAL, metrics)
        assert result == SecurityState.LOCKDOWN


class TestHysteresis:
    """Test hysteresis (consecutive evaluation requirement) behavior."""

    def test_hysteresis_requires_three_consecutive_evaluations(self, mock_event_logger):
        """Transition requires 3 consecutive evaluations showing same next-state."""
        controller = StateMachineController(
            initial_state=SecurityState.NORMAL,
            event_logger=mock_event_logger,
            hysteresis_count=3,
        )

        metrics = SecurityMetrics(risk_score=0.65)  # Triggers NORMAL -> ELEVATED

        # First evaluation - candidate set, hysteresis not satisfied
        result1 = controller.evaluate_state_transition(SecurityState.NORMAL, metrics)
        assert result1 == SecurityState.NORMAL
        assert not mock_event_logger.log_security_state_change.called

        # Second evaluation - same candidate, hysteresis not satisfied
        result2 = controller.evaluate_state_transition(SecurityState.NORMAL, metrics)
        assert result2 == SecurityState.NORMAL
        assert not mock_event_logger.log_security_state_change.called

        # Third evaluation - same candidate, hysteresis satisfied
        result3 = controller.evaluate_state_transition(SecurityState.NORMAL, metrics)
        assert result3 == SecurityState.ELEVATED
        mock_event_logger.log_security_state_change.assert_called_once()

    def test_hysteresis_resets_on_different_candidate(self, mock_event_logger):
        """Hysteresis counter resets if candidate state changes."""
        controller = StateMachineController(
            initial_state=SecurityState.NORMAL,
            event_logger=mock_event_logger,
            hysteresis_count=3,
        )

        # First evaluation with high risk
        metrics_high = SecurityMetrics(risk_score=0.65)
        controller.evaluate_state_transition(SecurityState.NORMAL, metrics_high)
        assert not mock_event_logger.log_security_state_change.called

        # Second evaluation - same candidate
        controller.evaluate_state_transition(SecurityState.NORMAL, metrics_high)
        assert not mock_event_logger.log_security_state_change.called

        # Third evaluation - different candidate (lower risk)
        metrics_low = SecurityMetrics(risk_score=0.1)
        result = controller.evaluate_state_transition(SecurityState.NORMAL, metrics_low)
        assert result == SecurityState.NORMAL

        # Hysteresis counter should reset, so transition still hasn't happened
        assert not mock_event_logger.log_security_state_change.called

        # Now evaluate with high risk again - should need 3 more
        controller.evaluate_state_transition(SecurityState.NORMAL, metrics_high)
        assert not mock_event_logger.log_security_state_change.called

    def test_hysteresis_resets_on_stable_state(self, mock_event_logger):
        """Hysteresis counter resets when current state matches candidate."""
        controller = StateMachineController(
            initial_state=SecurityState.NORMAL,
            event_logger=mock_event_logger,
            hysteresis_count=3,
        )

        # Evaluate with metric that would transition
        metrics = SecurityMetrics(risk_score=0.65)
        controller.evaluate_state_transition(SecurityState.NORMAL, metrics)
        controller.evaluate_state_transition(SecurityState.NORMAL, metrics)

        # Now evaluate with metric that keeps state stable
        metrics_stable = SecurityMetrics(risk_score=0.2)
        result = controller.evaluate_state_transition(SecurityState.NORMAL, metrics_stable)
        assert result == SecurityState.NORMAL

        # Hysteresis should be reset, so next transition needs 3 fresh evaluations
        controller.evaluate_state_transition(SecurityState.NORMAL, metrics)
        assert not mock_event_logger.log_security_state_change.called

    def test_hysteresis_can_be_customized(self, mock_event_logger):
        """Hysteresis count is configurable."""
        controller = StateMachineController(
            initial_state=SecurityState.NORMAL,
            event_logger=mock_event_logger,
            hysteresis_count=1,  # No hysteresis
        )

        metrics = SecurityMetrics(risk_score=0.65)
        result = controller.evaluate_state_transition(SecurityState.NORMAL, metrics)

        # Should transition immediately with hysteresis_count=1
        assert result == SecurityState.ELEVATED
        mock_event_logger.log_security_state_change.assert_called_once()


class TestEventEmission:
    """Test security event logging on state changes."""

    def test_state_change_emits_event(self, mock_event_logger):
        """Event is emitted when state changes."""
        controller = StateMachineController(
            initial_state=SecurityState.NORMAL,
            event_logger=mock_event_logger,
            hysteresis_count=1,
        )

        metrics = SecurityMetrics(risk_score=0.65)
        controller.evaluate_state_transition(SecurityState.NORMAL, metrics)

        mock_event_logger.log_security_state_change.assert_called_once()
        call_kwargs = mock_event_logger.log_security_state_change.call_args.kwargs
        assert call_kwargs["old_state"] == "NORMAL"
        assert call_kwargs["new_state"] == "ELEVATED"
        assert "0.650" in call_kwargs["trigger"]

    def test_event_contains_reason(self, mock_event_logger):
        """Event includes reason for the transition."""
        controller = StateMachineController(
            initial_state=SecurityState.NORMAL,
            event_logger=mock_event_logger,
            hysteresis_count=1,
        )

        metrics = SecurityMetrics(risk_score=0.1, failed_auth=15)
        controller.evaluate_state_transition(SecurityState.NORMAL, metrics)

        call_kwargs = mock_event_logger.log_security_state_change.call_args.kwargs
        assert "failed_auth=15" in call_kwargs["trigger"]

    def test_event_no_emission_on_no_transition(self, mock_event_logger):
        """Event is not emitted when state remains same."""
        controller = StateMachineController(
            initial_state=SecurityState.NORMAL,
            event_logger=mock_event_logger,
            hysteresis_count=1,
        )

        metrics = SecurityMetrics(risk_score=0.2)  # Below transition threshold
        controller.evaluate_state_transition(SecurityState.NORMAL, metrics)

        mock_event_logger.log_security_state_change.assert_not_called()

    def test_event_metadata_includes_controller_info(self, mock_event_logger):
        """Event metadata includes controller information."""
        controller = StateMachineController(
            initial_state=SecurityState.ELEVATED,
            event_logger=mock_event_logger,
            hysteresis_count=3,
        )

        metrics = SecurityMetrics(risk_score=0.85)
        # Need 3 evaluations to reach transition due to hysteresis
        for _ in range(3):
            controller.evaluate_state_transition(SecurityState.ELEVATED, metrics)

        call_kwargs = mock_event_logger.log_security_state_change.call_args.kwargs
        metadata = call_kwargs.get("metadata", {})
        assert metadata.get("controller") == "StateMachineController"
        assert metadata.get("hysteresis_required") == 3


class TestMethodAPIs:
    """Test the public API methods."""

    def test_trigger_state_change_method(self, mock_event_logger):
        """trigger_state_change() applies state change directly."""
        controller = StateMachineController(
            initial_state=SecurityState.NORMAL,
            event_logger=mock_event_logger,
        )

        controller.trigger_state_change(SecurityState.CRITICAL, "manual operator request")

        assert controller.get_current_state() == SecurityState.CRITICAL
        mock_event_logger.log_security_state_change.assert_called_once()

    def test_trigger_state_change_validates_reason(self, mock_event_logger):
        """trigger_state_change() requires non-empty reason."""
        controller = StateMachineController(
            initial_state=SecurityState.NORMAL,
            event_logger=mock_event_logger,
        )

        with pytest.raises(ValueError, match="reason must be a non-empty string"):
            controller.trigger_state_change(SecurityState.ELEVATED, "")

        with pytest.raises(ValueError, match="reason must be a non-empty string"):
            controller.trigger_state_change(SecurityState.ELEVATED, "  ")

    def test_trigger_state_change_no_op_for_same_state(self, mock_event_logger):
        """trigger_state_change() does nothing if already in that state."""
        controller = StateMachineController(
            initial_state=SecurityState.NORMAL,
            event_logger=mock_event_logger,
        )

        controller.trigger_state_change(SecurityState.NORMAL, "some reason")

        # Event should not be emitted
        mock_event_logger.log_security_state_change.assert_not_called()

    def test_get_current_state(self, controller):
        """get_current_state() returns active state."""
        state = controller.get_current_state()
        assert state == SecurityState.NORMAL

    def test_get_current_state_after_transition(self, mock_event_logger):
        """get_current_state() returns updated state after transition."""
        controller = StateMachineController(
            initial_state=SecurityState.NORMAL,
            event_logger=mock_event_logger,
            hysteresis_count=1,
        )

        assert controller.get_current_state() == SecurityState.NORMAL

        metrics = SecurityMetrics(risk_score=0.65)
        controller.evaluate_state_transition(SecurityState.NORMAL, metrics)

        assert controller.get_current_state() == SecurityState.ELEVATED


class TestMetricsValidation:
    """Test validation of SecurityMetrics."""

    def test_risk_score_must_be_in_range(self, controller):
        """risk_score must be in [0.0, 1.0]."""
        # Valid
        metrics = SecurityMetrics(risk_score=0.0)
        controller.evaluate_state_transition(SecurityState.NORMAL, metrics)

        metrics = SecurityMetrics(risk_score=1.0)
        controller.evaluate_state_transition(SecurityState.NORMAL, metrics)

        # Invalid - too high
        metrics = SecurityMetrics(risk_score=1.1)
        with pytest.raises(ValueError, match="risk_score must be in range"):
            controller.evaluate_state_transition(SecurityState.NORMAL, metrics)

        # Invalid - negative
        metrics = SecurityMetrics(risk_score=-0.1)
        with pytest.raises(ValueError, match="risk_score must be in range"):
            controller.evaluate_state_transition(SecurityState.NORMAL, metrics)

    def test_failed_auth_must_be_non_negative(self, controller):
        """failed_auth must be >= 0."""
        # Valid
        metrics = SecurityMetrics(risk_score=0.5, failed_auth=0)
        controller.evaluate_state_transition(SecurityState.NORMAL, metrics)

        # Invalid
        metrics = SecurityMetrics(risk_score=0.5, failed_auth=-1)
        with pytest.raises(ValueError, match="failed_auth must be >= 0"):
            controller.evaluate_state_transition(SecurityState.NORMAL, metrics)


class TestStatePresence:
    """Test handling of all required security states."""

    def test_all_required_states_present(self):
        """All required security states are defined."""
        required_states = {"LOW", "NORMAL", "ELEVATED", "CRITICAL", "LOCKDOWN"}
        actual_states = {state.value for state in SecurityState}
        assert required_states.issubset(actual_states)


class TestReasonsForTransitions:
    """Test that transition reasons are meaningful."""

    def test_low_to_normal_reason_includes_threshold(self, mock_event_logger):
        """LOW->NORMAL reason includes the risk score."""
        controller = StateMachineController(
            initial_state=SecurityState.LOW,
            event_logger=mock_event_logger,
            hysteresis_count=1,
        )

        metrics = SecurityMetrics(risk_score=0.42)
        controller.evaluate_state_transition(SecurityState.LOW, metrics)

        call_kwargs = mock_event_logger.log_security_state_change.call_args.kwargs
        assert "0.420" in call_kwargs["trigger"]
        assert "0.3" in call_kwargs["trigger"]

    def test_normal_to_elevated_by_risk_reason(self, mock_event_logger):
        """NORMAL->ELEVATED by risk reason includes risk score."""
        controller = StateMachineController(
            initial_state=SecurityState.NORMAL,
            event_logger=mock_event_logger,
            hysteresis_count=1,
        )

        metrics = SecurityMetrics(risk_score=0.72)
        controller.evaluate_state_transition(SecurityState.NORMAL, metrics)

        call_kwargs = mock_event_logger.log_security_state_change.call_args.kwargs
        assert "0.720" in call_kwargs["trigger"]

    def test_normal_to_elevated_by_failed_auth_reason(self, mock_event_logger):
        """NORMAL->ELEVATED by failed_auth reason."""
        controller = StateMachineController(
            initial_state=SecurityState.NORMAL,
            event_logger=mock_event_logger,
            hysteresis_count=1,
        )

        metrics = SecurityMetrics(risk_score=0.1, failed_auth=25)
        controller.evaluate_state_transition(SecurityState.NORMAL, metrics)

        call_kwargs = mock_event_logger.log_security_state_change.call_args.kwargs
        assert "failed_auth=25" in call_kwargs["trigger"]

    def test_elevated_to_critical_by_active_attack_reason(self, mock_event_logger):
        """ELEVATED->CRITICAL by active attack reason."""
        controller = StateMachineController(
            initial_state=SecurityState.ELEVATED,
            event_logger=mock_event_logger,
            hysteresis_count=1,
        )

        metrics = SecurityMetrics(risk_score=0.5, active_attack=True)
        controller.evaluate_state_transition(SecurityState.ELEVATED, metrics)

        call_kwargs = mock_event_logger.log_security_state_change.call_args.kwargs
        assert "active_attack" in call_kwargs["trigger"]

    def test_critical_to_lockdown_by_imminent_breach_reason(self, mock_event_logger):
        """CRITICAL->LOCKDOWN by imminent breach reason."""
        controller = StateMachineController(
            initial_state=SecurityState.CRITICAL,
            event_logger=mock_event_logger,
            hysteresis_count=1,
        )

        metrics = SecurityMetrics(risk_score=0.9, imminent_breach=True)
        controller.evaluate_state_transition(SecurityState.CRITICAL, metrics)

        call_kwargs = mock_event_logger.log_security_state_change.call_args.kwargs
        assert "imminent_breach" in call_kwargs["trigger"]

    def test_critical_to_lockdown_by_manual_trigger_reason(self, mock_event_logger):
        """CRITICAL->LOCKDOWN by manual trigger reason."""
        controller = StateMachineController(
            initial_state=SecurityState.CRITICAL,
            event_logger=mock_event_logger,
            hysteresis_count=1,
        )

        metrics = SecurityMetrics(risk_score=0.9, manual_trigger=True)
        controller.evaluate_state_transition(SecurityState.CRITICAL, metrics)

        call_kwargs = mock_event_logger.log_security_state_change.call_args.kwargs
        assert "manual lockdown trigger" in call_kwargs["trigger"]


class TestInitialState:
    """Test initial state handling."""

    def test_default_initial_state_is_normal(self, mock_event_logger):
        """Default initial state is NORMAL."""
        controller = StateMachineController(event_logger=mock_event_logger)
        assert controller.get_current_state() == SecurityState.NORMAL

    def test_custom_initial_state(self, mock_event_logger):
        """Custom initial state can be specified."""
        controller = StateMachineController(
            initial_state=SecurityState.CRITICAL,
            event_logger=mock_event_logger,
        )
        assert controller.get_current_state() == SecurityState.CRITICAL

    def test_default_event_logger_created(self):
        """Default SecurityEventLogger is created if not provided."""
        controller = StateMachineController(initial_state=SecurityState.NORMAL)
        assert controller._event_logger is not None
        assert isinstance(controller._event_logger, SecurityEventLogger)


class TestEdgeCases:
    """Test edge cases and corner scenarios."""

    def test_stay_in_lockdown_state(self, mock_event_logger):
        """Lockdown state has no outgoing transitions (terminal state)."""
        controller = StateMachineController(
            initial_state=SecurityState.LOCKDOWN,
            event_logger=mock_event_logger,
            hysteresis_count=1,
        )

        # Any metric should keep system in LOCKDOWN
        metrics = SecurityMetrics(risk_score=0.1)
        result = controller.evaluate_state_transition(SecurityState.LOCKDOWN, metrics)
        assert result == SecurityState.LOCKDOWN
        assert not mock_event_logger.log_security_state_change.called

    def test_threshold_boundaries(self, mock_event_logger):
        """Transitions occur exactly at threshold boundaries."""
        controller = StateMachineController(
            initial_state=SecurityState.NORMAL,
            event_logger=mock_event_logger,
            hysteresis_count=1,
        )

        # Exactly at 0.6 - should NOT transition (> not >=)
        metrics = SecurityMetrics(risk_score=0.60001)  # Just above
        result = controller.evaluate_state_transition(SecurityState.NORMAL, metrics)
        assert result == SecurityState.ELEVATED

        # Just below threshold
        controller2 = StateMachineController(
            initial_state=SecurityState.NORMAL,
            event_logger=mock_event_logger,
            hysteresis_count=1,
        )
        metrics = SecurityMetrics(risk_score=0.59999)
        result = controller2.evaluate_state_transition(SecurityState.NORMAL, metrics)
        assert result == SecurityState.NORMAL

    def test_multiple_trigger_conditions_prioritized(self, mock_event_logger):
        """When multiple conditions are met, highest priority is reported."""
        controller = StateMachineController(
            initial_state=SecurityState.NORMAL,
            event_logger=mock_event_logger,
            hysteresis_count=1,
        )

        # Both risk_score AND failed_auth exceed threshold
        metrics = SecurityMetrics(risk_score=0.75, failed_auth=20)
        controller.evaluate_state_transition(SecurityState.NORMAL, metrics)

        call_kwargs = mock_event_logger.log_security_state_change.call_args.kwargs
        # Should prioritize failed_auth (checked first in _build_reason)
        assert "failed_auth" in call_kwargs["trigger"]
