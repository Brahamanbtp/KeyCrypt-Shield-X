"""Metacognitive monitoring for a self-aware security system."""

from __future__ import annotations

from dataclasses import dataclass
from statistics import mean, pstdev
from time import time
from typing import Any

from src.utils.logging import get_logger


logger = get_logger("src.consciousness.metacognition")


@dataclass(frozen=True)
class MetacognitiveJudgment:
    """Structured self-assessment judgment produced by the monitor."""

    timestamp: float
    subject: str
    confidence: float
    uncertainty: float
    verdict: str
    rationale: str


class MetacognitiveMonitor:
    """Tracks self-performance, uncertainty, calibration, and error-driven adaptation."""

    def __init__(self) -> None:
        self.performance_history: list[dict[str, Any]] = []
        self.calibration_history: list[dict[str, Any]] = []
        self.error_memory: list[dict[str, Any]] = []
        self.knowledge_map: dict[str, dict[str, float]] = {}
        self.internal_models: dict[str, Any] = {
            "policy_updates": {},
            "feature_reweighting": {},
            "recent_decision_failures": 0,
            "last_model_update_at": None,
        }
        self.metacognitive_judgments: list[MetacognitiveJudgment] = []
        self.self_assessment_accuracy: float = 0.0

    def monitor_own_performance(self, metrics: dict[str, Any]) -> dict[str, Any]:
        """Track performance signals and produce a metacognitive judgment."""
        accuracy = self._clamp01(float(metrics.get("accuracy", 0.0)))
        reliability = self._clamp01(float(metrics.get("reliability", 0.0)))
        precision = self._clamp01(float(metrics.get("precision", accuracy)))
        recall = self._clamp01(float(metrics.get("recall", accuracy)))

        uncertainty = self._quantify_uncertainty(accuracy, reliability, precision, recall)
        confidence = self._clamp01(1.0 - uncertainty)

        record = {
            "timestamp": time(),
            "accuracy": accuracy,
            "reliability": reliability,
            "precision": precision,
            "recall": recall,
            "uncertainty": uncertainty,
            "confidence": confidence,
            "context": metrics.get("context", "general"),
        }
        self.performance_history.append(record)

        if len(self.performance_history) > 512:
            self.performance_history = self.performance_history[-512:]

        trend = self._performance_trend()
        verdict = "stable" if uncertainty < 0.3 and trend >= -0.03 else "degrading"
        rationale = (
            "uncertainty low and trend stable"
            if verdict == "stable"
            else "high uncertainty or declining trend detected"
        )

        judgment = MetacognitiveJudgment(
            timestamp=record["timestamp"],
            subject="overall_performance",
            confidence=confidence,
            uncertainty=uncertainty,
            verdict=verdict,
            rationale=rationale,
        )
        self.metacognitive_judgments.append(judgment)

        summary = {
            "accuracy": accuracy,
            "reliability": reliability,
            "uncertainty": uncertainty,
            "confidence": confidence,
            "trend": trend,
            "judgment": judgment,
            "self_assessment_accuracy": self.self_assessment_accuracy,
        }

        logger.info(
            "performance monitored accuracy={accuracy} reliability={reliability} "
            "uncertainty={uncertainty} trend={trend}",
            accuracy=accuracy,
            reliability=reliability,
            uncertainty=uncertainty,
            trend=trend,
        )
        return summary

    def detect_knowledge_gaps(self) -> dict[str, Any]:
        """Identify uncertainty-heavy domains and sparse-evidence blind spots."""
        if not self.performance_history:
            result = {
                "knowledge_gaps": [
                    {
                        "area": "global",
                        "severity": "high",
                        "reason": "no performance history available",
                    }
                ],
                "uncertainty_index": 1.0,
                "metacognitive_judgment": "insufficient_evidence",
            }
            logger.warning("knowledge gap detection found no historical evidence")
            return result

        domain_buckets: dict[str, list[float]] = {}
        for entry in self.performance_history:
            domain = str(entry.get("context", "general"))
            domain_buckets.setdefault(domain, []).append(float(entry.get("uncertainty", 1.0)))

        gaps: list[dict[str, Any]] = []
        for domain, uncertainties in domain_buckets.items():
            avg_uncertainty = mean(uncertainties)
            evidence_count = len(uncertainties)
            severity = "high" if avg_uncertainty > 0.55 else "medium" if avg_uncertainty > 0.35 else "low"

            if avg_uncertainty > 0.35 or evidence_count < 5:
                gaps.append(
                    {
                        "area": domain,
                        "severity": severity,
                        "uncertainty": avg_uncertainty,
                        "evidence_count": evidence_count,
                        "reason": "high uncertainty" if avg_uncertainty > 0.35 else "insufficient samples",
                    }
                )

            self.knowledge_map[domain] = {
                "mean_uncertainty": avg_uncertainty,
                "evidence_count": float(evidence_count),
            }

        uncertainty_index = mean(float(item["uncertainty"]) for item in gaps) if gaps else 0.15
        judgment = "targeted_learning_required" if gaps else "knowledge_state_coherent"

        meta = MetacognitiveJudgment(
            timestamp=time(),
            subject="knowledge_gaps",
            confidence=self._clamp01(1.0 - uncertainty_index),
            uncertainty=self._clamp01(uncertainty_index),
            verdict=judgment,
            rationale="gaps detected" if gaps else "no major gaps detected",
        )
        self.metacognitive_judgments.append(meta)

        result = {
            "knowledge_gaps": sorted(gaps, key=lambda x: (x["severity"], x["uncertainty"]), reverse=True),
            "uncertainty_index": self._clamp01(uncertainty_index),
            "metacognitive_judgment": judgment,
            "self_assessment_accuracy": self.self_assessment_accuracy,
        }

        logger.info(
            "knowledge gaps analyzed gap_count={count} uncertainty_index={uncertainty}",
            count=len(gaps),
            uncertainty=result["uncertainty_index"],
        )
        return result

    def confidence_calibration(self, prediction: dict[str, Any], actual: Any) -> dict[str, Any]:
        """Calibrate prediction confidence based on observed outcome alignment."""
        predicted_confidence = self._clamp01(float(prediction.get("confidence", 0.5)))
        predicted_value = prediction.get("value")

        correctness = self._correctness(predicted_value, actual)
        calibration_error = abs(predicted_confidence - correctness)

        entry = {
            "timestamp": time(),
            "predicted_confidence": predicted_confidence,
            "correctness": correctness,
            "calibration_error": calibration_error,
        }
        self.calibration_history.append(entry)
        if len(self.calibration_history) > 1024:
            self.calibration_history = self.calibration_history[-1024:]

        mean_error = mean(item["calibration_error"] for item in self.calibration_history)
        bias = mean(item["predicted_confidence"] - item["correctness"] for item in self.calibration_history)

        # Shift confidence against persistent over/under-confidence bias.
        calibrated_confidence = self._clamp01(predicted_confidence - (0.5 * bias))

        # Self-assessment accuracy tracks how well confidence matches outcomes.
        self.self_assessment_accuracy = self._clamp01(1.0 - mean_error)

        verdict = "well_calibrated" if calibration_error < 0.2 else "miscalibrated"
        judgment = MetacognitiveJudgment(
            timestamp=entry["timestamp"],
            subject="confidence_calibration",
            confidence=calibrated_confidence,
            uncertainty=calibration_error,
            verdict=verdict,
            rationale="confidence aligned with outcome" if verdict == "well_calibrated" else "confidence mismatch",
        )
        self.metacognitive_judgments.append(judgment)

        result = {
            "predicted_confidence": predicted_confidence,
            "calibrated_confidence": calibrated_confidence,
            "correctness": correctness,
            "calibration_error": calibration_error,
            "running_mean_error": mean_error,
            "self_assessment_accuracy": self.self_assessment_accuracy,
        }

        logger.info(
            "confidence calibrated raw={raw} calibrated={calibrated} error={error} self_assessment={self_assessment}",
            raw=predicted_confidence,
            calibrated=calibrated_confidence,
            error=calibration_error,
            self_assessment=self.self_assessment_accuracy,
        )
        return result

    def learning_from_mistakes(self, error_log: list[dict[str, Any]]) -> dict[str, Any]:
        """Update internal models from observed failures and corrective patterns."""
        if not error_log:
            return {
                "updated": False,
                "message": "no errors supplied",
                "internal_models": self.internal_models,
            }

        self.error_memory.extend(error_log)
        if len(self.error_memory) > 2048:
            self.error_memory = self.error_memory[-2048:]

        root_cause_counts: dict[str, int] = {}
        domain_counts: dict[str, int] = {}
        severity_weight = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        total_weighted_error = 0

        for error in error_log:
            cause = str(error.get("root_cause", "unknown"))
            domain = str(error.get("domain", "general"))
            severity = str(error.get("severity", "medium")).lower()

            root_cause_counts[cause] = root_cause_counts.get(cause, 0) + 1
            domain_counts[domain] = domain_counts.get(domain, 0) + 1
            total_weighted_error += severity_weight.get(severity, 2)

        for cause, count in root_cause_counts.items():
            self.internal_models["policy_updates"][cause] = {
                "priority": "high" if count >= 3 else "normal",
                "count": count,
            }

        for domain, count in domain_counts.items():
            current = float(self.internal_models["feature_reweighting"].get(domain, 1.0))
            self.internal_models["feature_reweighting"][domain] = min(2.0, current + (0.05 * count))

        self.internal_models["recent_decision_failures"] = int(total_weighted_error)
        self.internal_models["last_model_update_at"] = time()

        volatility = self._error_volatility()
        uncertainty = self._clamp01(min(1.0, total_weighted_error / max(len(error_log) * 4, 1)) + (0.2 * volatility))
        confidence = self._clamp01(1.0 - uncertainty)

        judgment = MetacognitiveJudgment(
            timestamp=time(),
            subject="learning_from_mistakes",
            confidence=confidence,
            uncertainty=uncertainty,
            verdict="adaptive_update_applied",
            rationale="internal models updated using observed error patterns",
        )
        self.metacognitive_judgments.append(judgment)

        result = {
            "updated": True,
            "root_cause_counts": root_cause_counts,
            "domain_counts": domain_counts,
            "uncertainty": uncertainty,
            "confidence": confidence,
            "internal_models": self.internal_models,
            "self_assessment_accuracy": self.self_assessment_accuracy,
        }

        logger.info(
            "learning from mistakes updated errors={errors} uncertainty={uncertainty}",
            errors=len(error_log),
            uncertainty=uncertainty,
        )
        return result

    def _quantify_uncertainty(
        self,
        accuracy: float,
        reliability: float,
        precision: float,
        recall: float,
    ) -> float:
        central_tendency = mean([accuracy, reliability, precision, recall])
        dispersion = pstdev([accuracy, reliability, precision, recall])
        uncertainty = (1.0 - central_tendency) + (0.5 * dispersion)
        return self._clamp01(uncertainty)

    def _performance_trend(self) -> float:
        if len(self.performance_history) < 4:
            return 0.0

        recent = self.performance_history[-4:]
        recent_mean = mean(item["accuracy"] for item in recent)
        past_window = self.performance_history[-8:-4]

        if not past_window:
            return 0.0

        past_mean = mean(item["accuracy"] for item in past_window)
        return recent_mean - past_mean

    def _error_volatility(self) -> float:
        if len(self.error_memory) < 2:
            return 0.0

        numeric = []
        severity_map = {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}
        for error in self.error_memory[-32:]:
            severity = str(error.get("severity", "medium")).lower()
            numeric.append(severity_map.get(severity, 0.5))

        return self._clamp01(pstdev(numeric) if len(numeric) > 1 else 0.0)

    def _correctness(self, predicted: Any, actual: Any) -> float:
        if isinstance(predicted, bool) or isinstance(actual, bool):
            return 1.0 if bool(predicted) == bool(actual) else 0.0

        if isinstance(predicted, (int, float)) and isinstance(actual, (int, float)):
            pred = float(predicted)
            act = float(actual)

            if 0.0 <= pred <= 1.0 and 0.0 <= act <= 1.0:
                return self._clamp01(1.0 - abs(pred - act))

            tolerance = max(1.0, abs(act) * 0.05)
            return 1.0 if abs(pred - act) <= tolerance else 0.0

        return 1.0 if str(predicted) == str(actual) else 0.0

    def _clamp01(self, value: float) -> float:
        return max(0.0, min(1.0, float(value)))


__all__ = ["MetacognitiveJudgment", "MetacognitiveMonitor"]
