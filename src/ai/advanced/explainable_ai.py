from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

try:
    import numpy as np
except Exception:  # pragma: no cover - numpy optional
    np = None  # type: ignore

try:  # optional explainability libraries
    import shap  # type: ignore
except Exception:  # pragma: no cover - shap optional
    shap = None  # type: ignore

try:
    from lime import lime_tabular  # type: ignore
except Exception:  # pragma: no cover - lime optional
    lime_tabular = None  # type: ignore

try:
    from sklearn.tree import export_text  # type: ignore
    from sklearn.tree import DecisionTreeClassifier  # type: ignore
except Exception:  # pragma: no cover - sklearn optional
    export_text = None  # type: ignore
    DecisionTreeClassifier = None  # type: ignore


@dataclass
class AlgorithmDecision:
    algorithm_name: str
    features: List[str]
    model: Optional[Any] = None


@dataclass
class RiskScore:
    score: float
    factors: Dict[str, float] = field(default_factory=dict)


@dataclass
class Explanation:
    text: str
    local_importances: Dict[str, float] = field(default_factory=dict)
    global_importances: Dict[str, float] = field(default_factory=dict)
    visualization: Optional[Any] = None


@dataclass
class DecisionTreeVisualization:
    ascii_tree: Optional[str] = None
    image_bytes: Optional[bytes] = None


@dataclass
class Counterfactual:
    changed_features: Dict[str, Any]
    new_decision: str
    confidence: Optional[float] = None


def explain_algorithm_selection(decision: AlgorithmDecision, background_data: Optional[List[List[float]]] = None) -> Explanation:
    """Explain why a specific algorithm was chosen for the given feature vector.

    Tries SHAP then LIME, and falls back to simple feature importance based on model attributes
    or feature value magnitudes if no explainability libs are available.
    """
    model = decision.model
    feature_names = decision.features

    local_imp: Dict[str, float] = {}
    global_imp: Dict[str, float] = {}

    # Try SHAP (best effort)
    if shap is not None and model is not None and np is not None:
        try:
            explainer = shap.Explainer(model, data=background_data) if background_data is not None else shap.Explainer(model)
            # create a single-obs explanation with zeros if no background provided
            data_row = np.zeros(len(feature_names)) if background_data is None else np.array(background_data[0])
            shap_vals = explainer(data_row)
            values = np.abs(shap_vals.values).sum(axis=0) if hasattr(shap_vals, "values") else np.abs(shap_vals).sum(axis=0)
            for name, val in zip(feature_names, values.tolist() if hasattr(values, "tolist") else list(values)):
                local_imp[name] = float(val)
        except Exception:
            local_imp = {}

    # Try LIME
    if not local_imp and lime_tabular is not None and model is not None and np is not None and background_data is not None:
        try:
            explainer = lime_tabular.LimeTabularExplainer(np.array(background_data), feature_names=feature_names, verbose=False, mode="classification")
            exp = explainer.explain_instance(np.array(background_data[0]), model.predict_proba, num_features=len(feature_names))
            for name, val in exp.as_list():
                local_imp[name] = abs(val)
        except Exception:
            local_imp = {}

    # Fallback: use model attribute or simple heuristics
    if not local_imp:
        if model is not None:
            # sklearn style coef or feature_importances_
            try:
                if hasattr(model, "feature_importances_"):
                    vals = getattr(model, "feature_importances_")
                    for n, v in zip(feature_names, vals):
                        local_imp[n] = float(abs(v))
                elif hasattr(model, "coef_"):
                    vals = getattr(model, "coef_")
                    # coefficient can be 2d (multiclass)
                    arr = np.array(vals)
                    vals_mean = np.mean(np.abs(arr), axis=0).tolist()
                    for n, v in zip(feature_names, vals_mean):
                        local_imp[n] = float(v)
            except Exception:
                local_imp = {}

    # Last-resort heuristic: feature magnitudes if numeric
    if not local_imp and background_data is not None:
        try:
            row = background_data[0]
            for n, v in zip(feature_names, row):
                local_imp[n] = float(abs(v)) if isinstance(v, (int, float)) else 1.0
        except Exception:
            for n in feature_names:
                local_imp[n] = 1.0

    # Normalize local importances
    total = sum(local_imp.values()) or 1.0
    for k in list(local_imp.keys()):
        local_imp[k] = local_imp[k] / total

    # Global importances: if model has them use them, else aggregate from local
    if model is not None and hasattr(model, "feature_importances_"):
        try:
            vals = getattr(model, "feature_importances_")
            total_g = sum(vals) or 1.0
            for n, v in zip(feature_names, vals):
                global_imp[n] = float(v) / total_g
        except Exception:
            global_imp = {}
    else:
        global_imp = dict(local_imp)

    text = f"Algorithm '{decision.algorithm_name}' chosen based on weighted feature contributions."
    return Explanation(text=text, local_importances=local_imp, global_importances=global_imp)


def explain_risk_score(risk_assessment: RiskScore) -> Explanation:
    """Break down a risk score into contributing factors and return a human-friendly explanation.

    The factors dict in RiskScore is expected to map factor name -> contribution (positive increases risk).
    """
    sorted_factors = sorted(risk_assessment.factors.items(), key=lambda kv: abs(kv[1]), reverse=True)
    lines: List[str] = [f"Overall risk score: {risk_assessment.score:.4f}"]
    local: Dict[str, float] = {}
    for name, val in sorted_factors:
        lines.append(f"- {name}: {'+' if val >= 0 else ''}{val:.4f}")
        local[name] = float(val)

    text = "\n".join(lines)
    # Normalize contributions for explanation
    tot = sum(abs(v) for v in local.values()) or 1.0
    norm = {k: v / tot for k, v in local.items()}
    return Explanation(text=text, local_importances=norm, global_importances=norm)


def visualize_decision_tree(model: Any, feature_names: Optional[List[str]] = None) -> DecisionTreeVisualization:
    """Visualize a decision tree model. Returns ASCII tree if no rendering libs available.

    Supports sklearn DecisionTreeClassifier via `export_text` fallback to ASCII.
    """
    if export_text is not None and isinstance(model, DecisionTreeClassifier):
        try:
            tree_text = export_text(model, feature_names=feature_names)
            return DecisionTreeVisualization(ascii_tree=tree_text)
        except Exception:
            pass

    # If sklearn not available or model not tree, try to call .to_text() if present
    if hasattr(model, "to_text"):
        try:
            return DecisionTreeVisualization(ascii_tree=model.to_text())
        except Exception:
            pass

    return DecisionTreeVisualization(ascii_tree="Decision tree visualization not available in this environment.")


def generate_counterfactual_explanation(decision_input: Dict[str, Any], model: Any, feature_names: List[str], predict_fn: Optional[Any] = None, max_changes: int = 3) -> Counterfactual:
    """Generate a simple counterfactual by perturbing most important features until decision flips.

    - `decision_input`: mapping feature -> value for a single instance
    - `model` : the predictive model
    - `predict_fn`: optional function f(instance_dict) -> label or (label, confidence)
    """
    # resolve prediction function
    def _predict(instance: Dict[str, Any]) -> Tuple[Any, Optional[float]]:
        if predict_fn is not None:
            out = predict_fn(instance)
            if isinstance(out, tuple):
                return out[0], out[1]
            return out, None
        if model is None:
            raise ValueError("No model or predict_fn provided for counterfactual generation")
        # assume tabular numpy style
        if np is not None:
            x = np.array([list(instance[k] for k in feature_names)])
            if hasattr(model, "predict_proba"):
                probs = model.predict_proba(x)
                label = model.predict(x)[0]
                conf = float(max(probs[0]))
                return label, conf
            else:
                label = model.predict(x)[0]
                return label, None
        else:
            label = model.predict([list(instance[k] for k in feature_names)])[0]
            return label, None

    orig_label, orig_conf = _predict(decision_input)

    # importance ranking: use model-based or value-magnitude
    importance_order: List[str] = list(feature_names)
    try:
        # try to use coef or feature_importances_
        if model is not None and hasattr(model, "feature_importances_"):
            vals = getattr(model, "feature_importances_")
            importance_order = [f for _, f in sorted(zip(vals, feature_names), key=lambda kv: abs(kv[0]), reverse=True)]
        elif model is not None and hasattr(model, "coef_") and np is not None:
            arr = np.array(getattr(model, "coef_"))
            scores = np.mean(np.abs(arr), axis=0)
            importance_order = [f for _, f in sorted(zip(scores, feature_names), key=lambda kv: abs(kv[0]), reverse=True)]
    except Exception:
        importance_order = feature_names

    cf = dict(decision_input)
    changed: Dict[str, Any] = {}
    changes = 0
    for fname in importance_order:
        if changes >= max_changes:
            break
        val = cf[fname]
        # apply perturbation depending on numeric or categorical
        if isinstance(val, (int, float)):
            delta = (0.1 if abs(val) < 1e-6 else 0.2 * float(val)) or 0.1
            cf[fname] = val + delta
        else:
            # flip categorical by appending marker
            cf[fname] = f"{val}_cf"

        new_label, new_conf = _predict(cf)
        changed[fname] = cf[fname]
        changes += 1
        if new_label != orig_label:
            return Counterfactual(changed_features=changed, new_decision=str(new_label), confidence=new_conf)

    # if we didn't flip, return the last attempted change
    return Counterfactual(changed_features=changed, new_decision=str(orig_label), confidence=orig_conf)
