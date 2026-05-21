import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.ai.advanced.federated_threat_learning import (
    Node,
    ThreatEvent,
    initialize_federated_learning,
    train_local_model,
    aggregate_models,
    share_threat_intelligence_privately,
)


def _make_events_for_node(prefix: str, count: int, dim: int, value: float):
    return [ThreatEvent(event_id=f"{prefix}-{i}", features=[value] * dim, label="malware") for i in range(count)]


def test_federated_training_and_aggregation() -> None:
    nodes = [Node(node_id="node-a"), Node(node_id="node-b"), Node(node_id="node-c")]
    fed = initialize_federated_learning(nodes)

    a_events = _make_events_for_node("a", 10, 4, 1.0)
    b_events = _make_events_for_node("b", 20, 4, 2.0)
    c_events = _make_events_for_node("c", 30, 4, 3.0)

    ma = train_local_model(a_events)
    mb = train_local_model(b_events)
    mc = train_local_model(c_events)

    global_model = aggregate_models([ma, mb, mc])
    # weighted mean of values = (10*1 + 20*2 + 30*3) / 60 = (10 + 40 + 90)/60 = 140/60 = 2.333...
    expected = (10 * 1.0 + 20 * 2.0 + 30 * 3.0) / (10 + 20 + 30)
    assert abs(global_model.params.get("w0", 0.0) - expected) < 1e-6
    assert global_model.total_samples == 60


def test_share_threat_intelligence_privately_records_signature() -> None:
    nodes = [Node(node_id="n1")]
    fed = initialize_federated_learning(nodes)
    threat = ThreatEvent(event_id="t1", features=[0.1, 0.2, 0.3], label="phishing")

    share_threat_intelligence_privately(fed, threat, dp_noise=0.0)
    assert len(fed.shared_threat_signatures) == 1
    entry = fed.shared_threat_signatures[0]
    assert "signature" in entry and "summary" in entry
    assert entry["summary"]["label"] == "phishing"
