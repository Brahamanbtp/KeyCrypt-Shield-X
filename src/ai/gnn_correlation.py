"""Graph Neural Network threat-correlation pipeline.

This module provides:
- Event-log to graph construction for security telemetry
- 3-layer GCN threat campaign classifier
- NetworkX visualization helpers for graph inspection

Graph design:
- Nodes: individual security events
- Edges: temporal and causal relationships between events
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import networkx as nx
import torch
from torch import Tensor, nn
from torch.nn import functional as F
from torch.optim import Optimizer
from torch_geometric.data import Data
from torch_geometric.loader import DataLoader
from torch_geometric.nn import GCNConv, global_mean_pool


@dataclass
class SecurityEvent:
    """Structured security event used to build graph nodes."""

    event_id: str
    timestamp: float
    event_type: str
    severity: float
    source: str
    destination: str
    entropy: float
    auth_failures: int
    label: int | None = None


class ThreatCorrelationGNN(nn.Module):
    """GCN-based classifier for attack campaign correlation.

    Architecture:
    - 3 x GCNConv layers with 128 hidden features
    - Global mean pooling over node embeddings
    - MLP classifier head
    """

    def __init__(
        self,
        input_dim: int,
        hidden_dim: int = 128,
        num_classes: int = 2,
        dropout: float = 0.3,
    ) -> None:
        super().__init__()

        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.num_classes = num_classes
        self.dropout_rate = dropout

        self.conv1 = GCNConv(input_dim, hidden_dim)
        self.conv2 = GCNConv(hidden_dim, hidden_dim)
        self.conv3 = GCNConv(hidden_dim, hidden_dim)

        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, num_classes),
        )

    def forward(self, data: Data) -> Tensor:
        """Return graph-level logits for campaign classification."""
        x, edge_index = data.x, data.edge_index
        batch = data.batch if hasattr(data, "batch") and data.batch is not None else torch.zeros(
            x.size(0), dtype=torch.long, device=x.device
        )

        x = F.relu(self.conv1(x, edge_index))
        x = F.dropout(x, p=self.dropout_rate, training=self.training)

        x = F.relu(self.conv2(x, edge_index))
        x = F.dropout(x, p=self.dropout_rate, training=self.training)

        x = F.relu(self.conv3(x, edge_index))
        x = F.dropout(x, p=self.dropout_rate, training=self.training)

        pooled = global_mean_pool(x, batch)
        return self.classifier(pooled)


def build_event_graph(
    events: list[SecurityEvent],
    *,
    temporal_window_seconds: float = 300.0,
    include_causal_edges: bool = True,
) -> Data:
    """Construct a PyG graph from event logs.

    Edge strategy:
    - Temporal edges between events within a configurable time window
    - Optional causal edges when source/destination chains align
    """
    if not events:
        raise ValueError("events must not be empty")

    sorted_events = sorted(events, key=lambda e: e.timestamp)

    event_type_vocab = _build_vocab([e.event_type for e in sorted_events])
    endpoint_vocab = _build_vocab([e.source for e in sorted_events] + [e.destination for e in sorted_events])

    node_features: list[list[float]] = []
    for event in sorted_events:
        node_features.append(
            _event_to_features(
                event,
                event_type_vocab=event_type_vocab,
                endpoint_vocab=endpoint_vocab,
            )
        )

    x = torch.tensor(node_features, dtype=torch.float32)

    edges: list[tuple[int, int]] = []
    n = len(sorted_events)

    for i in range(n):
        for j in range(i + 1, n):
            dt = sorted_events[j].timestamp - sorted_events[i].timestamp
            if dt <= temporal_window_seconds:
                edges.append((i, j))
                edges.append((j, i))
            else:
                break

    if include_causal_edges:
        for i in range(n):
            for j in range(i + 1, n):
                if _causal_link(sorted_events[i], sorted_events[j]):
                    edges.append((i, j))
                    edges.append((j, i))

    if not edges:
        edges = [(i, i) for i in range(n)]

    edge_index = torch.tensor(edges, dtype=torch.long).t().contiguous()

    labels = [e.label for e in sorted_events if e.label is not None]
    y = torch.tensor([labels[0]], dtype=torch.long) if labels else None

    data = Data(x=x, edge_index=edge_index)
    if y is not None:
        data.y = y

    data.event_ids = [e.event_id for e in sorted_events]
    return data


def _build_vocab(values: list[str]) -> dict[str, int]:
    unique = sorted(set(values))
    return {value: idx for idx, value in enumerate(unique)}


def _event_to_features(
    event: SecurityEvent,
    *,
    event_type_vocab: dict[str, int],
    endpoint_vocab: dict[str, int],
) -> list[float]:
    num_event_types = len(event_type_vocab)
    num_endpoints = len(endpoint_vocab)

    event_type_one_hot = [0.0] * num_event_types
    event_type_one_hot[event_type_vocab[event.event_type]] = 1.0

    source_one_hot = [0.0] * num_endpoints
    source_one_hot[endpoint_vocab[event.source]] = 1.0

    destination_one_hot = [0.0] * num_endpoints
    destination_one_hot[endpoint_vocab[event.destination]] = 1.0

    numeric = [
        float(event.severity),
        float(event.entropy),
        float(event.auth_failures),
    ]

    return numeric + event_type_one_hot + source_one_hot + destination_one_hot


def _causal_link(a: SecurityEvent, b: SecurityEvent) -> bool:
    if a.destination == b.source:
        return True
    if a.source == b.source and a.event_type == b.event_type:
        return True
    if a.event_type in {"auth_failure", "credential_stuffing"} and b.event_type in {"privilege_escalation", "lateral_movement"}:
        return True
    return False


def train_one_epoch(
    model: ThreatCorrelationGNN,
    dataloader: DataLoader,
    optimizer: Optimizer,
    device: torch.device | str = "cpu",
    grad_clip_max_norm: float = 1.0,
) -> float:
    """Train one epoch for graph-level classification."""
    model.train()
    model.to(device)

    criterion = nn.CrossEntropyLoss()
    running_loss = 0.0
    total_graphs = 0

    for batch in dataloader:
        batch = batch.to(device)

        optimizer.zero_grad(set_to_none=True)
        logits = model(batch)
        loss = criterion(logits, batch.y.view(-1))
        loss.backward()

        nn.utils.clip_grad_norm_(model.parameters(), max_norm=grad_clip_max_norm)
        optimizer.step()

        running_loss += float(loss.item()) * batch.num_graphs
        total_graphs += int(batch.num_graphs)

    return running_loss / max(total_graphs, 1)


def evaluate(
    model: ThreatCorrelationGNN,
    dataloader: DataLoader,
    device: torch.device | str = "cpu",
) -> dict[str, float]:
    """Evaluate graph classifier and return loss/accuracy."""
    model.eval()
    model.to(device)
    criterion = nn.CrossEntropyLoss()

    running_loss = 0.0
    total_graphs = 0
    correct = 0

    with torch.no_grad():
        for batch in dataloader:
            batch = batch.to(device)
            logits = model(batch)
            loss = criterion(logits, batch.y.view(-1))

            preds = logits.argmax(dim=1)
            correct += int((preds == batch.y.view(-1)).sum().item())

            running_loss += float(loss.item()) * batch.num_graphs
            total_graphs += int(batch.num_graphs)

    return {
        "loss": running_loss / max(total_graphs, 1),
        "accuracy": correct / max(total_graphs, 1),
    }


def classify_campaign(
    model: ThreatCorrelationGNN,
    graph: Data,
    class_names: list[str] | None = None,
    device: torch.device | str = "cpu",
) -> dict[str, Any]:
    """Run inference for one campaign graph."""
    model.eval()
    model.to(device)

    with torch.no_grad():
        graph = graph.to(device)
        logits = model(graph)
        probs = torch.softmax(logits, dim=1).squeeze(0)
        label_idx = int(torch.argmax(probs).item())
        confidence = float(probs[label_idx].item())

    label_name = class_names[label_idx] if class_names and label_idx < len(class_names) else str(label_idx)
    return {
        "label_index": label_idx,
        "label": label_name,
        "confidence": confidence,
        "probabilities": probs.detach().cpu().tolist(),
    }


def to_networkx(graph: Data) -> nx.DiGraph:
    """Convert PyG Data graph to NetworkX DiGraph."""
    g = nx.DiGraph()

    num_nodes = int(graph.x.size(0))
    event_ids = getattr(graph, "event_ids", [str(i) for i in range(num_nodes)])

    for idx in range(num_nodes):
        g.add_node(idx, event_id=event_ids[idx])

    edges = graph.edge_index.t().detach().cpu().tolist()
    for src, dst in edges:
        g.add_edge(int(src), int(dst))

    return g


def visualize_graph(
    graph: Data,
    output_path: str | Path | None = None,
    *,
    figsize: tuple[int, int] = (12, 8),
    with_labels: bool = True,
) -> None:
    """Visualize a threat graph using NetworkX and matplotlib."""
    g = to_networkx(graph)

    plt.figure(figsize=figsize)
    pos = nx.spring_layout(g, seed=42)

    labels = {node: g.nodes[node].get("event_id", str(node)) for node in g.nodes} if with_labels else None

    nx.draw_networkx(
        g,
        pos=pos,
        labels=labels,
        node_size=500,
        font_size=8,
        arrows=True,
        edge_color="#666666",
        node_color="#9ecae1",
    )
    plt.title("Threat Event Correlation Graph")
    plt.axis("off")

    if output_path is not None:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        plt.savefig(output_path, bbox_inches="tight")
        plt.close()
    else:
        plt.show()


__all__ = [
    "SecurityEvent",
    "ThreatCorrelationGNN",
    "build_event_graph",
    "train_one_epoch",
    "evaluate",
    "classify_campaign",
    "to_networkx",
    "visualize_graph",
]
