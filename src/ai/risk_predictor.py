"""PyTorch risk prediction model for cryptographic telemetry.

Model architecture:
- 3-layer bidirectional LSTM with 128 hidden units
- Attention pooling over sequence outputs
- Fully connected head: 256 -> 128 -> 1

Input features are expected to contain telemetry over time, for example:
- Access pattern statistics
- Entropy-related signals
- Authentication failure indicators

Outputs are risk scores in [0, 1].
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import torch
from torch import Tensor, nn
from torch.optim import Optimizer
from torch.utils.data import DataLoader


class AttentionPool(nn.Module):
    """Simple additive attention pooling over sequence outputs."""

    def __init__(self, input_dim: int, dropout: float = 0.2) -> None:
        super().__init__()
        self.score = nn.Sequential(
            nn.Linear(input_dim, input_dim),
            nn.Tanh(),
            nn.Dropout(dropout),
            nn.Linear(input_dim, 1),
        )

    def forward(self, sequence_output: Tensor) -> tuple[Tensor, Tensor]:
        """Compute attention-weighted context vector.

        Args:
            sequence_output: Tensor with shape [batch, seq_len, hidden_dim].

        Returns:
            context: Tensor [batch, hidden_dim]
            attention_weights: Tensor [batch, seq_len]
        """
        scores = self.score(sequence_output).squeeze(-1)
        weights = torch.softmax(scores, dim=1)
        context = torch.bmm(weights.unsqueeze(1), sequence_output).squeeze(1)
        return context, weights


class RiskPredictor(nn.Module):
    """LSTM + Attention model for cryptographic risk prediction."""

    def __init__(
        self,
        input_size: int,
        lstm_hidden_size: int = 128,
        lstm_layers: int = 3,
        lstm_bidirectional: bool = True,
        dropout: float = 0.3,
    ) -> None:
        super().__init__()

        self.input_size = input_size
        self.lstm_hidden_size = lstm_hidden_size
        self.lstm_layers = lstm_layers
        self.lstm_bidirectional = lstm_bidirectional
        self.dropout_rate = dropout

        self.lstm = nn.LSTM(
            input_size=input_size,
            hidden_size=lstm_hidden_size,
            num_layers=lstm_layers,
            batch_first=True,
            dropout=dropout if lstm_layers > 1 else 0.0,
            bidirectional=lstm_bidirectional,
        )

        lstm_output_dim = lstm_hidden_size * 2 if lstm_bidirectional else lstm_hidden_size

        self.attention = AttentionPool(input_dim=lstm_output_dim, dropout=dropout)

        self.classifier = nn.Sequential(
            nn.Linear(lstm_output_dim, 256),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(256, 128),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(128, 1),
        )

        self.output_activation = nn.Sigmoid()

    def forward(self, x: Tensor) -> tuple[Tensor, Tensor]:
        """Forward pass.

        Args:
            x: Telemetry tensor [batch, seq_len, input_size].

        Returns:
            risk_scores: Tensor [batch]
            attention_weights: Tensor [batch, seq_len]
        """
        lstm_out, _ = self.lstm(x)
        context, attention_weights = self.attention(lstm_out)
        logits = self.classifier(context).squeeze(-1)
        risk_scores = self.output_activation(logits)
        return risk_scores, attention_weights


@dataclass
class EpochMetrics:
    loss: float
    accuracy: float
    precision: float
    recall: float
    f1: float


def _binary_metrics(predictions: Tensor, targets: Tensor, threshold: float = 0.5) -> dict[str, float]:
    preds = (predictions >= threshold).int()
    targs = targets.int()

    tp = int(((preds == 1) & (targs == 1)).sum().item())
    tn = int(((preds == 0) & (targs == 0)).sum().item())
    fp = int(((preds == 1) & (targs == 0)).sum().item())
    fn = int(((preds == 0) & (targs == 1)).sum().item())

    total = max(tp + tn + fp + fn, 1)
    accuracy = (tp + tn) / total
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-12)

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def train_one_epoch(
    model: RiskPredictor,
    dataloader: DataLoader,
    optimizer: Optimizer,
    criterion: nn.Module | None = None,
    device: torch.device | str = "cpu",
    grad_clip_max_norm: float = 1.0,
) -> EpochMetrics:
    """Train the model for one epoch with gradient clipping."""
    model.train()
    loss_fn = criterion if criterion is not None else nn.BCELoss()

    running_loss = 0.0
    all_preds: list[Tensor] = []
    all_targets: list[Tensor] = []

    for features, targets in dataloader:
        features = features.to(device)
        targets = targets.to(device).float().view(-1)

        optimizer.zero_grad(set_to_none=True)

        preds, _ = model(features)
        loss = loss_fn(preds, targets)
        loss.backward()

        nn.utils.clip_grad_norm_(model.parameters(), max_norm=grad_clip_max_norm)
        optimizer.step()

        batch_size = features.size(0)
        running_loss += loss.item() * batch_size
        all_preds.append(preds.detach().cpu())
        all_targets.append(targets.detach().cpu())

    epoch_preds = torch.cat(all_preds)
    epoch_targets = torch.cat(all_targets)
    metrics = _binary_metrics(epoch_preds, epoch_targets)

    return EpochMetrics(
        loss=running_loss / max(len(dataloader.dataset), 1),
        accuracy=metrics["accuracy"],
        precision=metrics["precision"],
        recall=metrics["recall"],
        f1=metrics["f1"],
    )


def evaluate(
    model: RiskPredictor,
    dataloader: DataLoader,
    criterion: nn.Module | None = None,
    device: torch.device | str = "cpu",
) -> EpochMetrics:
    """Evaluate the model and return aggregate metrics."""
    model.eval()
    loss_fn = criterion if criterion is not None else nn.BCELoss()

    running_loss = 0.0
    all_preds: list[Tensor] = []
    all_targets: list[Tensor] = []

    with torch.no_grad():
        for features, targets in dataloader:
            features = features.to(device)
            targets = targets.to(device).float().view(-1)

            preds, _ = model(features)
            loss = loss_fn(preds, targets)

            batch_size = features.size(0)
            running_loss += loss.item() * batch_size
            all_preds.append(preds.detach().cpu())
            all_targets.append(targets.detach().cpu())

    epoch_preds = torch.cat(all_preds)
    epoch_targets = torch.cat(all_targets)
    metrics = _binary_metrics(epoch_preds, epoch_targets)

    return EpochMetrics(
        loss=running_loss / max(len(dataloader.dataset), 1),
        accuracy=metrics["accuracy"],
        precision=metrics["precision"],
        recall=metrics["recall"],
        f1=metrics["f1"],
    )


def fit(
    model: RiskPredictor,
    train_loader: DataLoader,
    val_loader: DataLoader | None,
    optimizer: Optimizer,
    epochs: int,
    criterion: nn.Module | None = None,
    device: torch.device | str = "cpu",
    grad_clip_max_norm: float = 1.0,
) -> list[dict[str, Any]]:
    """Full training loop with optional validation."""
    model.to(device)
    history: list[dict[str, Any]] = []

    for epoch in range(1, epochs + 1):
        train_metrics = train_one_epoch(
            model=model,
            dataloader=train_loader,
            optimizer=optimizer,
            criterion=criterion,
            device=device,
            grad_clip_max_norm=grad_clip_max_norm,
        )

        row: dict[str, Any] = {
            "epoch": epoch,
            "train": train_metrics,
        }

        if val_loader is not None:
            val_metrics = evaluate(
                model=model,
                dataloader=val_loader,
                criterion=criterion,
                device=device,
            )
            row["val"] = val_metrics

        history.append(row)

    return history


def save_model(
    model: RiskPredictor,
    path: str | Path,
    optimizer: Optimizer | None = None,
    extra: dict[str, Any] | None = None,
) -> None:
    """Save model checkpoint including architecture configuration."""
    checkpoint = {
        "model_state_dict": model.state_dict(),
        "model_config": {
            "input_size": model.input_size,
            "lstm_hidden_size": model.lstm_hidden_size,
            "lstm_layers": model.lstm_layers,
            "lstm_bidirectional": model.lstm_bidirectional,
            "dropout": model.dropout_rate,
        },
    }

    if optimizer is not None:
        checkpoint["optimizer_state_dict"] = optimizer.state_dict()
    if extra is not None:
        checkpoint["extra"] = extra

    torch.save(checkpoint, str(path))


def load_model(
    path: str | Path,
    device: torch.device | str = "cpu",
    optimizer: Optimizer | None = None,
) -> tuple[RiskPredictor, dict[str, Any]]:
    """Load model checkpoint and optionally restore optimizer state."""
    checkpoint = torch.load(str(path), map_location=device)

    config = checkpoint["model_config"]
    model = RiskPredictor(**config)
    model.load_state_dict(checkpoint["model_state_dict"])
    model.to(device)

    if optimizer is not None and "optimizer_state_dict" in checkpoint:
        optimizer.load_state_dict(checkpoint["optimizer_state_dict"])

    extra = checkpoint.get("extra", {})
    return model, extra


__all__ = [
    "RiskPredictor",
    "AttentionPool",
    "EpochMetrics",
    "train_one_epoch",
    "evaluate",
    "fit",
    "save_model",
    "load_model",
]
