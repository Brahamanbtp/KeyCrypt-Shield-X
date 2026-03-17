"""Autoencoder-based anomaly detection for security telemetry events.

This module trains on normal behavior and flags anomalies via reconstruction
error. The default anomaly threshold is computed statistically as:

    threshold = mean(reconstruction_error) + 3 * std(reconstruction_error)

Expected feature vector shape per event is 64 dimensions.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import torch
from torch import Tensor, nn
from torch.optim import Optimizer
from torch.utils.data import DataLoader


class Encoder(nn.Module):
    """Encoder network mapping input_dim to latent_dim."""

    def __init__(self, input_dim: int = 64, latent_dim: int = 16, dropout: float = 0.2) -> None:
        super().__init__()
        self.network = nn.Sequential(
            nn.Linear(input_dim, 128),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(64, latent_dim),
        )

    def forward(self, x: Tensor) -> Tensor:
        return self.network(x)


class Decoder(nn.Module):
    """Decoder network mapping latent_dim back to output_dim."""

    def __init__(self, latent_dim: int = 16, output_dim: int = 64, dropout: float = 0.2) -> None:
        super().__init__()
        self.network = nn.Sequential(
            nn.Linear(latent_dim, 64),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(64, 128),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(128, output_dim),
        )

    def forward(self, z: Tensor) -> Tensor:
        return self.network(z)


class SecurityAutoencoder(nn.Module):
    """Autoencoder model for 64-dimensional security event vectors."""

    def __init__(self, input_dim: int = 64, latent_dim: int = 16, dropout: float = 0.2) -> None:
        super().__init__()
        self.input_dim = input_dim
        self.latent_dim = latent_dim
        self.dropout_rate = dropout

        self.encoder = Encoder(input_dim=input_dim, latent_dim=latent_dim, dropout=dropout)
        self.decoder = Decoder(latent_dim=latent_dim, output_dim=input_dim, dropout=dropout)

    def forward(self, x: Tensor) -> tuple[Tensor, Tensor]:
        latent = self.encoder(x)
        reconstructed = self.decoder(latent)
        return reconstructed, latent


@dataclass
class ReconstructionStats:
    mean_error: float
    std_error: float
    threshold: float


@dataclass
class EvaluationMetrics:
    loss: float
    mean_error: float
    std_error: float
    max_error: float
    anomaly_rate: float


class AnomalyDetector:
    """Training and inference wrapper for real-time anomaly detection."""

    def __init__(self, model: SecurityAutoencoder | None = None) -> None:
        self.model = model if model is not None else SecurityAutoencoder()
        self.threshold: float | None = None

    @staticmethod
    def _reconstruction_errors(inputs: Tensor, reconstructions: Tensor) -> Tensor:
        # Per-sample MSE across feature dimensions.
        return torch.mean((inputs - reconstructions) ** 2, dim=1)

    def calculate_threshold(self, normal_loader: DataLoader, device: torch.device | str = "cpu") -> ReconstructionStats:
        """Estimate anomaly threshold from normal behavior data.

        Threshold follows mean + 3*std over per-sample reconstruction errors.
        """
        self.model.to(device)
        self.model.eval()

        errors: list[Tensor] = []
        with torch.no_grad():
            for batch in normal_loader:
                features = batch[0] if isinstance(batch, (tuple, list)) else batch
                features = features.to(device).float()

                recon, _ = self.model(features)
                batch_errors = self._reconstruction_errors(features, recon)
                errors.append(batch_errors.detach().cpu())

        if not errors:
            raise ValueError("normal_loader produced no samples for threshold estimation")

        all_errors = torch.cat(errors)
        mean_error = float(all_errors.mean().item())
        std_error = float(all_errors.std(unbiased=False).item())
        threshold = mean_error + 3.0 * std_error

        self.threshold = threshold
        return ReconstructionStats(mean_error=mean_error, std_error=std_error, threshold=threshold)

    def train_one_epoch(
        self,
        dataloader: DataLoader,
        optimizer: Optimizer,
        criterion: nn.Module | None = None,
        device: torch.device | str = "cpu",
        grad_clip_max_norm: float = 1.0,
    ) -> float:
        """Train one epoch on normal behavior data."""
        self.model.to(device)
        self.model.train()
        loss_fn = criterion if criterion is not None else nn.MSELoss()

        running_loss = 0.0
        sample_count = 0

        for batch in dataloader:
            features = batch[0] if isinstance(batch, (tuple, list)) else batch
            features = features.to(device).float()

            optimizer.zero_grad(set_to_none=True)
            recon, _ = self.model(features)
            loss = loss_fn(recon, features)
            loss.backward()
            nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=grad_clip_max_norm)
            optimizer.step()

            batch_size = features.size(0)
            running_loss += loss.item() * batch_size
            sample_count += batch_size

        return running_loss / max(sample_count, 1)

    def fit(
        self,
        train_loader: DataLoader,
        epochs: int,
        optimizer: Optimizer,
        criterion: nn.Module | None = None,
        device: torch.device | str = "cpu",
        grad_clip_max_norm: float = 1.0,
        threshold_loader: DataLoader | None = None,
    ) -> list[float]:
        """Train autoencoder and optionally compute threshold at the end."""
        losses: list[float] = []
        for _ in range(epochs):
            epoch_loss = self.train_one_epoch(
                dataloader=train_loader,
                optimizer=optimizer,
                criterion=criterion,
                device=device,
                grad_clip_max_norm=grad_clip_max_norm,
            )
            losses.append(epoch_loss)

        if threshold_loader is not None:
            self.calculate_threshold(threshold_loader, device=device)

        return losses

    def evaluate(
        self,
        dataloader: DataLoader,
        criterion: nn.Module | None = None,
        device: torch.device | str = "cpu",
        threshold: float | None = None,
    ) -> EvaluationMetrics:
        """Evaluate reconstruction quality and anomaly rate on a dataset."""
        self.model.to(device)
        self.model.eval()
        loss_fn = criterion if criterion is not None else nn.MSELoss(reduction="mean")

        losses: list[float] = []
        errors: list[Tensor] = []

        with torch.no_grad():
            for batch in dataloader:
                features = batch[0] if isinstance(batch, (tuple, list)) else batch
                features = features.to(device).float()

                recon, _ = self.model(features)
                loss = loss_fn(recon, features)
                losses.append(float(loss.item()))

                batch_errors = self._reconstruction_errors(features, recon)
                errors.append(batch_errors.detach().cpu())

        if not errors:
            raise ValueError("dataloader produced no samples for evaluation")

        all_errors = torch.cat(errors)
        eval_threshold = threshold if threshold is not None else self.threshold
        if eval_threshold is None:
            eval_threshold = float(all_errors.mean().item() + 3.0 * all_errors.std(unbiased=False).item())

        anomaly_rate = float((all_errors > eval_threshold).float().mean().item())

        return EvaluationMetrics(
            loss=float(sum(losses) / max(len(losses), 1)),
            mean_error=float(all_errors.mean().item()),
            std_error=float(all_errors.std(unbiased=False).item()),
            max_error=float(all_errors.max().item()),
            anomaly_rate=anomaly_rate,
        )

    def score_realtime(self, event: Tensor, device: torch.device | str = "cpu") -> dict[str, float | bool]:
        """Score a single event in real time.

        Args:
            event: Tensor of shape [64] or [1, 64].

        Returns:
            Dict with reconstruction error, threshold, normalized score in [0,1],
            and anomaly flag.
        """
        if self.threshold is None:
            raise ValueError("threshold is not set; call calculate_threshold() first")

        if event.ndim == 1:
            event = event.unsqueeze(0)
        if event.ndim != 2:
            raise ValueError("event must have shape [64] or [1, 64]")
        if event.size(1) != self.model.input_dim:
            raise ValueError(f"event must have {self.model.input_dim} features")

        self.model.to(device)
        self.model.eval()

        with torch.no_grad():
            sample = event.to(device).float()
            recon, _ = self.model(sample)
            error = float(self._reconstruction_errors(sample, recon).item())

        score = min(error / max(self.threshold, 1e-12), 1.0)
        is_anomaly = error > self.threshold

        return {
            "reconstruction_error": error,
            "threshold": float(self.threshold),
            "risk_score": float(score),
            "is_anomaly": bool(is_anomaly),
        }

    def save(self, path: str | Path, optimizer: Optimizer | None = None, extra: dict[str, Any] | None = None) -> None:
        """Save model, configuration, and threshold."""
        checkpoint: dict[str, Any] = {
            "model_state_dict": self.model.state_dict(),
            "model_config": {
                "input_dim": self.model.input_dim,
                "latent_dim": self.model.latent_dim,
                "dropout": self.model.dropout_rate,
            },
            "threshold": self.threshold,
        }

        if optimizer is not None:
            checkpoint["optimizer_state_dict"] = optimizer.state_dict()
        if extra is not None:
            checkpoint["extra"] = extra

        torch.save(checkpoint, str(path))

    @classmethod
    def load(
        cls,
        path: str | Path,
        device: torch.device | str = "cpu",
        optimizer: Optimizer | None = None,
    ) -> tuple["AnomalyDetector", dict[str, Any]]:
        """Load detector state from checkpoint."""
        checkpoint = torch.load(str(path), map_location=device)

        model = SecurityAutoencoder(**checkpoint["model_config"])
        model.load_state_dict(checkpoint["model_state_dict"])
        model.to(device)

        detector = cls(model=model)
        detector.threshold = checkpoint.get("threshold")

        if optimizer is not None and "optimizer_state_dict" in checkpoint:
            optimizer.load_state_dict(checkpoint["optimizer_state_dict"])

        extra = checkpoint.get("extra", {})
        return detector, extra


__all__ = [
    "Encoder",
    "Decoder",
    "SecurityAutoencoder",
    "AnomalyDetector",
    "ReconstructionStats",
    "EvaluationMetrics",
]
