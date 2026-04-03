"""Adaptive crypto provider with AI-driven algorithm routing.

This module adds an intelligent routing layer on top of existing crypto
providers. A risk model from ``src.ai.risk_predictor`` is loaded during
initialization and used at encryption time to choose:
- low risk  -> classical AES-GCM
- high risk -> hybrid PQC-style routing via Kyber-backed PQC provider
"""

from __future__ import annotations

import math
import os
from pathlib import Path
from typing import Any, Mapping

from src.abstractions.crypto_provider import CryptoProvider
from src.providers.crypto.classical_provider import ClassicalCryptoProvider
from src.providers.crypto.pqc_provider import PQCCryptoProvider


class AdaptiveCryptoProvider(CryptoProvider):
    """AI-routed provider that delegates to classical or PQC backends.

    Encryption output format:
    - 1 byte route header
    - delegated provider ciphertext payload

    Route IDs:
    - 1: classical AES-GCM
    - 2: PQC Kyber route (used as hybrid PQC posture)
    """

    _ROUTE_CLASSICAL_AES = 1
    _ROUTE_PQC_HYBRID = 2

    def __init__(
        self,
        *,
        model_path: str | Path | None = None,
        risk_threshold: float = 0.65,
        model_input_size: int = 8,
        device: str = "cpu",
    ) -> None:
        if not 0.0 <= float(risk_threshold) <= 1.0:
            raise ValueError("risk_threshold must be in range [0.0, 1.0]")
        if int(model_input_size) <= 0:
            raise ValueError("model_input_size must be positive")

        self._torch = self._import_torch()
        self._device = self._torch.device(device)
        self._risk_model = self._load_risk_model(
            model_path=model_path,
            default_input_size=int(model_input_size),
            device=self._device,
        )
        self._risk_model.eval()

        self._risk_threshold = float(risk_threshold)
        self._classical_provider = ClassicalCryptoProvider("aes-gcm")
        self._pqc_provider: PQCCryptoProvider | None = None
        self._pqc_provider_error: Exception | None = None

        try:
            self._pqc_provider = PQCCryptoProvider("kyber-768")
        except Exception as exc:
            self._pqc_provider_error = exc

        self._last_risk_score = 0.0

    def encrypt(self, plaintext: bytes, context: EncryptionContext) -> bytes:
        """Encrypt plaintext via AI-guided provider selection.

        Steps:
        1. Predict risk score with risk model.
        2. Select classical AES or hybrid PQC route based on threshold.
        3. Delegate encryption to selected provider.
        """
        self._require_bytes("plaintext", plaintext)

        risk_score = self._predict_risk_score(plaintext=plaintext, context=context)
        self._last_risk_score = risk_score

        provider, route_id = self._select_provider_for_risk(risk_score)
        ciphertext = provider.encrypt(plaintext, context)
        if not isinstance(ciphertext, bytes):
            raise TypeError("delegated provider must return bytes")

        return bytes((route_id,)) + ciphertext

    def decrypt(self, ciphertext: bytes, context: DecryptionContext) -> bytes:
        """Decrypt payload using route header selected during encryption."""
        self._require_bytes("ciphertext", ciphertext)
        if len(ciphertext) < 2:
            raise ValueError("ciphertext is too short for adaptive route header")

        route_id = ciphertext[0]
        delegated_payload = ciphertext[1:]

        if route_id == self._ROUTE_CLASSICAL_AES:
            provider: CryptoProvider = self._classical_provider
        elif route_id == self._ROUTE_PQC_HYBRID:
            provider = self._require_pqc_provider()
        else:
            raise ValueError(f"unsupported adaptive route id: {route_id}")

        return provider.decrypt(delegated_payload, context)

    def get_algorithm_name(self) -> str:
        """Return adaptive algorithm family identifier."""
        return "adaptive-ai-routing"

    def get_security_level(self) -> int:
        """Return nominal security level advertised by adaptive routing.

        This value is intentionally conservative for broad compatibility with
        existing policy checks that treat larger values as stronger posture.
        """
        levels = [self._classical_provider.get_security_level()]
        if self._pqc_provider is not None:
            levels.append(self._pqc_provider.get_security_level())
        return max(levels)

    @property
    def last_risk_score(self) -> float:
        """Expose most recent risk score used for routing."""
        return self._last_risk_score

    def _select_provider_for_risk(self, risk_score: float) -> tuple[CryptoProvider, int]:
        if risk_score >= self._risk_threshold:
            return self._require_pqc_provider(), self._ROUTE_PQC_HYBRID
        return self._classical_provider, self._ROUTE_CLASSICAL_AES

    def _require_pqc_provider(self) -> PQCCryptoProvider:
        if self._pqc_provider is None:
            reason = f": {self._pqc_provider_error}" if self._pqc_provider_error is not None else ""
            raise RuntimeError(
                "high-risk adaptive route requires PQCCryptoProvider (kyber-768) but it is unavailable"
                f"{reason}"
            )
        return self._pqc_provider

    def _predict_risk_score(self, *, plaintext: bytes, context: Any) -> float:
        features = self._build_model_features(plaintext=plaintext, context=context)
        model_input = self._torch.tensor(
            features,
            dtype=self._torch.float32,
            device=self._device,
        ).view(1, 1, -1)

        with self._torch.no_grad():
            risk_scores, _attention = self._risk_model(model_input)

        risk_score = float(risk_scores.view(-1)[0].item())
        if math.isnan(risk_score):
            raise RuntimeError("risk model returned NaN score")
        return min(max(risk_score, 0.0), 1.0)

    def _build_model_features(self, *, plaintext: bytes, context: Any) -> list[float]:
        input_size = int(getattr(self._risk_model, "input_size", 8) or 8)

        associated_data = self._extract_value(context, "associated_data")
        metadata = self._extract_value(context, "metadata")
        metadata_mapping = metadata if isinstance(metadata, Mapping) else {}

        threat_level = self._coerce_float(
            metadata_mapping.get("threat_level", self._extract_value(context, "threat_level")),
            default=0.0,
        )
        sensitivity = self._coerce_float(
            metadata_mapping.get("sensitivity", self._extract_value(context, "sensitivity")),
            default=0.5,
        )

        base = [
            min(len(plaintext) / float(1024 * 1024), 1.0),
            self._normalized_entropy(plaintext),
            len(set(plaintext)) / 256.0 if plaintext else 0.0,
            1.0 if isinstance(associated_data, bytes) and len(associated_data) > 0 else 0.0,
            min(max(threat_level, 0.0), 1.0),
            min(max(sensitivity, 0.0), 1.0),
            1.0 if isinstance(self._extract_value(context, "key_id"), str) else 0.0,
            1.0 if isinstance(self._extract_value(context, "provider_name"), str) else 0.0,
        ]

        if len(base) < input_size:
            base.extend([0.0] * (input_size - len(base)))
        return base[:input_size]

    @staticmethod
    def _normalized_entropy(data: bytes) -> float:
        if not data:
            return 0.0

        counts = [0] * 256
        for value in data:
            counts[value] += 1

        total = float(len(data))
        entropy = 0.0
        for count in counts:
            if count == 0:
                continue
            p = count / total
            entropy -= p * math.log2(p)

        return min(max(entropy / 8.0, 0.0), 1.0)

    @staticmethod
    def _extract_value(context: Any, key: str) -> Any:
        if isinstance(context, Mapping):
            return context.get(key)
        return getattr(context, key, None)

    @staticmethod
    def _coerce_float(value: Any, *, default: float) -> float:
        try:
            return float(value)
        except Exception:
            return default

    @staticmethod
    def _load_risk_model(
        *,
        model_path: str | Path | None,
        default_input_size: int,
        device: Any,
    ) -> Any:
        try:
            from src.ai.risk_predictor import RiskPredictor, load_model
        except Exception as exc:
            raise RuntimeError(
                "AdaptiveCryptoProvider could not load RiskPredictor from src.ai.risk_predictor"
            ) from exc

        configured_path = model_path
        if configured_path is None:
            env_path = os.getenv("KEYCRYPT_RISK_MODEL_PATH")
            configured_path = env_path if env_path else None

        if configured_path:
            path_obj = Path(configured_path).expanduser().resolve()
            if not path_obj.is_file():
                raise FileNotFoundError(f"risk model checkpoint not found: {path_obj}")
            model, _extra = load_model(path_obj, device=device)
            model.eval()
            return model

        model = RiskPredictor(input_size=default_input_size)
        model.to(device)
        model.eval()
        return model

    @staticmethod
    def _import_torch() -> Any:
        try:
            import torch
        except Exception as exc:
            raise RuntimeError(
                "AdaptiveCryptoProvider requires torch for AI risk inference"
            ) from exc
        return torch

    @staticmethod
    def _require_bytes(name: str, value: object) -> None:
        if not isinstance(value, bytes):
            raise TypeError(f"{name} must be bytes")


__all__ = ["AdaptiveCryptoProvider"]
