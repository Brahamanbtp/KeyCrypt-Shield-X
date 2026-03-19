"""Wheeler-Feynman-inspired retrocausal cryptography (exploratory only).

This module is intentionally theoretical research code. It draws conceptual
inspiration from absorber theory and time-symmetric electrodynamics, where
retarded (forward-time) and advanced (backward-time) solutions are considered
together in a boundary-value formulation.

Important limitations:
- This code does not enable physical signaling to the past.
- No causality violation is implemented or claimed.
- Outputs are mathematical constructs for simulation and hypothesis testing.
- It must not be treated as a production cryptographic primitive.

Security note:
- The transformations here are not cryptographically proven.
- Use established algorithms (AES-GCM, ChaCha20-Poly1305, etc.) for real systems.
"""

from __future__ import annotations

import hashlib
from typing import Any

import numpy as np
from numpy.typing import ArrayLike, NDArray


FloatArray = NDArray[np.float64]


class RetrocausalCrypto:
    """Exploratory time-symmetric cryptography model.

    Physics framing:
    - Retarded wave: influence from past to future under ordinary causal flow.
    - Advanced wave: formal solution interpreted as future boundary contribution.

    In this implementation, both are encoded as deterministic transforms over
    state vectors and threat forecasts. They are used to study how a
    time-symmetric design might alter key material in simulation.

    This class is strictly for conceptual experimentation and educational
    analysis of retrocausal ideas. It is not a physically realizable
    communication protocol and not suitable for production security.
    """

    def __init__(self, coupling_strength: float = 0.5) -> None:
        if not (0.0 <= coupling_strength <= 1.0):
            raise ValueError("coupling_strength must be in [0, 1]")
        self.coupling_strength = float(coupling_strength)

    def advanced_wave(self, future_state: ArrayLike | dict[str, Any]) -> dict[str, Any]:
        """Compute a backward-in-time influence surrogate from a future state.

        Conceptual meaning:
        - In Wheeler-Feynman language, advanced solutions are mathematically
          valid time-reversed components of field equations.
        - Here, we model that as a deterministic transform that maps a future
          boundary condition into a present "influence field" used by research
          simulations.

        Parameters:
        - future_state: Numeric state vector or dict of numeric descriptors.

        Returns:
        - A dictionary with an advanced influence vector, scalar influence
          magnitude, and diagnostic metadata.

        Limitations:
        - This does not transmit information from the future.
        - The result is a synthetic statistical prior, not physical retrocausality.
        """
        state = self._as_state_vector(future_state)
        centered = state - np.mean(state)
        norm = float(np.linalg.norm(centered))

        if norm == 0.0:
            influence = np.zeros_like(centered)
        else:
            influence = -self.coupling_strength * (centered / norm)

        return {
            "wave_type": "advanced",
            "influence_vector": influence,
            "influence_magnitude": float(np.linalg.norm(influence)),
            "state_dimension": int(state.shape[0]),
        }

    def retarded_wave(self, past_state: ArrayLike | dict[str, Any]) -> dict[str, Any]:
        """Compute a forward-in-time influence surrogate from a past state.

        Conceptual meaning:
        - Retarded solutions represent ordinary causal propagation from earlier
          to later times.
        - This function computes a normalized forward influence field used in a
          time-symmetric pairing with the advanced component.

        Parameters:
        - past_state: Numeric state vector or dict of numeric descriptors.

        Returns:
        - A dictionary with retarded influence vector, scalar magnitude, and
          diagnostic metadata.

        Limitations:
        - This is a reduced toy model and omits full electrodynamics.
        - Numerical values are heuristic and for exploratory studies only.
        """
        state = self._as_state_vector(past_state)
        centered = state - np.mean(state)
        norm = float(np.linalg.norm(centered))

        if norm == 0.0:
            influence = np.zeros_like(centered)
        else:
            influence = self.coupling_strength * (centered / norm)

        return {
            "wave_type": "retarded",
            "influence_vector": influence,
            "influence_magnitude": float(np.linalg.norm(influence)),
            "state_dimension": int(state.shape[0]),
        }

    def absorber_theory_encryption(self, message: str) -> dict[str, Any]:
        """Apply symmetric-time toy encryption inspired by absorber theory.

        Procedure:
        1. Convert message bytes to a normalized signal state.
        2. Compute retarded and advanced influence vectors.
        3. Build a "time-symmetric" mask from their combination.
        4. XOR message bytes with mask to form ciphertext bytes.

        Returns:
        - Dictionary containing ciphertext hex, intermediate diagnostics, and
          reversible metadata for experimentation.

        Limitations and caution:
        - This is not cryptographically secure encryption.
        - It has no proof of IND-CPA/CCA security and should not protect real data.
        - Its purpose is exploratory modeling of time-symmetric constructs.
        """
        raw = message.encode("utf-8")
        if len(raw) == 0:
            raise ValueError("message must be non-empty")

        signal = np.frombuffer(raw, dtype=np.uint8).astype(np.float64)
        normalized_signal = signal / 255.0

        ret = self.retarded_wave(normalized_signal)
        adv = self.advanced_wave(normalized_signal)

        symmetric_field = (ret["influence_vector"] + adv["influence_vector"]) * 0.5
        mask = self._mask_from_field(symmetric_field, len(raw))

        ciphertext_bytes = bytes([b ^ m for b, m in zip(raw, mask)])

        return {
            "scheme": "absorber_theory_toy_model",
            "ciphertext_hex": ciphertext_bytes.hex(),
            "retarded_magnitude": ret["influence_magnitude"],
            "advanced_magnitude": adv["influence_magnitude"],
            "symmetric_field_norm": float(np.linalg.norm(symmetric_field)),
            "note": "Exploratory only; not production cryptography.",
        }

    def future_key_influence(self, predicted_threats: ArrayLike | dict[str, Any]) -> dict[str, Any]:
        """Model future-threat forecasts as a key-biasing influence field.

        Conceptual framing:
        - Forecasts act as a future boundary condition in a control-theoretic
          sense, not literal causal inversion.
        - The advanced-wave surrogate maps forecast intensity into a key
          adaptation vector that can be used by simulation pipelines.

        Parameters:
        - predicted_threats: Numeric vector or dict with threat intensities.

        Returns:
        - Suggested key adjustment vector, entropy estimate, and a digest tag.

        Limitations:
        - Output is a policy artifact for experiments, not a validated KDF.
        - No claim is made that this represents physically real retrocausal keys.
        """
        threats = self._as_state_vector(predicted_threats)
        advanced = self.advanced_wave(threats)
        influence = np.asarray(advanced["influence_vector"], dtype=np.float64)

        adjustment = np.tanh(4.0 * influence)
        entropy_proxy = float(np.var(adjustment) * adjustment.size)

        digest = hashlib.sha3_256(adjustment.tobytes()).hexdigest()

        return {
            "key_adjustment": adjustment,
            "entropy_proxy": entropy_proxy,
            "influence_digest": digest,
            "influence_magnitude": advanced["influence_magnitude"],
            "note": "Forecast-conditioned, exploratory adaptation only.",
        }

    def _as_state_vector(self, state: ArrayLike | dict[str, Any]) -> FloatArray:
        if isinstance(state, dict):
            values: list[float] = []
            for value in state.values():
                try:
                    values.append(float(value))
                except (TypeError, ValueError):
                    continue
            if not values:
                raise ValueError("state dictionary must contain at least one numeric value")
            arr = np.asarray(values, dtype=np.float64)
        else:
            arr = np.asarray(state, dtype=np.float64).reshape(-1)

        if arr.size == 0:
            raise ValueError("state vector must be non-empty")
        return arr

    def _mask_from_field(self, field: FloatArray, length: int) -> bytes:
        if length <= 0:
            return b""

        seed = hashlib.sha3_512(field.astype(np.float64).tobytes()).digest()
        output = bytearray()
        block = seed
        while len(output) < length:
            output.extend(block)
            block = hashlib.sha3_512(block).digest()

        return bytes(output[:length])


__all__ = ["RetrocausalCrypto"]
