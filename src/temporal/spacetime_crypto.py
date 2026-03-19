"""Relativistic encryption using special-relativistic spacetime geometry."""

from __future__ import annotations

import hashlib
from typing import Any

import numpy as np
from numpy.typing import ArrayLike, NDArray


FloatArray = NDArray[np.float64]


class SpacetimeCrypto:
    """Special-relativity-aware encryption and causal key distribution."""

    def __init__(self, speed_of_light: float = 299_792_458.0) -> None:
        if speed_of_light <= 0.0:
            raise ValueError("speed_of_light must be positive")
        self.c = float(speed_of_light)

    def minkowski_metric(self) -> FloatArray:
        """Return Minkowski metric tensor with signature (-,+,+,+)."""
        return np.diag(np.array([-1.0, 1.0, 1.0, 1.0], dtype=np.float64))

    def lightcone_encryption(self, event: ArrayLike | dict[str, Any], key: str) -> dict[str, Any]:
        """Encrypt event by propagating ciphertext into the future lightcone."""
        x = self._as_event(event)
        seed = self._seed_from_key(key)

        dt = 1e-6 + (5e-3 * self._unit_float(seed, offset=0))
        spatial_dir = self._direction_from_seed(seed)
        beta = 0.15 + (0.8 * self._unit_float(seed, offset=1))

        spatial_norm = self.c * dt * beta
        dxyz = spatial_dir * spatial_norm
        encrypted_event = x + np.array([dt, dxyz[0], dxyz[1], dxyz[2]], dtype=np.float64)

        causal = self.verify_causality(x, encrypted_event)
        if not causal["timelike"]:
            raise RuntimeError("generated encryption event violates causal timelike condition")

        payload = self._event_payload(x)
        mask = self._mask_from_seed(seed)
        ciphertext = payload ^ mask

        return {
            "encryption_event": encrypted_event,
            "ciphertext": int(ciphertext),
            "causal_interval": causal,
        }

    def causal_key_distribution(self, events: ArrayLike | list[ArrayLike] | list[dict[str, Any]]) -> dict[str, Any]:
        """Distribute pairwise keys only along approximately null geodesic separations."""
        event_list = self._as_event_sequence(events)
        if len(event_list) < 2:
            raise ValueError("at least two events are required for causal key distribution")

        distributed: list[dict[str, Any]] = []
        rejected: list[dict[str, Any]] = []

        for idx in range(len(event_list) - 1):
            e0 = event_list[idx]
            e1 = event_list[idx + 1]
            interval = self._minkowski_interval_squared(e0, e1)
            dt = float(e1[0] - e0[0])
            spatial = float(np.linalg.norm(e1[1:] - e0[1:]))
            ftl_speed = np.inf if dt <= 0.0 else spatial / dt

            if dt > 0.0 and abs(interval) <= (1e-6 * max(1.0, spatial**2)) and ftl_speed <= self.c * (1.0 + 1e-9):
                key_material = self._derive_pair_key(e0, e1)
                distributed.append(
                    {
                        "pair": (idx, idx + 1),
                        "key": key_material,
                        "interval_squared": interval,
                        "propagation_speed": ftl_speed,
                    }
                )
            else:
                rejected.append(
                    {
                        "pair": (idx, idx + 1),
                        "interval_squared": interval,
                        "propagation_speed": ftl_speed,
                        "reason": "not null-like or superluminal transfer detected",
                    }
                )

        return {
            "distributed_keys": distributed,
            "rejected_links": rejected,
            "all_causal": len(rejected) == 0,
        }

    def lorentz_transform(self, key: ArrayLike | str, velocity: ArrayLike) -> dict[str, Any]:
        """Transform key four-vector into a moving inertial frame."""
        v = np.asarray(velocity, dtype=np.float64).reshape(-1)
        if v.shape[0] != 3:
            raise ValueError("velocity must be a 3-vector")

        speed = float(np.linalg.norm(v))
        if speed >= self.c:
            raise ValueError("velocity magnitude must be strictly less than speed of light")

        key_four = self._as_key_four_vector(key)
        transform = self._lorentz_boost_matrix(v)
        transformed = transform @ key_four

        return {
            "transformed_key": transformed,
            "lorentz_matrix": transform,
            "gamma": 1.0 / np.sqrt(1.0 - (speed**2 / self.c**2)),
        }

    def verify_causality(
        self,
        encryption_event: ArrayLike | dict[str, Any],
        decryption_event: ArrayLike | dict[str, Any],
    ) -> dict[str, Any]:
        """Check if decryption event is timelike future-separated from encryption event."""
        e = self._as_event(encryption_event)
        d = self._as_event(decryption_event)

        dt = float(d[0] - e[0])
        dxyz = d[1:] - e[1:]
        spatial_sq = float(np.dot(dxyz, dxyz))
        interval_sq = self._minkowski_interval_squared(e, d)

        timelike = dt > 0.0 and interval_sq < 0.0
        luminal_or_slower = dt <= 0.0 or (np.sqrt(spatial_sq) / dt) <= self.c * (1.0 + 1e-12)

        return {
            "timelike": bool(timelike),
            "causal": bool(timelike and luminal_or_slower),
            "delta_t": dt,
            "spatial_distance": float(np.sqrt(spatial_sq)),
            "interval_squared": interval_sq,
            "speed": (np.inf if dt <= 0.0 else float(np.sqrt(spatial_sq) / dt)),
        }

    def _minkowski_interval_squared(self, event_a: FloatArray, event_b: FloatArray) -> float:
        dt = float(event_b[0] - event_a[0])
        dxyz = event_b[1:] - event_a[1:]
        spatial_sq = float(np.dot(dxyz, dxyz))
        return -(self.c**2) * (dt**2) + spatial_sq

    def _lorentz_boost_matrix(self, velocity: FloatArray) -> FloatArray:
        vx, vy, vz = velocity
        v_sq = float(np.dot(velocity, velocity))
        if v_sq == 0.0:
            return np.eye(4, dtype=np.float64)

        beta_vec = velocity / self.c
        beta_sq = float(np.dot(beta_vec, beta_vec))
        gamma = 1.0 / np.sqrt(1.0 - beta_sq)

        matrix = np.eye(4, dtype=np.float64)
        matrix[0, 0] = gamma
        matrix[0, 1:] = -gamma * beta_vec
        matrix[1:, 0] = -gamma * beta_vec

        outer = np.outer(beta_vec, beta_vec)
        spatial = np.eye(3, dtype=np.float64) + ((gamma - 1.0) / beta_sq) * outer
        matrix[1:, 1:] = spatial
        return matrix

    def _as_event(self, event: ArrayLike | dict[str, Any]) -> FloatArray:
        if isinstance(event, dict):
            values = [event.get("t"), event.get("x"), event.get("y"), event.get("z")]
            if any(v is None for v in values):
                raise ValueError("event dict must contain t, x, y, z")
            arr = np.asarray(values, dtype=np.float64)
        else:
            arr = np.asarray(event, dtype=np.float64).reshape(-1)

        if arr.shape[0] != 4:
            raise ValueError("event must be a 4-vector (t, x, y, z)")
        return arr

    def _as_event_sequence(self, events: Any) -> list[FloatArray]:
        if isinstance(events, np.ndarray) and events.ndim == 2 and events.shape[1] == 4:
            return [row.astype(np.float64) for row in events]

        if isinstance(events, list):
            return [self._as_event(item) for item in events]

        raise ValueError("events must be a list of events or an array with shape (n, 4)")

    def _seed_from_key(self, key: str) -> bytes:
        return hashlib.sha3_512(key.encode("utf-8")).digest()

    def _direction_from_seed(self, seed: bytes) -> FloatArray:
        raw = np.frombuffer(seed[:24], dtype=np.uint8).astype(np.float64)
        vec = (raw[:3] / 255.0) * 2.0 - 1.0
        norm = float(np.linalg.norm(vec))
        if norm == 0.0:
            return np.array([1.0, 0.0, 0.0], dtype=np.float64)
        return vec / norm

    def _unit_float(self, seed: bytes, offset: int = 0) -> float:
        start = (offset * 8) % (len(seed) - 8)
        chunk = seed[start : start + 8]
        intval = int.from_bytes(chunk, byteorder="big", signed=False)
        return intval / float(2**64 - 1)

    def _event_payload(self, event: FloatArray) -> int:
        scaled = np.rint(event * 1e6).astype(np.int64)
        folded = int(
            (scaled[0] & 0xFFFFFFFF)
            ^ ((scaled[1] << 1) & 0xFFFFFFFF)
            ^ ((scaled[2] << 2) & 0xFFFFFFFF)
            ^ ((scaled[3] << 3) & 0xFFFFFFFF)
        )
        return folded & 0xFFFFFFFF

    def _mask_from_seed(self, seed: bytes) -> int:
        return int.from_bytes(seed[:4], byteorder="big", signed=False)

    def _derive_pair_key(self, event_a: FloatArray, event_b: FloatArray) -> str:
        payload = np.concatenate((event_a, event_b)).astype(np.float64).tobytes()
        return hashlib.sha3_256(payload).hexdigest()

    def _as_key_four_vector(self, key: ArrayLike | str) -> FloatArray:
        if isinstance(key, str):
            digest = hashlib.sha3_512(key.encode("utf-8")).digest()
            raw = np.frombuffer(digest[:32], dtype=np.uint64).astype(np.float64)
            vec = (raw[:4] / float(2**64 - 1)) * 2.0 - 1.0
            return vec.astype(np.float64)

        arr = np.asarray(key, dtype=np.float64).reshape(-1)
        if arr.shape[0] != 4:
            raise ValueError("key must be a string or a 4-vector")
        return arr


__all__ = ["SpacetimeCrypto"]
