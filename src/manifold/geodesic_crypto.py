"""Geodesic-flow cryptography over hyperbolic Riemannian manifolds."""

from __future__ import annotations

import hashlib
from typing import Any

import numpy as np
from numpy.typing import ArrayLike, NDArray

from src.manifold.riemannian_manifold import RiemannianManifold


FloatArray = NDArray[np.float64]


class GeodesicCrypto:
    """Geometric encryption using hyperbolic manifold embeddings and geodesic flows."""

    def __init__(self, manifold: RiemannianManifold | None = None) -> None:
        self.manifold = manifold or RiemannianManifold(dimension=47, curvature=-1.0)
        self.dimension = self.manifold.dimension
        self._alpha = -self.manifold.curvature

        if self.dimension < 8:
            raise ValueError("manifold dimension must be at least 8 for message embedding")

        # Safe embedding scale keeps encoded points away from chart boundary.
        self._embed_scale = 0.2 / np.sqrt(self._alpha)

    def embed_message(self, plaintext: str) -> FloatArray:
        """Embed plaintext into a point in the manifold chart."""
        raw = plaintext.encode("utf-8")
        max_payload = self.dimension - 1
        if len(raw) > max_payload:
            raise ValueError(f"plaintext too long; maximum {max_payload} bytes for this manifold dimension")

        point = np.zeros(self.dimension, dtype=np.float64)
        point[0] = self._byte_to_coord(len(raw))

        for idx, value in enumerate(raw, start=1):
            point[idx] = self._byte_to_coord(value)

        return self._project_inside_chart(point)

    def key_to_tangent_vector(self, key: str, base_point: ArrayLike) -> FloatArray:
        """Derive a tangent vector from key material and base-point geometry."""
        base = self._as_point(base_point)
        digest = hashlib.sha3_512(key.encode("utf-8")).digest()

        needed = self.dimension
        stream = bytearray()
        seed = digest
        while len(stream) < needed:
            stream.extend(seed)
            seed = hashlib.sha3_512(seed).digest()

        coeffs = np.frombuffer(bytes(stream[:needed]), dtype=np.uint8).astype(np.float64)
        coeffs = (coeffs / 255.0) * 2.0 - 1.0

        radius_budget = max(0.01, (1.0 / np.sqrt(self._alpha)) - float(np.linalg.norm(base)))
        scale = min(0.02 / np.sqrt(self._alpha), 0.15 * radius_budget)

        tangent = coeffs * scale
        return tangent.astype(np.float64)

    def exponential_map(self, base: ArrayLike, tangent: ArrayLike, time: float = 1.0) -> FloatArray:
        """Apply geodesic flow from base point with tangent direction."""
        base_point = self._as_point(base)
        tangent_vec = np.asarray(tangent, dtype=np.float64).reshape(-1)
        if tangent_vec.shape[0] != self.dimension:
            raise ValueError("tangent must have shape (dimension,)")

        mapped = self.manifold.exponential_map(base_point, tangent_vec * float(time), time_horizon=1.0)
        return self._project_inside_chart(mapped)

    def encrypt(self, message: str, key: str) -> FloatArray:
        """Encrypt plaintext as a manifold point ciphertext."""
        message_point = self.embed_message(message)

        origin = np.zeros(self.dimension, dtype=np.float64)
        key_tangent = self.key_to_tangent_vector(key, origin)
        key_point = self.exponential_map(origin, key_tangent, time=1.0)

        # Use local chart translation for exact invertibility after geodesic key flow derivation.
        ciphertext = self._chart_add(message_point, key_point)
        return ciphertext

    def decrypt(self, ciphertext: ArrayLike, key: str) -> str:
        """Decrypt manifold-point ciphertext back into plaintext."""
        c = self._as_point(ciphertext)

        origin = np.zeros(self.dimension, dtype=np.float64)
        key_tangent = self.key_to_tangent_vector(key, origin)
        key_point = self.exponential_map(origin, key_tangent, time=1.0)

        message_point = self._chart_sub(c, key_point)
        return self._decode_message_point(message_point)

    def geodesic_distance(self, point1: ArrayLike, point2: ArrayLike) -> float:
        """Compute hyperbolic geodesic distance as security separation measure."""
        x = self._as_point(point1)
        y = self._as_point(point2)

        delta = self._mobius_add(-x, y)
        norm_delta = float(np.linalg.norm(delta))
        max_norm = (1.0 / np.sqrt(self._alpha)) * 0.999999
        norm_delta = min(norm_delta, max_norm)

        return (2.0 / np.sqrt(self._alpha)) * np.arctanh(np.sqrt(self._alpha) * norm_delta)

    def visualize_projection(
        self,
        points: ArrayLike,
        labels: list[str] | None = None,
        title: str = "Geodesic Crypto 3D Projection",
        save_path: str | None = None,
    ) -> Any:
        """Visualize manifold points using first 3 coordinates as projection."""
        import matplotlib.pyplot as plt

        arr = np.asarray(points, dtype=np.float64)
        if arr.ndim == 1:
            arr = arr.reshape(1, -1)
        if arr.ndim != 2 or arr.shape[1] != self.dimension:
            raise ValueError("points must have shape (n_points, dimension)")

        fig = plt.figure(figsize=(8, 6))
        ax = fig.add_subplot(111, projection="3d")

        x = arr[:, 0]
        y = arr[:, 1]
        z = arr[:, 2]

        ax.scatter(x, y, z, c=np.linspace(0.2, 0.9, arr.shape[0]), cmap="viridis", s=48)

        if labels:
            for idx, label in enumerate(labels[: arr.shape[0]]):
                ax.text(x[idx], y[idx], z[idx], label)

        ax.set_xlabel("x0")
        ax.set_ylabel("x1")
        ax.set_zlabel("x2")
        ax.set_title(title)

        if save_path:
            fig.savefig(save_path, dpi=160, bbox_inches="tight")

        return fig

    def _decode_message_point(self, point: FloatArray) -> str:
        msg_len = self._coord_to_byte(point[0])
        msg_len = min(msg_len, self.dimension - 1)

        payload = bytearray()
        for idx in range(1, msg_len + 1):
            payload.append(self._coord_to_byte(point[idx]))

        return payload.decode("utf-8", errors="strict")

    def _mobius_add(self, x: FloatArray, y: FloatArray) -> FloatArray:
        x = self._as_point(x)
        y = self._as_point(y)

        c = self._alpha
        x2 = float(np.dot(x, x))
        y2 = float(np.dot(y, y))
        xy = float(np.dot(x, y))

        denom = 1.0 + (2.0 * c * xy) + ((c**2) * x2 * y2)
        if abs(denom) < 1e-12:
            raise ValueError("mobius addition denominator too small")

        num = ((1.0 + 2.0 * c * xy + c * y2) * x) + ((1.0 - c * x2) * y)
        return self._project_inside_chart(num / denom)

    def _chart_add(self, x: FloatArray, y: FloatArray) -> FloatArray:
        candidate = np.asarray(x, dtype=np.float64) + np.asarray(y, dtype=np.float64)
        radius = float(np.linalg.norm(candidate))
        max_radius = (1.0 / np.sqrt(self._alpha)) * 0.999
        if radius >= max_radius:
            raise ValueError("ciphertext point left manifold chart; reduce key strength or message magnitude")
        return candidate

    def _chart_sub(self, x: FloatArray, y: FloatArray) -> FloatArray:
        candidate = np.asarray(x, dtype=np.float64) - np.asarray(y, dtype=np.float64)
        radius = float(np.linalg.norm(candidate))
        max_radius = (1.0 / np.sqrt(self._alpha)) * 0.999
        if radius >= max_radius:
            raise ValueError("decrypted point left manifold chart")
        return candidate

    def _byte_to_coord(self, value: int) -> float:
        return self._embed_scale * (((float(value) / 255.0) * 2.0) - 1.0)

    def _coord_to_byte(self, coord: float) -> int:
        normalized = (float(coord) / self._embed_scale + 1.0) / 2.0
        return int(np.clip(round(normalized * 255.0), 0, 255))

    def _as_point(self, point: ArrayLike) -> FloatArray:
        arr = np.asarray(point, dtype=np.float64).reshape(-1)
        if arr.shape[0] != self.dimension:
            raise ValueError("point must have shape (dimension,)")
        return self._project_inside_chart(arr)

    def _project_inside_chart(self, point: FloatArray) -> FloatArray:
        arr = np.asarray(point, dtype=np.float64).reshape(-1)
        radius = float(np.linalg.norm(arr))
        max_radius = (1.0 / np.sqrt(self._alpha)) * 0.999
        if radius <= max_radius:
            return arr
        if radius == 0.0:
            return arr
        return arr * (max_radius / radius)


__all__ = ["GeodesicCrypto"]
