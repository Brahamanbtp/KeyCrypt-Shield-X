"""Riemannian manifold utilities for geometric encryption workflows."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np
from numpy.typing import ArrayLike, NDArray
from scipy.integrate import solve_ivp


FloatArray = NDArray[np.float64]


@dataclass(frozen=True)
class GeodesicSolution:
    """Container for geodesic integration outputs."""

    t: FloatArray
    points: FloatArray
    velocities: FloatArray


class RiemannianManifold:
    """Hyperbolic Riemannian manifold modeled in a Poincare-ball chart."""

    def __init__(self, dimension: int = 47, curvature: float = -1.0) -> None:
        if dimension <= 0:
            raise ValueError("dimension must be positive")
        if curvature >= 0.0:
            raise ValueError("curvature must be negative for hyperbolic manifold")

        self.dimension = int(dimension)
        self.curvature = float(curvature)
        self._alpha = -self.curvature
        self._identity = np.eye(self.dimension, dtype=np.float64)

    def metric_tensor(self, point: ArrayLike) -> FloatArray:
        """Return the Riemannian metric tensor g_ij at a point."""
        x = self._as_point(point)
        conformal = self._conformal_factor(x)
        return (conformal**2) * self._identity

    def christoffel_symbols(self, point: ArrayLike) -> FloatArray:
        """Compute Levi-Civita connection coefficients Gamma^k_{ij}."""
        x = self._as_point(point)
        grad_phi = self._grad_log_conformal(x)

        gamma = np.zeros((self.dimension, self.dimension, self.dimension), dtype=np.float64)
        for k in range(self.dimension):
            for i in range(self.dimension):
                for j in range(self.dimension):
                    term_1 = 1.0 if k == i else 0.0
                    term_2 = 1.0 if k == j else 0.0
                    term_3 = 1.0 if i == j else 0.0
                    gamma[k, i, j] = (
                        term_1 * grad_phi[j] + term_2 * grad_phi[i] - term_3 * grad_phi[k]
                    )

        return gamma

    def parallel_transport(self, vector: ArrayLike, curve: ArrayLike) -> FloatArray:
        """Parallel transport a tangent vector along a sampled curve."""
        v0 = np.asarray(vector, dtype=np.float64).reshape(-1)
        if v0.shape[0] != self.dimension:
            raise ValueError("vector must have shape (dimension,)")

        curve_points = np.asarray(curve, dtype=np.float64)
        if curve_points.ndim != 2 or curve_points.shape[1] != self.dimension:
            raise ValueError("curve must have shape (num_points, dimension)")
        if curve_points.shape[0] < 2:
            raise ValueError("curve must contain at least two points")

        for row in curve_points:
            self._validate_point(row)

        t_nodes = np.linspace(0.0, 1.0, curve_points.shape[0], dtype=np.float64)
        curve_velocity = np.gradient(curve_points, t_nodes, axis=0)

        def x_of_t(t_value: float) -> FloatArray:
            return np.array(
                [np.interp(t_value, t_nodes, curve_points[:, idx]) for idx in range(self.dimension)],
                dtype=np.float64,
            )

        def dxdt_of_t(t_value: float) -> FloatArray:
            return np.array(
                [np.interp(t_value, t_nodes, curve_velocity[:, idx]) for idx in range(self.dimension)],
                dtype=np.float64,
            )

        def rhs(t_value: float, v_state: FloatArray) -> FloatArray:
            x_t = x_of_t(t_value)
            dx_t = dxdt_of_t(t_value)
            gamma = self.christoffel_symbols(x_t)
            return -np.einsum("kij,i,j->k", gamma, dx_t, v_state, optimize=True)

        sol = solve_ivp(
            fun=rhs,
            t_span=(0.0, 1.0),
            y0=v0,
            t_eval=t_nodes,
            rtol=1e-7,
            atol=1e-9,
        )

        if not sol.success:
            raise RuntimeError(f"parallel transport integration failed: {sol.message}")

        return sol.y.T

    def geodesic_equation(
        self,
        initial_point: ArrayLike,
        initial_velocity: ArrayLike,
        t_span: tuple[float, float] = (0.0, 1.0),
        num_points: int = 128,
    ) -> GeodesicSolution:
        """Solve geodesic ODE with initial position and velocity."""
        x0 = self._as_point(initial_point)
        v0 = np.asarray(initial_velocity, dtype=np.float64).reshape(-1)
        if v0.shape[0] != self.dimension:
            raise ValueError("initial_velocity must have shape (dimension,)")

        if num_points < 2:
            raise ValueError("num_points must be at least 2")

        y0 = np.concatenate((x0, v0), axis=0)
        t_eval = np.linspace(float(t_span[0]), float(t_span[1]), num_points, dtype=np.float64)

        def rhs(_: float, state: FloatArray) -> FloatArray:
            x = state[: self.dimension]
            v = state[self.dimension :]
            gamma = self.christoffel_symbols(x)
            acceleration = -np.einsum("kij,i,j->k", gamma, v, v, optimize=True)
            return np.concatenate((v, acceleration), axis=0)

        sol = solve_ivp(
            fun=rhs,
            t_span=(float(t_span[0]), float(t_span[1])),
            y0=y0,
            t_eval=t_eval,
            rtol=1e-7,
            atol=1e-9,
        )

        if not sol.success:
            raise RuntimeError(f"geodesic integration failed: {sol.message}")

        points = sol.y[: self.dimension, :].T
        velocities = sol.y[self.dimension :, :].T

        return GeodesicSolution(t=sol.t.astype(np.float64), points=points, velocities=velocities)

    def exponential_map(
        self,
        point: ArrayLike,
        tangent_vector: ArrayLike,
        time_horizon: float = 1.0,
    ) -> FloatArray:
        """Map a tangent vector at point onto the manifold via geodesic flow."""
        solution = self.geodesic_equation(
            initial_point=point,
            initial_velocity=tangent_vector,
            t_span=(0.0, float(time_horizon)),
            num_points=64,
        )
        endpoint = solution.points[-1]

        # Numerical integration can slightly leave chart bounds; re-project safely.
        return self._project_inside_chart(endpoint)

    def _as_point(self, point: ArrayLike) -> FloatArray:
        x = np.asarray(point, dtype=np.float64).reshape(-1)
        if x.shape[0] != self.dimension:
            raise ValueError("point must have shape (dimension,)")
        self._validate_point(x)
        return x

    def _validate_point(self, point: FloatArray) -> None:
        radius_sq = float(np.dot(point, point))
        if self._alpha * radius_sq >= 1.0:
            raise ValueError("point is outside Poincare chart for the configured curvature")

    def _conformal_factor(self, point: FloatArray) -> float:
        denom = 1.0 - (self._alpha * float(np.dot(point, point)))
        if denom <= 0.0:
            raise ValueError("metric undefined at or beyond chart boundary")
        return 2.0 / denom

    def _grad_log_conformal(self, point: FloatArray) -> FloatArray:
        denom = 1.0 - (self._alpha * float(np.dot(point, point)))
        if denom <= 0.0:
            raise ValueError("connection undefined at or beyond chart boundary")
        return (2.0 * self._alpha / denom) * point

    def _project_inside_chart(self, point: FloatArray) -> FloatArray:
        radius = float(np.linalg.norm(point))
        max_radius = (1.0 / np.sqrt(self._alpha)) * 0.999
        if radius <= max_radius:
            return point
        if radius == 0.0:
            return point
        scale = max_radius / radius
        return point * scale


__all__ = ["GeodesicSolution", "RiemannianManifold"]
