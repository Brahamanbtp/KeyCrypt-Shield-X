"""Topological invariants for manifold-based security verification."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np
from numpy.typing import ArrayLike, NDArray


try:
    import gudhi as gd
except ModuleNotFoundError:  # pragma: no cover - depends on environment
    gd = None


FloatArray = NDArray[np.float64]


@dataclass(frozen=True)
class TopologySnapshot:
    """Snapshot of topological invariants for integrity checks."""

    betti_numbers: dict[int, int]
    homology_groups: dict[str, str]
    topological_charge: int


class TopologicalSecurity:
    """Computes topology-derived security invariants and verifies preservation."""

    def __init__(self, max_dimension: int = 3, max_edge_length: float = 1.0) -> None:
        if max_dimension < 1:
            raise ValueError("max_dimension must be at least 1")
        if max_edge_length <= 0.0:
            raise ValueError("max_edge_length must be positive")

        self.max_dimension = int(max_dimension)
        self.max_edge_length = float(max_edge_length)

        self._latest_betti: dict[int, int] | None = None
        self._latest_homology_groups: dict[str, str] | None = None
        self._latest_charge: int | None = None
        self._latest_diagrams: dict[int, list[tuple[float, float]]] | None = None

        self._baseline: TopologySnapshot | None = None

    def compute_homology_groups(self, manifold: Any) -> dict[str, Any]:
        """Compute homology groups H_0, H_1, ... from a Vietoris-Rips complex."""
        self._require_gudhi()

        points = self._extract_point_cloud(manifold)
        simplex_tree = self._build_rips_complex(points)

        simplex_tree.compute_persistence()
        betti_list = simplex_tree.betti_numbers()

        betti: dict[int, int] = {dim: int(value) for dim, value in enumerate(betti_list)}
        homology = {f"H_{dim}": f"Z^{rank}" for dim, rank in betti.items()}

        self._latest_betti = betti
        self._latest_homology_groups = homology

        return {
            "betti_numbers": betti,
            "homology_groups": homology,
            "num_simplices": simplex_tree.num_simplices(),
            "num_vertices": simplex_tree.num_vertices(),
        }

    def persistent_homology(self, filtration: Any) -> dict[str, Any]:
        """Compute persistence diagrams and generate barcode visualization."""
        self._require_gudhi()

        points, max_edge_length, max_dimension, save_path = self._extract_filtration_config(filtration)
        rips = gd.RipsComplex(points=points, max_edge_length=max_edge_length)
        simplex_tree = rips.create_simplex_tree(max_dimension=max_dimension)

        simplex_tree.compute_persistence()

        diagrams: dict[int, list[tuple[float, float]]] = {}
        for dim in range(max_dimension + 1):
            intervals = simplex_tree.persistence_intervals_in_dimension(dim)
            diagrams[dim] = [(float(birth), float(death)) for birth, death in intervals]

        self._latest_diagrams = diagrams

        figure = None
        try:
            import matplotlib.pyplot as plt
            from gudhi.plotting import plot_persistence_barcode

            figure = plt.figure(figsize=(8, 4))
            plot_persistence_barcode(simplex_tree.persistence(), axes=figure.add_subplot(111))
            figure.suptitle("Persistence Barcode")
            if save_path:
                figure.savefig(save_path, dpi=160, bbox_inches="tight")
        except Exception:
            figure = None

        return {
            "persistence_diagrams": diagrams,
            "num_simplices": simplex_tree.num_simplices(),
            "barcode_figure": figure,
            "barcode_saved_to": save_path,
        }

    def topological_charge(self, configuration: Any) -> int:
        """Compute a conserved integer topological charge from configuration phases."""
        values = self._extract_phase_series(configuration)

        if values.size < 2:
            charge = 0
        else:
            phases = np.angle(values)
            phase_diffs = np.diff(phases)
            wrapped = (phase_diffs + np.pi) % (2.0 * np.pi) - np.pi
            charge = int(np.rint(np.sum(wrapped) / (2.0 * np.pi)))

        self._latest_charge = charge
        return charge

    def verify_topological_security(self) -> dict[str, Any]:
        """Verify whether computed topological invariants remain preserved."""
        if self._latest_betti is None or self._latest_homology_groups is None or self._latest_charge is None:
            raise ValueError(
                "no invariants computed yet; run compute_homology_groups and topological_charge first"
            )

        current = TopologySnapshot(
            betti_numbers=self._latest_betti,
            homology_groups=self._latest_homology_groups,
            topological_charge=self._latest_charge,
        )

        if self._baseline is None:
            self._baseline = current
            return {
                "secure": True,
                "status": "baseline_initialized",
                "baseline": self._snapshot_to_dict(current),
                "current": self._snapshot_to_dict(current),
                "invariants_preserved": True,
            }

        betti_preserved = current.betti_numbers == self._baseline.betti_numbers
        charge_preserved = current.topological_charge == self._baseline.topological_charge
        invariants_preserved = betti_preserved and charge_preserved

        return {
            "secure": invariants_preserved,
            "status": "verified",
            "invariants_preserved": invariants_preserved,
            "betti_preserved": betti_preserved,
            "charge_preserved": charge_preserved,
            "baseline": self._snapshot_to_dict(self._baseline),
            "current": self._snapshot_to_dict(current),
        }

    def _build_rips_complex(self, points: FloatArray):
        rips = gd.RipsComplex(points=points, max_edge_length=self.max_edge_length)
        return rips.create_simplex_tree(max_dimension=self.max_dimension)

    def _extract_point_cloud(self, manifold: Any) -> FloatArray:
        if isinstance(manifold, np.ndarray):
            points = manifold.astype(np.float64)
        elif isinstance(manifold, dict) and "points" in manifold:
            points = np.asarray(manifold["points"], dtype=np.float64)
        elif hasattr(manifold, "dimension"):
            points = self._sample_points_from_manifold(manifold)
        else:
            points = np.asarray(manifold, dtype=np.float64)

        if points.ndim != 2:
            raise ValueError("point cloud must be a 2D array with shape (n_points, dimension)")
        if points.shape[0] < 2:
            raise ValueError("point cloud must contain at least 2 points")

        return points

    def _sample_points_from_manifold(self, manifold: Any) -> FloatArray:
        dimension = int(getattr(manifold, "dimension", 3))
        base_count = max(16, min(64, 2 * dimension))
        rng = np.random.default_rng(42)

        cloud = rng.normal(loc=0.0, scale=0.08, size=(base_count, dimension)).astype(np.float64)
        return cloud

    def _extract_filtration_config(
        self,
        filtration: Any,
    ) -> tuple[FloatArray, float, int, str | None]:
        if isinstance(filtration, dict):
            points = self._extract_point_cloud(filtration.get("points", filtration))
            max_edge_length = float(filtration.get("max_edge_length", self.max_edge_length))
            max_dimension = int(filtration.get("max_dimension", self.max_dimension))
            save_path = filtration.get("save_path")
            save_path = str(save_path) if save_path else None
            return points, max_edge_length, max_dimension, save_path

        return self._extract_point_cloud(filtration), self.max_edge_length, self.max_dimension, None

    def _extract_phase_series(self, configuration: Any) -> NDArray[np.complex128]:
        arr = np.asarray(configuration)

        if np.iscomplexobj(arr):
            flat = np.asarray(arr, dtype=np.complex128).reshape(-1)
            return flat

        real = np.asarray(arr, dtype=np.float64)
        if real.ndim == 1:
            phases = real.reshape(-1)
            return np.exp(1j * phases)

        if real.ndim == 2 and real.shape[1] >= 2:
            complex_series = real[:, 0] + 1j * real[:, 1]
            return complex_series.astype(np.complex128)

        flat = real.reshape(-1)
        return np.exp(1j * flat)

    def _snapshot_to_dict(self, snapshot: TopologySnapshot) -> dict[str, Any]:
        return {
            "betti_numbers": snapshot.betti_numbers,
            "homology_groups": snapshot.homology_groups,
            "topological_charge": snapshot.topological_charge,
        }

    def _require_gudhi(self) -> None:
        if gd is None:
            raise ModuleNotFoundError(
                "Gudhi is required for topological computations. Install with: pip install gudhi"
            )


__all__ = ["TopologicalSecurity", "TopologySnapshot"]
