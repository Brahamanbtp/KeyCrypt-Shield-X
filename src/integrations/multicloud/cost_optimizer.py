from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
import math
import random


@dataclass
class CostAnalysis:
    provider_costs: Dict[str, float]
    details: Dict[str, Dict[str, float]]


@dataclass
class CloudRecommendation:
    provider: str
    estimated_monthly_cost: float
    reason: str


@dataclass
class TieringPolicy:
    hot_store: str
    cold_store: str
    thresholds: Dict[str, float]


@dataclass
class MigrationTask:
    data_id: str
    from_cloud: str
    to_cloud: str
    size_bytes: int
    estimated_egress_cost: float
    estimated_ingest_cost: float


@dataclass
class MigrationPlan:
    tasks: List[MigrationTask]
    total_estimated_cost: float


# Simulated pricing database (USD per GB-month for storage, per GB egress)
_PRICING = {
    "aws": {"storage_gb_month": 0.023, "egress_per_gb": 0.09, "ingest_per_gb": 0.0},
    "azure": {"storage_gb_month": 0.0208, "egress_per_gb": 0.087, "ingest_per_gb": 0.0},
    "gcp": {"storage_gb_month": 0.020, "egress_per_gb": 0.085, "ingest_per_gb": 0.0},
    "ibm": {"storage_gb_month": 0.025, "egress_per_gb": 0.08, "ingest_per_gb": 0.0},
    "oracle": {"storage_gb_month": 0.021, "egress_per_gb": 0.05, "ingest_per_gb": 0.0},
}


def analyze_storage_costs(data_profile: Dict[str, int]) -> CostAnalysis:
    """Estimate monthly storage costs for a profile across providers.

    `data_profile` maps tier->size_bytes, e.g. {"hot": 10_000_000, "cold": 1_000_000_000}
    """
    provider_costs: Dict[str, float] = {}
    details: Dict[str, Dict[str, float]] = {}
    total_gb = {k: v / (1024 ** 3) for k, v in data_profile.items()}
    for prov, price in _PRICING.items():
        cost = 0.0
        d = {}
        for tier, gb in total_gb.items():
            # assume hot is stored in standard, cold in archival cheaper tier (50% of standard)
            multiplier = 1.0 if tier == "hot" else 0.5
            tier_cost = gb * price["storage_gb_month"] * multiplier
            d[tier] = tier_cost
            cost += tier_cost
        provider_costs[prov] = cost
        details[prov] = d
    return CostAnalysis(provider_costs=provider_costs, details=details)


def recommend_optimal_cloud(requirements: Dict[str, Any]) -> CloudRecommendation:
    """Recommend the cheapest provider satisfying simple requirements.

    requirements may contain: min_region (ignored in sim), max_monthly_cost, required_redundancy, capacity_gb
    """
    capacity_gb = requirements.get("capacity_gb", 10)
    max_cost = requirements.get("max_monthly_cost")

    best = None
    for prov, price in _PRICING.items():
        est = capacity_gb * price["storage_gb_month"]
        # apply small randomness to simulate discounts
        est *= random.uniform(0.95, 1.05)
        if max_cost is not None and est > max_cost:
            continue
        if best is None or est < best[1]:
            best = (prov, est)

    if best is None:
        raise ValueError("no provider meets requirements")

    reason = f"Estimated monthly cost ${best[1]:.2f} for {capacity_gb}GB"
    return CloudRecommendation(provider=best[0], estimated_monthly_cost=best[1], reason=reason)


def implement_tiered_storage(data_access_pattern: Dict[str, float]) -> TieringPolicy:
    """Create a simple tiering policy based on access frequency.

    `data_access_pattern` maps data_id->accesses_per_month.
    We'll put items accessed > threshold into hot tier.
    """
    # compute threshold as 25th percentile
    values = sorted(data_access_pattern.values()) if data_access_pattern else [0]
    idx = max(0, int(len(values) * 0.25))
    threshold = values[idx] if values else 0
    return TieringPolicy(hot_store="standard", cold_store="archive", thresholds={"accesses_per_month": threshold})


def schedule_data_migration(from_cloud: str, to_cloud: str, data_ids: List[str], sizes_bytes: Optional[Dict[str, int]] = None) -> MigrationPlan:
    """Schedule migration tasks and estimate egress/ingest costs.

    `sizes_bytes` is optional mapping of data_id->size.
    """
    sizes_bytes = sizes_bytes or {did: 10 * 1024 ** 3 for did in data_ids}  # default 10GB
    tasks: List[MigrationTask] = []
    total = 0.0
    from_price = _PRICING.get(from_cloud.lower())
    to_price = _PRICING.get(to_cloud.lower())
    if from_price is None or to_price is None:
        raise ValueError("unknown provider for migration")

    for did in data_ids:
        size = sizes_bytes.get(did, 10 * 1024 ** 3)
        gb = size / (1024 ** 3)
        egress = gb * from_price["egress_per_gb"]
        ingest = gb * to_price.get("ingest_per_gb", 0.0)
        task = MigrationTask(data_id=did, from_cloud=from_cloud, to_cloud=to_cloud, size_bytes=size, estimated_egress_cost=egress, estimated_ingest_cost=ingest)
        tasks.append(task)
        total += egress + ingest

    return MigrationPlan(tasks=tasks, total_estimated_cost=total)
