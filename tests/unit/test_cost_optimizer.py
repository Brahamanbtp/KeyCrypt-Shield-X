import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.integrations.multicloud.cost_optimizer import (
    analyze_storage_costs,
    recommend_optimal_cloud,
    implement_tiered_storage,
    schedule_data_migration,
)


def test_analyze_storage_costs_returns_providers():
    profile = {"hot": 10 * 1024 ** 3, "cold": 100 * 1024 ** 3}
    res = analyze_storage_costs(profile)
    assert "aws" in res.provider_costs
    assert res.provider_costs["gcp"] >= 0.0


def test_recommend_optimal_cloud_picks_cheapest_within_budget():
    req = {"capacity_gb": 50, "max_monthly_cost": 2.5}
    rec = recommend_optimal_cloud(req)
    assert rec.estimated_monthly_cost <= req["max_monthly_cost"]


def test_implement_tiering_policy_threshold():
    pattern = {"a": 100, "b": 10, "c": 5, "d": 1}
    policy = implement_tiered_storage(pattern)
    assert policy.hot_store == "standard"
    assert "accesses_per_month" in policy.thresholds


def test_schedule_migration_estimates_costs():
    plan = schedule_data_migration("aws", "gcp", ["obj1", "obj2"], sizes_bytes={"obj1": 5 * 1024 ** 3, "obj2": 1 * 1024 ** 3})
    assert plan.total_estimated_cost >= 0.0
    assert len(plan.tasks) == 2
