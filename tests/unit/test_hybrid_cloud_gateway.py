import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.integrations.multicloud.hybrid_cloud_gateway import (
    setup_hybrid_gateway,
    sync_keys_hybrid,
    route_traffic_hybrid,
    Request,
    implement_data_sovereignty,
)


def test_setup_and_sync_to_cloud():
    gw = setup_hybrid_gateway({"region": "eu-west-1"}, {"provider": "aws"})
    # ensure HSM keys exist
    assert len(gw.hsm_keys) >= 1
    res = sync_keys_hybrid(gw, direction="to_cloud")
    assert res.success
    assert res.synced_keys == len(gw.hsm_keys)
    assert len(gw.kms_keys) == len(gw.hsm_keys)


def test_route_respects_data_sovereignty_and_capacity():
    gw = setup_hybrid_gateway({"region": "eu"}, {"provider": "gcp"})
    implement_data_sovereignty(gw, {"data_region": "eu"})
    # request from EU should route to on-prem
    req = Request(path="/store", payload=b"small", region="eu")
    r = route_traffic_hybrid(gw, req)
    assert r.destination == "on_prem"

    # big payload should route to cloud due to capacity
    big = Request(path="/store", payload=b"x" * (gw.on_prem_capacity + 10), region="eu")
    rb = route_traffic_hybrid(gw, big)
    assert rb.destination == "cloud"
