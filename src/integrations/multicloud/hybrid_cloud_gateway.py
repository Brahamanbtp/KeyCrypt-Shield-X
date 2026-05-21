from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional
import secrets


@dataclass
class Gateway:
    on_prem_config: Dict[str, Any]
    cloud_config: Dict[str, Any]
    hsm_keys: Dict[str, bytes] = field(default_factory=dict)
    kms_keys: Dict[str, bytes] = field(default_factory=dict)
    policy: Optional[Dict[str, Any]] = None
    on_prem_capacity: int = 100  # arbitrary available capacity units


@dataclass
class SyncResult:
    success: bool
    synced_keys: int
    direction: str


@dataclass
class Request:
    path: str
    payload: bytes
    region: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class Response:
    destination: str
    status: int
    body: Optional[bytes] = None


@dataclass
class Policy:
    region_requirements: Dict[str, str]


def setup_hybrid_gateway(on_prem_config: Dict[str, Any], cloud_config: Dict[str, Any]) -> Gateway:
    gw = Gateway(on_prem_config=on_prem_config.copy(), cloud_config=cloud_config.copy())
    # provision a few sample keys in HSM
    for i in range(3):
        kid = f"key-{i}"
        gw.hsm_keys[kid] = secrets.token_bytes(32)
    # cloud KMS initially empty
    return gw


def sync_keys_hybrid(gw: Gateway, direction: str = "to_cloud") -> SyncResult:
    """Sync keys between on-prem HSM and cloud KMS.

    direction: 'to_cloud' or 'to_onprem'
    """
    if direction not in ("to_cloud", "to_onprem"):
        raise ValueError("direction must be 'to_cloud' or 'to_onprem'")

    synced = 0
    if direction == "to_cloud":
        for k, v in list(gw.hsm_keys.items()):
            gw.kms_keys[k] = v
            synced += 1
    else:
        for k, v in list(gw.kms_keys.items()):
            gw.hsm_keys[k] = v
            synced += 1

    return SyncResult(success=True, synced_keys=synced, direction=direction)


def route_traffic_hybrid(gw: Gateway, req: Request) -> Response:
    """Route requests to on-prem or cloud based on policy and capacity.

    Rules:
    - If policy requires region and request.region matches an on-prem region, route on-prem.
    - If on-prem capacity insufficient (payload size > capacity), route to cloud.
    - Otherwise prefer on-prem for low-latency.
    """
    # capacity-based routing: if payload size > on_prem_capacity, route to cloud
    if len(req.payload) > gw.on_prem_capacity:
        return Response(destination="cloud", status=200, body=b"routed_cloud_capacity")

    # honor data sovereignty afterwards (if capacity allows on-prem)
    if gw.policy and isinstance(gw.policy, dict):
        req_region = req.region
        if req_region:
            required = gw.policy.get("region_requirements", {})
            # if policy says certain data must remain in region X, prefer that
            for k, v in required.items():
                if k == "data_region" and v == req_region:
                    # if on-prem in same region
                    if gw.on_prem_config.get("region") == req_region:
                        return Response(destination="on_prem", status=200, body=b"routed_on_prem")
                    else:
                        return Response(destination="cloud", status=200, body=b"routed_cloud_for_sovereignty")

    # default to on-prem
    return Response(destination="on_prem", status=200, body=b"routed_on_prem_default")


def implement_data_sovereignty(gw: Gateway, region_requirements: Dict[str, str]) -> Policy:
    gw.policy = {"region_requirements": region_requirements}
    return Policy(region_requirements=region_requirements)
