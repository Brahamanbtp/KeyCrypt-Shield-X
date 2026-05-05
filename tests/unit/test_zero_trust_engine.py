import time

from src.security.zero_trust_engine import (
    ZeroTrustEngine,
    DevicePosture,
    SecurityContext,
    User,
    Resource,
    Request,
)


def test_verify_every_request_allows_owner_with_good_posture():
    engine = ZeroTrustEngine()
    device = DevicePosture(os_version="11", antivirus_running=True, patch_level="2026-01-01")
    ctx = SecurityContext(device=device, user_behavior_score=0.0, location_risk=0.0)
    user = User(user_id="alice", roles=["admin"], groups=["devs"])
    resource = Resource(resource_id="res1", owner="alice", allowed_groups=["ops"])
    sid = engine.create_session(authenticated=True)
    req = Request(request_id="r1", user=user, resource=resource, headers={"X-Session-Id": sid}, context=ctx)
    res = engine.verify_every_request(req)
    assert res.success is True
    assert res.trust_score == 100.0


def test_verify_every_request_denies_by_segmentation_and_low_trust():
    engine = ZeroTrustEngine()
    device = DevicePosture(os_version="9", antivirus_running=False, patch_level="old")
    ctx = SecurityContext(device=device, user_behavior_score=0.9, location_risk=0.9)
    user = User(user_id="bob", roles=["user"], groups=["sales"])
    resource = Resource(resource_id="res2", owner="alice", allowed_groups=["devs"])
    sid = engine.create_session(authenticated=True)
    req = Request(request_id="r2", user=user, resource=resource, headers={"X-Session-Id": sid}, context=ctx)
    res = engine.verify_every_request(req)
    assert res.success is False
    # should indicate segmentation deny and low trust
    assert "micro_segmentation_deny" in res.reasons
    assert "low_trust_score" in res.reasons


def test_continuous_authentication_requires_reauth_after_timeout():
    engine = ZeroTrustEngine()
    sid = engine.create_session(authenticated=True)
    # simulate old last_verified
    engine._sessions[sid].last_verified = time.time() - (16 * 60)
    status = engine.continuous_authentication(sid)
    assert status.authenticated is False
    assert status.reason == "reauth_required"
