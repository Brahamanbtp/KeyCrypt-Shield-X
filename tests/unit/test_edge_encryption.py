import sys
from pathlib import Path
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.integrations.iot.edge_encryption import (
    deploy_to_edge_device,
    encrypt_at_edge,
    manage_edge_keys,
    aggregate_encrypted_data,
    parse_aggregated_envelope,
    _decrypt_edge_payload,
    delta_encode,
)


def test_deploy_and_key_caching() -> None:
    device_id = "dev-1"
    res = deploy_to_edge_device(device_id, encryption_config={"key_ttl": 2})
    assert res.success

    k1 = manage_edge_keys(device_id, ttl_seconds=2)
    assert k1.success
    # re-request within TTL should return same key_id and not expire
    k2 = manage_edge_keys(device_id, ttl_seconds=2)
    assert k2.key_id == k1.key_id
    # wait until expiry
    time.sleep(2.1)
    k3 = manage_edge_keys(device_id, ttl_seconds=2)
    assert k3.key_id == device_id


def test_encrypt_decrypt_roundtrip() -> None:
    device_id = "dev-enc"
    deploy_to_edge_device(device_id)
    payload = b"temperature:24.5"
    ct = encrypt_at_edge(payload, device_id)
    pt = _decrypt_edge_payload(ct, device_id)
    assert pt == payload


def test_aggregate_and_parse() -> None:
    device_id = "dev-agg"
    deploy_to_edge_device(device_id)
    streams = [encrypt_at_edge(f"m{i}".encode(), device_id) for i in range(4)]
    env = aggregate_encrypted_data(streams)
    parsed = parse_aggregated_envelope(env)
    assert len(parsed) == 4
    for orig, got in zip(streams, parsed):
        assert orig == got


def test_delta_encoding() -> None:
    a = b"sensor:100"
    b = b"sensor:101"
    d = delta_encode(a, b)
    # simple check: decode format: first 4 bytes prefix len
    import struct

    prefix_len = struct.unpack_from(
        ">I", d, 0
    )[0]
    assert prefix_len == min(len(a), len(b))
