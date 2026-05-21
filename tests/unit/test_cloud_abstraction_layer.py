import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.integrations.multicloud.cloud_abstraction_layer import (
    initialize_cloud_provider,
    encrypt_and_store_multicloud,
    retrieve_from_multicloud,
    implement_cloud_failover,
    _get_provider,
)


def test_store_and_retrieve_across_providers() -> None:
    p1 = initialize_cloud_provider("aws", {"region": "us-west-1"})
    p2 = initialize_cloud_provider("azure", {"region": "westus"})
    data = b"The quick brown fox jumps over the lazy dog" * 10
    res = encrypt_and_store_multicloud(data, [p1.name, p2.name], chunk_size=50)
    assert res.chunks >= 1
    out = retrieve_from_multicloud(res.object_id, providers=[p1.name, p2.name])
    assert out == data


def test_failover_replication_and_retrieve_when_primary_missing() -> None:
    p1 = initialize_cloud_provider("gcp", {"region": "us-central1"})
    p2 = initialize_cloud_provider("ibm", {"region": "us-south"})
    implement_cloud_failover(p1.name, p2.name, replicate_all=True)
    data = b"important data for failover testing" * 20
    res = encrypt_and_store_multicloud(data, [p1.name], chunk_size=64)
    # simulate primary outage by clearing provider storage
    primary = _get_provider(p1.name)
    primary.storage.clear()
    out = retrieve_from_multicloud(res.object_id, providers=[p1.name, p2.name])
    assert out == data
