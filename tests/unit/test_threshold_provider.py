"""Unit tests for src/providers/crypto/threshold_provider.py."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


def _load_module():
    module_path = PROJECT_ROOT / "src/providers/crypto/threshold_provider.py"
    spec = importlib.util.spec_from_file_location("threshold_provider_module", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load threshold_provider module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _FakeShamirBackend:
    @staticmethod
    def split_secret(secret, threshold, shares):
        return [
            {"index": i + 1, "value": secret + bytes([i + 1])}
            for i in range(shares)
        ]

    @staticmethod
    def reconstruct_secret(shares):
        # Shares are passed as (index, value_bytes); strip synthetic index suffix.
        first_value = shares[0][1]
        return first_value[:-1]


class _FakeDKGBackend:
    @staticmethod
    def distributed_key_generation(parties, threshold):
        normalized_parties = [
            {"party_id": p.party_id, "endpoint": p.endpoint}
            for p in parties
        ]
        key_shares = [
            {"index": i + 1, "value": f"dkg-share-{i + 1}"}
            for i, _ in enumerate(parties)
        ]
        return {
            "session_id": "dkg-session-1",
            "parties": normalized_parties,
            "public_key": b"dkg-public-key",
            "key_shares": key_shares,
            "vss_enabled": True,
            "metadata": {"source": "fake-dkg"},
        }


class _FakeRefreshShamirBackend(_FakeShamirBackend):
    @staticmethod
    def refresh_shares(shares, threshold, total_shares):
        return [
            {"index": i + 1, "value": f"refresh-{i + 1}"}
            for i in range(total_shares)
        ]


def test_split_and_reconstruct_roundtrip() -> None:
    module = _load_module()
    provider = module.ThresholdCryptoProvider(
        shamir_backend=_FakeShamirBackend,
        dkg_backend=_FakeDKGBackend,
    )

    key = b"threshold-secret"
    split = provider.split_key_threshold(key=key, threshold=3, shares=5)

    reconstructed = provider.reconstruct_key(split[:3])

    assert reconstructed == key
    assert len(split) == 5
    assert all(item.vss_commitment for item in split)


def test_distributed_key_generation_wraps_backend() -> None:
    module = _load_module()
    provider = module.ThresholdCryptoProvider(
        shamir_backend=_FakeShamirBackend,
        dkg_backend=_FakeDKGBackend,
    )

    parties = [
        module.Party(party_id="p1", endpoint="node1"),
        module.Party(party_id="p2", endpoint="node2"),
        module.Party(party_id="p3", endpoint="node3"),
    ]

    result = provider.distributed_key_generation(parties=parties, threshold=2)

    assert result.session_id == "dkg-session-1"
    assert result.threshold == 2
    assert result.public_key == b"dkg-public-key"
    assert len(result.key_shares) == 3


def test_vss_detects_tampered_share() -> None:
    module = _load_module()
    provider = module.ThresholdCryptoProvider(
        shamir_backend=_FakeShamirBackend,
        dkg_backend=_FakeDKGBackend,
    )

    shares = provider.split_key_threshold(key=b"abc", threshold=2, shares=3)
    tampered = module.KeyShare(
        share_id=shares[0].share_id,
        index=shares[0].index,
        value=b"tampered",
        threshold=shares[0].threshold,
        total_shares=shares[0].total_shares,
        epoch=shares[0].epoch,
        vss_commitment=shares[0].vss_commitment,
        metadata=shares[0].metadata,
        created_at=shares[0].created_at,
    )

    assert provider.verify_share_vss(shares[0]) is True
    assert provider.verify_share_vss(tampered) is False


def test_proactive_refresh_updates_epoch() -> None:
    module = _load_module()
    provider = module.ThresholdCryptoProvider(
        shamir_backend=_FakeRefreshShamirBackend,
        dkg_backend=_FakeDKGBackend,
    )

    shares = provider.split_key_threshold(key=b"abc", threshold=2, shares=3)
    refreshed = provider.proactive_refresh_shares(shares)

    assert len(refreshed) == len(shares)
    assert all(item.epoch == 1 for item in refreshed)
    assert all(item.vss_commitment for item in refreshed)


def test_key_share_serialization_roundtrip() -> None:
    module = _load_module()
    provider = module.ThresholdCryptoProvider(
        shamir_backend=_FakeShamirBackend,
        dkg_backend=_FakeDKGBackend,
    )

    share = provider.split_key_threshold(key=b"abc", threshold=2, shares=3)[0]

    serialized = provider.serialize_key_share(share)
    restored = provider.deserialize_key_share(serialized)

    assert restored.index == share.index
    assert restored.threshold == share.threshold
    assert restored.total_shares == share.total_shares
    assert provider.verify_share_vss(restored) is True
