import hashlib
from src.security.mpc_coordinator import (
    MPCCoordinator,
    Party,
    Computation,
    ComputationType,
    ComputationResult,
    Proof,
)


def test_initiate_mpc_session():
    coord = MPCCoordinator()
    parties = [
        Party(party_id="p1", public_key="key1"),
        Party(party_id="p2", public_key="key2"),
        Party(party_id="p3", public_key="key3"),
    ]
    comp = Computation(computation_id="c1", computation_type=ComputationType.ADDITION, inputs={"p1": b"a", "p2": b"b", "p3": b"c"})
    session = coord.initiate_mpc_session(parties, comp)
    assert session.session_id is not None
    assert len(session.parties) == 3
    assert session.byzantine_tolerance == 0  # (3-1)//3 = 0


def test_coordinate_secret_sharing():
    coord = MPCCoordinator()
    secret = b"my_secret_data"
    threshold = 2
    parties = [Party(party_id=f"p{i}", public_key=f"key{i}") for i in range(3)]
    shares_dict = coord.coordinate_secret_sharing(secret, threshold, parties)
    assert len(shares_dict) == 1
    secret_id = list(shares_dict.keys())[0]
    shares = shares_dict[secret_id]
    assert len(shares) == 3
    # verify shares are unique
    share_values = [s.share_value.hex() for s in shares]
    assert len(set(share_values)) == 3


def test_execute_mpc_computation_honest():
    coord = MPCCoordinator()
    parties = [
        Party(party_id="p1", public_key="key1", trusted=True),
        Party(party_id="p2", public_key="key2", trusted=True),
    ]
    comp = Computation(
        computation_id="c1",
        computation_type=ComputationType.ADDITION,
        inputs={"p1": b"input1", "p2": b"input2"},
    )
    session = coord.initiate_mpc_session(parties, comp)
    result = coord.execute_mpc_computation(session)
    assert result.session_id == session.session_id
    assert result.result is not None
    assert len(result.contributions) == 2


def test_execute_mpc_computation_with_byzantine():
    coord = MPCCoordinator()
    parties = [
        Party(party_id="p1", public_key="key1", trusted=True),
        Party(party_id="p2", public_key="key2", trusted=False),  # Byzantine party
        Party(party_id="p3", public_key="key3", trusted=True),
    ]
    comp = Computation(
        computation_id="c1",
        computation_type=ComputationType.ADDITION,
        inputs={"p1": b"data", "p2": b"data", "p3": b"data"},
    )
    session = coord.initiate_mpc_session(parties, comp)
    result = coord.execute_mpc_computation(session)
    malicious = coord.detect_byzantine_behavior(session)
    assert "p2" in malicious  # p2 should be detected as malicious


def test_verify_mpc_result():
    coord = MPCCoordinator()
    parties = [Party(party_id="p1", public_key="key1")]
    comp = Computation(computation_id="c1", computation_type=ComputationType.ADDITION, inputs={"p1": b"data"})
    session = coord.initiate_mpc_session(parties, comp)
    result = coord.execute_mpc_computation(session)
    # create valid proof
    result_hash = hashlib.sha256(result.result).hexdigest()
    proof = Proof(
        proof_id="proof1",
        result_hash=result_hash,
        merkle_root="root_" + result_hash[:8],
        signatures={"p1": "sig1"},
    )
    assert coord.verify_mpc_result(result, proof) is True
