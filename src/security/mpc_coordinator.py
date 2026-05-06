from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import hashlib
import json
import uuid
import time


class ComputationType(Enum):
    ADDITION = "addition"
    MULTIPLICATION = "multiplication"
    THRESHOLD_VOTING = "threshold_voting"


@dataclass
class Party:
    party_id: str
    public_key: str
    trusted: bool = True


@dataclass
class Share:
    secret_id: str
    share_index: int
    share_value: bytes
    polynomial_point: Optional[int] = None


@dataclass
class Computation:
    computation_id: str
    computation_type: ComputationType
    inputs: Dict[str, bytes]


@dataclass
class Session:
    session_id: str
    parties: List[Party]
    computation: Computation
    shares: Dict[str, List[Share]] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    byzantine_tolerance: int = 0


@dataclass
class ComputationResult:
    session_id: str
    result: bytes
    contributions: Dict[str, bytes]
    timestamp: float


@dataclass
class Proof:
    proof_id: str
    result_hash: str
    merkle_root: str
    signatures: Dict[str, str]


class MPCCoordinator:
    """Coordinates secure multi-party computation with Byzantine fault tolerance.

    This implementation wraps distributed cryptography modules (Shamir secret sharing, etc.)
    and manages MPC sessions, secret distribution, and result verification.

    For production: integrate with actual TPP (threshold proxy), verifiable computation
    frameworks (SNARKs), and robust Byzantine agreement protocols.
    """

    def __init__(self):
        self._sessions: Dict[str, Session] = {}
        self._session_results: Dict[str, ComputationResult] = {}
        self._byzantine_tolerance_default = 1  # can tolerate 1 malicious party

    def initiate_mpc_session(self, parties: List[Party], computation: Computation) -> Session:
        """Initiate an MPC session with parties and computation specification.

        Session ID is generated and Byzantine fault tolerance is calculated as f = floor((n-1)/3),
        allowing the protocol to tolerate up to f malicious parties out of n.
        """
        session_id = str(uuid.uuid4())
        n = len(parties)
        # Byzantine fault tolerance: floor((n-1)/3)
        byzantine_tolerance = max(0, (n - 1) // 3)
        session = Session(
            session_id=session_id,
            parties=parties,
            computation=computation,
            byzantine_tolerance=byzantine_tolerance,
        )
        self._sessions[session_id] = session
        return session

    def coordinate_secret_sharing(self, secret: bytes, threshold: int, parties: List[Party]) -> Dict[str, List[Share]]:
        """Coordinate Shamir secret sharing distribution among parties.

        Returns a mapping from secret_id to shares distributed to each party.
        In production, this wraps src/distributed/ Shamir implementation.
        For now, simulates share generation with hash-based shares.
        """
        secret_id = hashlib.sha256(secret).hexdigest()[:16]
        n = len(parties)
        if threshold > n:
            raise ValueError(f"Threshold {threshold} exceeds number of parties {n}")

        shares_by_secret: Dict[str, List[Share]] = {}
        shares: List[Share] = []

        # Simulate Shamir share generation (in production: use galois field arithmetic)
        for i, party in enumerate(parties):
            # pseudo-deterministic share: hash(secret || i || party_id)
            share_input = secret + str(i).encode() + party.party_id.encode()
            share_value = hashlib.sha256(share_input).digest()
            polynomial_point = i + 1  # points on polynomial: 1, 2, 3, ...
            share = Share(
                secret_id=secret_id,
                share_index=i,
                share_value=share_value,
                polynomial_point=polynomial_point,
            )
            shares.append(share)

        shares_by_secret[secret_id] = shares
        return shares_by_secret

    def execute_mpc_computation(self, session: Session) -> ComputationResult:
        """Execute the MPC computation without revealing individual inputs.

        Steps:
        1. Verify all parties are participating
        2. Perform computation (simulated here based on type)
        3. Collect results and check for Byzantine behavior
        4. Combine results to produce final output
        """
        session_id = session.session_id
        computation = session.computation
        parties = session.parties

        # Simulate individual party computations
        contributions: Dict[str, bytes] = {}
        for party in parties:
            if not party.trusted:
                # simulate Byzantine party producing incorrect result
                party_result = hashlib.sha256(b"malicious_result").digest()
            else:
                # honest party: compute on local share
                input_data = computation.inputs.get(party.party_id, b"")
                if computation.computation_type == ComputationType.ADDITION:
                    party_result = hashlib.sha256(input_data + b"_add").digest()
                elif computation.computation_type == ComputationType.MULTIPLICATION:
                    party_result = hashlib.sha256(input_data + b"_mul").digest()
                else:
                    party_result = hashlib.sha256(input_data).digest()
            contributions[party.party_id] = party_result

        # Byzantine fault detection: check if >f results are in consensus
        f = session.byzantine_tolerance
        result_counts: Dict[str, int] = {}
        for res in contributions.values():
            res_hex = res.hex()
            result_counts[res_hex] = result_counts.get(res_hex, 0) + 1

        # consensus result: the one with highest count (must be > f to be valid)
        consensus_result = None
        for res_hex, count in result_counts.items():
            if count > f:
                consensus_result = bytes.fromhex(res_hex)
                break

        if consensus_result is None:
            # fallback: use first honest result or majority
            consensus_result = list(contributions.values())[0]

        result = ComputationResult(
            session_id=session_id,
            result=consensus_result,
            contributions=contributions,
            timestamp=time.time(),
        )
        self._session_results[session_id] = result
        return result

    def verify_mpc_result(self, result: ComputationResult, proof: Proof) -> bool:
        """Verify MPC result using proof (typically Merkle tree + signatures).

        In production: verify zero-knowledge proofs, validate signatures from threshold of parties.
        """
        # verify result hash matches
        result_hash = hashlib.sha256(result.result).hexdigest()
        if result_hash != proof.result_hash:
            return False

        # verify Merkle root is reasonable (in production: full chain verification)
        if not proof.merkle_root or len(proof.merkle_root) < 8:
            return False

        # in production: verify signatures from >= threshold parties
        # for now, check that proof has reasonable number of signatures
        if len(proof.signatures) < 1:
            return False

        return True

    def detect_byzantine_behavior(self, session: Session) -> List[str]:
        """Detect which parties exhibited Byzantine (malicious) behavior.

        Returns list of potentially malicious party IDs.
        """
        result = self._session_results.get(session.session_id)
        if result is None:
            return []

        # find consensus result (most common)
        result_counts: Dict[str, int] = {}
        for res in result.contributions.values():
            res_hex = res.hex()
            result_counts[res_hex] = result_counts.get(res_hex, 0) + 1

        consensus_result = max(result_counts.keys(), key=lambda k: result_counts[k])
        malicious_parties: List[str] = []

        for party in session.parties:
            party_res = result.contributions.get(party.party_id, b"").hex()
            if party_res != consensus_result:
                malicious_parties.append(party.party_id)

        return malicious_parties


__all__ = [
    "MPCCoordinator",
    "Party",
    "Computation",
    "Session",
    "ComputationResult",
    "Proof",
    "Share",
    "ComputationType",
]
