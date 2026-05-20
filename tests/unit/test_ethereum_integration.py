import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.integrations.blockchain.ethereum_integration import EthereumBlockchainIntegration
from src.observability.audit_event_schema import AuditEvent


class _FakeFunctionCall:
    def __init__(self, result: Any) -> None:
        self._result = result

    def transact(self, tx_params: dict[str, Any]) -> Any:
        _ = tx_params
        return self._result


class _FakeContractFunctions:
    def __init__(self, tx_hash: str) -> None:
        self._tx_hash = tx_hash

    def recordBatch(self, *args: Any) -> _FakeFunctionCall:
        _ = args
        return _FakeFunctionCall(self._tx_hash)

    def recordEvent(self, *args: Any) -> _FakeFunctionCall:
        _ = args
        return _FakeFunctionCall(self._tx_hash)


class _FakeContract:
    def __init__(self, tx_hash: str, address: str) -> None:
        self.functions = _FakeContractFunctions(tx_hash)
        self.address = address

    def constructor(self) -> _FakeFunctionCall:
        return _FakeFunctionCall("0xdeployer")


class _FakeReceipt:
    def __init__(self, contract_address: str | None = None, block_number: int = 7) -> None:
        self.contractAddress = contract_address
        self.blockNumber = block_number


class _FakeEth:
    def __init__(self) -> None:
        self.contract_calls: list[dict[str, Any]] = []
        self.sent_txs: list[dict[str, Any]] = []
        self.receipts: dict[str, _FakeReceipt] = {}
        self.tx_hash = "0xabc123"

    def contract(self, *, abi: list[dict[str, Any]], bytecode: str | None = None, address: str | None = None) -> _FakeContract:
        self.contract_calls.append({"abi": abi, "bytecode": bytecode, "address": address})
        return _FakeContract(self.tx_hash, address or "0x1234567890abcdef1234567890abcdef12345678")

    def wait_for_transaction_receipt(self, tx_hash: Any) -> _FakeReceipt:
        return _FakeReceipt(contract_address="0x1234567890abcdef1234567890abcdef12345678", block_number=99)

    def get_transaction_receipt(self, tx_hash: Any) -> _FakeReceipt:
        return self.receipts.get(str(tx_hash), _FakeReceipt(block_number=99))


class _FakeWeb3:
    def __init__(self) -> None:
        self.eth = _FakeEth()


class _FakeIPFS:
    def add_json(self, payload: dict[str, Any]) -> dict[str, str]:
        return {"Hash": f"Qm{len(str(payload))}"}


def _make_event(event_id: str, *, big: bool = False) -> AuditEvent:
    resource = "/vault/records/1"
    if big:
        resource = "/vault/" + ("records/" * 400) + "1"
    return AuditEvent(
        timestamp=datetime.now(UTC),
        event_id=event_id,
        event_type="access",
        actor="alice",
        resource=resource,
        action="read",
        outcome="success",
    )


def test_deploy_log_query_and_proof_round_trip() -> None:
    web3 = _FakeWeb3()
    ipfs = _FakeIPFS()
    integration = EthereumBlockchainIntegration(web3_client=web3, ipfs_client=ipfs, batch_size=2, large_payload_threshold=50)

    address = integration.deploy_audit_contract()
    assert address.startswith("0x")

    first = _make_event("evt-1", big=True)
    second = _make_event("evt-2", big=True)

    tx1 = integration.log_event_to_blockchain(first)
    assert tx1.startswith("0x")
    tx2 = integration.log_event_to_blockchain(second)
    assert tx2.startswith("0x")

    filtered = integration.query_blockchain_audit_trail({"actor": "alice", "event_type": "access"})
    assert len(filtered) == 2

    assert integration.verify_event_integrity("evt-1") is True

    proof = integration.generate_blockchain_proof("evt-1")
    assert proof.event_id == "evt-1"
    assert proof.contract_address.startswith("0x")
    assert proof.merkle_root
    assert proof.inclusion_path


def test_batch_events_to_blockchain_and_ipfs_storage() -> None:
    web3 = _FakeWeb3()
    ipfs = _FakeIPFS()
    integration = EthereumBlockchainIntegration(web3_client=web3, ipfs_client=ipfs, batch_size=3, large_payload_threshold=10)

    events = [_make_event(f"evt-{index}", big=True) for index in range(3)]
    tx_hashes = integration.batch_events_to_blockchain(events)

    assert len(tx_hashes) == 3
    assert integration.query_blockchain_audit_trail({})
    assert integration.verify_event_integrity("evt-2") is True