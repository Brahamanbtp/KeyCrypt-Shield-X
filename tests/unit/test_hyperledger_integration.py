import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.integrations.blockchain.hyperledger_integration import FabricConfig, HyperledgerFabricIntegration, KeyEvent


class _FakeFabricClient:
    def __init__(self) -> None:
        self.created_channels: list[str] = []
        self.joined_channels: list[str] = []
        self.invocations: list[dict[str, Any]] = []
        self.connected_profile: str | None = None

    def connect(self, profile: str) -> None:
        self.connected_profile = profile

    def create_channel(self, channel_name: str) -> None:
        self.created_channels.append(channel_name)

    def join_channel(self, channel_name: str) -> None:
        self.joined_channels.append(channel_name)

    def invoke_chaincode(self, *, chaincode: str, function: str, args: list[str], channel_name: str) -> dict[str, str]:
        self.invocations.append(
            {
                "chaincode": chaincode,
                "function": function,
                "args": list(args),
                "channel_name": channel_name,
            }
        )
        return {"transaction_id": f"tx-{len(self.invocations)}"}


def test_initialize_fabric_network_and_manage_channels() -> None:
    client = _FakeFabricClient()
    integration = HyperledgerFabricIntegration(fabric_client=client)
    config = FabricConfig(network_profile_path="network.yaml", tenants=["tenant-a", "tenant-b"], channel_prefix="audit")

    network = integration.initialize_fabric_network(config)

    assert network.connected is True
    assert network.tenant_channels["tenant-a"] == "audit-tenant-a"
    assert network.tenant_channels["tenant-b"] == "audit-tenant-b"
    assert set(client.created_channels) == {"audit-tenant-a", "audit-tenant-b"}
    assert client.connected_profile == "network.yaml"


def test_record_query_invoke_and_audit_state() -> None:
    client = _FakeFabricClient()
    integration = HyperledgerFabricIntegration(fabric_client=client)
    config = FabricConfig(network_profile_path="network.yaml", tenants=["tenant-a"], channel_prefix="audit", chaincode_name="key-audit")
    integration.initialize_fabric_network(config)

    key_event = KeyEvent(
        key_id="key-1",
        tenant_id="tenant-a",
        event_type="rotation",
        actor="kms",
        timestamp=datetime.now(UTC),
        previous_key_id="key-0",
        new_key_id="key-1",
        metadata={"reason": "scheduled"},
    )

    tx_id = integration.record_key_lifecycle(key_event)
    assert tx_id.startswith("tx-")

    entry = integration.query_ledger("key-1")
    assert entry.key == "key-1"
    assert entry.channel == "audit-tenant-a"
    assert entry.integrity_hash

    response = integration.invoke_chaincode("key-audit", "auditKey", ["key-1", "rotation"])
    assert response.status == "confirmed"
    assert response.channel == "audit-tenant-a"

    report = integration.audit_blockchain_state()
    assert report.connected is True
    assert report.compliance_score == 100
    assert report.violations == []
    assert report.channel_status["tenant-a"]["compliant"] is True