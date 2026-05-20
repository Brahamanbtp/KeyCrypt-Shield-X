import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.integrations.blockchain.nft_metadata import NFTMetadataIntegration
from src.sdk.client import EncryptedFile


class _FakeCall:
    def __init__(self, result: Any) -> None:
        self._result = result

    def transact(self, tx_params: dict[str, Any]) -> Any:
        _ = tx_params
        return self._result


class _FakeNFTFunctions:
    def __init__(self) -> None:
        self.minted: list[dict[str, Any]] = []
        self.transfers: list[dict[str, Any]] = []
        self.owners: dict[int, str] = {}

    def safeMint(self, to: str, token_id: int, token_uri: str | None) -> _FakeCall:
        self.minted.append({"to": to, "token_id": token_id, "token_uri": token_uri})
        self.owners[token_id] = to
        return _FakeCall(f"0xmint{len(self.minted):02x}")

    def transferFrom(self, from_owner: str, to_owner: str, token_id: int) -> _FakeCall:
        self.transfers.append({"from": from_owner, "to": to_owner, "token_id": token_id})
        self.owners[token_id] = to_owner
        return _FakeCall(f"0xtransfer{len(self.transfers):02x}")

    def ownerOf(self, token_id: int) -> _FakeCall:
        return _FakeCall(self.owners[token_id])


class _FakeContract:
    def __init__(self) -> None:
        self.functions = _FakeNFTFunctions()


class _FakeEth:
    def __init__(self) -> None:
        self.contract_calls: list[dict[str, Any]] = []
        self.contract_instance = _FakeContract()

    def contract(self, *, address: str, abi: list[dict[str, Any]]) -> _FakeContract:
        self.contract_calls.append({"address": address, "abi": abi})
        return self.contract_instance


class _FakeWeb3:
    def __init__(self) -> None:
        self.eth = _FakeEth()


def _make_encrypted_file() -> EncryptedFile:
    return EncryptedFile(
        source_path="/tmp/secret.txt",
        encrypted_path="/tmp/secret.txt.kcx.json",
        object_id="object-1",
        key_id="key-1",
        algorithm="chacha20",
        encrypted_size=128,
        metadata={"ciphertext_b64": "Y2lwaGVydGV4dA=="},
    )


def test_mint_transfer_verify_and_decrypt_with_nft() -> None:
    web3 = _FakeWeb3()
    integration = NFTMetadataIntegration(
        web3_client=web3,
        contract_address="0x1234567890abcdef1234567890abcdef12345678",
        decryptor=lambda _: b"decrypted-payload",
    )
    encrypted_file = _make_encrypted_file()

    nft_id = integration.mint_encryption_nft(encrypted_file, {"owner": "0xAaa0000000000000000000000000000000000001", "token_uri": "ipfs://metadata"})
    assert nft_id.startswith("nft-")

    assert integration.verify_nft_ownership(nft_id, "0xaaa0000000000000000000000000000000000001") is True
    assert integration.verify_nft_ownership(nft_id, "0xbbb0000000000000000000000000000000000002") is False

    tx_hash = integration.transfer_nft_ownership(nft_id, "0xBBB0000000000000000000000000000000000002")
    assert tx_hash.startswith("0x")
    assert integration.verify_nft_ownership(nft_id, "0xbbb0000000000000000000000000000000000002") is True

    decrypted = integration.decrypt_with_nft(
        nft_id,
        "0xbbb0000000000000000000000000000000000002",
    )
    assert decrypted == b"decrypted-payload"


def test_decrypt_rejects_non_owner() -> None:
    integration = NFTMetadataIntegration(decryptor=lambda _: b"decrypted-payload")
    nft_id = integration.mint_encryption_nft(
        _make_encrypted_file(),
        {"owner_address": "0xCcc0000000000000000000000000000000000003"},
    )

    try:
        integration.decrypt_with_nft(nft_id, "0xddd0000000000000000000000000000000000004")
    except PermissionError:
        assert True
    else:
        raise AssertionError("expected PermissionError")