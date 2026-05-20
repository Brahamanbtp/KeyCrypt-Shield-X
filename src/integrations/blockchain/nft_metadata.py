"""NFT integration for encryption metadata.

PRESERVE: NFT integration
EXTEND: Blockchain-based ownership

This module provides an NFT-backed access-control layer for encrypted files.
It keeps web3.py and OpenZeppelin-style contract interaction optional while
maintaining an in-memory fallback so ownership workflows can be exercised in
tests without a live chain.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Callable
import base64
import copy
import json

from src.sdk.client import EncryptedFile

try:  # pragma: no cover - optional dependency boundary
    from web3 import Web3
except Exception as exc:  # pragma: no cover - optional dependency boundary
    Web3 = None  # type: ignore[assignment]
    _WEB3_IMPORT_ERROR = exc
else:
    _WEB3_IMPORT_ERROR = None


NFTID = str
TransactionHash = str


@dataclass(frozen=True)
class NFTRecord:
    nft_id: NFTID
    token_id: int
    owner_address: str
    encrypted_file: EncryptedFile
    metadata: dict[str, Any]
    contract_address: str
    transaction_hash: TransactionHash
    token_uri: str | None
    minted_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    transfer_history: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class NFTTransferEvent:
    nft_id: NFTID
    from_owner: str
    to_owner: str
    transaction_hash: TransactionHash
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


class NFTMetadataIntegration:
    """Manage NFT-backed ownership for encrypted file metadata."""

    def __init__(
        self,
        *,
        web3_client: Any | None = None,
        provider_uri: str | None = None,
        contract_address: str | None = None,
        contract_abi: list[dict[str, Any]] | None = None,
        account_address: str | None = None,
        private_key: str | None = None,
        chain_id: int = 1,
        web3_factory: Callable[[str], Any] | None = None,
        decryptor: Callable[[EncryptedFile], bytes] | None = None,
    ) -> None:
        self._web3 = web3_client
        self._provider_uri = provider_uri
        self._contract_address = contract_address
        self._contract_abi = list(contract_abi or self._default_contract_abi())
        self._account_address = account_address
        self._private_key = private_key
        self._chain_id = chain_id
        self._web3_factory = web3_factory
        self._decryptor = decryptor

        self._contract = None
        self._records: dict[NFTID, NFTRecord] = {}
        self._token_owner_index: dict[int, str] = {}
        self._transfer_events: list[NFTTransferEvent] = []

    def mint_encryption_nft(self, encrypted_file: EncryptedFile, metadata: dict) -> NFTID:
        """Mint NFT representing encrypted file ownership."""
        self._require_encrypted_file(encrypted_file)

        owner_address = self._resolve_owner(metadata, encrypted_file)
        token_uri = self._resolve_token_uri(metadata, encrypted_file)
        metadata_snapshot = copy.deepcopy(metadata or {})

        nft_id, token_id = self._derive_nft_identity(encrypted_file, owner_address, metadata_snapshot)
        contract_address = self._ensure_contract_address()
        tx_hash = self._mint_on_chain(contract_address, token_id, owner_address, token_uri)

        record = NFTRecord(
            nft_id=nft_id,
            token_id=token_id,
            owner_address=owner_address,
            encrypted_file=copy.deepcopy(encrypted_file),
            metadata=metadata_snapshot,
            contract_address=contract_address,
            transaction_hash=tx_hash,
            token_uri=token_uri,
        )
        self._records[nft_id] = record
        self._token_owner_index[token_id] = owner_address
        return nft_id

    def transfer_nft_ownership(self, nft_id: str, new_owner: str) -> TransactionHash:
        """Transfers encrypted file ownership via NFT."""
        record = self._require_record(nft_id)
        normalized_new_owner = self._normalize_address(new_owner)
        previous_owner = record.owner_address

        tx_hash = self._transfer_on_chain(record, normalized_new_owner)
        updated_record = NFTRecord(
            nft_id=record.nft_id,
            token_id=record.token_id,
            owner_address=normalized_new_owner,
            encrypted_file=record.encrypted_file,
            metadata=copy.deepcopy(record.metadata),
            contract_address=record.contract_address,
            transaction_hash=tx_hash,
            token_uri=record.token_uri,
            minted_at=record.minted_at,
            transfer_history=[
                *record.transfer_history,
                {
                    "from_owner": previous_owner,
                    "to_owner": normalized_new_owner,
                    "transaction_hash": tx_hash,
                    "timestamp": datetime.now(UTC).isoformat(),
                },
            ],
        )
        self._records[nft_id] = updated_record
        self._token_owner_index[record.token_id] = normalized_new_owner
        self._transfer_events.append(
            NFTTransferEvent(
                nft_id=record.nft_id,
                from_owner=previous_owner,
                to_owner=normalized_new_owner,
                transaction_hash=tx_hash,
            )
        )
        return tx_hash

    def verify_nft_ownership(self, nft_id: str, claimed_owner: str) -> bool:
        """Verifies ownership claim."""
        record = self._records.get(nft_id)
        if record is None:
            return False
        return record.owner_address == self._normalize_address(claimed_owner)

    def decrypt_with_nft(self, nft_id: str, wallet_address: str) -> bytes:
        """Decrypts file if caller owns NFT."""
        record = self._require_record(nft_id)
        normalized_wallet = self._normalize_address(wallet_address)

        if not self.verify_nft_ownership(nft_id, normalized_wallet):
            raise PermissionError("wallet does not own this NFT")

        if self._decryptor is not None:
            return self._decryptor(record.encrypted_file)

        payload = record.encrypted_file.metadata.get("decrypted_bytes_b64")
        if isinstance(payload, str) and payload:
            return base64.b64decode(payload.encode("ascii"))

        fallback_plaintext = record.encrypted_file.metadata.get("plaintext_bytes")
        if isinstance(fallback_plaintext, bytes):
            return fallback_plaintext

        raise RuntimeError("no decryptor configured for NFT-backed decryption")

    def _mint_on_chain(self, contract_address: str, token_id: int, owner_address: str, token_uri: str | None) -> TransactionHash:
        contract = self._get_contract(contract_address)
        tx_hash = self._local_transaction_hash("mint", contract_address, token_id, owner_address, token_uri)

        if contract is None:
            return tx_hash

        minted = self._invoke_contract_function(
            contract,
            ("safeMint", "mintNFT", "mint"),
            owner_address,
            token_id,
            token_uri,
        )
        return self._normalize_transaction_hash(minted, tx_hash)

    def _transfer_on_chain(self, record: NFTRecord, new_owner: str) -> TransactionHash:
        contract = self._get_contract(record.contract_address)
        tx_hash = self._local_transaction_hash("transfer", record.contract_address, record.token_id, record.owner_address, new_owner)

        if contract is None:
            return tx_hash

        transferred = self._invoke_contract_function(
            contract,
            ("transferFrom", "safeTransferFrom"),
            record.owner_address,
            new_owner,
            record.token_id,
        )
        return self._normalize_transaction_hash(transferred, tx_hash)

    def _invoke_contract_function(self, contract: Any, candidates: tuple[str, ...], *args: Any) -> Any:
        functions = getattr(contract, "functions", None)
        if functions is None:
            return None

        for name in candidates:
            function = getattr(functions, name, None)
            if function is None:
                continue
            try:
                call = function(*args)
            except TypeError:
                try:
                    call = function(*[arg for arg in args if arg is not None])
                except Exception:
                    continue
            except Exception:
                continue

            for method_name in ("transact", "build_transaction", "call"):
                method = getattr(call, method_name, None)
                if callable(method):
                    try:
                        if method_name == "call":
                            return method()
                        tx_params = self._build_tx_params()
                        return method(tx_params)
                    except TypeError:
                        try:
                            return method()
                        except Exception:
                            continue
                    except Exception:
                        continue
            return call

        return None

    def _get_contract(self, contract_address: str) -> Any | None:
        if self._web3 is None:
            self._web3 = self._build_web3_client()

        if self._web3 is None:
            return None

        if self._contract is not None:
            return self._contract

        if hasattr(self._web3.eth, "contract"):
            self._contract = self._web3.eth.contract(address=contract_address, abi=self._contract_abi)
        return self._contract

    def _build_web3_client(self) -> Any | None:
        if self._web3_factory is not None and self._provider_uri:
            return self._web3_factory(self._provider_uri)
        if Web3 is None or self._provider_uri is None:
            return None
        return Web3(Web3.HTTPProvider(self._provider_uri))

    def _ensure_contract_address(self) -> str:
        if self._contract_address:
            return self._contract_address
        seed = json.dumps({"collection": self._contract_abi, "account": self._account_address, "chain_id": self._chain_id}, sort_keys=True, default=str).encode("utf-8")
        self._contract_address = "0x" + sha256(seed).hexdigest()[:40]
        return self._contract_address

    def _build_tx_params(self) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if self._account_address is not None:
            params["from"] = self._account_address
        if self._chain_id is not None:
            params["chainId"] = self._chain_id
        return params

    def _normalize_transaction_hash(self, value: Any, fallback: TransactionHash) -> TransactionHash:
        if isinstance(value, str) and value:
            return value if value.startswith("0x") else f"0x{sha256(value.encode('utf-8')).hexdigest()}"
        if isinstance(value, dict):
            for key in ("transactionHash", "transaction_hash", "tx_hash", "hash"):
                candidate = value.get(key)
                if isinstance(candidate, str) and candidate:
                    return candidate
        return fallback

    def _derive_nft_identity(
        self,
        encrypted_file: EncryptedFile,
        owner_address: str,
        metadata: dict[str, Any],
    ) -> tuple[NFTID, int]:
        payload = json.dumps(
            {
                "source_path": encrypted_file.source_path,
                "encrypted_path": encrypted_file.encrypted_path,
                "object_id": encrypted_file.object_id,
                "key_id": encrypted_file.key_id,
                "algorithm": encrypted_file.algorithm,
                "encrypted_size": encrypted_file.encrypted_size,
                "owner": owner_address,
                "metadata": metadata,
            },
            sort_keys=True,
            default=str,
        ).encode("utf-8")
        digest = sha256(payload).hexdigest()
        token_id = int(digest, 16)
        nft_id = f"nft-{digest[:32]}"
        return nft_id, token_id

    def _resolve_owner(self, metadata: dict[str, Any], encrypted_file: EncryptedFile) -> str:
        for key in ("owner", "owner_address", "wallet_address", "recipient", "beneficiary"):
            value = metadata.get(key)
            if isinstance(value, str) and value.strip():
                return self._normalize_address(value)

        for key in ("owner", "owner_address", "wallet_address"):
            value = encrypted_file.metadata.get(key)
            if isinstance(value, str) and value.strip():
                return self._normalize_address(value)

        raise ValueError("metadata must include an owner or wallet_address")

    def _resolve_token_uri(self, metadata: dict[str, Any], encrypted_file: EncryptedFile) -> str | None:
        for source in (metadata, encrypted_file.metadata):
            value = source.get("token_uri")
            if isinstance(value, str) and value.strip():
                return value.strip()
        return None

    def _normalize_address(self, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("address must be a non-empty string")
        if Web3 is not None:
            try:
                return Web3.to_checksum_address(normalized)
            except Exception:
                pass
        return normalized.lower()

    def _require_record(self, nft_id: str) -> NFTRecord:
        record = self._records.get(nft_id)
        if record is None:
            raise KeyError(f"NFT not found: {nft_id}")
        return record

    def _require_encrypted_file(self, encrypted_file: EncryptedFile) -> None:
        if not isinstance(encrypted_file, EncryptedFile):
            raise TypeError("encrypted_file must be EncryptedFile")

    def _local_transaction_hash(self, action: str, contract_address: str, *parts: Any) -> TransactionHash:
        payload = json.dumps({"action": action, "contract_address": contract_address, "parts": parts}, sort_keys=True, default=str).encode("utf-8")
        return "0x" + sha256(payload).hexdigest()

    def _default_contract_abi(self) -> list[dict[str, Any]]:
        return [
            {
                "inputs": [
                    {"internalType": "address", "name": "to", "type": "address"},
                    {"internalType": "uint256", "name": "tokenId", "type": "uint256"},
                    {"internalType": "string", "name": "tokenURI", "type": "string"},
                ],
                "name": "safeMint",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function",
            },
            {
                "inputs": [{"internalType": "uint256", "name": "tokenId", "type": "uint256"}],
                "name": "ownerOf",
                "outputs": [{"internalType": "address", "name": "", "type": "address"}],
                "stateMutability": "view",
                "type": "function",
            },
            {
                "inputs": [
                    {"internalType": "address", "name": "from", "type": "address"},
                    {"internalType": "address", "name": "to", "type": "address"},
                    {"internalType": "uint256", "name": "tokenId", "type": "uint256"},
                ],
                "name": "transferFrom",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function",
            },
            {
                "inputs": [{"internalType": "uint256", "name": "tokenId", "type": "uint256"}],
                "name": "tokenURI",
                "outputs": [{"internalType": "string", "name": "", "type": "string"}],
                "stateMutability": "view",
                "type": "function",
            },
        ]


__all__ = [
    "NFTID",
    "TransactionHash",
    "NFTRecord",
    "NFTTransferEvent",
    "NFTMetadataIntegration",
]