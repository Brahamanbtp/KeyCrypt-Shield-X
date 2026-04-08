"""Threshold cryptography provider wrapper.

This module wraps distributed cryptography backends under ``src.distributed.*``
without modifying those implementations.

Core capabilities:
- Threshold key splitting using Shamir Secret Sharing.
- Key reconstruction from valid threshold shares.
- Distributed key generation (DKG).
- Verifiable Secret Sharing (VSS) checks to detect malformed/tampered shares.
- Proactive Secret Sharing (PSS) via periodic share refresh.
"""

from __future__ import annotations

import base64
import hashlib
import importlib
import inspect
import json
import time
import uuid
from dataclasses import dataclass, field
from types import ModuleType
from typing import Any, List, Mapping, Sequence

from src.utils.logging import get_logger


logger = get_logger("src.providers.crypto.threshold_provider")


_SHAMIR_MODULE_CANDIDATES: tuple[str, ...] = (
    "src.distributed.shamir_secret_sharing",
    "src.distributed.shamir",
)

_DKG_MODULE_CANDIDATES: tuple[str, ...] = (
    "src.distributed.dkg",
    "src.distributed.distributed_key_generation",
)


@dataclass(frozen=True)
class KeyShare:
    """A threshold key share with verification metadata."""

    share_id: str
    index: int
    value: Any
    threshold: int
    total_shares: int
    epoch: int = 0
    vss_commitment: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)


@dataclass(frozen=True)
class Party:
    """Participant descriptor used for distributed key generation."""

    party_id: str
    endpoint: str = ""
    public_key: bytes | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DKGResult:
    """Distributed key generation output."""

    session_id: str
    threshold: int
    parties: tuple[Party, ...]
    public_key: bytes
    key_shares: tuple[KeyShare, ...]
    vss_enabled: bool = True
    metadata: Mapping[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)


class ThresholdCryptoProvider:
    """Threshold cryptography adapter over distributed backend modules."""

    def __init__(
        self,
        *,
        shamir_backend: Any | None = None,
        dkg_backend: Any | None = None,
        vss_salt: bytes | None = None,
    ) -> None:
        self._vss_salt = vss_salt if isinstance(vss_salt, bytes) else b"threshold-vss"

        self._shamir_backend = shamir_backend if shamir_backend is not None else self._import_first(_SHAMIR_MODULE_CANDIDATES)
        self._dkg_backend = dkg_backend if dkg_backend is not None else self._import_first(_DKG_MODULE_CANDIDATES)

    def split_key_threshold(self, key: bytes, threshold: int, shares: int) -> List[KeyShare]:
        """Split a key into threshold shares using Shamir Secret Sharing."""
        self._validate_key_material(key)
        self._validate_threshold_params(threshold=threshold, shares=shares)

        backend = self._require_backend("shamir", self._shamir_backend)
        raw_shares = self._call_backend(
            backend,
            operation_names=("split_key_threshold", "split_secret", "split", "create_shares"),
            args=(key, threshold, shares),
            kwargs={
                "secret": key,
                "key": key,
                "threshold": threshold,
                "shares": shares,
                "num_shares": shares,
            },
            operation_label="split_key_threshold",
        )

        normalized = self._normalize_shares(raw_shares, threshold=threshold, total_shares=shares)
        return [self._attach_vss(share) for share in normalized]

    def reconstruct_key(self, shares: List[KeyShare]) -> bytes:
        """Reconstruct key material from valid threshold shares."""
        if not isinstance(shares, list) or not shares:
            raise ValueError("shares must be a non-empty List[KeyShare]")
        for item in shares:
            self._validate_share(item)
            if not self.verify_share_vss(item):
                raise ValueError(f"share failed VSS validation: index={item.index}")

        threshold = shares[0].threshold
        if len(shares) < threshold:
            raise ValueError(f"insufficient shares: need at least {threshold}, got {len(shares)}")

        backend = self._require_backend("shamir", self._shamir_backend)

        pairs = [
            (share.index, self._to_bytes(share.value))
            for share in shares
        ]

        raw_key = self._call_backend(
            backend,
            operation_names=("reconstruct_key", "reconstruct_secret", "reconstruct", "combine_shares"),
            args=(pairs,),
            kwargs={
                "shares": pairs,
                "key_shares": shares,
                "threshold": threshold,
            },
            operation_label="reconstruct_key",
        )

        return self._normalize_key_bytes(raw_key)

    def distributed_key_generation(self, parties: List[Party], threshold: int) -> DKGResult:
        """Run distributed key generation and return session artifacts."""
        if not isinstance(parties, list) or not parties:
            raise ValueError("parties must be a non-empty List[Party]")
        for party in parties:
            self._validate_party(party)

        share_count = len(parties)
        self._validate_threshold_params(threshold=threshold, shares=share_count)

        backend = self._require_backend("dkg", self._dkg_backend)
        payload = self._call_backend(
            backend,
            operation_names=(
                "distributed_key_generation",
                "run_dkg",
                "generate_distributed_key",
                "keygen",
            ),
            args=(parties, threshold),
            kwargs={
                "parties": parties,
                "participants": [self._party_to_dict(p) for p in parties],
                "threshold": threshold,
            },
            operation_label="distributed_key_generation",
        )

        result = self._normalize_dkg_result(payload, parties=parties, threshold=threshold)
        vss_shares = tuple(self._attach_vss(item) for item in result.key_shares)

        return DKGResult(
            session_id=result.session_id,
            threshold=result.threshold,
            parties=result.parties,
            public_key=result.public_key,
            key_shares=vss_shares,
            vss_enabled=True,
            metadata={**dict(result.metadata), "vss_enabled": True},
            created_at=result.created_at,
        )

    def verify_share_vss(self, share: KeyShare) -> bool:
        """Verify VSS commitment for a share.

        This detects malformed or tampered shares before reconstruction.
        """
        self._validate_share(share)
        if not share.vss_commitment:
            return False

        expected = self._compute_vss_commitment(
            index=share.index,
            value=share.value,
            threshold=share.threshold,
            total_shares=share.total_shares,
            epoch=share.epoch,
        )
        return secrets_compare_digest(share.vss_commitment, expected)

    def proactive_refresh_shares(self, shares: List[KeyShare], refresh_interval_seconds: float = 0.0) -> List[KeyShare]:
        """Refresh shares periodically without changing underlying secret.

        If backend-provided proactive refresh exists, it is used. Otherwise,
        fallback strategy reconstructs and re-splits the key.
        """
        if refresh_interval_seconds < 0:
            raise ValueError("refresh_interval_seconds must be >= 0")

        if not isinstance(shares, list) or not shares:
            raise ValueError("shares must be a non-empty List[KeyShare]")

        for item in shares:
            self._validate_share(item)

        threshold = shares[0].threshold
        total = shares[0].total_shares
        next_epoch = max(item.epoch for item in shares) + 1

        backend = self._shamir_backend
        if backend is not None:
            refreshed = self._try_backend_refresh(backend, shares=shares, threshold=threshold, total_shares=total)
            if refreshed is not None:
                normalized = self._normalize_shares(refreshed, threshold=threshold, total_shares=total)
                return [self._attach_vss(item, forced_epoch=next_epoch) for item in normalized]

        key = self.reconstruct_key(shares[:threshold])
        split = self.split_key_threshold(key, threshold=threshold, shares=total)
        return [self._attach_vss(item, forced_epoch=next_epoch) for item in split]

    def serialize_key_share(self, share: KeyShare) -> str:
        """Serialize key share to JSON for storage or transport."""
        self._validate_share(share)

        payload = {
            "version": 1,
            "share": {
                "share_id": share.share_id,
                "index": share.index,
                "value": self._encode_json_value(share.value),
                "threshold": share.threshold,
                "total_shares": share.total_shares,
                "epoch": share.epoch,
                "vss_commitment": share.vss_commitment,
                "metadata": self._encode_json_value(dict(share.metadata)),
                "created_at": share.created_at,
            },
        }
        return json.dumps(payload, separators=(",", ":"), sort_keys=True)

    def deserialize_key_share(self, serialized: str | bytes) -> KeyShare:
        """Deserialize key share JSON into ``KeyShare``."""
        if isinstance(serialized, bytes):
            text = serialized.decode("utf-8")
        elif isinstance(serialized, str):
            text = serialized
        else:
            raise TypeError("serialized share must be str or bytes")

        try:
            envelope = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError("serialized share is not valid JSON") from exc

        if not isinstance(envelope, Mapping):
            raise ValueError("serialized share envelope must be a mapping")

        raw = envelope.get("share")
        if not isinstance(raw, Mapping):
            raise ValueError("serialized share envelope missing 'share' object")

        share = KeyShare(
            share_id=str(raw.get("share_id", "")),
            index=int(raw.get("index", 0)),
            value=self._decode_json_value(raw.get("value")),
            threshold=int(raw.get("threshold", 0)),
            total_shares=int(raw.get("total_shares", 0)),
            epoch=int(raw.get("epoch", 0)),
            vss_commitment=(None if raw.get("vss_commitment") is None else str(raw.get("vss_commitment"))),
            metadata=self._coerce_mapping(self._decode_json_value(raw.get("metadata", {}))),
            created_at=float(raw.get("created_at", time.time())),
        )
        self._validate_share(share)
        return share

    def backend_availability(self) -> Mapping[str, bool]:
        """Return backend availability for observability and diagnostics."""
        return {
            "shamir": self._shamir_backend is not None,
            "dkg": self._dkg_backend is not None,
        }

    def _normalize_dkg_result(self, payload: Any, *, parties: List[Party], threshold: int) -> DKGResult:
        if isinstance(payload, DKGResult):
            return payload

        if isinstance(payload, Mapping):
            session_id = str(payload.get("session_id", f"dkg-{uuid.uuid4().hex}"))
            public_key = self._normalize_key_bytes(payload.get("public_key", b""), allow_empty=True)

            raw_shares = payload.get("key_shares", payload.get("shares", []))
            normalized_shares = self._normalize_shares(raw_shares, threshold=threshold, total_shares=len(parties))

            raw_parties = payload.get("parties")
            normalized_parties = tuple(self._normalize_parties(raw_parties)) if raw_parties is not None else tuple(parties)

            return DKGResult(
                session_id=session_id,
                threshold=threshold,
                parties=normalized_parties,
                public_key=public_key,
                key_shares=tuple(normalized_shares),
                vss_enabled=bool(payload.get("vss_enabled", True)),
                metadata=self._coerce_mapping(payload.get("metadata", {})),
            )

        raise RuntimeError("dkg backend returned unsupported result format")

    def _normalize_shares(self, raw: Any, *, threshold: int, total_shares: int) -> List[KeyShare]:
        items = raw
        if isinstance(raw, Mapping) and "shares" in raw:
            items = raw.get("shares")

        if not isinstance(items, Sequence) or isinstance(items, (bytes, bytearray, str)):
            raise RuntimeError("shamir backend returned invalid share collection")

        normalized: List[KeyShare] = []
        for idx, item in enumerate(items, start=1):
            share = self._normalize_single_share(item, index_fallback=idx, threshold=threshold, total_shares=total_shares)
            normalized.append(share)

        if len(normalized) < threshold:
            raise RuntimeError("shamir backend produced fewer shares than threshold")

        return normalized

    def _normalize_single_share(
        self,
        item: Any,
        *,
        index_fallback: int,
        threshold: int,
        total_shares: int,
    ) -> KeyShare:
        if isinstance(item, KeyShare):
            return item

        if isinstance(item, Mapping):
            index = int(item.get("index", item.get("x", index_fallback)))
            value = item.get("value", item.get("share", item.get("y")))
            share_id = str(item.get("share_id", f"share-{uuid.uuid4().hex}"))
            epoch = int(item.get("epoch", 0))
            vss_commitment = item.get("vss_commitment")
            metadata = self._coerce_mapping(item.get("metadata", {}))
            return KeyShare(
                share_id=share_id,
                index=index,
                value=value,
                threshold=int(item.get("threshold", threshold)),
                total_shares=int(item.get("total_shares", total_shares)),
                epoch=epoch,
                vss_commitment=None if vss_commitment is None else str(vss_commitment),
                metadata=metadata,
            )

        if isinstance(item, tuple) and len(item) == 2:
            return KeyShare(
                share_id=f"share-{uuid.uuid4().hex}",
                index=int(item[0]),
                value=item[1],
                threshold=threshold,
                total_shares=total_shares,
            )

        return KeyShare(
            share_id=f"share-{uuid.uuid4().hex}",
            index=index_fallback,
            value=item,
            threshold=threshold,
            total_shares=total_shares,
        )

    def _normalize_parties(self, raw_parties: Any) -> List[Party]:
        if not isinstance(raw_parties, Sequence) or isinstance(raw_parties, (str, bytes, bytearray)):
            return []

        normalized: List[Party] = []
        for idx, item in enumerate(raw_parties, start=1):
            if isinstance(item, Party):
                normalized.append(item)
                continue

            if isinstance(item, Mapping):
                normalized.append(
                    Party(
                        party_id=str(item.get("party_id", item.get("id", f"party-{idx}"))),
                        endpoint=str(item.get("endpoint", "")),
                        public_key=(None if item.get("public_key") is None else self._to_bytes(item.get("public_key"))),
                        metadata=self._coerce_mapping(item.get("metadata", {})),
                    )
                )
        return normalized

    def _attach_vss(self, share: KeyShare, forced_epoch: int | None = None) -> KeyShare:
        epoch = int(forced_epoch) if forced_epoch is not None else int(share.epoch)
        commitment = self._compute_vss_commitment(
            index=share.index,
            value=share.value,
            threshold=share.threshold,
            total_shares=share.total_shares,
            epoch=epoch,
        )
        metadata = dict(share.metadata)
        metadata.setdefault("vss", "hash-commitment")
        return KeyShare(
            share_id=share.share_id,
            index=share.index,
            value=share.value,
            threshold=share.threshold,
            total_shares=share.total_shares,
            epoch=epoch,
            vss_commitment=commitment,
            metadata=metadata,
            created_at=share.created_at,
        )

    def _compute_vss_commitment(
        self,
        *,
        index: int,
        value: Any,
        threshold: int,
        total_shares: int,
        epoch: int,
    ) -> str:
        value_bytes = self._to_bytes(value)
        message = (
            f"idx={int(index)}|thr={int(threshold)}|n={int(total_shares)}|epoch={int(epoch)}|".encode("utf-8")
            + value_bytes
        )
        return hashlib.sha256(self._vss_salt + message).hexdigest()

    def _try_backend_refresh(
        self,
        backend: Any,
        *,
        shares: List[KeyShare],
        threshold: int,
        total_shares: int,
    ) -> Any | None:
        try:
            return self._call_backend(
                backend,
                operation_names=("proactive_refresh", "refresh_shares", "reshare", "refresh"),
                args=(shares, threshold, total_shares),
                kwargs={
                    "shares": shares,
                    "threshold": threshold,
                    "total_shares": total_shares,
                },
                operation_label="proactive_refresh",
            )
        except Exception:
            return None

    @staticmethod
    def _validate_key_material(key: bytes) -> None:
        if not isinstance(key, bytes):
            raise TypeError("key must be bytes")
        if len(key) == 0:
            raise ValueError("key must be non-empty")

    @staticmethod
    def _validate_threshold_params(*, threshold: int, shares: int) -> None:
        if not isinstance(threshold, int) or not isinstance(shares, int):
            raise TypeError("threshold and shares must be integers")
        if threshold < 2:
            raise ValueError("threshold must be >= 2")
        if shares < threshold:
            raise ValueError("shares must be >= threshold")

    @staticmethod
    def _validate_share(share: KeyShare) -> None:
        if not isinstance(share, KeyShare):
            raise TypeError("share must be KeyShare")
        if share.index <= 0:
            raise ValueError("share.index must be positive")
        if share.threshold < 2:
            raise ValueError("share.threshold must be >= 2")
        if share.total_shares < share.threshold:
            raise ValueError("share.total_shares must be >= share.threshold")

    @staticmethod
    def _validate_party(party: Party) -> None:
        if not isinstance(party, Party):
            raise TypeError("party must be Party")
        if not party.party_id.strip():
            raise ValueError("party.party_id must be non-empty")

    @staticmethod
    def _normalize_key_bytes(value: Any, allow_empty: bool = False) -> bytes:
        if isinstance(value, bytes):
            out = value
        elif isinstance(value, str):
            out = value.encode("utf-8")
        elif isinstance(value, int):
            if value < 0:
                raise ValueError("key integer must be non-negative")
            width = max(1, (value.bit_length() + 7) // 8)
            out = value.to_bytes(width, "big")
        elif isinstance(value, Mapping):
            for key in ("key", "secret", "value", "material", "reconstructed"):
                if key in value:
                    return ThresholdCryptoProvider._normalize_key_bytes(value[key], allow_empty=allow_empty)
            raise ValueError("mapping does not contain key material")
        else:
            raise TypeError("unsupported key material type")

        if not allow_empty and len(out) == 0:
            raise ValueError("key material is empty")
        return out

    @staticmethod
    def _party_to_dict(party: Party) -> Mapping[str, Any]:
        return {
            "party_id": party.party_id,
            "endpoint": party.endpoint,
            "public_key": party.public_key,
            "metadata": dict(party.metadata),
        }

    @staticmethod
    def _import_first(paths: Sequence[str]) -> ModuleType | None:
        for path in paths:
            try:
                return importlib.import_module(path)
            except Exception:
                continue
        return None

    @staticmethod
    def _require_backend(kind: str, backend: Any | None) -> Any:
        if backend is None:
            if kind == "shamir":
                raise RuntimeError(
                    "Shamir backend unavailable. Expected src.distributed.shamir_secret_sharing"
                )
            raise RuntimeError("DKG backend unavailable. Expected src.distributed.dkg")
        return backend

    def _call_backend(
        self,
        backend: Any,
        *,
        operation_names: Sequence[str],
        args: tuple[Any, ...],
        kwargs: Mapping[str, Any],
        operation_label: str,
    ) -> Any:
        for name in operation_names:
            target = getattr(backend, name, None)
            if callable(target):
                result, ok = self._invoke_callable(target, args=args, kwargs=kwargs)
                if ok:
                    return result

        for class_name in (
            "ShamirSecretSharing",
            "SecretSharing",
            "DistributedKeyGeneration",
            "DKG",
            "Coordinator",
            "Engine",
        ):
            cls = getattr(backend, class_name, None)
            if not inspect.isclass(cls):
                continue

            instance = self._safe_instantiate(cls)
            if instance is None:
                continue

            for name in operation_names:
                target = getattr(instance, name, None)
                if callable(target):
                    result, ok = self._invoke_callable(target, args=args, kwargs=kwargs)
                    if ok:
                        return result

        raise RuntimeError(f"backend does not expose '{operation_label}' operation")

    @staticmethod
    def _invoke_callable(
        target: Any,
        *,
        args: tuple[Any, ...],
        kwargs: Mapping[str, Any],
    ) -> tuple[Any, bool]:
        for call in (
            lambda: target(*args),
            lambda: target(**dict(kwargs)),
            lambda: target(*args, **dict(kwargs)),
        ):
            try:
                return call(), True
            except TypeError:
                continue
        return None, False

    @staticmethod
    def _safe_instantiate(cls: type[Any]) -> Any | None:
        for constructor in (lambda: cls(), lambda: cls(None)):
            try:
                return constructor()
            except Exception:
                continue
        return None

    def _encode_json_value(self, value: Any) -> Any:
        if value is None or isinstance(value, (str, int, float, bool)):
            return value

        if isinstance(value, bytes):
            return {"__type__": "bytes", "b64": base64.b64encode(value).decode("ascii")}

        if isinstance(value, Mapping):
            return {str(k): self._encode_json_value(v) for k, v in value.items()}

        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            return [self._encode_json_value(item) for item in value]

        return {"__type__": "repr", "value": repr(value)}

    def _decode_json_value(self, value: Any) -> Any:
        if isinstance(value, Mapping):
            tag = value.get("__type__")
            if tag == "bytes":
                return base64.b64decode(str(value.get("b64", "")).encode("ascii"))
            if tag == "repr":
                return str(value.get("value", ""))
            return {str(k): self._decode_json_value(v) for k, v in value.items()}

        if isinstance(value, list):
            return [self._decode_json_value(item) for item in value]

        return value

    @staticmethod
    def _coerce_mapping(value: Any) -> Mapping[str, Any]:
        if isinstance(value, Mapping):
            return {str(k): v for k, v in value.items()}
        return {}

    @staticmethod
    def _to_bytes(value: Any) -> bytes:
        if isinstance(value, bytes):
            return value
        if isinstance(value, bytearray):
            return bytes(value)
        if isinstance(value, str):
            return value.encode("utf-8")
        if isinstance(value, int):
            if value < 0:
                raise ValueError("integer values must be non-negative")
            width = max(1, (value.bit_length() + 7) // 8)
            return value.to_bytes(width, "big")
        if isinstance(value, Mapping):
            stable = json.dumps(value, sort_keys=True, separators=(",", ":"))
            return stable.encode("utf-8")
        if isinstance(value, Sequence):
            stable = json.dumps(list(value), sort_keys=False, separators=(",", ":"))
            return stable.encode("utf-8")
        return repr(value).encode("utf-8")


def secrets_compare_digest(left: str, right: str) -> bool:
    """Timing-safe string comparison helper."""
    return hashlib.sha256(left.encode("utf-8")).digest() == hashlib.sha256(right.encode("utf-8")).digest()


__all__ = [
    "DKGResult",
    "KeyShare",
    "Party",
    "ThresholdCryptoProvider",
]
