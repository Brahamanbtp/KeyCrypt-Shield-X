from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional, List, Protocol, Any, Dict


class ClassificationLevel(Enum):
    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    SECRET = 3
    TOP_SECRET = 4


@dataclass
class EncryptionPolicy:
    algorithm: str
    key_size: Optional[int]
    pqc_hybrid: bool = False
    features: List[str] = None


@dataclass
class DataLabel:
    data_id: Optional[str]
    classification: ClassificationLevel
    encryption_policy: EncryptionPolicy
    encrypted: bool


class MLModelProtocol(Protocol):
    def predict(self, data: bytes, metadata: dict) -> ClassificationLevel: ...


class SimpleKeywordModel:
    """A tiny, pluggable heuristic "ML" model used as a default.

    This is intentionally lightweight and deterministic so the project
    can be extended to replace it with a real model later.
    """

    SENSITIVE_KEYWORDS = (b'password', b'ssn', b'social security', b'secret', b'api_key', b'private')

    def predict(self, data: bytes, metadata: dict) -> ClassificationLevel:
        if metadata.get("sensitive"):
            return ClassificationLevel.CONFIDENTIAL
        text = data.lower() if isinstance(data, (bytes, bytearray)) else str(data).encode('utf-8')
        matches = sum(1 for k in self.SENSITIVE_KEYWORDS if k in text)
        if matches >= 2:
            return ClassificationLevel.SECRET
        if matches == 1:
            return ClassificationLevel.CONFIDENTIAL
        return ClassificationLevel.INTERNAL


class DataClassifier:
    """Data classification framework used by the governance layer.

    - `classify_data`: uses an ML model (pluggable) and fallback heuristics
    - `apply_classification_policy`: maps levels to encryption policies
    - `label_data`: attaches classification label for a data id
    - `validate_classification_handling`: checks whether a user is authorized
      to access data by its classification
    """

    def __init__(self, model: Optional[MLModelProtocol] = None):
        self.model = model or SimpleKeywordModel()
        self._labels: Dict[str, DataLabel] = {}

    def classify_data(self, data: bytes, metadata: dict) -> ClassificationLevel:
        """Return a `ClassificationLevel` for `data` using the configured model.

        The method is intentionally simple: projects should replace the model
        with a trained classifier for production use.
        """
        try:
            return self.model.predict(data, metadata)
        except Exception:
            # conservative fallback: treat unknowns as CONFIDENTIAL if metadata says sensitive
            if metadata.get("sensitive"):
                return ClassificationLevel.CONFIDENTIAL
            return ClassificationLevel.INTERNAL

    def apply_classification_policy(self, classification: ClassificationLevel) -> EncryptionPolicy:
        """Map a `ClassificationLevel` to an `EncryptionPolicy`.

        Mapping:
        - PUBLIC: none
        - INTERNAL: AES-128
        - CONFIDENTIAL: AES-256
        - SECRET: Hybrid PQC + AES-256
        - TOP_SECRET: All advanced features (PQC, HSM, multi-key rotation)
        """
        if classification == ClassificationLevel.PUBLIC:
            return EncryptionPolicy(algorithm="none", key_size=None, pqc_hybrid=False, features=[])
        if classification == ClassificationLevel.INTERNAL:
            return EncryptionPolicy(algorithm="AES", key_size=128, pqc_hybrid=False, features=["encrypt-at-rest"])
        if classification == ClassificationLevel.CONFIDENTIAL:
            return EncryptionPolicy(algorithm="AES", key_size=256, pqc_hybrid=False, features=["encrypt-at-rest", "encrypt-in-transit"])
        if classification == ClassificationLevel.SECRET:
            return EncryptionPolicy(algorithm="AES+PQC", key_size=256, pqc_hybrid=True, features=["hybrid-encryption", "key-rotation"])
        # TOP_SECRET
        return EncryptionPolicy(algorithm="AES+PQC+HSM", key_size=256, pqc_hybrid=True, features=["hybrid-encryption", "hsm", "mandatory-multi-key-rotation"])

    def label_data(self, data_id: str, classification: ClassificationLevel) -> DataLabel:
        """Create and persist a `DataLabel` for `data_id` in-memory.

        In production this should persist to a canonical metadata store and
        integrate with the audit/evidence pipeline.
        """
        policy = self.apply_classification_policy(classification)
        encrypted = policy.algorithm != "none"
        label = DataLabel(data_id=data_id, classification=classification, encryption_policy=policy, encrypted=encrypted)
        self._labels[data_id] = label
        return label

    def get_label(self, data_id: str) -> Optional[DataLabel]:
        return self._labels.get(data_id)

    def _required_clearance(self, classification: ClassificationLevel) -> int:
        return classification.value

    def validate_classification_handling(self, data_id: str, user: Any) -> bool:
        """Verify `user` is authorized to handle the data labelled by `data_id`.

        Authorization rules (default): user must have `clearance_level` >= classification value.
        Supports either a numeric `clearance_level` attribute on `user` or a `roles` iterable with
        role strings like `clearance:TOP_SECRET`.
        """
        label = self.get_label(data_id)
        if label is None:
            # unknown data -> be conservative
            return False
        required = self._required_clearance(label.classification)

        # Prefer role-based clearance when roles are explicitly provided.
        roles = getattr(user, "roles", None)
        if roles:
            # roles like 'clearance:CONFIDENTIAL'
            for r in roles:
                if isinstance(r, str) and r.startswith("clearance:"):
                    try:
                        level = ClassificationLevel[r.split(":", 1)[1]]
                        if level.value >= required:
                            return True
                    except Exception:
                        continue

        # Fallback to numeric clearance if available
        if hasattr(user, "clearance_level"):
            try:
                return int(user.clearance_level) >= required
            except Exception:
                return False

        return False


__all__ = ["ClassificationLevel", "EncryptionPolicy", "DataLabel", "DataClassifier"]
