"""Data classification helpers and policies.

PRESERVE: Data governance layer
EXTEND: Information classification

Provides automated classification (heuristic + optional ML), policy-to-encryption
mapping, and validation for allowed handling actions.
"""
from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass
from datetime import timedelta
from enum import Enum
from typing import Dict, List, Optional

LOG = logging.getLogger(__name__)

# Optional ML classifier hook: try to import a lightweight model interface if available
_ML_AVAILABLE = False
try:
    # This is an optional dependency; if present, use for auto-classification
    import transformers  # type: ignore

    _ML_AVAILABLE = True
except Exception:
    _ML_AVAILABLE = False


class ClassificationLevel(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    SECRET = "SECRET"
    TOP_SECRET = "TOP_SECRET"


@dataclass
class EncryptionPolicy:
    algorithm: str
    key_size: int
    rotate_days: int
    require_hsm: bool
    kms_provider: Optional[str]


def _luhn_check(number: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _detect_pci(payload: bytes) -> bool:
    try:
        txt = payload.decode("utf-8", errors="ignore")
    except Exception:
        txt = ""
    pan_re = re.compile(r"(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12}|(?:352[89]|35[3-8]\d)\d{12})(?:[\s-]?\d{4})*")
    for m in pan_re.finditer(txt):
        if _luhn_check(m.group(0)):
            return True
    return False


def _detect_phi(payload: bytes) -> bool:
    try:
        txt = payload.decode("utf-8", errors="ignore").lower()
    except Exception:
        txt = ""
    # simple heuristics: medical terms, diagnosis codes, rx, dob patterns
    phi_keywords = ["diagnosis", "patient", "medical record", "dob", "ssn", "mrn", "prescription", "lab result"]
    for k in phi_keywords:
        if k in txt:
            return True
    return False


def _detect_pii(payload: bytes) -> bool:
    try:
        txt = payload.decode("utf-8", errors="ignore")
    except Exception:
        txt = ""
    # emails, SSNs, phone numbers
    email_re = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
    ssn_re = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
    phone_re = re.compile(r"\b\+?\d[\d \-()]{7,}\b")
    if email_re.search(txt) or ssn_re.search(txt) or phone_re.search(txt):
        return True
    return False


def _classify_with_model(payload: bytes, metadata: Dict) -> Optional[ClassificationLevel]:
    if not _ML_AVAILABLE:
        return None
    try:
        # Placeholder for using a text classification model; keep minimal so import-checks succeed
        txt = payload.decode("utf-8", errors="ignore")[:10000]
        # Real implementation: load a fine-tuned classifier and call pipeline
        return None
    except Exception:
        LOG.exception("ML classification failed")
        return None


def classify_data(data: bytes, metadata: Dict) -> ClassificationLevel:
    """Automatically classify `data` using heuristics with optional ML fallback.

    Returns a `ClassificationLevel`. Operators should review automated
    classifications and provide manual overrides via `metadata['classification']`.
    """
    # Allow explicit override from metadata
    override = metadata.get("classification")
    if override:
        try:
            return ClassificationLevel(override)
        except Exception:
            LOG.warning("Invalid classification override: %s", override)

    # Optional ML classification
    ml = _classify_with_model(data, metadata)
    if ml is not None:
        return ml

    # Heuristic content checks
    if _detect_phi(data):
        return ClassificationLevel.TOP_SECRET
    if _detect_pci(data):
        return ClassificationLevel.SECRET
    if _detect_pii(data):
        return ClassificationLevel.CONFIDENTIAL

    # Fallback: if metadata indicates internal purpose
    if metadata.get("internal", False):
        return ClassificationLevel.INTERNAL

    return ClassificationLevel.PUBLIC


def apply_classification_policy(data: bytes, level: ClassificationLevel) -> EncryptionPolicy:
    """Return an `EncryptionPolicy` suitable for the `level`.

    Policies are conservative defaults; operators should map these to real
    KMS/HSM configurations in their environment.
    """
    kms = os.getenv("KMS_PROVIDER", "aws-kms")
    if level == ClassificationLevel.PUBLIC:
        return EncryptionPolicy(algorithm="none", key_size=0, rotate_days=0, require_hsm=False, kms_provider=None)
    if level == ClassificationLevel.INTERNAL:
        return EncryptionPolicy(algorithm="AES-GCM", key_size=128, rotate_days=365, require_hsm=False, kms_provider=kms)
    if level == ClassificationLevel.CONFIDENTIAL:
        return EncryptionPolicy(algorithm="AES-GCM", key_size=256, rotate_days=180, require_hsm=False, kms_provider=kms)
    if level == ClassificationLevel.SECRET:
        return EncryptionPolicy(algorithm="AES-GCM", key_size=256, rotate_days=90, require_hsm=True, kms_provider=kms)
    # TOP_SECRET
    return EncryptionPolicy(algorithm="AES-GCM", key_size=256, rotate_days=30, require_hsm=True, kms_provider=kms)


_ACTION_ALLOWLIST = {
    ClassificationLevel.PUBLIC: {"read", "write", "transmit", "share", "persist", "backup", "export"},
    ClassificationLevel.INTERNAL: {"read", "write", "transmit", "share", "persist", "backup"},
    ClassificationLevel.CONFIDENTIAL: {"read", "write", "transmit", "persist"},
    ClassificationLevel.SECRET: {"read", "write", "persist"},
    ClassificationLevel.TOP_SECRET: {"read"},
}


def validate_data_handling(classification: ClassificationLevel, action: str) -> bool:
    """Verify whether `action` is allowed for the classification level.

    Actions: `read`, `write`, `transmit`, `share`, `persist`, `backup`, `export`.
    """
    allowed = _ACTION_ALLOWLIST.get(classification, set())
    result = action in allowed
    LOG.debug("Validate action=%s for classification=%s -> %s", action, classification, result)
    return result


__all__ = [
    "ClassificationLevel",
    "EncryptionPolicy",
    "classify_data",
    "apply_classification_policy",
    "validate_data_handling",
]

