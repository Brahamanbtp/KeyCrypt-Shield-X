"""PCI-DSS compliance automation helpers.

PRESERVE: PCI-DSS compliance layer
EXTEND: Payment security compliance

Provides helpers to discover cardholder data, validate PCI requirements,
document compensating controls, and run quarterly vulnerability scans with
optional ASV (Approved Scanning Vendor) integration.
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

LOG = logging.getLogger(__name__)

COMPENSATING_STORE = os.getenv("PCI_COMPENSATING_STORE", "/var/lib/keycrypt/pci_compensating_controls.jsonl")
ASV_API_URL = os.getenv("PCI_ASV_API_URL")
ASV_API_KEY = os.getenv("PCI_ASV_API_KEY")


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


@dataclass
class CardholderDataItem:
    file_path: str
    line_number: int
    sample: str
    offset: int


@dataclass
class CardholderDataInventory:
    scanned_at: datetime
    scope: str
    items: List[CardholderDataItem]
    total_hits: int


@dataclass
class RequirementResult:
    requirement: str
    compliant: bool
    notes: List[str]


@dataclass
class PCIValidationReport:
    generated_at: datetime
    results: List[RequirementResult]
    overall_compliant: bool


@dataclass
class VulnerabilityFinding:
    id: str
    severity: str
    description: str


@dataclass
class VulnerabilityScanReport:
    started_at: datetime
    finished_at: Optional[datetime]
    scope: str
    findings: List[VulnerabilityFinding]
    asv_report_id: Optional[str]


def scan_for_cardholder_data(scope: str) -> CardholderDataInventory:
    """Discover files containing potential cardholder data under `scope`.

    Uses a simple PAN regex with Luhn validation to reduce false positives.
    Operators must review and classify findings.
    """
    LOG.info("Scanning scope for cardholder data: %s", scope)
    pan_re = re.compile(r"(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12}|(?:352[89]|35[3-8]\d)\d{12})(?:[\s-]?\d{4})*")
    items: List[CardholderDataItem] = []
    scanned_at = datetime.utcnow()
    total = 0

    if not os.path.exists(scope):
        LOG.warning("Scope path does not exist: %s", scope)
        return CardholderDataInventory(scanned_at=scanned_at, scope=scope, items=[], total_hits=0)

    for root, _, files in os.walk(scope):
        for fname in files:
            path = os.path.join(root, fname)
            try:
                with open(path, "r", errors="ignore", encoding="utf-8") as fh:
                    for i, line in enumerate(fh, start=1):
                        for m in pan_re.finditer(line):
                            sample = m.group(0)
                            if _luhn_check(sample):
                                total += 1
                                items.append(CardholderDataItem(file_path=path, line_number=i, sample=sample, offset=m.start()))
            except Exception:
                LOG.debug("Skipping unreadable file: %s", path)

    inv = CardholderDataInventory(scanned_at=scanned_at, scope=scope, items=items, total_hits=total)
    LOG.info("Cardholder data scan complete: %d hits", total)
    return inv


def _check_encryption_at_rest() -> RequirementResult:
    notes: List[str] = []
    # Heuristic checks: presence of KMS env, enabled disk encryption flag
    kms = os.getenv("KMS_PROVIDER")
    if not kms:
        notes.append("No KMS_PROVIDER env set; unable to verify encryption at rest")
    else:
        notes.append(f"KMS_PROVIDER={kms}")

    # Check for probable encrypted storage mount
    enc_flag = os.getenv("ENCRYPTED_STORAGE", "false").lower() in ("1", "true", "yes")
    if not enc_flag:
        notes.append("ENCRYPTED_STORAGE flag not set; verify disk/DB encryption")

    compliant = kms is not None and enc_flag
    return RequirementResult(requirement="3 - Protect stored cardholder data", compliant=compliant, notes=notes)


def _check_encryption_in_transit() -> RequirementResult:
    notes: List[str] = []
    tls_min = os.getenv("TLS_MIN_VERSION", "1.2")
    if tls_min < "1.2":
        notes.append(f"TLS_MIN_VERSION={tls_min} is lower than 1.2")
    else:
        notes.append(f"TLS_MIN_VERSION={tls_min}")

    # mTLS flag heuristic
    mTLS = os.getenv("MTLS_ENABLED", "false").lower() in ("1", "true", "yes")
    notes.append(f"mTLS_enabled={mTLS}")
    compliant = tls_min >= "1.2"
    return RequirementResult(requirement="4 - Encrypt transmission", compliant=compliant, notes=notes)


def _check_identify_and_authenticate() -> RequirementResult:
    notes: List[str] = []
    # Check for SSO/IdP or local auth system envs
    idp = os.getenv("IDP_PROVIDER")
    if not idp:
        notes.append("No IDP_PROVIDER set; verify authentication controls")
    else:
        notes.append(f"IDP_PROVIDER={idp}")

    # Check for MFA enforcement flag
    mfa = os.getenv("MFA_ENFORCED", "false").lower() in ("1", "true", "yes")
    if not mfa:
        notes.append("MFA_ENFORCED not set; enforce MFA for all users")

    compliant = bool(idp) and mfa
    return RequirementResult(requirement="8 - Identify and authenticate access", compliant=compliant, notes=notes)


def _check_track_and_monitor() -> RequirementResult:
    notes: List[str] = []
    audit = os.getenv("AUDIT_LOG_PATH")
    if not audit or not os.path.exists(audit or ""):
        notes.append("Audit log path missing or not found")
    else:
        notes.append(f"Audit log found: {audit}")

    # Example: SIEM integration flag
    siem = os.getenv("SIEM_ENABLED", "false").lower() in ("1", "true", "yes")
    notes.append(f"SIEM_enabled={siem}")

    compliant = bool(audit and os.path.exists(audit)) and siem
    return RequirementResult(requirement="10 - Track and monitor all access", compliant=compliant, notes=notes)


def validate_pci_requirements() -> PCIValidationReport:
    """Validate key PCI-DSS requirements and return a report object.

    The function performs heuristic checks for several key requirements and
    marks other requirements as "manual review required". Operators/auditors
    must review and replace heuristics with concrete checks tied to their
    environment.
    """
    LOG.info("Running PCI-DSS validation checks")
    results: List[RequirementResult] = []
    checks = [
        _check_encryption_at_rest,
        _check_encryption_in_transit,
        _check_identify_and_authenticate,
        _check_track_and_monitor,
    ]

    for fn in checks:
        try:
            results.append(fn())
        except Exception:
            LOG.exception("Error running check %s", fn.__name__)
            results.append(RequirementResult(requirement=fn.__name__, compliant=False, notes=["check failed"]))

    # Mark remaining PCI requirements as manual review entries
    manual_requirements = [str(i) for i in range(1, 13) if i not in (3, 4, 8, 10)]
    for r in manual_requirements:
        results.append(RequirementResult(requirement=f"{r} - Manual review required", compliant=False, notes=["Operator/auditor review required"]))

    overall = all(r.compliant for r in results if not r.requirement.endswith("Manual review required"))
    report = PCIValidationReport(generated_at=datetime.utcnow(), results=results, overall_compliant=overall)
    LOG.info("PCI validation completed; overall_compliant=%s", overall)
    return report


def implement_compensating_controls(requirement: str, justification: str) -> None:
    """Document a compensating control for a PCI requirement.

    Documents are appended as JSONL to `COMPENSATING_STORE` for auditor review.
    """
    entry = {
        "requirement": requirement,
        "justification": justification,
        "documented_at": datetime.utcnow().isoformat(),
    }
    try:
        os.makedirs(os.path.dirname(COMPENSATING_STORE), exist_ok=True)
        with open(COMPENSATING_STORE, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
        LOG.info("Recorded compensating control for %s", requirement)
    except Exception:
        LOG.exception("Failed to record compensating control to %s", COMPENSATING_STORE)


def _call_asv_scan(scope: str) -> Optional[str]:
    """Submit a scan request to an ASV if configured and return an ASV report id.

    This is an integration helper; real ASV APIs vary and require proper
    authentication and operator review.
    """
    if not ASV_API_URL or not ASV_API_KEY:
        LOG.info("ASV not configured (PCI_ASV_API_URL/PCI_ASV_API_KEY)")
        return None
    try:
        import requests

        payload = {"scope": scope, "requested_at": datetime.utcnow().isoformat()}
        headers = {"Authorization": f"Bearer {ASV_API_KEY}", "Content-Type": "application/json"}
        resp = requests.post(ASV_API_URL, json=payload, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        report_id = data.get("report_id") or data.get("id")
        LOG.info("ASV accepted scan request, report id=%s", report_id)
        return report_id
    except Exception:
        LOG.exception("ASV scan submission failed")
        return None


def quarterly_scan(scope: str) -> VulnerabilityScanReport:
    """Run a quarterly vulnerability scan for the given scope.

    Integrates with ASV when available; otherwise performs a lightweight
    local scan (heuristic file checks) and returns a `VulnerabilityScanReport`.
    """
    started = datetime.utcnow()
    findings: List[VulnerabilityFinding] = []
    asv_id = None

    # Try ASV integration first
    try:
        asv_id = _call_asv_scan(scope)
    except Exception:
        LOG.exception("ASV integration error")

    # Local best-effort scan: look for outdated libs and common misconfigs
    # NOTE: Operators should replace with real scanners (Nessus, Qualys, etc.)
    # Heuristic: search for presence of .env, private key files, or debug flags
    suspicious = []
    for root, _, files in os.walk(scope):
        for f in files:
            if f.endswith(".env") or f.endswith(".pem") or f.endswith(".key"):
                suspicious.append(os.path.join(root, f))

    for i, p in enumerate(suspicious, start=1):
        findings.append(VulnerabilityFinding(id=f"LOCAL-{i}", severity="HIGH", description=f"Sensitive file exposed: {p}"))

    finished = datetime.utcnow()
    report = VulnerabilityScanReport(started_at=started, finished_at=finished, scope=scope, findings=findings, asv_report_id=asv_id)
    LOG.info("Quarterly scan complete: %d findings (asv_id=%s)", len(findings), asv_id)
    return report


__all__ = [
    "scan_for_cardholder_data",
    "CardholderDataInventory",
    "validate_pci_requirements",
    "PCIValidationReport",
    "implement_compensating_controls",
    "quarterly_scan",
    "VulnerabilityScanReport",
]
