from dataclasses import dataclass, field
from typing import Dict, Optional, List
import time


@dataclass
class DeviceInfo:
    device_id: str
    os_version: str
    disk_encrypted: bool
    antivirus_running: bool
    tpm_enabled: bool
    tpm_attestation_token: Optional[str] = None
    certificate_thumbprint: Optional[str] = None


@dataclass
class Certificate:
    subject: str
    thumbprint: str
    issuer: str
    raw: Optional[str] = None


@dataclass
class HealthAttestation:
    device_id: str
    is_trusted: bool
    reasons: List[str]
    timestamp: float


class DeviceInventory:
    def __init__(self):
        self._devices: Dict[str, DeviceInfo] = {}

    def add(self, info: DeviceInfo) -> None:
        self._devices[info.device_id] = info

    def get(self, device_id: str) -> Optional[DeviceInfo]:
        return self._devices.get(device_id)

    def list(self) -> List[DeviceInfo]:
        return list(self._devices.values())


class DeviceTrustManager:
    """Manages device registration, attestation, certificate verification, and quarantine.

    This implementation uses in-memory stores and simulates TPM attestation checks.
    For production, integrate with a real TPM attestation service and certificate chain validation.
    """

    def __init__(self):
        self.inventory = DeviceInventory()
        self._quarantined: Dict[str, float] = {}

    def register_device(self, device_id: str, device_info: DeviceInfo) -> None:
        device_info.device_id = device_id
        self.inventory.add(device_info)

    def attest_device_health(self, device_id: str) -> HealthAttestation:
        info = self.inventory.get(device_id)
        now = time.time()
        if info is None:
            return HealthAttestation(device_id=device_id, is_trusted=False, reasons=["unknown_device"], timestamp=now)
        if self._quarantined.get(device_id):
            return HealthAttestation(device_id=device_id, is_trusted=False, reasons=["quarantined"], timestamp=now)

        reasons: List[str] = []
        if not info.disk_encrypted:
            reasons.append("disk_unencrypted")
        if not info.antivirus_running:
            reasons.append("antivirus_inactive")
        # simple OS freshness check: major version >= 10 assumed OK
        try:
            if info.os_version and int(info.os_version.split(".")[0]) < 10:
                reasons.append("os_outdated")
        except Exception:
            # if parsing fails, be conservative and flag it
            reasons.append("os_version_unknown")

        # TPM attestation simulation
        if info.tpm_enabled:
            if not info.tpm_attestation_token or not info.tpm_attestation_token.startswith("TPM-"):
                reasons.append("tpm_attestation_failed")
        else:
            reasons.append("tpm_missing")

        trusted = len(reasons) == 0
        return HealthAttestation(device_id=device_id, is_trusted=trusted, reasons=reasons, timestamp=now)

    def verify_device_certificate(self, device_id: str, certificate: Certificate) -> bool:
        info = self.inventory.get(device_id)
        if info is None:
            return False
        # basic thumbprint match; production should verify chain and signature
        return bool(info.certificate_thumbprint and certificate.thumbprint == info.certificate_thumbprint)

    def quarantine_untrusted_device(self, device_id: str) -> None:
        self._quarantined[device_id] = time.time()

    def release_quarantine(self, device_id: str) -> None:
        if device_id in self._quarantined:
            del self._quarantined[device_id]

    def is_quarantined(self, device_id: str) -> bool:
        return device_id in self._quarantined


__all__ = ["DeviceInfo", "Certificate", "HealthAttestation", "DeviceTrustManager", "DeviceInventory"]
