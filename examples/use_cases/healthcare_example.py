"""HIPAA-compliant patient data encryption example.

This example demonstrates:
- Configuring a HIPAA policy (written to artifacts/config/hipaa_policy.yaml)
- Encrypting patient records (PHI) with envelope encryption
- Role-based access controls for decryption
- Generating audit logs for compliance (artifacts/logs/hipaa_audit.jsonl)
- Demonstrating key rotation (re-encrypt records with new data keys)
- Secure deletion of data (overwriting + audit)
- Generating a HIPAA compliance report using tools.audit_reporter
- Producing deployment artifacts (Dockerfile and Kubernetes manifest)

Run as a script to execute the demo and write artifacts.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import time
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Dict, List, Optional

try:
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except Exception:  # pragma: no cover - optional
    CRYPTO_AVAILABLE = False

from tools import audit_reporter


ARTIFACTS = Path("artifacts/healthcare_example")
ARTIFACTS.mkdir(parents=True, exist_ok=True)
LOG_DIR = ARTIFACTS / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
CONFIG_DIR = ARTIFACTS / "config"
CONFIG_DIR.mkdir(parents=True, exist_ok=True)
DEPLOY_DIR = ARTIFACTS / "deployment"
DEPLOY_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR = ARTIFACTS / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

AUDIT_LOG = LOG_DIR / "hipaa_audit.jsonl"


def _audit(event: Dict[str, any]) -> None:
    event.setdefault("timestamp", datetime.utcnow().isoformat())
    with AUDIT_LOG.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(event, default=str) + "\n")


@dataclass
class PatientRecord:
    patient_id: str
    name: str
    dob: str
    diagnosis: str


class KeyStore:
    """Simple in-memory keystore with file-backed persistent storage for demo purposes."""

    def __init__(self, path: Path):
        self.path = path
        self.path.mkdir(parents=True, exist_ok=True)
        self.master_key = self._load_master_key()

    def _load_master_key(self) -> bytes:
        mk = self.path / "master.key"
        if mk.exists():
            return mk.read_bytes()
        k = Fernet.generate_key() if CRYPTO_AVAILABLE else b"demo_master_key_32bytes_012345"
        mk.write_bytes(k)
        return k

    def generate_data_key(self) -> bytes:
        # Envelope encryption: generate a symmetric data key and 'wrap' it with master (simulated)
        dk = Fernet.generate_key() if CRYPTO_AVAILABLE else os.urandom(32)
        # In a real KMS, you'd encrypt (wrap) dk with the master key; here we simulate by storing
        wrapped = dk  # For demo store plaintext wrapped value (DO NOT do this in production)
        ts = int(time.time())
        key_id = f"data-{ts}"
        (self.path / f"{key_id}.key").write_bytes(wrapped)
        _audit({"action": "generate_data_key", "key_id": key_id})
        return key_id

    def get_data_key(self, key_id: str) -> bytes:
        p = self.path / f"{key_id}.key"
        if not p.exists():
            raise KeyError("key not found")
        return p.read_bytes()

    def rotate_master_key(self) -> None:
        # Simulate master key rotation by writing a new master key and audit
        mk = self.path / "master.key"
        new = Fernet.generate_key() if CRYPTO_AVAILABLE else os.urandom(32)
        mk.write_bytes(new)
        _audit({"action": "rotate_master_key"})


# Role based access control (simplified)
ROLE_POLICIES = {
    "doctor": {"can_decrypt": True},
    "nurse": {"can_decrypt": True},
    "billing": {"can_decrypt": False},
    "research": {"can_decrypt": False},
}


def check_access(role: str, operation: str) -> bool:
    pol = ROLE_POLICIES.get(role, {})
    if operation == "decrypt":
        return pol.get("can_decrypt", False)
    return True


def encrypt_patient_record(record: PatientRecord, key_store: KeyStore, key_id: str) -> Path:
    data = json.dumps(record.__dict__, default=str).encode()
    dk = key_store.get_data_key(key_id)
    if CRYPTO_AVAILABLE:
        f = Fernet(dk)
        token = f.encrypt(data)
    else:
        # insecure fallback: simple XOR
        token = bytes(b ^ dk[i % len(dk)] for i, b in enumerate(data))
    out = DATA_DIR / f"{record.patient_id}.enc"
    out.write_bytes(token)
    _audit({"action": "encrypt", "patient_id": record.patient_id, "key_id": key_id})
    return out


def decrypt_patient_record(patient_id: str, key_store: KeyStore, key_id: str, role: str) -> Optional[PatientRecord]:
    if not check_access(role, "decrypt"):
        _audit({"action": "unauthorized_decrypt_attempt", "patient_id": patient_id, "role": role})
        raise PermissionError("role not authorized to decrypt")
    p = DATA_DIR / f"{patient_id}.enc"
    if not p.exists():
        raise FileNotFoundError("encrypted record not found")
    token = p.read_bytes()
    dk = key_store.get_data_key(key_id)
    if CRYPTO_AVAILABLE:
        f = Fernet(dk)
        data = f.decrypt(token)
    else:
        data = bytes(b ^ dk[i % len(dk)] for i, b in enumerate(token))
    obj = json.loads(data.decode())
    _audit({"action": "decrypt", "patient_id": patient_id, "by_role": role, "key_id": key_id})
    return PatientRecord(**obj)


def secure_delete(patient_id: str) -> bool:
    p = DATA_DIR / f"{patient_id}.enc"
    if not p.exists():
        return False
    # Overwrite file contents before deleting (best-effort)
    try:
        length = p.stat().st_size
        with p.open("r+b") as fh:
            fh.seek(0)
            fh.write(b"\x00" * length)
            fh.flush()
            os.fsync(fh.fileno())
        p.unlink()
        _audit({"action": "secure_delete", "patient_id": patient_id})
        return True
    except Exception:
        # Fallback to simple delete
        try:
            p.unlink()
            _audit({"action": "delete", "patient_id": patient_id, "note": "fallback"})
            return True
        except Exception:
            return False


def configure_hipaa_policy() -> Path:
    policy = {
        "standard": "HIPAA",
        "encryption": {"algorithm": "AES-GCM", "min_key_length": 256},
        "access_control": {"roles": ROLE_POLICIES},
        "audit": {"retain_days": 365},
    }
    out = CONFIG_DIR / "hipaa_policy.json"
    out.write_text(json.dumps(policy, indent=2), encoding="utf-8")
    _audit({"action": "configure_policy", "policy": "hipaa"})
    return out


def generate_demo_deployment_files() -> None:
    # Dockerfile
    dockerfile = DEPLOY_DIR / "Dockerfile"
    dockerfile.write_text(
        """FROM python:3.12-slim
WORKDIR /app
COPY . /app
RUN pip install -r requirements.txt || true
CMD ["python", "-c", "print('Run your service')"]
""",
        encoding="utf-8",
    )
    # Kubernetes manifest (simple)
    k8s = DEPLOY_DIR / "deployment.yaml"
    k8s.write_text(
        """apiVersion: apps/v1
kind: Deployment
metadata:
  name: keycrypt-healthcare-demo
spec:
  replicas: 1
  selector:
    matchLabels:
      app: keycrypt-healthcare-demo
  template:
    metadata:
      labels:
        app: keycrypt-healthcare-demo
    spec:
      containers:
      - name: app
        image: keycrypt-healthcare-demo:latest
        ports:
        - containerPort: 8080
""",
        encoding="utf-8",
    )
    _audit({"action": "generate_deployment_files"})


def generate_hipaa_compliance_report(period: str = "2026-Q2") -> Path:
    # Use tools.audit_reporter to generate a compliance report and export it
    report = audit_reporter.generate_compliance_report("HIPAA", period)
    path = audit_reporter.export_report(report, format="json")
    _audit({"action": "generate_compliance_report", "report": str(path)})
    return path


def demo_flow():
    print("HIPAA demo: starting")
    _audit({"action": "demo_start"})
    ks = KeyStore(ARTIFACTS / "keystore")
    policy_path = configure_hipaa_policy()
    print("Wrote policy to", policy_path)

    # generate a data key and create demo patient records
    key_id = ks.generate_data_key()
    patients = [
        PatientRecord(patient_id="p001", name="Alice Smith", dob="1980-01-01", diagnosis="Condition A"),
        PatientRecord(patient_id="p002", name="Bob Jones", dob="1975-05-05", diagnosis="Condition B"),
    ]
    for rec in patients:
        p = encrypt_patient_record(rec, ks, key_id)
        print("Encrypted", rec.patient_id, "->", p)

    # Attempt a decrypt with a permitted role
    try:
        r = decrypt_patient_record("p001", ks, key_id, role="doctor")
        print("Decrypted record for p001:", r)
    except Exception as exc:
        print("Decrypt failed:", exc)

    # Attempt a decrypt with an unauthorized role
    try:
        decrypt_patient_record("p001", ks, key_id, role="billing")
    except PermissionError:
        print("Unauthorized access correctly blocked for billing role")

    # Rotate keys (generate new data key and re-encrypt records)
    new_key_id = ks.generate_data_key()
    for rec in patients:
        # decrypt with old key, encrypt with new key
        r = decrypt_patient_record(rec.patient_id, ks, key_id, role="doctor")
        encrypt_patient_record(r, ks, new_key_id)
        _audit({"action": "key_rotation_reencrypt", "patient_id": rec.patient_id, "old_key": key_id, "new_key": new_key_id})
    print("Rotated data keys from", key_id, "to", new_key_id)

    # Secure delete one patient's data (right to be forgotten)
    ok = secure_delete("p002")
    print("Secure deletion p002:", ok)

    # generate deployment artifacts
    generate_demo_deployment_files()

    # produce a compliance report
    report_path = generate_hipaa_compliance_report()
    print("Generated HIPAA compliance report:", report_path)
    _audit({"action": "demo_end"})


if __name__ == "__main__":
    demo_flow()
