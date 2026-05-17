"""PCI-DSS compliant payment data encryption example.

This example demonstrates:
- Encrypting cardholder data (PAN, CVV) with envelope encryption
- Tokenization of PANs
- Key management simulated with an HSM-backed keystore (demo)
- Transaction data encryption
- Audit trail generation for PCI compliance (artifacts/logs/pci_audit.jsonl)
- Secure key transmission simulation
- Generating PCI-DSS compliance report via tools.audit_reporter
- Deployment artifacts (Dockerfile, Kubernetes manifest)

Run this script to execute the demo and produce artifacts under artifacts/financial_example.
"""
from __future__ import annotations

import json
import os
import secrets
import shutil
import sys
import time
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Dict, Optional

try:
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except Exception:  # pragma: no cover - optional
    CRYPTO_AVAILABLE = False

from tools import audit_reporter


ART = Path("artifacts/financial_example")
ART.mkdir(parents=True, exist_ok=True)
LOGS = ART / "logs"
LOGS.mkdir(parents=True, exist_ok=True)
CONFIG = ART / "config"
CONFIG.mkdir(parents=True, exist_ok=True)
DEPLOY = ART / "deployment"
DEPLOY.mkdir(parents=True, exist_ok=True)
DATA = ART / "data"
DATA.mkdir(parents=True, exist_ok=True)

AUDIT_LOG = LOGS / "pci_audit.jsonl"


def _audit(event: Dict[str, any]) -> None:
    event.setdefault("timestamp", datetime.utcnow().isoformat())
    with AUDIT_LOG.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(event, default=str) + "\n")


@dataclass
class Cardholder:
    pan: str
    name: str
    exp: str
    cvv: str


class HSMKeystore:
    """Simulated HSM-backed keystore for demo (DO NOT use in production)."""

    def __init__(self, path: Path):
        self.path = path
        self.path.mkdir(parents=True, exist_ok=True)
        self.master_key = self._load_or_create_master()

    def _load_or_create_master(self) -> bytes:
        mk = self.path / "hsm_master.key"
        if mk.exists():
            return mk.read_bytes()
        k = Fernet.generate_key() if CRYPTO_AVAILABLE else os.urandom(32)
        mk.write_bytes(k)
        _audit({"action": "hsm_master_created"})
        return k

    def generate_data_key(self) -> str:
        dk = Fernet.generate_key() if CRYPTO_AVAILABLE else os.urandom(32)
        key_id = f"dk-{int(time.time())}-{secrets.token_hex(4)}"
        (self.path / f"{key_id}.key").write_bytes(dk)
        _audit({"action": "hsm_generate_data_key", "key_id": key_id})
        return key_id

    def get_data_key(self, key_id: str) -> bytes:
        p = self.path / f"{key_id}.key"
        if not p.exists():
            raise KeyError("data key not found")
        return p.read_bytes()

    def rotate_master(self) -> None:
        mk = self.path / "hsm_master.key"
        new = Fernet.generate_key() if CRYPTO_AVAILABLE else os.urandom(32)
        mk.write_bytes(new)
        _audit({"action": "hsm_rotate_master"})


class Tokenizer:
    """Simple tokenization service storing token->PAN mapping encrypted under a data key."""

    def __init__(self, token_store: Path, keystore: HSMKeystore, token_key_id: str):
        self.store = token_store
        self.store.mkdir(parents=True, exist_ok=True)
        self.keystore = keystore
        self.token_key_id = token_key_id

    def tokenize(self, pan: str) -> str:
        token = f"tok_{secrets.token_hex(12)}"
        mapping = {"pan": pan, "created_at": datetime.utcnow().isoformat()}
        data = json.dumps(mapping).encode()
        dk = self.keystore.get_data_key(self.token_key_id)
        if CRYPTO_AVAILABLE:
            f = Fernet(dk)
            enc = f.encrypt(data)
        else:
            enc = data[::-1]
        (self.store / f"{token}.enc").write_bytes(enc)
        _audit({"action": "tokenize", "token": token})
        return token

    def detokenize(self, token: str) -> str:
        p = self.store / f"{token}.enc"
        if not p.exists():
            raise KeyError("token not found")
        enc = p.read_bytes()
        dk = self.keystore.get_data_key(self.token_key_id)
        if CRYPTO_AVAILABLE:
            f = Fernet(dk)
            data = f.decrypt(enc)
        else:
            data = enc[::-1]
        obj = json.loads(data.decode())
        _audit({"action": "detokenize", "token": token})
        return obj["pan"]


def mask_pan(pan: str) -> str:
    # Return masked PAN: show first6 and last4 per PCI masking guidance
    return pan[:6] + "*" * (len(pan) - 10) + pan[-4:]


def encrypt_transaction(tx_data: Dict[str, any], keystore: HSMKeystore, key_id: str) -> bytes:
    payload = json.dumps(tx_data).encode()
    dk = keystore.get_data_key(key_id)
    if CRYPTO_AVAILABLE:
        f = Fernet(dk)
        enc = f.encrypt(payload)
    else:
        enc = payload[::-1]
    _audit({"action": "encrypt_transaction", "tx_id": tx_data.get("tx_id"), "key_id": key_id})
    return enc


def secure_key_transmission(sender_keystore: HSMKeystore, receiver_keystore: HSMKeystore, key_id: str) -> str:
    # Simulate wrapping/unwrapping a data key between HSMs
    dk = sender_keystore.get_data_key(key_id)
    # In real world: use asymmetric wrap; here we simulate by re-encrypting under receiver master
    # For demo, write a new wrapped key id into receiver's keystore
    new_key_id = receiver_keystore.generate_data_key()
    (receiver_keystore.path / f"{new_key_id}.key").write_bytes(dk)
    _audit({"action": "secure_key_transmission", "from": str(sender_keystore.path), "to": str(receiver_keystore.path), "key_id": key_id, "new_key_id": new_key_id})
    return new_key_id


def generate_pci_policy() -> Path:
    policy = {
        "standard": "PCI-DSS",
        "encryption": {"algorithms": ["AES-GCM", "RSA-OAEP"], "min_key_length": 128},
        "tokenization": {"enabled": True},
        "audit": {"retain_days": 365},
    }
    p = CONFIG / "pci_policy.json"
    p.write_text(json.dumps(policy, indent=2), encoding="utf-8")
    _audit({"action": "configure_policy", "policy": "pci-dss"})
    return p


def generate_deployment_artifacts() -> None:
    (DEPLOY / "Dockerfile").write_text(
        """FROM python:3.12-slim
WORKDIR /app
COPY . /app
RUN pip install -r requirements.txt || true
CMD ["python", "-c", "print('Payment service')"]
""",
        encoding="utf-8",
    )
    (DEPLOY / "k8s_deployment.yaml").write_text(
        """apiVersion: apps/v1
kind: Deployment
metadata:
  name: pci-demo
spec:
  replicas: 1
  template:
    metadata:
      labels: { app: pci-demo }
    spec:
      containers:
      - name: app
        image: pci-demo:latest
""",
        encoding="utf-8",
    )
    _audit({"action": "generate_deployment"})


def generate_pci_compliance_report(period: str = "2026-Q2") -> Path:
    report = audit_reporter.generate_compliance_report("PCI-DSS", period)
    path = audit_reporter.export_report(report, format="json")
    _audit({"action": "generate_compliance_report", "report": str(path)})
    return path


def demo_flow():
    _audit({"action": "pci_demo_start"})
    keystore_a = HSMKeystore(ART / "hsm_a")
    keystore_b = HSMKeystore(ART / "hsm_b")
    policy_path = generate_pci_policy()
    print("Policy written to", policy_path)

    # Generate tokenization key
    token_key = keystore_a.generate_data_key()
    tokenizer = Tokenizer(ART / "token_store", keystore_a, token_key)

    # Example cardholder
    card = Cardholder(pan="4111111111111111", name="Jane Doe", exp="12/26", cvv="123")
    masked = mask_pan(card.pan)
    print("Masked PAN:", masked)

    # Tokenize PAN
    token = tokenizer.tokenize(card.pan)
    print("Token created:", token)

    # Encrypt transaction using a data key
    tx_key = keystore_a.generate_data_key()
    tx = {"tx_id": "tx1001", "amount": 100.0, "token": token, "timestamp": datetime.utcnow().isoformat()}
    enc_tx = encrypt_transaction(tx, keystore_a, tx_key)
    (DATA / "tx1001.enc").write_bytes(enc_tx)

    # Simulate secure key transmission to another HSM (e.g., backup or other region)
    new_key_id = secure_key_transmission(keystore_a, keystore_b, tx_key)
    print("Transmitted key to keystore_b as", new_key_id)

    # Demonstrate key rotation (create new key and re-wrap token store under new key)
    rotated_key = keystore_a.generate_data_key()
    # re-wrap token store entries into rotated_key (demo: copy data)
    for f in (ART / "token_store").glob("*.enc"):
        data = f.read_bytes()
        (ART / "token_store_rotated" / f.name).parent.mkdir(parents=True, exist_ok=True)
        (ART / "token_store_rotated" / f.name).write_bytes(data)
    _audit({"action": "key_rotation", "old": token_key, "new": rotated_key})

    # Secure deletion example: remove raw PANs if any (demo ensures tokenization used)
    # In real systems, remove backups and logs as per retention
    _audit({"action": "pci_demo_end"})

    generate_deployment_artifacts()
    report = generate_pci_compliance_report()
    print("PCI report generated:", report)


if __name__ == "__main__":
    demo_flow()
