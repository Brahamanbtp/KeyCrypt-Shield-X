"""Advanced Tutorial Generator (Markdown)

This script generates `examples/tutorials/advanced_tutorial.md` containing
expert-level tutorials on:
1. Implementing custom crypto provider
2. Developing a plugin
3. Setting up policy-driven encryption
4. Integrating with cloud KMS
5. Performance optimization techniques
6. Multi-party threshold cryptography
7. Homomorphic encryption workflows
8. Zero-knowledge proof generation

Each section contains conceptual explanation, a working example (where possible),
best practices, and performance considerations. Executable code blocks are included
so the `.md` can be used as a runnable reference in notebooks or reviewed by humans.

Run: python -m examples.tutorials.advanced_tutorial
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


OUT_MD = Path("examples/tutorials/advanced_tutorial.md")
OUT_MD.parent.mkdir(parents=True, exist_ok=True)


@dataclass
class Section:
    title: str
    explanation: str
    code_example: str
    best_practices: str
    performance: str


def _shallow_escape(s: str) -> str:
    return s


def make_sections() -> list[Section]:
    sections: list[Section] = []

    # 1. Custom Crypto Provider
    sections.append(Section(
        title="1. Implementing a Custom Crypto Provider",
        explanation=(
            "Implement a provider that conforms to the project's `CryptoProvider` interface. "
            "Keep APIs minimal (encrypt/decrypt/sign/verify) and clearly separate key material handling."
        ),
        code_example=(
            "```python\n"
            "# Minimal custom provider example (AES-GCM)\n"
            "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
            "from dataclasses import dataclass\n\n"
            "@dataclass\n"
            "class CustomProvider:\n"
            "    key: bytes\n\n"
            "    def encrypt(self, plaintext: bytes, associated_data: bytes | None = None) -> dict:\n"
            "        aesgcm = AESGCM(self.key)\n"
            "        nonce = AESGCM.generate_key(bit_length=96) if False else b'000000000000'\n"
            "        ct = aesgcm.encrypt(nonce, plaintext, associated_data)\n"
            "        return {'nonce': nonce, 'ciphertext': ct}\n\n"
            "    def decrypt(self, nonce: bytes, ciphertext: bytes, associated_data: bytes | None = None) -> bytes:\n"
            "        aesgcm = AESGCM(self.key)\n"
            "        return aesgcm.decrypt(nonce, ciphertext, associated_data)\n"
            "```"
        ),
        best_practices=(
            "- Keep provider code small and well-tested.\n- Validate inputs and avoid exposing raw keys.\n- Use secure RNG for nonces."
        ),
        performance=(
            "Benchmark encrypt/decrypt over representative payloads; prefer streaming APIs for large files."
        ),
    ))

    # 2. Developing a plugin
    sections.append(Section(
        title="2. Developing a Plugin",
        explanation=(
            "Plugins should expose a small registration API and be discoverable via entry_points. "
            "Design clear versioned interfaces for compatibility."
        ),
        code_example=(
            "```python\n"
            "# plugin_example.py\n"
            "class MyPlugin:\n"
            "    def name(self):\n"
            "        return 'my-plugin'\n\n"
            "    def initialize(self, config):\n"
            "        print('initialized', config)\n\n"
            "# In setup.cfg / pyproject, register under entry_points: keycrypt.plugins = myplugin:MyPlugin\n"
            "```"
        ),
        best_practices=(
            "- Provide clear lifecycle hooks (init, shutdown).\n- Avoid blocking work on import; prefer lazy initialization."
        ),
        performance=(
            "Measure plugin init time and isolate heavy IO to worker threads/processes."
        ),
    ))

    # 3. Policy-driven encryption
    sections.append(Section(
        title="3. Policy-Driven Encryption",
        explanation=(
            "Express encryption rules as data (YAML/JSON) and enforce them at runtime. Policies can include key rotation, algorithm selection, and scope."
        ),
        code_example=(
            "```python\n"
            "# Example policy as Python dict (in practice store as YAML/JSON)\n"
            "policy = {\n"
            "    'buckets': {\n"
            "        'sensitive': {'algorithm': 'AES-GCM', 'key_id': 'key-1'},\n"
            "        'public': {'algorithm': 'None'}\n"
            "    }\n"
            "}\n\n"
            "def apply_policy(bucket_name, plaintext):\n"
            "    p = policy['buckets'].get(bucket_name)\n"
            "    if p and p['algorithm'] != 'None':\n"
            "        # route to provider keyed by p['key_id']\n"
            "        return f'encrypted with {p[\'algorithm\']}'\n"
            "    return plaintext\n"
            "```"
        ),
        best_practices=(
            "- Keep policies auditable and versioned.\n- Provide overrides for emergency migration."
        ),
        performance=(
            "Cache policy lookups and compile into efficient rule checks for high-throughput paths."
        ),
    ))

    # 4. Integrating with cloud KMS
    sections.append(Section(
        title="4. Integrating with Cloud KMS",
        explanation=(
            "Use cloud KMS for envelope encryption and key lifecycle. Keep minimal plaintext exposure on compute nodes."
        ),
        code_example=(
            "```python\n"
            "# AWS KMS example (requires boto3 and credentials)\n"
            "try:\n"
            "    import boto3\n"
            "except Exception:\n"
            "    boto3 = None\n\n"
            "def kms_encrypt(key_id, plaintext: bytes):\n"
            "    if boto3 is None:\n"
            "        raise RuntimeError('boto3 not installed')\n"
            "    client = boto3.client('kms')\n"
            "    resp = client.encrypt(KeyId=key_id, Plaintext=plaintext)\n"
            "    return resp['CiphertextBlob']\n"
            "```"
        ),
        best_practices=(
            "- Prefer envelope encryption: use KMS to encrypt a data key, use symmetric key locally.\n- Rotate data keys regularly."
        ),
        performance=(
            "Cache decrypted data keys in memory for short-lived processes; avoid calling KMS per object."
        ),
    ))

    # 5. Performance optimization techniques
    sections.append(Section(
        title="5. Performance Optimization Techniques",
        explanation=(
            "Profile your code, batch operations, use streaming encryption for large files, and parallelize independent work."
        ),
        code_example=(
            "```python\n"
            "# Example: parallel batch encryption using concurrent.futures\n"
            "from concurrent.futures import ThreadPoolExecutor\n\n"
            "def encrypt_file(path):\n"
            "    data = path.read_bytes()\n"
            "    # placeholder encryption\n"
            "    return hash(data)\n\n"
            "paths = []  # list of Path objects\n"
            "with ThreadPoolExecutor(max_workers=4) as ex:\n"
            "    results = list(ex.map(encrypt_file, paths))\n"
            "```"
        ),
        best_practices=(
            "- Use appropriate worker counts; measure CPU vs IO bound behavior.\n- Avoid global interpreter lock bottlenecks by using processes for CPU-bound tasks."
        ),
        performance=(
            "Profile end-to-end and focus optimization where it moves the needle (hot loops, serialization)."
        ),
    ))

    # 6. Multi-party threshold cryptography
    sections.append(Section(
        title="6. Multi-Party Threshold Cryptography",
        explanation=(
            "Threshold schemes allow splitting key control across multiple parties. Use audited libraries for production (Shamir, Feldman, or KZG schemes)."
        ),
        code_example=(
            "```python\n"
            "# Simple XOR-split demo (NOT a threshold scheme; for educational use only)\n"
            "import os\n\n"
            "def xor_split(secret: bytes, parts: int):\n"
            "    shares = [bytearray(len(secret)) for _ in range(parts)]\n"
            "    for i in range(len(secret)):\n"
            "        r = os.urandom(parts - 1)\n"
            "        xor_sum = 0\n"
            "        for j, b in enumerate(r):\n"
            "            shares[j][i] = b\n"
            "            xor_sum ^= b\n"
            "        shares[-1][i] = xor_sum ^ secret[i]\n"
            "    return [bytes(s) for s in shares]\n\n"
            "def xor_combine(shares):\n"
            "    secret = bytearray(len(shares[0]))\n"
            "    for i in range(len(secret)):\n"
            "        v = 0\n"
            "        for s in shares:\n"
            "            v ^= s[i]\n"
            "        secret[i] = v\n"
            "    return bytes(secret)\n"
            "```"
        ),
        best_practices=(
            "- Use established threshold libraries for real security.\n- Ensure share transport and storage are authenticated and encrypted."
        ),
        performance=(
            "- Secret splitting is cheap; network and coordination are the dominating costs."
        ),
    ))

    # 7. Homomorphic encryption workflows
    sections.append(Section(
        title="7. Homomorphic Encryption Workflows",
        explanation=(
            "Homomorphic encryption allows computations on encrypted data. Use libraries like Microsoft SEAL or Pyfhel for experiments."
        ),
        code_example=(
            "```python\n"
            "# Conceptual example: using Pyfhel (if installed)\n"
            "try:\n"
            "    from pyfhel import Pyfhel, PyCtxt\n"
            "except Exception:\n"
            "    Pyfhel = None\n\n"
            "def he_demo():\n"
            "    if Pyfhel is None:\n"
            "        print('Pyfhel not available; install for full demo')\n"
            "        return\n"
            "    HE = Pyfhel()\n"
            "    HE.contextGen(p=65537)\n"
            "    HE.keyGen()\n"
            "    a = HE.encryptInt(3)\n"
            "    b = HE.encryptInt(4)\n"
            "    c = a + b\n"
            "    print('decrypted', HE.decryptInt(c))\n"
            "```"
        ),
        best_practices=(
            "- Homomorphic schemes are slow and require parameter tuning.\n- Understand noise growth and plan relinearization/bootstrapping."
        ),
        performance=(
            "- Offload heavy HE workloads to specialized hardware or batched jobs where possible."
        ),
    ))

    # 8. Zero-knowledge proof generation
    sections.append(Section(
        title="8. Zero-Knowledge Proof Generation",
        explanation=(
            "ZKPs let one party prove knowledge of a secret without revealing it. For short demos use Schnorr-style proofs."
        ),
        code_example=(
            "```python\n"
            "# Simple Schnorr non-interactive proof demo (educational, small primes)\n"
            "import secrets, hashlib\n\n"
            "# Use small toy parameters for demo only\n"
            "p = 2**127 - 1\n"
            "g = 5\n\n"
            "def schnorr_prove(x):\n"
            "    # x is secret exponent; public key y = g^x mod p\n"
            "    y = pow(g, x, p)\n"
            "    r = secrets.randbelow(p - 1)\n"
            "    t = pow(g, r, p)\n"
            "    c = int(hashlib.sha256(str(t).encode() + str(y).encode()).hexdigest(), 16)\n"
            "    s = (r + c * x) % (p - 1)\n"
            "    return {'y': y, 't': t, 's': s}\n\n"
            "def schnorr_verify(proof):\n"
            "    y = proof['y']\n"
            "    t = proof['t']\n"
            "    s = proof['s']\n"
            "    c = int(hashlib.sha256(str(t).encode() + str(y).encode()).hexdigest(), 16)\n"
            "    lhs = pow(g, s, p)\n"
            "    rhs = (t * pow(y, c, p)) % p\n"
            "    return lhs == rhs\n"
            "```"
        ),
        best_practices=(
            "- Use audited ZKP libraries for production (libsnark, zkSNARK frameworks).\n- Non-interactive Fiat-Shamir transforms require secure hashes."
        ),
        performance=(
            "- Proof generation can be expensive; use batch verification when supported."
        ),
    ))

    return sections


def generate_markdown(out: Optional[Path] = None) -> Path:
    outp = out or OUT_MD
    sections = make_sections()
    with outp.open("w", encoding="utf-8") as fh:
        fh.write("# Advanced Tutorial — KeyCrypt-Shield-X\n\n")
        fh.write("This document is intended for experienced engineers and researchers.\n\n")
        for sec in sections:
            fh.write(f"## {sec.title}\n\n")
            fh.write(f"{sec.explanation}\n\n")
            fh.write("### Example\n\n")
            fh.write(f"{_shallow_escape(sec.code_example)}\n\n")
            fh.write("### Best Practices\n\n")
            fh.write(f"{sec.best_practices}\n\n")
            fh.write("### Performance Considerations\n\n")
            fh.write(f"{sec.performance}\n\n")
    return outp


if __name__ == "__main__":
    md = generate_markdown()
    print("Generated:", md)
