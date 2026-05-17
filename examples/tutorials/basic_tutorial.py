"""Interactive Basic Tutorial for KeyCrypt-Shield-X

Run as a script: python -m examples.tutorials.basic_tutorial

This script walks a beginner through installation notes, encrypt/decrypt examples,
algorithm explanations, key management basics, batch encryption, and security tuning.
Each step shows an explanation, a code example, an exercise, and an automatic validation.
Progress is saved to `artifacts/tutorial_progress.json`.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict

try:
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except Exception:  # pragma: no cover - optional
    CRYPTO_AVAILABLE = False


PROGRESS_PATH = Path("artifacts/tutorial_progress.json")
PROGRESS_PATH.parent.mkdir(parents=True, exist_ok=True)


@dataclass
class Step:
    id: str
    title: str
    explanation: str
    code_example: str
    exercise: str
    validator: Callable[[], bool]


def save_progress(state: Dict[str, str]) -> None:
    state["updated_at"] = datetime.utcnow().isoformat()
    PROGRESS_PATH.write_text(json.dumps(state, indent=2), encoding="utf-8")


def load_progress() -> Dict[str, str]:
    if PROGRESS_PATH.exists():
        try:
            return json.loads(PROGRESS_PATH.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def step_installation_validator() -> bool:
    # Check for optional dependencies
    ok = CRYPTO_AVAILABLE
    print("Optional dependency 'cryptography' available:" , ok)
    return ok


def _simple_encrypt_bytes(data: bytes, key: bytes) -> bytes:
    if CRYPTO_AVAILABLE:
        f = Fernet(key)
        return f.encrypt(data)
    # Fallback: XOR with key repeated (educational only; insecure)
    out = bytearray()
    for i, b in enumerate(data):
        out.append(b ^ key[i % len(key)])
    return bytes(out)


def _simple_decrypt_bytes(data: bytes, key: bytes) -> bytes:
    if CRYPTO_AVAILABLE:
        f = Fernet(key)
        return f.decrypt(data)
    # XOR fallback symmetric
    return _simple_encrypt_bytes(data, key)


def step_encrypt_example_validator() -> bool:
    # Create temp file, encrypt, decrypt, validate content
    key = Fernet.generate_key() if CRYPTO_AVAILABLE else b"simplekey12345"
    content = b"hello tutorial"
    enc = _simple_encrypt_bytes(content, key)
    dec = _simple_decrypt_bytes(enc, key)
    ok = dec == content
    print("Encrypt/decrypt roundtrip successful:", ok)
    return ok


def step_decrypt_example_validator() -> bool:
    # Reuse the same check as encrypt
    return step_encrypt_example_validator()


def step_algorithms_validator() -> bool:
    # Basic check: demonstrate AES vs ChaCha description present
    print("AES vs ChaCha20: AES is widely used; ChaCha20 is faster on some platforms.")
    return True


def step_key_management_validator() -> bool:
    # Simple key storage simulation
    ks = Path("artifacts/keys_demo")
    ks.mkdir(parents=True, exist_ok=True)
    key_file = ks / "demo.key"
    key_file.write_bytes(Fernet.generate_key() if CRYPTO_AVAILABLE else b"demo_key")
    ok = key_file.exists()
    print("Key stored at:", key_file)
    return ok


def step_batch_validator() -> bool:
    # Batch encrypt multiple small files
    ks = Path(tempfile.mkdtemp())
    files = []
    for i in range(3):
        p = ks / f"file_{i}.txt"
        p.write_text(f"content {i}")
        files.append(p)
    key = Fernet.generate_key() if CRYPTO_AVAILABLE else b"batchkey"
    for p in files:
        data = p.read_bytes()
        p.write_bytes(_simple_encrypt_bytes(data, key))
    # Check files are non-empty and not equal to original text
    ok = all(p.exists() and p.read_bytes() != f"content {files.index(p)}".encode() for p in files)
    print("Batch encryption simulated, files encrypted:", ok)
    return ok


def step_config_validator() -> bool:
    # Simple security level check
    levels = {"low": 1000, "medium": 10000, "high": 100000}
    print("Recommended iteration counts for PBKDF2 (example):", levels)
    return True


def make_steps() -> Dict[str, Step]:
    steps: Dict[str, Step] = {}
    steps["1"] = Step(
        id="1",
        title="Installation and setup",
        explanation="Install optional dependency 'cryptography' for stronger examples.",
        code_example="pip install cryptography",
        exercise="Run the installation command and ensure import works.",
        validator=step_installation_validator,
    )
    steps["2"] = Step(
        id="2",
        title="Encrypting your first file",
        explanation="Shows a simple encrypt/decrypt example using Fernet (or XOR fallback).",
        code_example=(
            "from cryptography.fernet import Fernet\n"
            "key = Fernet.generate_key()\n"
            "f = Fernet(key)\n"
            "token = f.encrypt(b'hello')\n"
            "print(f.decrypt(token))"
        ),
        exercise="Run the code example in a Python REPL or this script.",
        validator=step_encrypt_example_validator,
    )
    steps["3"] = Step(
        id="3",
        title="Decrypting the file",
        explanation="Reverse the encryption and verify content matches.",
        code_example="(Use the same Fernet key and call f.decrypt(token))",
        exercise="Decrypt the token from step 2 and verify the plaintext.",
        validator=step_decrypt_example_validator,
    )
    steps["4"] = Step(
        id="4",
        title="Understanding encryption algorithms",
        explanation="Compare AES vs ChaCha20: performance, implementation, and use-cases.",
        code_example="# AES uses block modes; ChaCha20 is a stream cipher (example descriptions)",
        exercise="Read the short explanation and summarize one key difference.",
        validator=step_algorithms_validator,
    )
    steps["5"] = Step(
        id="5",
        title="Key management basics",
        explanation="Store keys securely; prefer OS key stores or hardware modules.",
        code_example="# Example: write key to secure file (demo)",
        exercise="Create a demo key file using the shown pattern.",
        validator=step_key_management_validator,
    )
    steps["6"] = Step(
        id="6",
        title="Batch encryption",
        explanation="Encrypt multiple files programmatically (demonstration).",
        code_example="# Loop over files and encrypt with a symmetric key",
        exercise="Run a batch encryption on sample files and verify they were transformed.",
        validator=step_batch_validator,
    )
    steps["7"] = Step(
        id="7",
        title="Configuring security levels",
        explanation="Choose iteration counts and algorithm parameters based on threat model.",
        code_example="# PBKDF2 iterations examples",
        exercise="Pick a security level for your environment and document it.",
        validator=step_config_validator,
    )
    return steps


def run():
    steps = make_steps()
    progress = load_progress()
    print("Interactive Basic Tutorial — KeyCrypt-Shield-X")
    print("Progress file:", PROGRESS_PATH)
    while True:
        print("\nSteps:")
        for k in sorted(steps.keys()):
            done = progress.get(k) == "done"
            print(f"{k}. {steps[k].title} {'(done)' if done else ''}")
        choice = input("Choose step number to run (or 'q' to quit, 'r' to reset progress): ").strip()
        if choice.lower() == "q":
            break
        if choice.lower() == "r":
            progress = {}
            save_progress(progress)
            print("Progress reset.")
            continue
        if choice not in steps:
            print("Invalid choice")
            continue
        s = steps[choice]
        print(f"\n== {s.title} ==\n")
        print(s.explanation)
        print("\nCode example:\n")
        print(s.code_example)
        input("Press Enter when ready to run validation (or Ctrl-C to cancel)")
        try:
            ok = s.validator()
        except Exception as exc:
            print("Validation failed with exception:", exc)
            ok = False
        print("Validation result:", ok)
        progress[choice] = "done" if ok else "failed"
        save_progress(progress)
    print("Goodbye — progress saved to", PROGRESS_PATH)


if __name__ == "__main__":
    # Allow running via `python -m examples.tutorials.basic_tutorial`
    run()
