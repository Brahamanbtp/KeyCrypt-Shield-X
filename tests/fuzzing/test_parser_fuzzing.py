"""Fuzzing tests for parser and deserializer robustness.

This module provides corpus-driven fuzz campaigns for:
- policy YAML parsing
- encryption metadata deserialization
- API request parsing against the REST surface

Fuzzing is opt-in and can be enabled with:
KEYCRYPT_RUN_FUZZ_TESTS=1 pytest tests/fuzzing/test_parser_fuzzing.py -q
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import random
import string
import sys
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import pytest
import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from src.core.key_manager import KeyManager
from src.policy.policy_loader import PolicyLoader
from src.storage.local_storage import SecureLocalStorage


MAX_INPUT_BYTES = 16 * 1024
MUTATIONS_PER_SEED = 28

_ENCRYPTED_METADATA_PAYLOAD = b"fuzzing-metadata-ciphertext-payload"
_ENCRYPTED_METADATA_CHUNK_ID = hashlib.sha256(_ENCRYPTED_METADATA_PAYLOAD).hexdigest()

_KNOWN_API_PATHS = [
    "/auth/token",
    "/decrypt",
    "/encrypt",
    "/keys/generate",
    "/status",
]
_ALLOWED_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}


def _env_enabled(name: str) -> bool:
    value = os.getenv(name, "")
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _detect_fuzz_backend() -> str | None:
    try:
        import atheris as _atheris  # type: ignore

        _ = _atheris
        return "atheris"
    except Exception:
        pass

    try:
        import pythonfuzz as _pythonfuzz  # type: ignore

        _ = _pythonfuzz
        return "pythonfuzz"
    except Exception:
        return None


@pytest.fixture(scope="module", autouse=True)
def _require_fuzz_opt_in() -> None:
    if not _env_enabled("KEYCRYPT_RUN_FUZZ_TESTS"):
        pytest.skip("Set KEYCRYPT_RUN_FUZZ_TESTS=1 to run parser fuzzing tests")


@pytest.fixture(scope="module")
def fuzz_backend() -> str:
    backend = _detect_fuzz_backend()
    if backend is None:
        pytest.skip("Install atheris or pythonfuzz to run parser fuzzing tests")
    return backend


def _policy_valid_corpus() -> list[bytes]:
    valid_schema_wrapped = """
schema_version: "1.0"
policy:
  name: "fuzz-policy"
  version: "1"
  rules:
    - condition:
        field: "metadata.classification"
        operator: "EQUALS"
        value: "restricted"
      action:
        algorithm: "AES-256-GCM"
        key_rotation: "90d"
        compliance: ["SOC2"]
        metadata:
          mode: "strict"
  default_action:
    algorithm: "AES-256-GCM"
    key_rotation: "30d"
    compliance: []
    metadata: {}
""".strip()

    valid_direct_policy = """
name: "direct-policy"
version: "2"
rules:
  - condition:
      field: "file.extension"
      operator: "IN"
      value: ["pdf", "docx"]
    action:
      algorithm: "CHACHA20-POLY1305"
      key_rotation: "7d"
      compliance: ["PCI"]
      metadata:
        region: "eu"
default_action:
  algorithm: "AES-256-GCM"
  key_rotation: "14d"
  compliance: ["ISO27001"]
  metadata: {}
""".strip()

    valid_json_inline = json.dumps(
        {
            "schema_version": "2.0",
            "policy": {
                "name": "json-policy",
                "version": "3",
                "rules": [
                    {
                        "condition": {
                            "field": "metadata.tier",
                            "operator": "EQUALS",
                            "value": "gold",
                        },
                        "action": {
                            "algorithm": "AES-256-GCM",
                            "key_rotation": "60d",
                            "compliance": ["HIPAA"],
                            "metadata": {"approval": "manual"},
                        },
                    }
                ],
                "default_action": {
                    "algorithm": "AES-256-GCM",
                    "key_rotation": "30d",
                    "compliance": [],
                    "metadata": {},
                },
            },
        },
        separators=(",", ":"),
    )

    return [valid_schema_wrapped.encode("utf-8"), valid_direct_policy.encode("utf-8"), valid_json_inline.encode("utf-8")]


def _metadata_valid_corpus() -> list[bytes]:
    seeds: list[dict[str, Any]] = [
        {
            "chunk_id": _ENCRYPTED_METADATA_CHUNK_ID,
            "data_checksum": _ENCRYPTED_METADATA_CHUNK_ID,
            "size": len(_ENCRYPTED_METADATA_PAYLOAD),
            "metadata": {
                "algorithm": "aes-gcm",
                "nonce_b64": "bm9uY2U=",
                "associated_data_b64": "YWFk",
            },
        },
        {
            "chunk_id": _ENCRYPTED_METADATA_CHUNK_ID,
            "data_checksum": _ENCRYPTED_METADATA_CHUNK_ID,
            "size": len(_ENCRYPTED_METADATA_PAYLOAD),
            "metadata": {
                "algorithm": "chacha20",
                "tag_b64": "dGFn",
                "source": "fuzz-corpus",
            },
        },
    ]
    return [json.dumps(item, separators=(",", ":")).encode("utf-8") for item in seeds]


def _api_valid_corpus() -> list[bytes]:
    auth_body = b'{"username":"admin","password":"change-me"}'
    auth_request = (
        b"POST /auth/token HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Type: application/json\r\n"
        + f"Content-Length: {len(auth_body)}\r\n".encode("ascii")
        + b"\r\n"
        + auth_body
    )

    status_request = b"GET /status HTTP/1.1\r\nHost: localhost\r\n\r\n"

    malformed_but_recoverable = (
        b"POST /decrypt HTTP/1.1\n"
        b"Host: localhost\n"
        b"Content-Type: application/json\n\n"
        b"{not-json"
    )

    return [auth_request, status_request, malformed_but_recoverable]


def _write_guided_corpus(root: Path) -> dict[str, list[Path]]:
    root.mkdir(parents=True, exist_ok=True)

    groups: dict[str, list[bytes]] = {
        "policy_yaml_parser": _policy_valid_corpus(),
        "encryption_metadata_deserializer": _metadata_valid_corpus(),
        "api_request_parser": _api_valid_corpus(),
    }

    written: dict[str, list[Path]] = {}
    for group_name, seeds in groups.items():
        group_dir = root / group_name
        group_dir.mkdir(parents=True, exist_ok=True)
        files: list[Path] = []
        for index, payload in enumerate(seeds):
            suffix = ".http" if group_name == "api_request_parser" else ".seed"
            path = group_dir / f"seed-{index:03d}{suffix}"
            path.write_bytes(payload)
            files.append(path)
        written[group_name] = files

    return written


def _mutate_payload(seed: bytes, *, rng: random.Random) -> bytes:
    data = bytearray(seed[:MAX_INPUT_BYTES])
    operation = rng.randrange(6)

    if operation == 0 and data:
        index = rng.randrange(len(data))
        data[index] ^= 1 << rng.randrange(8)
    elif operation == 1:
        insert_len = rng.randrange(1, 33)
        insert_at = rng.randrange(len(data) + 1) if data else 0
        data[insert_at:insert_at] = os.urandom(insert_len)
    elif operation == 2 and data:
        start = rng.randrange(len(data))
        end = min(len(data), start + rng.randrange(1, 33))
        del data[start:end]
    elif operation == 3 and data:
        start = rng.randrange(len(data))
        end = min(len(data), start + rng.randrange(1, 64))
        segment = data[start:end]
        data.extend(segment)
    elif operation == 4:
        data.extend(os.urandom(rng.randrange(1, 65)))
    else:
        if data:
            new_len = rng.randrange(0, len(data) + 1)
            del data[new_len:]

    if not data:
        data.extend(os.urandom(1))

    return bytes(data[:MAX_INPUT_BYTES])


def _iter_fuzz_inputs(
    corpus: Iterable[bytes],
    *,
    backend: str,
    mutations_per_seed: int,
) -> Iterable[bytes]:
    for seed in corpus:
        bounded_seed = seed[:MAX_INPUT_BYTES]
        yield bounded_seed

        seed_hash = hashlib.sha256(bounded_seed).digest()
        rng = random.Random(int.from_bytes(seed_hash[:8], "big"))

        for _ in range(max(1, mutations_per_seed)):
            candidate = _mutate_payload(bounded_seed, rng=rng)
            yield candidate

            if backend == "atheris":
                try:
                    import atheris  # type: ignore

                    provider = atheris.FuzzedDataProvider(candidate)
                    consume_len = provider.ConsumeIntInRange(0, min(MAX_INPUT_BYTES, len(candidate)))
                    derived = provider.ConsumeBytes(consume_len)
                    if derived:
                        yield derived
                except Exception:
                    # Backend integration is opportunistic for local pytest runs.
                    pass


def fuzz_policy_yaml_parser(yaml_input: bytes) -> None:
    """Feed random YAML into policy parsing and schema validation flow."""
    payload_bytes = bytes(yaml_input[:MAX_INPUT_BYTES])
    if not payload_bytes:
        return

    loader = PolicyLoader(cache_limit=8)

    try:
        text = payload_bytes.decode("utf-8", errors="ignore")
        if not text.strip():
            return

        parsed = loader._parse_string_payload(text)
        try:
            _ = loader._validate_and_build_policy(parsed, source="fuzz:policy", signature=None)
        except ValueError:
            # Invalid policy structures are acceptable and expected.
            return
    except (ValueError, TypeError, yaml.YAMLError, UnicodeError, RecursionError):
        return


def fuzz_encryption_metadata_deserializer(metadata_input: bytes) -> None:
    """Feed random bytes into encryption metadata deserialization path."""
    payload = bytes(metadata_input[:MAX_INPUT_BYTES])

    with TemporaryDirectory(prefix="keycrypt-fuzz-meta-") as temp_root:
        storage = SecureLocalStorage(root_dir=temp_root)
        chunk_path = storage._chunk_path(_ENCRYPTED_METADATA_CHUNK_ID)
        meta_path = storage._meta_path(_ENCRYPTED_METADATA_CHUNK_ID)
        chunk_path.parent.mkdir(parents=True, exist_ok=True)

        chunk_path.write_bytes(_ENCRYPTED_METADATA_PAYLOAD)
        meta_path.write_bytes(payload)

        try:
            _ = storage.retrieve_chunk(_ENCRYPTED_METADATA_CHUNK_ID)
        except (ValueError, TypeError, FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
            return


def _sanitize_header_name(name: str) -> str:
    candidate = "".join(ch for ch in name.strip() if ch in string.ascii_letters + string.digits + "-")
    return candidate[:64]


def _sanitize_path(path: str) -> str:
    candidate = "".join(ch for ch in path.strip() if ch >= " " and ch not in {"\x7f"})
    if not candidate:
        return "/auth/token"
    if not candidate.startswith("/"):
        candidate = "/" + candidate.lstrip("/")
    return candidate[:256]


def _parse_http_request_bytes(raw: bytes) -> tuple[str, str, dict[str, str], bytes]:
    bounded = raw[:MAX_INPUT_BYTES]

    head: bytes
    body: bytes
    if b"\r\n\r\n" in bounded:
        head, body = bounded.split(b"\r\n\r\n", 1)
        header_lines = head.split(b"\r\n")
    elif b"\n\n" in bounded:
        head, body = bounded.split(b"\n\n", 1)
        header_lines = head.splitlines()
    else:
        header_lines = bounded.splitlines()
        body = b""

    request_line = header_lines[0].decode("latin-1", errors="ignore") if header_lines else ""
    parts = request_line.split()

    method = parts[0].upper() if parts else "POST"
    if method not in _ALLOWED_HTTP_METHODS:
        method = "POST"

    path = _sanitize_path(parts[1] if len(parts) > 1 else "/auth/token")

    headers: dict[str, str] = {}
    for line in header_lines[1:40]:
        decoded = line.decode("latin-1", errors="ignore")
        if ":" not in decoded:
            continue
        key, value = decoded.split(":", 1)
        normalized_key = _sanitize_header_name(key)
        if not normalized_key:
            continue
        headers[normalized_key] = value.strip()[:512]

    return method, path, headers, body[:MAX_INPUT_BYTES]


def fuzz_api_request_parser(
    http_request: bytes,
    *,
    client: Any,
    default_headers: Mapping[str, str],
) -> int:
    """Feed malformed raw HTTP-like requests into the FastAPI request parser."""
    method, path, headers, body = _parse_http_request_bytes(http_request)

    merged_headers = dict(headers)
    lowered = {key.lower(): value for key, value in merged_headers.items()}

    if path != "/auth/token" and "authorization" not in lowered:
        merged_headers.update(default_headers)

    if method in {"POST", "PUT", "PATCH"} and body and "content-type" not in lowered:
        merged_headers["Content-Type"] = "application/json"

    try:
        response = client.request(method=method, url=path, headers=merged_headers, content=body)
    except Exception:
        # Malformed wire-format can fail before app-level parsing; this is acceptable.
        return 0

    if response.status_code >= 500:
        raise AssertionError(
            f"API parser emitted server error for fuzz input: method={method} path={path} status={response.status_code}"
        )

    return int(response.status_code)


@pytest.fixture(scope="module")
def api_fuzz_context(tmp_path_factory: pytest.TempPathFactory) -> tuple[Any, dict[str, str]]:
    fastapi_testclient = pytest.importorskip(
        "fastapi.testclient",
        reason="API parser fuzzing requires fastapi.testclient",
    )
    rest_api = importlib.import_module("src.api.rest_api")
    test_client_cls = getattr(fastapi_testclient, "TestClient")

    original_key_manager = rest_api.key_manager
    original_rate_limiter = rest_api.rate_limiter

    isolated_db_path = tmp_path_factory.mktemp("fuzz_api") / "key_manager.db"
    rest_api.key_manager = KeyManager(db_path=isolated_db_path, kek=b"F" * 32)
    rest_api.rate_limiter = rest_api.RateLimiter(requests_per_second=200_000)

    try:
        with test_client_cls(rest_api.app) as client:
            token_response = client.post(
                "/auth/token",
                json={
                    "username": rest_api.DEFAULT_API_USER,
                    "password": rest_api.DEFAULT_API_PASSWORD,
                },
            )
            if token_response.status_code != 200:
                raise RuntimeError(f"failed to obtain API auth token for fuzzing: {token_response.status_code}")

            access_token = token_response.json().get("access_token")
            if not isinstance(access_token, str) or not access_token:
                raise RuntimeError("API auth token response missing access_token")

            yield client, {"Authorization": f"Bearer {access_token}"}
    finally:
        rest_api.key_manager = original_key_manager
        rest_api.rate_limiter = original_rate_limiter


def _run_fuzz_campaign(
    *,
    target: Callable[[bytes], None],
    corpus: Iterable[bytes],
    backend: str,
    mutations_per_seed: int,
) -> int:
    executed = 0
    for payload in _iter_fuzz_inputs(corpus, backend=backend, mutations_per_seed=mutations_per_seed):
        target(payload)
        executed += 1
    return executed


def test_fuzz_policy_yaml_parser(
    tmp_path: Path,
    fuzz_backend: str,
    record_property: pytest.RecordProperty,
) -> None:
    corpus_root = tmp_path / "fuzz_corpus"
    written = _write_guided_corpus(corpus_root)
    policy_corpus = [path.read_bytes() for path in written["policy_yaml_parser"]]

    executed = _run_fuzz_campaign(
        target=fuzz_policy_yaml_parser,
        corpus=policy_corpus,
        backend=fuzz_backend,
        mutations_per_seed=MUTATIONS_PER_SEED,
    )

    record_property("fuzz_backend", fuzz_backend)
    record_property("policy_yaml_seed_count", len(policy_corpus))
    record_property("policy_yaml_inputs_executed", executed)
    record_property("policy_yaml_corpus_dir", str(corpus_root / "policy_yaml_parser"))

    assert len(policy_corpus) >= 3
    assert executed >= len(policy_corpus)


def test_fuzz_encryption_metadata_deserializer(
    tmp_path: Path,
    fuzz_backend: str,
    record_property: pytest.RecordProperty,
) -> None:
    corpus_root = tmp_path / "fuzz_corpus"
    written = _write_guided_corpus(corpus_root)
    metadata_corpus = [path.read_bytes() for path in written["encryption_metadata_deserializer"]]

    executed = _run_fuzz_campaign(
        target=fuzz_encryption_metadata_deserializer,
        corpus=metadata_corpus,
        backend=fuzz_backend,
        mutations_per_seed=MUTATIONS_PER_SEED,
    )

    record_property("fuzz_backend", fuzz_backend)
    record_property("metadata_seed_count", len(metadata_corpus))
    record_property("metadata_inputs_executed", executed)
    record_property("metadata_corpus_dir", str(corpus_root / "encryption_metadata_deserializer"))

    assert len(metadata_corpus) >= 2
    assert executed >= len(metadata_corpus)


def test_fuzz_api_request_parser(
    tmp_path: Path,
    fuzz_backend: str,
    api_fuzz_context: tuple[Any, dict[str, str]],
    record_property: pytest.RecordProperty,
) -> None:
    client, default_headers = api_fuzz_context

    corpus_root = tmp_path / "fuzz_corpus"
    written = _write_guided_corpus(corpus_root)
    api_corpus = [path.read_bytes() for path in written["api_request_parser"]]

    statuses: list[int] = []

    def _target(payload: bytes) -> None:
        status = fuzz_api_request_parser(payload, client=client, default_headers=default_headers)
        statuses.append(status)

    executed = _run_fuzz_campaign(
        target=_target,
        corpus=api_corpus,
        backend=fuzz_backend,
        mutations_per_seed=MUTATIONS_PER_SEED,
    )

    nonzero_statuses = [status for status in statuses if status > 0]

    record_property("fuzz_backend", fuzz_backend)
    record_property("api_seed_count", len(api_corpus))
    record_property("api_inputs_executed", executed)
    record_property("api_nonzero_statuses", len(nonzero_statuses))
    record_property("api_corpus_dir", str(corpus_root / "api_request_parser"))

    assert len(api_corpus) >= 3
    assert executed >= len(api_corpus)
