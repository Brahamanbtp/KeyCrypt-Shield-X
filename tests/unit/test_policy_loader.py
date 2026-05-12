"""Unit tests for PolicyLoader multi-source loading and caching."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.policy.policy_loader import Database, PolicyLoader, SignatureVerifier
from src.policy.policy_schema import Policy


def _base_policy_dict() -> dict[str, Any]:
    return {
        "name": "test-policy",
        "version": "1.0",
        "default_action": {
            "algorithm": "aes-256-gcm",
            "key_rotation": "90d",
            "compliance": ["baseline"],
            "metadata": {},
        },
        "rules": [],
    }


def _base_policy_with_schema(schema_version: object = "1.0") -> dict[str, Any]:
    return {
        "schema_version": schema_version,
        "policy": _base_policy_dict(),
    }


class MockSignatureVerifier:
    """Mock signature verifier that accepts all signatures."""

    def verify(self, payload: bytes, signature: str, *, source: str) -> bool:
        return signature == "valid-signature"


class MockDatabase:
    """Mock database that returns policy tuples."""

    def __init__(self, policy: dict[str, Any] | None = None) -> None:
        self._policy = policy or _base_policy_dict()

    def get_policy(self, policy_id: str) -> tuple[dict[str, Any], str | None]:
        return (self._policy, None)


@pytest.fixture
def temp_policy_yaml(tmp_path: Path) -> Path:
    yaml_file = tmp_path / "policy.yaml"
    yaml_file.write_text(yaml.dump(_base_policy_dict()), encoding="utf-8")
    return yaml_file


@pytest.fixture
def temp_policy_json(tmp_path: Path) -> Path:
    import json

    json_file = tmp_path / "policy.json"
    json_file.write_text(json.dumps(_base_policy_dict()), encoding="utf-8")
    return json_file


@pytest.fixture
def temp_policy_with_signature(tmp_path: Path) -> tuple[Path, Path]:
    """Policy file with sidecar signature file."""
    yaml_file = tmp_path / "signed_policy.yaml"
    sig_file = yaml_file.with_suffix(yaml_file.suffix + ".sig")

    yaml_file.write_text(yaml.dump(_base_policy_dict()), encoding="utf-8")
    sig_file.write_text("test-signature", encoding="utf-8")

    return yaml_file, sig_file


def test_policy_loader_loads_from_yaml(temp_policy_yaml: Path) -> None:
    loader = PolicyLoader()
    policy = loader.load_from_yaml(temp_policy_yaml)

    assert isinstance(policy, Policy)
    assert policy.name == "test-policy"
    assert policy.default_action.algorithm == "aes-256-gcm"


def test_policy_loader_loads_from_json(temp_policy_json: Path) -> None:
    loader = PolicyLoader()
    policy = loader.load_from_json(temp_policy_json)

    assert isinstance(policy, Policy)
    assert policy.name == "test-policy"
    assert policy.version == "1.0"


def test_policy_loader_detects_invalid_yaml(tmp_path: Path) -> None:
    invalid_yaml = tmp_path / "invalid.yaml"
    invalid_yaml.write_text("{ invalid yaml: [", encoding="utf-8")

    loader = PolicyLoader()
    with pytest.raises(ValueError, match="invalid YAML"):
        loader.load_from_yaml(invalid_yaml)


def test_policy_loader_detects_non_mapping_payload(tmp_path: Path) -> None:
    yaml_file = tmp_path / "array.yaml"
    yaml_file.write_text(yaml.dump([1, 2, 3]), encoding="utf-8")

    loader = PolicyLoader()
    with pytest.raises(ValueError, match="must be a mapping"):
        loader.load_from_yaml(yaml_file)


def test_policy_loader_caches_policy_files(temp_policy_yaml: Path) -> None:
    loader = PolicyLoader(cache_limit=10)
    policy1 = loader.load_from_yaml(temp_policy_yaml)
    policy2 = loader.load_from_yaml(temp_policy_yaml)

    assert policy1.name == policy2.name
    assert len(loader._cache) == 1


def test_policy_loader_detects_changed_files(temp_policy_yaml: Path, tmp_path: Path) -> None:
    """Cache detects when file modification time changes."""
    loader = PolicyLoader(cache_limit=10)
    policy1 = loader.load_from_yaml(temp_policy_yaml)
    initial_cache_size = len(loader._cache)

    modified_dict = _base_policy_dict()
    modified_dict["name"] = "modified-policy"
    temp_policy_yaml.write_text(yaml.dump(modified_dict), encoding="utf-8")

    policy2 = loader.load_from_yaml(temp_policy_yaml)

    assert policy1.name != policy2.name
    assert policy2.name == "modified-policy"


def test_policy_loader_enforces_cache_limit(temp_policy_yaml: Path, tmp_path: Path) -> None:
    """Cache drops oldest entries when limit is exceeded."""
    cache_limit = 3
    loader = PolicyLoader(cache_limit=cache_limit)

    # Create multiple policy files
    yaml_files = []
    for i in range(cache_limit + 2):
        file = tmp_path / f"policy_{i}.yaml"
        policy_dict = _base_policy_dict()
        policy_dict["name"] = f"policy-{i}"
        file.write_text(yaml.dump(policy_dict), encoding="utf-8")
        yaml_files.append(file)

    # Load all policies
    for file in yaml_files:
        loader.load_from_yaml(file)

    # Cache should contain only the most recent cache_limit entries
    assert len(loader._cache) == cache_limit


def test_policy_loader_reads_sidecar_signature(temp_policy_with_signature: tuple[Path, Path]) -> None:
    yaml_file, sig_file = temp_policy_with_signature
    loader = PolicyLoader()

    policy = loader.load_from_yaml(yaml_file)

    assert isinstance(policy, Policy)
    assert policy.name == "test-policy"


def test_policy_loader_verifies_signature(temp_policy_yaml: Path) -> None:
    """Signature verification is called when verifier is provided."""
    verifier = MockSignatureVerifier()
    loader = PolicyLoader(signature_verifier=verifier)

    with pytest.raises(ValueError, match="signature verification failed"):
        loader._verify_signature(
            payload=_base_policy_dict(),
            signature="invalid-signature",
            source="test",
        )


def test_policy_loader_requires_signature_when_configured(temp_policy_yaml: Path) -> None:
    """Loader blocks unsigned policies when require_signature=True."""
    verifier = MockSignatureVerifier()
    loader = PolicyLoader(signature_verifier=verifier, require_signature=True)

    with pytest.raises(ValueError, match="signature is required"):
        loader._verify_signature(
            payload=_base_policy_dict(),
            signature=None,
            source="test",
        )


def test_policy_loader_loads_from_database() -> None:
    db = MockDatabase(_base_policy_dict())
    loader = PolicyLoader()

    policy = loader.load_from_database("policy-123", db)

    assert isinstance(policy, Policy)
    assert policy.name == "test-policy"


def test_policy_loader_validates_policy_id_for_database() -> None:
    db = MockDatabase()
    loader = PolicyLoader()

    with pytest.raises(ValueError, match="policy_id must be a non-empty string"):
        loader.load_from_database("", db)

    with pytest.raises(ValueError, match="policy_id must be a non-empty string"):
        loader.load_from_database("   ", db)


def test_policy_loader_handles_database_tuple_records() -> None:
    """Database can return (payload, signature) tuples."""
    policy_dict = _base_policy_dict()
    db_mock = Mock(spec=Database)
    db_mock.get_policy.return_value = (policy_dict, "sig-value")

    loader = PolicyLoader()
    policy = loader.load_from_database("test-id", db_mock)

    assert policy.name == "test-policy"


def test_policy_loader_handles_database_mapping_records() -> None:
    """Database can return records with payload, signature, fingerprint keys."""
    policy_dict = _base_policy_dict()
    record = {
        "payload": policy_dict,
        "signature": "sig-value",
        "fingerprint": "fp-value",
    }
    db_mock = Mock(spec=Database)
    db_mock.get_policy.return_value = record

    loader = PolicyLoader()
    policy = loader.load_from_database("test-id", db_mock)

    assert policy.name == "test-policy"


def test_policy_loader_rejects_async_database_methods() -> None:
    """Async database methods are not supported."""
    db_mock = Mock(spec=Database)

    async def async_get():
        return _base_policy_dict()

    db_mock.get_policy.return_value = async_get()

    loader = PolicyLoader()
    with pytest.raises(TypeError, match="asynchronous database methods are not supported"):
        loader.load_from_database("test-id", db_mock)


def test_policy_loader_extracts_record_parts_from_database() -> None:
    """Tests the tuple unpacking of database records."""
    loader = PolicyLoader()
    policy_dict = _base_policy_dict()

    # Test 2-tuple: (payload, signature)
    payload, sig, fp = loader._extract_record_parts((policy_dict, "sig"))
    assert payload == policy_dict
    assert sig == "sig"
    assert fp is None

    # Test 3-tuple: (payload, signature, fingerprint)
    payload, sig, fp = loader._extract_record_parts((policy_dict, "sig", "fp"))
    assert payload == policy_dict
    assert sig == "sig"
    assert fp == "fp"

    # Test mapping: {payload, signature, fingerprint}
    record_mapping = {
        "payload": policy_dict,
        "signature": "sig",
        "fingerprint": "fp",
    }
    payload, sig, fp = loader._extract_record_parts(record_mapping)
    assert payload == policy_dict
    assert sig == "sig"
    assert fp == "fp"


def test_policy_loader_coerces_string_payload() -> None:
    """Loader can parse policy from JSON or YAML strings."""
    loader = PolicyLoader()
    import json

    policy_dict = _base_policy_dict()
    json_str = json.dumps(policy_dict)
    yaml_str = yaml.dump(policy_dict)

    payload_from_json = loader._coerce_payload(json_str)
    payload_from_yaml = loader._coerce_payload(yaml_str)

    assert payload_from_json == policy_dict
    assert payload_from_yaml == policy_dict


def test_policy_loader_coerces_bytes_payload() -> None:
    """Loader can parse policy from bytes."""
    loader = PolicyLoader()
    import json

    policy_dict = _base_policy_dict()
    json_bytes = json.dumps(policy_dict).encode("utf-8")

    payload = loader._coerce_payload(json_bytes)
    assert payload == policy_dict


def test_policy_loader_rejects_invalid_record_tuples() -> None:
    """Loader rejects database tuples of invalid length."""
    loader = PolicyLoader()

    with pytest.raises(TypeError, match="tuple records must have length 2 or 3"):
        loader._extract_record_parts((1, 2, 3, 4))

    with pytest.raises(TypeError, match="tuple records must have length 2 or 3"):
        loader._extract_record_parts((1,))


def test_policy_loader_clears_cache() -> None:
    """clear_cache() removes all cached policies."""
    loader = PolicyLoader()
    loader._cache["key1"] = Mock()
    loader._cache["key2"] = Mock()

    assert len(loader._cache) == 2
    loader.clear_cache()
    assert len(loader._cache) == 0


def test_policy_loader_validates_remote_url() -> None:
    """Loader rejects empty or whitespace-only URLs."""
    loader = PolicyLoader()

    with pytest.raises(ValueError, match="url must be a non-empty string"):
        loader.load_from_remote("")

    with pytest.raises(ValueError, match="url must be a non-empty string"):
        loader.load_from_remote("   ")


def test_policy_loader_validates_file_path() -> None:
    """Loader rejects non-existent file paths."""
    loader = PolicyLoader()

    with pytest.raises(FileNotFoundError, match="policy file not found"):
        loader.load_from_yaml(Path("/nonexistent/policy.yaml"))

    with pytest.raises(FileNotFoundError, match="policy file not found"):
        loader.load_from_json(Path("/nonexistent/policy.json"))
