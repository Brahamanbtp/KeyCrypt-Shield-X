"""Integration tests for cloud provider integrations.

Execution modes:
- Default: mocked/local emulation so tests are deterministic in CI.
- Optional real cloud: enable with KEYCRYPT_RUN_REAL_CLOUD_TESTS=1 and set
  provider credentials in environment (for example via pytest-env).

AWS emulation preference order:
1. LocalStack (KEYCRYPT_AWS_LOCALSTACK_ENDPOINT)
2. moto (if installed)
3. In-memory fallback clients
"""

from __future__ import annotations

import asyncio
import importlib.util
import os
import sys
import time
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from src.abstractions.crypto_provider import CryptoProvider
from src.abstractions.key_provider import KeyGenerationParams
from src.integrations import s3_encrypted_storage


def _load_plugin_class(plugin_relative_path: str, module_name: str, class_name: str) -> type[Any]:
    plugin_path = PROJECT_ROOT / plugin_relative_path
    spec = importlib.util.spec_from_file_location(module_name, plugin_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load plugin module at {plugin_path}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    klass = getattr(module, class_name, None)
    if not isinstance(klass, type):
        raise RuntimeError(f"class {class_name} not found in plugin {plugin_path}")
    return klass


class _PrefixCryptoProvider(CryptoProvider):
    def encrypt(self, plaintext: bytes, context: Any) -> bytes:
        _ = context
        if not isinstance(plaintext, bytes):
            raise TypeError("plaintext must be bytes")
        return b"enc:" + plaintext

    def decrypt(self, ciphertext: bytes, context: Any) -> bytes:
        _ = context
        if not isinstance(ciphertext, bytes) or not ciphertext.startswith(b"enc:"):
            raise ValueError("invalid ciphertext")
        return ciphertext[4:]

    def get_algorithm_name(self) -> str:
        return "prefix"

    def get_security_level(self) -> int:
        return 1


class _InMemoryBody:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    async def read(self) -> bytes:
        return self._payload


class _InMemoryAsyncS3Client:
    def __init__(self) -> None:
        self.objects: dict[tuple[str, str], dict[str, Any]] = {}

    async def put_object(self, **kwargs: Any) -> dict[str, Any]:
        bucket = str(kwargs["Bucket"])
        key = str(kwargs["Key"])
        self.objects[(bucket, key)] = {
            "Body": bytes(kwargs["Body"]),
            "Metadata": dict(kwargs.get("Metadata", {})),
        }
        return {"ETag": '"in-memory-etag"'}

    async def get_object(self, **kwargs: Any) -> dict[str, Any]:
        bucket = str(kwargs["Bucket"])
        key = str(kwargs["Key"])
        stored = self.objects[(bucket, key)]
        return {
            "Body": _InMemoryBody(stored["Body"]),
            "Metadata": dict(stored["Metadata"]),
        }


class _SyncS3ToAsyncAdapter:
    def __init__(self, sync_client: Any) -> None:
        self._sync_client = sync_client

    async def put_object(self, **kwargs: Any) -> dict[str, Any]:
        return await asyncio.to_thread(self._sync_client.put_object, **kwargs)

    async def get_object(self, **kwargs: Any) -> dict[str, Any]:
        return await asyncio.to_thread(self._sync_client.get_object, **kwargs)


class _FakeKMSClient:
    def __init__(self) -> None:
        self._keys: dict[str, dict[str, Any]] = {}
        self._counter = 0

    def create_key(self, **kwargs: Any) -> dict[str, Any]:
        _ = kwargs
        self._counter += 1
        key_id = f"fake-kms-key-{self._counter}"
        self._keys[key_id] = {
            "KeyId": key_id,
            "Arn": f"arn:aws:kms:local:000000000000:key/{key_id}",
            "Enabled": True,
            "KeyState": "Enabled",
            "KeySpec": "SYMMETRIC_DEFAULT",
            "CreationDate": time.time(),
            "Origin": "AWS_KMS",
            "KeyManager": "CUSTOMER",
            "KeyUsage": "ENCRYPT_DECRYPT",
        }
        return {"KeyMetadata": {"KeyId": key_id}}

    def describe_key(self, **kwargs: Any) -> dict[str, Any]:
        key_id = str(kwargs["KeyId"])
        metadata = dict(self._keys[key_id])
        return {"KeyMetadata": metadata}

    def list_resource_tags(self, **kwargs: Any) -> dict[str, Any]:
        _ = kwargs
        return {"Tags": []}

    def encrypt(self, **kwargs: Any) -> dict[str, Any]:
        plaintext = bytes(kwargs["Plaintext"])
        return {"CiphertextBlob": b"fakekms:" + plaintext}

    def decrypt(self, **kwargs: Any) -> dict[str, Any]:
        ciphertext = bytes(kwargs["CiphertextBlob"])
        if not ciphertext.startswith(b"fakekms:"):
            raise ValueError("invalid fake kms ciphertext")
        return {"Plaintext": ciphertext[8:]}


class _FakeAzureCryptoResult:
    def __init__(self, *, ciphertext: bytes | None = None, plaintext: bytes | None = None) -> None:
        self.ciphertext = ciphertext
        self.plaintext = plaintext


class _FakeAzureCryptoClient:
    def encrypt(self, *, algorithm: Any, plaintext: bytes) -> _FakeAzureCryptoResult:
        _ = algorithm
        return _FakeAzureCryptoResult(ciphertext=b"azureenc:" + plaintext)

    def decrypt(self, *, algorithm: Any, ciphertext: bytes) -> _FakeAzureCryptoResult:
        _ = algorithm
        if not ciphertext.startswith(b"azureenc:"):
            return _FakeAzureCryptoResult(plaintext=b"")
        return _FakeAzureCryptoResult(plaintext=ciphertext[9:])


class _FakeAzureKey:
    def __init__(self, *, vault_url: str, name: str, version: str, enabled: bool = True) -> None:
        self.name = name
        self.id = f"{vault_url.rstrip('/')}/keys/{name}/{version}"
        self.key_type = "RSA"
        self.key = SimpleNamespace(size=2048, crv=None)
        self.properties = SimpleNamespace(
            name=name,
            version=version,
            enabled=enabled,
            tags={"test": "true"},
            created_on=None,
            updated_on=None,
            expires_on=None,
            not_before=None,
            recovery_level="Recoverable",
        )


class _FakeAzureKeyClient:
    def __init__(self, vault_url: str) -> None:
        self.vault_url = vault_url
        self._keys: dict[str, list[_FakeAzureKey]] = {}

    def create_rsa_key(self, *, name: str, size: int, enabled: bool, tags: dict[str, str]) -> _FakeAzureKey:
        _ = size, tags
        version = f"v{len(self._keys.get(name, [])) + 1}"
        key = _FakeAzureKey(vault_url=self.vault_url, name=name, version=version, enabled=enabled)
        self._keys.setdefault(name, []).append(key)
        return key

    def get_key(self, *, name: str, version: str | None = None) -> _FakeAzureKey:
        versions = self._keys[name]
        if version is None:
            return versions[-1]
        for item in versions:
            if item.properties.version == version:
                return item
        raise KeyError(f"unknown key version {name}/{version}")

    def list_properties_of_key_versions(self, *, name: str):
        for item in reversed(self._keys.get(name, [])):
            yield item.properties


class _FakeGCPKMSClient:
    def __init__(self, project_id: str, location_id: str) -> None:
        self._project_id = project_id
        self._location_id = location_id
        self._rings: set[str] = set()
        self._keys: dict[str, dict[str, Any]] = {}

    def _location_name(self) -> str:
        return f"projects/{self._project_id}/locations/{self._location_id}"

    def get_key_ring(self, *, request: dict[str, Any]) -> dict[str, Any]:
        name = str(request["name"])
        if name not in self._rings:
            raise RuntimeError("not found")
        return {"name": name}

    def create_key_ring(self, *, request: dict[str, Any]) -> dict[str, Any]:
        parent = str(request["parent"])
        ring_id = str(request["key_ring_id"])
        name = f"{parent}/keyRings/{ring_id}"
        self._rings.add(name)
        return {"name": name}

    def create_crypto_key(self, *, request: dict[str, Any]) -> dict[str, Any]:
        parent = str(request["parent"])
        key_id = str(request["crypto_key_id"])
        payload = dict(request["crypto_key"])
        name = f"{parent}/cryptoKeys/{key_id}"
        version_name = f"{name}/cryptoKeyVersions/1"
        record = {
            "name": name,
            "purpose": payload.get("purpose", "ENCRYPT_DECRYPT"),
            "version_template": dict(payload.get("version_template", {})),
            "labels": dict(payload.get("labels", {})),
            "create_time": time.time(),
            "primary": {"name": version_name, "state": "ENABLED"},
            "versions": [version_name],
        }
        self._keys[name] = record
        return dict(record)

    def get_crypto_key(self, *, request: dict[str, Any]) -> dict[str, Any]:
        return dict(self._keys[str(request["name"])])

    def encrypt(self, *, request: dict[str, Any]) -> dict[str, Any]:
        return {"ciphertext": b"gcpkms:" + bytes(request["plaintext"])}

    def decrypt(self, *, request: dict[str, Any]) -> dict[str, Any]:
        ciphertext = bytes(request["ciphertext"])
        if not ciphertext.startswith(b"gcpkms:"):
            return {"plaintext": b""}
        return {"plaintext": ciphertext[7:]}

    def list_crypto_key_versions(self, *, request: dict[str, Any]):
        parent = str(request["parent"])
        versions = list(self._keys[parent]["versions"])
        versions.reverse()
        return [{"name": name} for name in versions]


def _env_bool(name: str) -> bool:
    value = os.getenv(name, "")
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _real_cloud_enabled() -> bool:
    return _env_bool("KEYCRYPT_RUN_REAL_CLOUD_TESTS")


def _load_aws_provider_class() -> type[Any]:
    return _load_plugin_class(
        "plugins/official/aws_kms_provider/aws_kms_provider.py",
        "aws_kms_provider_plugin_integration",
        "AWSKMSKeyProvider",
    )


def _load_azure_provider_class() -> type[Any]:
    return _load_plugin_class(
        "plugins/official/azure_keyvault_provider/azure_keyvault_provider.py",
        "azure_keyvault_provider_plugin_integration",
        "AzureKeyVaultProvider",
    )


def _load_gcp_provider_module() -> Any:
    plugin_path = PROJECT_ROOT / "plugins/official/gcp_kms_provider/gcp_kms_provider.py"
    spec = importlib.util.spec_from_file_location("gcp_kms_provider_plugin_integration", plugin_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load gcp kms provider module")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _create_bucket_if_needed(s3_client: Any, bucket_name: str, region_name: str) -> None:
    if region_name == "us-east-1":
        s3_client.create_bucket(Bucket=bucket_name)
        return

    s3_client.create_bucket(
        Bucket=bucket_name,
        CreateBucketConfiguration={"LocationConstraint": region_name},
    )


@pytest.fixture
def aws_test_backend(tmp_path: Path) -> dict[str, Any]:
    region = os.getenv("KEYCRYPT_AWS_REGION") or os.getenv("AWS_REGION") or "us-east-1"
    localstack_endpoint = os.getenv("KEYCRYPT_AWS_LOCALSTACK_ENDPOINT", "").strip()

    bucket_name = f"keycrypt-it-{int(time.time())}-{os.getpid()}"
    object_key = "payload.bin"

    if localstack_endpoint:
        try:
            import boto3

            kms_client = boto3.client(
                "kms",
                region_name=region,
                endpoint_url=localstack_endpoint,
                aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID", "test"),
                aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY", "test"),
                aws_session_token=os.getenv("AWS_SESSION_TOKEN"),
            )
            s3_client = boto3.client(
                "s3",
                region_name=region,
                endpoint_url=localstack_endpoint,
                aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID", "test"),
                aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY", "test"),
                aws_session_token=os.getenv("AWS_SESSION_TOKEN"),
            )

            _create_bucket_if_needed(s3_client, bucket_name, region)
            key_id = str(kms_client.create_key(Description="KeyCrypt integration test key")["KeyMetadata"]["KeyId"])

            return {
                "mode": "localstack",
                "region": region,
                "bucket": bucket_name,
                "object_key": object_key,
                "kms_client": kms_client,
                "kms_key_id": key_id,
                "s3_async_client": _SyncS3ToAsyncAdapter(s3_client),
                "raw_s3_reader": lambda bucket, key: s3_client.get_object(Bucket=bucket, Key=key)["Body"].read(),
            }
        except Exception:
            pass

    try:
        from moto import mock_aws
        import boto3

        stack = ExitStack()
        stack.enter_context(mock_aws())
        kms_client = boto3.client("kms", region_name=region)
        s3_client = boto3.client("s3", region_name=region)
        _create_bucket_if_needed(s3_client, bucket_name, region)
        key_id = str(kms_client.create_key(Description="KeyCrypt integration test key")["KeyMetadata"]["KeyId"])

        backend = {
            "mode": "moto",
            "region": region,
            "bucket": bucket_name,
            "object_key": object_key,
            "kms_client": kms_client,
            "kms_key_id": key_id,
            "s3_async_client": _SyncS3ToAsyncAdapter(s3_client),
            "raw_s3_reader": lambda bucket, key: s3_client.get_object(Bucket=bucket, Key=key)["Body"].read(),
        }
        try:
            yield backend
        finally:
            stack.close()
        return
    except Exception:
        pass

    fake_kms = _FakeKMSClient()
    key_id = str(fake_kms.create_key(Description="KeyCrypt integration test key")["KeyMetadata"]["KeyId"])
    fake_s3 = _InMemoryAsyncS3Client()

    backend = {
        "mode": "in-memory",
        "region": region,
        "bucket": bucket_name,
        "object_key": object_key,
        "kms_client": fake_kms,
        "kms_key_id": key_id,
        "s3_async_client": fake_s3,
        "raw_s3_reader": lambda bucket, key: fake_s3.objects[(bucket, key)]["Body"],
    }
    yield backend


def test_aws_kms_provider_encrypt_decrypt(aws_test_backend: dict[str, Any]) -> None:
    AWSKMSKeyProvider = _load_aws_provider_class()

    if _real_cloud_enabled() and os.getenv("KEYCRYPT_AWS_KMS_KEY_ID", "").strip():
        provider = AWSKMSKeyProvider(
            region_name=os.getenv("KEYCRYPT_AWS_REGION") or os.getenv("AWS_REGION"),
            aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
            aws_session_token=os.getenv("AWS_SESSION_TOKEN"),
            endpoint_url=os.getenv("KEYCRYPT_AWS_LOCALSTACK_ENDPOINT") or None,
        )
        key_id = os.getenv("KEYCRYPT_AWS_KMS_KEY_ID", "").strip()
    else:
        provider = AWSKMSKeyProvider(kms_client=aws_test_backend["kms_client"])
        key_id = str(aws_test_backend["kms_key_id"])

    key_material = provider.get_key(key_id)
    ciphertext = provider.encrypt(key_id, b"aws-kms-roundtrip")
    plaintext = provider.decrypt(key_id, ciphertext)

    assert plaintext == b"aws-kms-roundtrip"
    assert key_material.material == b""
    assert key_material.metadata.get("material_exportable") is False


def test_s3_encrypted_storage_upload_download(aws_test_backend: dict[str, Any], tmp_path: Path) -> None:
    source = tmp_path / "plain.bin"
    output = tmp_path / "downloaded.bin"
    source.write_bytes(b"s3 encrypted storage payload")

    provider = _PrefixCryptoProvider()
    s3_encrypted_storage.configure_s3_encrypted_storage(
        client=aws_test_backend["s3_async_client"],
        region_name=aws_test_backend["region"],
        default_provider=provider,
    )

    bucket = str(aws_test_backend["bucket"])
    key = str(aws_test_backend["object_key"])

    asyncio.run(s3_encrypted_storage.upload_encrypted(bucket, key, source, provider))
    raw_encrypted = aws_test_backend["raw_s3_reader"](bucket, key)
    assert raw_encrypted.startswith(b"enc:")

    asyncio.run(s3_encrypted_storage.download_encrypted(bucket, key, output, provider))
    assert output.read_bytes() == source.read_bytes()


def test_azure_keyvault_provider_key_generation() -> None:
    AzureKeyVaultProvider = _load_azure_provider_class()

    if _real_cloud_enabled() and os.getenv("KEYCRYPT_AZURE_VAULT_URL", "").strip():
        vault_url = os.getenv("KEYCRYPT_AZURE_VAULT_URL", "").strip()
        credential_mode = os.getenv("KEYCRYPT_AZURE_CREDENTIAL_MODE", "default").strip() or "default"

        provider = AzureKeyVaultProvider(
            vault_url=vault_url,
            credential_mode=credential_mode,
            tenant_id=os.getenv("AZURE_TENANT_ID"),
            client_id=os.getenv("AZURE_CLIENT_ID"),
            client_secret=os.getenv("AZURE_CLIENT_SECRET"),
        )
    else:
        fake_vault_url = "https://integration-test-vault.vault.azure.net"
        key_client = _FakeAzureKeyClient(fake_vault_url)
        crypto_client = _FakeAzureCryptoClient()
        provider = AzureKeyVaultProvider(
            key_client=key_client,
            vault_url=fake_vault_url,
            crypto_client_factory=lambda _key_identifier: crypto_client,
        )

    key_name = f"keycrypt-it-{int(time.time())}"
    key_id = provider.generate_key(
        KeyGenerationParams(
            algorithm="RSA-2048",
            tags={"key_name": key_name, "env": "integration"},
        )
    )

    encrypted = provider.encrypt(key_id, b"azure-keyvault-roundtrip")
    plaintext = provider.decrypt(key_id, encrypted)
    key_material = provider.get_key(key_id)

    assert key_id
    assert plaintext == b"azure-keyvault-roundtrip"
    assert key_material.material == b""


def test_gcp_kms_provider_with_service_account(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_gcp_provider_module()
    GCPKMSProvider = module.GCPKMSProvider

    if _real_cloud_enabled() and os.getenv("KEYCRYPT_GCP_PROJECT_ID", "").strip():
        project_id = os.getenv("KEYCRYPT_GCP_PROJECT_ID", "").strip()
        location_id = os.getenv("KEYCRYPT_GCP_LOCATION", "global").strip() or "global"
        key_ring_id = os.getenv("KEYCRYPT_GCP_KEY_RING_ID", "keycrypt-integration").strip() or "keycrypt-integration"
        credentials_path = (
            os.getenv("KEYCRYPT_GCP_SERVICE_ACCOUNT_FILE", "").strip()
            or os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "").strip()
            or None
        )

        provider = GCPKMSProvider(
            project_id=project_id,
            location_id=location_id,
            key_ring_id=key_ring_id,
            credentials_path=credentials_path,
        )
    else:
        captured: dict[str, Any] = {}

        class _FakeCredentialsFactory:
            @staticmethod
            def from_service_account_info(info: dict[str, Any]) -> Any:
                captured["service_account_info"] = dict(info)
                return "fake-gcp-credentials"

        class _FakeClientFactory:
            def __init__(self, *, credentials: Any = None) -> None:
                captured["credentials"] = credentials
                self._delegate = _FakeGCPKMSClient(project_id="integration-project", location_id="us-central1")

            def __getattr__(self, item: str) -> Any:
                return getattr(self._delegate, item)

        monkeypatch.setattr(module, "service_account", SimpleNamespace(Credentials=_FakeCredentialsFactory))
        monkeypatch.setattr(module, "kms_v1", SimpleNamespace(KeyManagementServiceClient=_FakeClientFactory))

        provider = GCPKMSProvider(
            project_id="integration-project",
            location_id="us-central1",
            key_ring_id="integration-ring",
            service_account_info={
                "type": "service_account",
                "project_id": "integration-project",
                "private_key_id": "fake",
                "private_key": "-----BEGIN PRIVATE KEY-----\\nFAKE\\n-----END PRIVATE KEY-----\\n",
                "client_email": "fake@integration-project.iam.gserviceaccount.com",
                "client_id": "12345",
                "token_uri": "https://oauth2.googleapis.com/token",
            },
        )

        assert captured.get("credentials") == "fake-gcp-credentials"
        assert isinstance(captured.get("service_account_info"), dict)

    key_name = provider.generate_key(
        KeyGenerationParams(
            algorithm="AES-256-GCM",
            tags={"key_name": f"gcp-it-{int(time.time())}"},
        )
    )
    ciphertext = provider.encrypt(key_name, b"gcp-kms-roundtrip")
    plaintext = provider.decrypt(key_name, ciphertext)
    key_material = provider.get_key(key_name)

    assert key_name
    assert plaintext == b"gcp-kms-roundtrip"
    assert key_material.material == b""