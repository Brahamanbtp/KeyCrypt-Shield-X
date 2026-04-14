"""Unit tests for deployment/kubernetes/csi_driver/keycrypt_csi.py."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from src.abstractions.key_provider import KeyGenerationParams, KeyMaterial, KeyProvider



def _load_module():
    module_path = PROJECT_ROOT / "deployment/kubernetes/csi_driver/keycrypt_csi.py"
    spec = importlib.util.spec_from_file_location("keycrypt_csi_module", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load keycrypt_csi module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _FakeKeyProvider(KeyProvider):
    def __init__(self) -> None:
        self._keys: dict[str, KeyMaterial] = {}
        self._counter = 0
        self.generate_calls: list[dict[str, Any]] = []
        self.rotate_calls: list[str] = []
        self.delete_calls: list[str] = []

    def get_key(self, key_id: str) -> KeyMaterial:
        material = self._keys.get(key_id)
        if material is None:
            raise ValueError(f"unknown key id: {key_id}")
        return material

    def generate_key(self, params: KeyGenerationParams) -> str:
        self._counter += 1
        key_id = f"key-{self._counter}"
        self.generate_calls.append({"algorithm": params.algorithm, "metadata": dict(params.metadata)})
        self._keys[key_id] = KeyMaterial(
            key_id=key_id,
            algorithm=params.algorithm,
            material=f"material-{self._counter}".encode("ascii"),
            version=1,
            metadata=dict(params.metadata),
        )
        return key_id

    def rotate_key(self, key_id: str) -> str:
        self.rotate_calls.append(key_id)
        original = self.get_key(key_id)

        self._counter += 1
        new_key_id = f"key-{self._counter}"
        self._keys[new_key_id] = KeyMaterial(
            key_id=new_key_id,
            algorithm=original.algorithm,
            material=f"material-{self._counter}".encode("ascii"),
            version=original.version + 1,
            metadata=dict(original.metadata),
        )
        return new_key_id

    def list_keys(self, filter: Any) -> list[Any]:
        _ = filter
        return []

    def delete_key(self, key_id: str) -> None:
        self.delete_calls.append(key_id)
        self._keys.pop(key_id, None)


class _FakeVolumeBackend:
    def __init__(self) -> None:
        self.created: list[dict[str, Any]] = []
        self.deleted: list[dict[str, Any]] = []

    def create_volume(self, volume_id: str, name: str, size_bytes: int, parameters: dict[str, str]) -> str:
        self.created.append(
            {
                "volume_id": volume_id,
                "name": name,
                "size_bytes": size_bytes,
                "parameters": dict(parameters),
            }
        )
        return f"/dev/fake/{volume_id}"

    def secure_delete_volume(self, volume_id: str, device_path: str) -> None:
        self.deleted.append({"volume_id": volume_id, "device_path": device_path})


class _FakeNodePublisher:
    def __init__(self) -> None:
        self.attached: list[dict[str, str]] = []

    def attach(self, volume_id: str, node_id: str, device_path: str) -> None:
        self.attached.append({"volume_id": volume_id, "node_id": node_id, "device_path": device_path})


class _FakeDmCryptManager:
    def __init__(self) -> None:
        self.stage_calls: list[dict[str, Any]] = []
        self.unstage_calls: list[dict[str, Any]] = []
        self.rotate_calls: list[dict[str, Any]] = []

    def stage_volume(self, **kwargs: Any) -> str:
        self.stage_calls.append(dict(kwargs))
        volume_id = str(kwargs["volume_id"])
        return f"/dev/mapper/fake-{volume_id[:8]}"

    def unstage_volume(self, **kwargs: Any) -> None:
        self.unstage_calls.append(dict(kwargs))

    def rotate_volume_key(self, **kwargs: Any) -> None:
        self.rotate_calls.append(dict(kwargs))



def test_create_volume_creates_encrypted_volume_context() -> None:
    module = _load_module()

    provider = _FakeKeyProvider()
    backend = _FakeVolumeBackend()
    node_publisher = _FakeNodePublisher()
    dmcrypt = _FakeDmCryptManager()

    driver = module.KeycryptCSIDriver(
        key_provider_registry={"default": provider},
        volume_backend=backend,
        node_publisher=node_publisher,
        dmcrypt_manager=dmcrypt,
        volume_id_factory=lambda name: f"vol-{name}",
    )

    volume = driver.CreateVolume(
        name="orders",
        size=4096,
        parameters={
            "provider": "default",
            "algorithm": "AES-256-XTS",
            "rotationIntervalSeconds": "120",
        },
    )

    assert volume.volume_id == "vol-orders"
    assert volume.capacity_bytes == 4096
    assert volume.volume_context["encrypted"] == "true"
    assert volume.volume_context["provider"] == "default"
    assert volume.volume_context["csi.specVersion"] == "1.5.0"
    assert backend.created and backend.created[0]["size_bytes"] == 4096



def test_publish_and_stage_uses_node_and_dmcrypt() -> None:
    module = _load_module()

    provider = _FakeKeyProvider()
    backend = _FakeVolumeBackend()
    node_publisher = _FakeNodePublisher()
    dmcrypt = _FakeDmCryptManager()

    driver = module.KeycryptCSIDriver(
        key_provider_registry={"default": provider},
        volume_backend=backend,
        node_publisher=node_publisher,
        dmcrypt_manager=dmcrypt,
        volume_id_factory=lambda name: f"vol-{name}",
    )

    volume = driver.CreateVolume(name="analytics", size=2048, parameters={})
    driver.ControllerPublishVolume(volume.volume_id, "node-a")
    driver.NodeStageVolume(volume.volume_id, "/var/lib/kubelet/plugins/kcsi/staging/analytics")

    assert node_publisher.attached
    assert node_publisher.attached[0]["node_id"] == "node-a"
    assert dmcrypt.stage_calls
    assert dmcrypt.stage_calls[0]["needs_format"] is True



def test_rotation_cycle_rotates_without_remount() -> None:
    module = _load_module()

    provider = _FakeKeyProvider()
    backend = _FakeVolumeBackend()
    dmcrypt = _FakeDmCryptManager()

    now = {"value": 1_000.0}

    driver = module.KeycryptCSIDriver(
        key_provider_registry={"default": provider},
        volume_backend=backend,
        node_publisher=_FakeNodePublisher(),
        dmcrypt_manager=dmcrypt,
        now_fn=lambda: now["value"],
        volume_id_factory=lambda name: f"vol-{name}",
    )

    volume = driver.CreateVolume(
        name="payments",
        size=1024,
        parameters={"rotationIntervalSeconds": "5"},
    )
    driver.NodeStageVolume(volume.volume_id, "/var/lib/kubelet/plugins/kcsi/staging/payments")

    now["value"] = 1_010.0
    result = driver.run_key_rotation_cycle()

    assert volume.volume_id in result["rotated"]
    assert provider.rotate_calls
    assert dmcrypt.rotate_calls
    assert not dmcrypt.unstage_calls



def test_delete_volume_secures_backend_and_key() -> None:
    module = _load_module()

    provider = _FakeKeyProvider()
    backend = _FakeVolumeBackend()
    dmcrypt = _FakeDmCryptManager()
    destroyed: list[tuple[str, str]] = []

    def destroy_key(provider_name: str, key_id: str, key_provider: _FakeKeyProvider) -> None:
        _ = key_provider
        destroyed.append((provider_name, key_id))

    driver = module.KeycryptCSIDriver(
        key_provider_registry={"default": provider},
        volume_backend=backend,
        node_publisher=_FakeNodePublisher(),
        dmcrypt_manager=dmcrypt,
        key_destroyer=destroy_key,
        volume_id_factory=lambda name: f"vol-{name}",
    )

    volume = driver.CreateVolume(name="audit", size=512, parameters={})
    driver.NodeStageVolume(volume.volume_id, "/var/lib/kubelet/plugins/kcsi/staging/audit")
    driver.DeleteVolume(volume.volume_id)

    assert backend.deleted and backend.deleted[0]["volume_id"] == volume.volume_id
    assert destroyed and destroyed[0][0] == "default"
    assert dmcrypt.unstage_calls and dmcrypt.unstage_calls[0]["volume_id"] == volume.volume_id
