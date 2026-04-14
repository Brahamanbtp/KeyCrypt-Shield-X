"""KeyCrypt Kubernetes CSI driver for encrypted persistent volumes.

This module implements a lightweight, testable CSI controller/node driver shape
with explicit methods aligned to CSI v1.5.0 workflows:
- CreateVolume(name, size, parameters)
- DeleteVolume(volume_id)
- ControllerPublishVolume(volume_id, node_id)
- NodeStageVolume(volume_id, staging_path)

Encrypted volume support is backed by pluggable key providers and dm-crypt
managers. Automatic in-place key rotation is supported via a background worker
or explicit run_key_rotation_cycle invocation, so mounted volumes do not need to
be remounted to receive new encryption keys.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, MutableMapping, Protocol

from src.abstractions.key_provider import KeyGenerationParams, KeyMaterial, KeyProvider


CSI_SPEC_VERSION = "1.5.0"
DEFAULT_DRIVER_NAME = "io.keycrypt.csi"
DEFAULT_ALGORITHM = "AES-256-XTS"
DEFAULT_ROTATION_INTERVAL_SECONDS = 3600


class CSIDriverError(RuntimeError):
    """Base exception for KeyCrypt CSI driver errors."""


class VolumeNotFoundError(CSIDriverError):
    """Raised when a volume identifier is unknown to the driver."""


class ProviderNotFoundError(CSIDriverError):
    """Raised when a named key provider is not configured."""


class VolumeBackend(Protocol):
    """Abstract interface for persistent volume backing storage."""

    def create_volume(self, volume_id: str, name: str, size_bytes: int, parameters: Mapping[str, str]) -> str:
        """Create backing storage and return a device path or handle path."""

    def secure_delete_volume(self, volume_id: str, device_path: str) -> None:
        """Securely erase backing storage and remove it from the backend."""


class NodePublisher(Protocol):
    """Abstract interface for controller publish/attach actions."""

    def attach(self, volume_id: str, node_id: str, device_path: str) -> None:
        """Attach a backing volume to the provided node."""


class DmCryptManager(Protocol):
    """Abstract interface for dm-crypt/LUKS stage/rotation operations."""

    def stage_volume(
        self,
        *,
        volume_id: str,
        device_path: str,
        staging_path: str,
        key_material: bytes,
        fs_type: str,
        cipher: str,
        key_size_bits: int,
        needs_format: bool,
    ) -> str:
        """Open LUKS mapping and mount it to staging_path."""

    def unstage_volume(
        self,
        *,
        volume_id: str,
        staging_path: str,
        mapped_device: str,
    ) -> None:
        """Unmount and close dm-crypt mapping for the volume."""

    def rotate_volume_key(
        self,
        *,
        volume_id: str,
        device_path: str,
        mapped_device: str,
        old_key_material: bytes,
        new_key_material: bytes,
    ) -> None:
        """Rotate active LUKS key in place while volume remains mounted."""


class InMemoryVolumeBackend:
    """Simple test-friendly volume backend with pseudo device paths."""

    def __init__(self, root: str = "/tmp/keycrypt-csi") -> None:
        self._root = root
        self._devices: dict[str, str] = {}

    def create_volume(self, volume_id: str, name: str, size_bytes: int, parameters: Mapping[str, str]) -> str:
        _ = name, size_bytes, parameters
        path = os.path.join(self._root, "devices", volume_id)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._devices[volume_id] = path
        return path

    def secure_delete_volume(self, volume_id: str, device_path: str) -> None:
        _ = device_path
        self._devices.pop(volume_id, None)


class InMemoryNodePublisher:
    """In-memory attach manager for tests and local development."""

    def __init__(self) -> None:
        self.attachments: dict[str, str] = {}

    def attach(self, volume_id: str, node_id: str, device_path: str) -> None:
        _ = device_path
        self.attachments[volume_id] = node_id


class NoopDmCryptManager:
    """No-op dm-crypt manager used when host tools are unavailable."""

    def __init__(self, mapper_prefix: str = "keycrypt") -> None:
        self._mapper_prefix = mapper_prefix

    def stage_volume(
        self,
        *,
        volume_id: str,
        device_path: str,
        staging_path: str,
        key_material: bytes,
        fs_type: str,
        cipher: str,
        key_size_bits: int,
        needs_format: bool,
    ) -> str:
        _ = device_path, key_material, fs_type, cipher, key_size_bits, needs_format
        os.makedirs(staging_path, exist_ok=True)
        return f"/dev/mapper/{self._mapper_prefix}-{volume_id[:12]}"

    def unstage_volume(
        self,
        *,
        volume_id: str,
        staging_path: str,
        mapped_device: str,
    ) -> None:
        _ = volume_id, mapped_device
        if os.path.isdir(staging_path):
            return

    def rotate_volume_key(
        self,
        *,
        volume_id: str,
        device_path: str,
        mapped_device: str,
        old_key_material: bytes,
        new_key_material: bytes,
    ) -> None:
        _ = volume_id, device_path, mapped_device, old_key_material, new_key_material


class SystemDmCryptManager:
    """Host dm-crypt manager using cryptsetup and mount utilities.

    This implementation requires root capabilities and cryptsetup/mount binaries.
    """

    def __init__(
        self,
        mapper_prefix: str = "keycrypt",
        command_runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
    ) -> None:
        self._mapper_prefix = mapper_prefix
        self._command_runner = command_runner or subprocess.run

    def stage_volume(
        self,
        *,
        volume_id: str,
        device_path: str,
        staging_path: str,
        key_material: bytes,
        fs_type: str,
        cipher: str,
        key_size_bits: int,
        needs_format: bool,
    ) -> str:
        mapped_name = f"{self._mapper_prefix}-{volume_id[:12]}"
        mapped_device = f"/dev/mapper/{mapped_name}"

        if needs_format:
            self._run(
                [
                    "cryptsetup",
                    "luksFormat",
                    "--type",
                    "luks2",
                    "--cipher",
                    cipher,
                    "--key-size",
                    str(key_size_bits),
                    "--batch-mode",
                    device_path,
                    "-",
                ],
                input_bytes=key_material,
            )

        self._run(
            [
                "cryptsetup",
                "open",
                "--type",
                "luks",
                "--key-file",
                "-",
                device_path,
                mapped_name,
            ],
            input_bytes=key_material,
        )

        os.makedirs(staging_path, exist_ok=True)
        self._run(["mount", "-t", fs_type, mapped_device, staging_path])
        return mapped_device

    def unstage_volume(
        self,
        *,
        volume_id: str,
        staging_path: str,
        mapped_device: str,
    ) -> None:
        _ = mapped_device
        mapped_name = f"{self._mapper_prefix}-{volume_id[:12]}"

        if os.path.isdir(staging_path):
            self._run(["umount", staging_path])
        self._run(["cryptsetup", "close", mapped_name])

    def rotate_volume_key(
        self,
        *,
        volume_id: str,
        device_path: str,
        mapped_device: str,
        old_key_material: bytes,
        new_key_material: bytes,
    ) -> None:
        _ = volume_id, mapped_device
        # Key-slot rekey keeps the active mapping mounted and avoids remount.
        with tempfile.NamedTemporaryFile(mode="wb", delete=True) as old_f:
            with tempfile.NamedTemporaryFile(mode="wb", delete=True) as new_f:
                old_f.write(old_key_material)
                old_f.flush()
                new_f.write(new_key_material)
                new_f.flush()

                self._run(
                    [
                        "cryptsetup",
                        "luksAddKey",
                        "--key-file",
                        old_f.name,
                        device_path,
                        new_f.name,
                    ]
                )
                self._run(["cryptsetup", "luksRemoveKey", device_path, old_f.name])

    def _run(self, command: list[str], input_bytes: bytes | None = None) -> None:
        try:
            self._command_runner(
                command,
                input=input_bytes,
                check=True,
                capture_output=True,
                text=False,
            )
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.decode("utf-8", errors="replace") if exc.stderr else ""
            raise CSIDriverError(f"command failed: {' '.join(command)}; stderr={stderr}") from exc


@dataclass
class Volume:
    """Minimal CSI-like volume object returned by CreateVolume."""

    volume_id: str
    capacity_bytes: int
    volume_context: dict[str, str] = field(default_factory=dict)


@dataclass
class _EncryptedVolumeState:
    volume_id: str
    name: str
    size_bytes: int
    provider_name: str
    key_id: str
    device_path: str
    parameters: dict[str, str]
    created_at: float
    last_rotated_at: float
    rotation_interval_seconds: int
    attached_node_id: str | None = None
    staging_path: str | None = None
    mapped_device: str | None = None
    luks_formatted: bool = False

    def to_csi_volume(self) -> Volume:
        return Volume(
            volume_id=self.volume_id,
            capacity_bytes=self.size_bytes,
            volume_context={
                "encrypted": "true",
                "provider": self.provider_name,
                "keyId": self.key_id,
                "csi.specVersion": CSI_SPEC_VERSION,
                "rotationIntervalSeconds": str(self.rotation_interval_seconds),
                "devicePath": self.device_path,
            },
        )


class KeycryptCSIDriver:
    """CSI v1.5.0 compatible encrypted volume driver."""

    def __init__(
        self,
        *,
        key_provider_registry: Mapping[str, KeyProvider],
        volume_backend: VolumeBackend | None = None,
        node_publisher: NodePublisher | None = None,
        dmcrypt_manager: DmCryptManager | None = None,
        now_fn: Callable[[], float] | None = None,
        key_destroyer: Callable[[str, str, KeyProvider], None] | None = None,
        volume_id_factory: Callable[[str], str] | None = None,
        rotation_poll_interval_seconds: float = 30.0,
    ) -> None:
        if not key_provider_registry:
            raise CSIDriverError("key_provider_registry must not be empty")

        self._key_providers: dict[str, KeyProvider] = dict(key_provider_registry)
        self._volume_backend = volume_backend or InMemoryVolumeBackend()
        self._node_publisher = node_publisher or InMemoryNodePublisher()
        self._dmcrypt_manager = dmcrypt_manager or self._build_default_dmcrypt_manager()
        self._now_fn = now_fn or time.time
        self._key_destroyer = key_destroyer
        self._volume_id_factory = volume_id_factory or (lambda name: self._default_volume_id(name))
        self._rotation_poll_interval_seconds = max(1.0, float(rotation_poll_interval_seconds))

        self._volumes: MutableMapping[str, _EncryptedVolumeState] = {}
        self._volume_name_index: MutableMapping[str, str] = {}

        self._lock = threading.RLock()
        self._rotation_thread: threading.Thread | None = None
        self._rotation_stop_event = threading.Event()

    def GetPluginInfo(self) -> dict[str, str]:
        """Return CSI identity information for the plugin."""
        return {
            "name": DEFAULT_DRIVER_NAME,
            "vendor_version": CSI_SPEC_VERSION,
            "manifest": "keycrypt-encrypted-persistent-volumes",
        }

    def CreateVolume(self, name: str, size: int, parameters: Mapping[str, Any] | None) -> Volume:
        """Create an encrypted volume and return CSI volume metadata."""
        normalized_name = _require_non_empty("name", name)
        size_bytes = _parse_positive_int("size", size)
        options = _stringify_mapping(parameters)

        with self._lock:
            existing_id = self._volume_name_index.get(normalized_name)
            if existing_id is not None:
                return self._volumes[existing_id].to_csi_volume()

            provider_name = self._resolve_provider_name(options)
            provider = self._get_provider(provider_name)

            algorithm = options.get("algorithm", DEFAULT_ALGORITHM)
            key_size_bytes = _coerce_optional_positive_int(options.get("keySizeBytes"))
            key_id = provider.generate_key(
                KeyGenerationParams(
                    algorithm=algorithm,
                    key_size_bytes=key_size_bytes,
                    exportable=False,
                    metadata={
                        "volume_name": normalized_name,
                        "encrypted": "true",
                    },
                )
            )

            volume_id = self._volume_id_factory(normalized_name)
            device_path = self._volume_backend.create_volume(volume_id, normalized_name, size_bytes, options)
            rotation_interval_seconds = _parse_rotation_interval_seconds(options)

            now = self._now_fn()
            state = _EncryptedVolumeState(
                volume_id=volume_id,
                name=normalized_name,
                size_bytes=size_bytes,
                provider_name=provider_name,
                key_id=key_id,
                device_path=device_path,
                parameters=options,
                created_at=now,
                last_rotated_at=now,
                rotation_interval_seconds=rotation_interval_seconds,
            )
            self._volumes[volume_id] = state
            self._volume_name_index[normalized_name] = volume_id
            return state.to_csi_volume()

    def DeleteVolume(self, volume_id: str) -> None:
        """Securely delete an encrypted volume and retire its key material."""
        normalized_id = _require_non_empty("volume_id", volume_id)

        with self._lock:
            state = self._volumes.get(normalized_id)
            if state is None:
                return

            provider = self._get_provider(state.provider_name)

            if state.staging_path and state.mapped_device:
                self._dmcrypt_manager.unstage_volume(
                    volume_id=state.volume_id,
                    staging_path=state.staging_path,
                    mapped_device=state.mapped_device,
                )

            self._volume_backend.secure_delete_volume(state.volume_id, state.device_path)
            self._destroy_key(state.provider_name, state.key_id, provider)

            self._volumes.pop(normalized_id, None)
            self._volume_name_index.pop(state.name, None)

    def ControllerPublishVolume(self, volume_id: str, node_id: str) -> None:
        """Attach an encrypted volume to a Kubernetes node."""
        normalized_id = _require_non_empty("volume_id", volume_id)
        normalized_node = _require_non_empty("node_id", node_id)

        with self._lock:
            state = self._volumes.get(normalized_id)
            if state is None:
                raise VolumeNotFoundError(f"unknown volume_id: {normalized_id}")

            self._node_publisher.attach(state.volume_id, normalized_node, state.device_path)
            state.attached_node_id = normalized_node

    def NodeStageVolume(self, volume_id: str, staging_path: str) -> None:
        """Open LUKS mapping and mount encrypted volume at staging path."""
        normalized_id = _require_non_empty("volume_id", volume_id)
        normalized_stage_path = _require_non_empty("staging_path", staging_path)

        with self._lock:
            state = self._volumes.get(normalized_id)
            if state is None:
                raise VolumeNotFoundError(f"unknown volume_id: {normalized_id}")

            provider = self._get_provider(state.provider_name)
            key = provider.get_key(state.key_id)

            mapped_device = self._dmcrypt_manager.stage_volume(
                volume_id=state.volume_id,
                device_path=state.device_path,
                staging_path=normalized_stage_path,
                key_material=key.material,
                fs_type=state.parameters.get("fsType", "ext4"),
                cipher=state.parameters.get("cipher", "aes-xts-plain64"),
                key_size_bits=_coerce_optional_positive_int(state.parameters.get("keySizeBits")) or 512,
                needs_format=not state.luks_formatted,
            )

            state.staging_path = normalized_stage_path
            state.mapped_device = mapped_device
            state.luks_formatted = True

    def run_key_rotation_cycle(self) -> dict[str, Any]:
        """Rotate due volume keys without unmounting existing mappings."""
        rotated: list[str] = []
        skipped: list[str] = []

        with self._lock:
            now = self._now_fn()
            for volume_id, state in list(self._volumes.items()):
                # Rotation is meaningful only for staged volumes that have active mapping.
                if not state.mapped_device:
                    skipped.append(volume_id)
                    continue

                age = now - state.last_rotated_at
                if age < state.rotation_interval_seconds:
                    skipped.append(volume_id)
                    continue

                provider = self._get_provider(state.provider_name)
                old_key_id = state.key_id
                old_key = provider.get_key(old_key_id)

                new_key_id = provider.rotate_key(old_key_id)
                new_key = provider.get_key(new_key_id)

                self._dmcrypt_manager.rotate_volume_key(
                    volume_id=state.volume_id,
                    device_path=state.device_path,
                    mapped_device=state.mapped_device,
                    old_key_material=old_key.material,
                    new_key_material=new_key.material,
                )

                state.key_id = new_key_id
                state.last_rotated_at = now
                rotated.append(volume_id)

        return {
            "rotated": rotated,
            "skipped": skipped,
            "checked_at": now,
        }

    def start_rotation_worker(self) -> None:
        """Start periodic key-rotation worker thread."""
        with self._lock:
            if self._rotation_thread and self._rotation_thread.is_alive():
                return

            self._rotation_stop_event.clear()
            self._rotation_thread = threading.Thread(
                target=self._rotation_worker_loop,
                name="keycrypt-csi-rotation",
                daemon=True,
            )
            self._rotation_thread.start()

    def stop_rotation_worker(self, timeout: float = 5.0) -> None:
        """Stop periodic key-rotation worker thread."""
        thread: threading.Thread | None
        with self._lock:
            thread = self._rotation_thread
            self._rotation_stop_event.set()
            self._rotation_thread = None

        if thread is not None:
            thread.join(timeout=timeout)

    def _rotation_worker_loop(self) -> None:
        while not self._rotation_stop_event.is_set():
            try:
                self.run_key_rotation_cycle()
            except Exception:
                # Background loop should remain resilient to single-cycle failures.
                pass
            self._rotation_stop_event.wait(self._rotation_poll_interval_seconds)

    def _resolve_provider_name(self, parameters: Mapping[str, str]) -> str:
        requested = parameters.get("provider")
        if requested:
            return requested
        if "default" in self._key_providers:
            return "default"
        return next(iter(self._key_providers.keys()))

    def _get_provider(self, provider_name: str) -> KeyProvider:
        provider = self._key_providers.get(provider_name)
        if provider is None:
            raise ProviderNotFoundError(f"unknown provider: {provider_name}")
        return provider

    def _destroy_key(self, provider_name: str, key_id: str, provider: KeyProvider) -> None:
        if self._key_destroyer is not None:
            self._key_destroyer(provider_name, key_id, provider)
            return

        for method_name in ("delete_key", "revoke_key", "destroy_key", "disable_key"):
            method = getattr(provider, method_name, None)
            if callable(method):
                method(key_id)
                return

    def _build_default_dmcrypt_manager(self) -> DmCryptManager:
        if shutil.which("cryptsetup") and shutil.which("mount") and shutil.which("umount"):
            return SystemDmCryptManager()
        return NoopDmCryptManager()

    def _default_volume_id(self, name: str) -> str:
        sanitized = "".join(ch if ch.isalnum() else "-" for ch in name).strip("-") or "volume"
        return f"kcsi-{sanitized}-{uuid.uuid4().hex[:16]}"


class InMemoryKeyProvider(KeyProvider):
    """Small in-memory key provider for local smoke testing."""

    def __init__(self) -> None:
        self._keys: dict[str, KeyMaterial] = {}
        self._counter = 0

    def get_key(self, key_id: str) -> KeyMaterial:
        material = self._keys.get(key_id)
        if material is None:
            raise CSIDriverError(f"unknown key_id: {key_id}")
        return material

    def generate_key(self, params: KeyGenerationParams) -> str:
        self._counter += 1
        key_id = f"key-{self._counter}"
        key_size = params.key_size_bytes or 32
        self._keys[key_id] = KeyMaterial(
            key_id=key_id,
            algorithm=params.algorithm,
            material=(b"k" * key_size),
            version=1,
            metadata=dict(params.metadata),
        )
        return key_id

    def rotate_key(self, key_id: str) -> str:
        existing = self.get_key(key_id)
        self._counter += 1
        new_key_id = f"key-{self._counter}"
        new_version = existing.version + 1
        self._keys[new_key_id] = KeyMaterial(
            key_id=new_key_id,
            algorithm=existing.algorithm,
            material=((b"k" * max(len(existing.material), 1)) + str(new_version).encode("ascii"))[: len(existing.material)],
            version=new_version,
            metadata=dict(existing.metadata),
        )
        return new_key_id

    def list_keys(self, filter: Any) -> list[Any]:
        _ = filter
        return []



def _require_non_empty(field_name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CSIDriverError(f"{field_name} must be a non-empty string")
    return value.strip()



def _parse_positive_int(field_name: str, value: Any) -> int:
    try:
        integer = int(value)
    except Exception as exc:
        raise CSIDriverError(f"{field_name} must be an integer") from exc

    if integer <= 0:
        raise CSIDriverError(f"{field_name} must be > 0")
    return integer



def _coerce_optional_positive_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, str) and not value.strip():
        return None

    integer = int(value)
    if integer <= 0:
        raise CSIDriverError("value must be > 0")
    return integer



def _parse_rotation_interval_seconds(parameters: Mapping[str, str]) -> int:
    explicit = parameters.get("rotationIntervalSeconds")
    if explicit:
        return _parse_positive_int("rotationIntervalSeconds", explicit)

    shorthand = parameters.get("rotationInterval")
    if shorthand:
        normalized = shorthand.strip().lower()
        aliases = {
            "hourly": 3600,
            "daily": 86400,
            "weekly": 7 * 86400,
        }
        if normalized in aliases:
            return aliases[normalized]

        unit = normalized[-1]
        amount_raw = normalized[:-1]
        if unit in {"s", "m", "h", "d"} and amount_raw.isdigit():
            amount = int(amount_raw)
            factors = {"s": 1, "m": 60, "h": 3600, "d": 86400}
            return amount * factors[unit]

        raise CSIDriverError("unsupported rotationInterval format")

    return DEFAULT_ROTATION_INTERVAL_SECONDS



def _stringify_mapping(mapping: Mapping[str, Any] | None) -> dict[str, str]:
    if mapping is None:
        return {}
    return {str(key): str(value) for key, value in mapping.items()}


__all__ = [
    "CSI_SPEC_VERSION",
    "CSIDriverError",
    "DEFAULT_DRIVER_NAME",
    "InMemoryKeyProvider",
    "KeycryptCSIDriver",
    "ProviderNotFoundError",
    "Volume",
    "VolumeNotFoundError",
]
