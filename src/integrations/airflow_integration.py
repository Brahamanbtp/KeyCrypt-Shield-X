"""Apache Airflow integration for workflow-based encryption orchestration.

This module provides Airflow operators and sensors for encryption workflows:
- EncryptFileOperator
- DecryptFileOperator
- RotateKeysOperator
- EncryptedFileSensor

The implementation wraps project-native primitives (KeyManager + AESGCM) and
supports XCom metadata handoff between tasks.
"""

from __future__ import annotations

import base64
import json
import os
import time
from pathlib import Path
from typing import Any, Mapping, Sequence

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.core.key_manager import KeyManager, KeyManagerError


try:
    from airflow.exceptions import AirflowException
    from airflow.models.baseoperator import BaseOperator
    from airflow.sensors.base import BaseSensorOperator
except Exception as exc:  # pragma: no cover - optional dependency boundary
    _AIRFLOW_IMPORT_ERROR = exc

    class AirflowException(RuntimeError):
        """Fallback Airflow exception for local/test environments."""

    class BaseOperator:  # type: ignore[override]
        """Minimal BaseOperator fallback used when airflow is unavailable."""

        template_fields: tuple[str, ...] = tuple()

        def __init__(self, *args: Any, task_id: str | None = None, **kwargs: Any) -> None:
            _ = args
            _ = kwargs
            self.task_id = task_id or self.__class__.__name__

        def execute(self, context: Mapping[str, Any]) -> Any:  # pragma: no cover - interface fallback
            raise NotImplementedError()

    class BaseSensorOperator(BaseOperator):  # type: ignore[override]
        """Minimal BaseSensorOperator fallback used when airflow is unavailable."""

        def __init__(
            self,
            *args: Any,
            poke_interval: float = 30.0,
            timeout: float = 300.0,
            mode: str = "poke",
            task_id: str | None = None,
            **kwargs: Any,
        ) -> None:
            super().__init__(*args, task_id=task_id, **kwargs)
            self.poke_interval = float(poke_interval)
            self.timeout = float(timeout)
            self.mode = str(mode)

        def poke(self, context: Mapping[str, Any]) -> bool:  # pragma: no cover - interface fallback
            raise NotImplementedError()

        def execute(self, context: Mapping[str, Any]) -> bool:
            started = time.monotonic()
            while True:
                if self.poke(context):
                    return True
                if (time.monotonic() - started) >= self.timeout:
                    raise AirflowException("sensor timed out")
                time.sleep(max(0.01, min(self.poke_interval, 1.0)))

else:
    _AIRFLOW_IMPORT_ERROR = None


class EncryptFileOperator(BaseOperator):
    """Airflow operator for file encryption with XCom metadata output."""

    template_fields: tuple[str, ...] = ("input_path", "output_path", "algorithm")

    def __init__(
        self,
        *,
        task_id: str,
        input_path: str | Path,
        output_path: str | Path,
        algorithm: str = "AES-256-GCM",
        key_manager: KeyManager | None = None,
        aad: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(task_id=task_id, **kwargs)
        self.input_path = Path(input_path)
        self.output_path = Path(output_path)
        self.algorithm = str(algorithm)
        self._aad = aad
        self._key_manager = key_manager

    def execute(self, context: Mapping[str, Any]) -> dict[str, Any]:
        if not self.input_path.exists() or not self.input_path.is_file():
            raise AirflowException(f"input file not found: {self.input_path}")

        manager = self._key_manager or KeyManager()

        try:
            generated = manager.generate_master_key(self.algorithm)
        except Exception as exc:
            raise AirflowException(f"key generation failed: {exc}") from exc

        key = generated["key"]
        key_id = str(generated["key_id"])
        resolved_algorithm = str(generated.get("algorithm", self.algorithm))

        plaintext = self.input_path.read_bytes()
        nonce = os.urandom(12)
        aad_text = self._aad or f"airflow:task={self.task_id}|file={self.input_path.name}|algorithm={resolved_algorithm}"
        aad_bytes = aad_text.encode("utf-8")

        try:
            ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad_bytes)
        except Exception as exc:
            raise AirflowException(f"encryption failed: {exc}") from exc

        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.output_path.write_bytes(ciphertext)

        sidecar = self._metadata_path_for(self.output_path)
        metadata = {
            "input_path": str(self.input_path),
            "output_path": str(self.output_path),
            "metadata_path": str(sidecar),
            "key_id": key_id,
            "algorithm": resolved_algorithm,
            "nonce_b64": base64.b64encode(nonce).decode("ascii"),
            "aad": aad_text,
            "plaintext_size": len(plaintext),
            "ciphertext_size": len(ciphertext),
            "created_at": time.time(),
        }
        sidecar.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

        self._xcom_push(context, "encryption_metadata", metadata)
        self._xcom_push(context, "key_id", key_id)
        return metadata

    @staticmethod
    def _metadata_path_for(path: Path) -> Path:
        return path.with_suffix(path.suffix + ".meta.json")

    @staticmethod
    def _xcom_push(context: Mapping[str, Any], key: str, value: Any) -> None:
        ti = context.get("ti")
        push = getattr(ti, "xcom_push", None)
        if callable(push):
            push(key=key, value=value)


class DecryptFileOperator(BaseOperator):
    """Airflow operator for file decryption with XCom metadata consumption."""

    template_fields: tuple[str, ...] = ("input_path", "output_path", "key_id")

    def __init__(
        self,
        *,
        task_id: str,
        input_path: str | Path,
        output_path: str | Path,
        key_id: str | None,
        metadata_path: str | Path | None = None,
        xcom_task_id: str | None = None,
        key_manager: KeyManager | None = None,
        aad: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(task_id=task_id, **kwargs)
        self.input_path = Path(input_path)
        self.output_path = Path(output_path)
        self.key_id = key_id
        self.metadata_path = None if metadata_path is None else Path(metadata_path)
        self.xcom_task_id = xcom_task_id
        self._key_manager = key_manager
        self._aad = aad

    def execute(self, context: Mapping[str, Any]) -> dict[str, Any]:
        if not self.input_path.exists() or not self.input_path.is_file():
            raise AirflowException(f"encrypted input file not found: {self.input_path}")

        sidecar = self.metadata_path or EncryptFileOperator._metadata_path_for(self.input_path)
        sidecar_meta = self._read_metadata(sidecar)
        xcom_meta = self._xcom_pull_metadata(context)

        resolved_key_id = self.key_id or sidecar_meta.get("key_id") or xcom_meta.get("key_id")
        if not isinstance(resolved_key_id, str) or not resolved_key_id.strip():
            raise AirflowException("key_id is required for decryption and was not found in args/metadata/XCom")

        nonce_b64 = sidecar_meta.get("nonce_b64") or xcom_meta.get("nonce_b64")
        if not isinstance(nonce_b64, str) or not nonce_b64:
            raise AirflowException("nonce_b64 missing in metadata/XCom for decryption")

        aad_text = self._aad or sidecar_meta.get("aad") or xcom_meta.get("aad") or ""
        aad_bytes = str(aad_text).encode("utf-8")

        try:
            nonce = base64.b64decode(nonce_b64.encode("ascii"))
        except Exception as exc:
            raise AirflowException(f"invalid nonce_b64: {exc}") from exc

        manager = self._key_manager or KeyManager()
        try:
            key = manager.get_key(resolved_key_id)
        except KeyManagerError as exc:
            raise AirflowException(f"failed to resolve key: {exc}") from exc

        ciphertext = self.input_path.read_bytes()

        try:
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, aad_bytes)
        except Exception as exc:
            raise AirflowException(f"decryption failed: {exc}") from exc

        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.output_path.write_bytes(plaintext)

        payload = {
            "input_path": str(self.input_path),
            "output_path": str(self.output_path),
            "key_id": resolved_key_id,
            "plaintext_size": len(plaintext),
            "decrypted_at": time.time(),
        }
        self._xcom_push(context, "decryption_metadata", payload)
        return payload

    def _xcom_pull_metadata(self, context: Mapping[str, Any]) -> dict[str, Any]:
        ti = context.get("ti")
        pull = getattr(ti, "xcom_pull", None)
        if not callable(pull):
            return {}

        kwargs: dict[str, Any] = {"key": "encryption_metadata"}
        if self.xcom_task_id:
            kwargs["task_ids"] = self.xcom_task_id

        value = pull(**kwargs)
        if isinstance(value, Mapping):
            return {str(k): v for k, v in value.items()}
        return {}

    @staticmethod
    def _xcom_push(context: Mapping[str, Any], key: str, value: Any) -> None:
        ti = context.get("ti")
        push = getattr(ti, "xcom_push", None)
        if callable(push):
            push(key=key, value=value)

    @staticmethod
    def _read_metadata(path: Path) -> dict[str, Any]:
        if not path.exists():
            return {}
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}
        if isinstance(payload, Mapping):
            return {str(k): v for k, v in payload.items()}
        return {}


class RotateKeysOperator(BaseOperator):
    """Airflow operator for scheduled key rotation."""

    template_fields: tuple[str, ...] = ("key_ids",)

    def __init__(
        self,
        *,
        task_id: str,
        key_ids: Sequence[str],
        reason: str = "scheduled_rotation",
        key_manager: KeyManager | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(task_id=task_id, **kwargs)
        self.key_ids = list(key_ids)
        self.reason = str(reason)
        self._key_manager = key_manager

    def execute(self, context: Mapping[str, Any]) -> list[dict[str, Any]]:
        if not self.key_ids:
            raise AirflowException("key_ids must be non-empty")

        manager = self._key_manager or KeyManager()
        results: list[dict[str, Any]] = []

        for key_id in self.key_ids:
            if not isinstance(key_id, str) or not key_id.strip():
                raise AirflowException("key_ids contains invalid value")

            try:
                rotated = manager.rotate_key(key_id, self.reason)
            except Exception as exc:
                raise AirflowException(f"key rotation failed for {key_id}: {exc}") from exc

            results.append(
                {
                    "old_key_id": rotated["old_key_id"],
                    "new_key_id": rotated["new_key_id"],
                    "algorithm": rotated["algorithm"],
                    "revoked_reason": rotated["revoked_reason"],
                }
            )

        ti = context.get("ti")
        push = getattr(ti, "xcom_push", None)
        if callable(push):
            push(key="rotation_results", value=results)

        return results


class EncryptedFileSensor(BaseSensorOperator):
    """Airflow sensor that waits for encrypted file (and metadata) existence."""

    template_fields: tuple[str, ...] = ("filepath",)

    def __init__(
        self,
        *,
        task_id: str,
        filepath: str | Path,
        timeout: float = 300.0,
        poke_interval: float = 30.0,
        require_metadata: bool = True,
        **kwargs: Any,
    ) -> None:
        super().__init__(task_id=task_id, timeout=timeout, poke_interval=poke_interval, **kwargs)
        self.filepath = Path(filepath)
        self.require_metadata = bool(require_metadata)

    def poke(self, context: Mapping[str, Any]) -> bool:
        if not self.filepath.exists() or not self.filepath.is_file():
            return False

        if self.require_metadata:
            sidecar = EncryptFileOperator._metadata_path_for(self.filepath)
            if not sidecar.exists() or not sidecar.is_file():
                return False

        ti = context.get("ti")
        push = getattr(ti, "xcom_push", None)
        if callable(push):
            push(key="encrypted_file_path", value=str(self.filepath))
        return True


__all__ = [
    "AirflowException",
    "BaseOperator",
    "BaseSensorOperator",
    "DecryptFileOperator",
    "EncryptFileOperator",
    "EncryptedFileSensor",
    "RotateKeysOperator",
]
