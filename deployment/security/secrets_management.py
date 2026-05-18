from __future__ import annotations

import json
import logging
import os
import random
import string
import subprocess
import tempfile
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


@dataclass
class Secret:
    key: str
    value: str
    metadata: Dict[str, Any]
    created_at: datetime


@dataclass
class AccessEvent:
    key: str
    actor: str
    action: str
    timestamp: datetime
    success: bool
    details: Optional[str] = None


class SecretsBackendBase:
    def store_secret(self, key: str, value: str, metadata: Dict[str, Any]) -> None:
        raise NotImplementedError()

    def retrieve_secret(self, key: str) -> Secret:
        raise NotImplementedError()

    def rotate_secret(self, key: str, new_value: Optional[str] = None) -> Secret:
        raise NotImplementedError()

    def audit_secret_access(self, key: str) -> List[AccessEvent]:
        raise NotImplementedError()


class VaultBackend(SecretsBackendBase):
    def __init__(self, url: str, token: Optional[str] = None, mount_point: str = 'secret'):
        try:
            import hvac

            self.client = hvac.Client(url=url, token=token or os.environ.get('VAULT_TOKEN'))
            if not self.client.is_authenticated():
                logger.warning('Vault client not authenticated — check token')
        except Exception:
            self.client = None
            logger.exception('hvac not available or Vault init failed')
        self.mount = mount_point

    def store_secret(self, key: str, value: str, metadata: Dict[str, Any]) -> None:
        if not self.client:
            raise RuntimeError('Vault client not available')
        path = f'{self.mount}/data/{key}'
        payload = {'data': {'value': value, 'metadata': metadata}}
        self.client.secrets.kv.v2.create_or_update_secret(path=key, secret={'value': value, 'metadata': metadata})

    def retrieve_secret(self, key: str) -> Secret:
        if not self.client:
            raise RuntimeError('Vault client not available')
        try:
            res = self.client.secrets.kv.v2.read_secret_version(path=key)
            data = res['data']['data']
            value = data.get('value')
            metadata = data.get('metadata', {})
            s = Secret(key=key, value=value, metadata=metadata, created_at=datetime.utcnow())
            _log_access(key, 'vault', 'retrieve', True, 'retrieved from vault')
            return s
        except Exception as e:
            _log_access(key, 'vault', 'retrieve', False, str(e))
            raise

    def rotate_secret(self, key: str, new_value: Optional[str] = None) -> Secret:
        new_value = new_value or _generate_random_secret()
        self.store_secret(key, new_value, {'rotated_at': datetime.utcnow().isoformat()})
        s = Secret(key=key, value=new_value, metadata={'rotated': True}, created_at=datetime.utcnow())
        _log_access(key, 'vault', 'rotate', True, 'rotated via VaultBackend')
        return s

    def audit_secret_access(self, key: str) -> List[AccessEvent]:
        # Vault audit devices are external; provide fallback to local audit log
        return _read_local_audit(key)


class AWSSecretsManagerBackend(SecretsBackendBase):
    def __init__(self, region_name: Optional[str] = None):
        try:
            import boto3

            self.client = boto3.client('secretsmanager', region_name=region_name or os.environ.get('AWS_REGION'))
        except Exception:
            self.client = None
            logger.exception('boto3 not available or client init failed')

    def store_secret(self, key: str, value: str, metadata: Dict[str, Any]) -> None:
        if not self.client:
            raise RuntimeError('AWS SecretsManager client not available')
        try:
            # Try create, otherwise put value
            self.client.create_secret(Name=key, SecretString=value, Tags=[{'Key': k, 'Value': str(v)} for k, v in metadata.items()])
        except Exception:
            self.client.put_secret_value(SecretId=key, SecretString=value)

    def retrieve_secret(self, key: str) -> Secret:
        if not self.client:
            raise RuntimeError('AWS SecretsManager client not available')
        try:
            res = self.client.get_secret_value(SecretId=key)
            val = res.get('SecretString')
            s = Secret(key=key, value=val, metadata={}, created_at=datetime.utcnow())
            _log_access(key, 'aws', 'retrieve', True, 'retrieved from AWS Secrets Manager')
            return s
        except Exception as e:
            _log_access(key, 'aws', 'retrieve', False, str(e))
            raise

    def rotate_secret(self, key: str, new_value: Optional[str] = None) -> Secret:
        if not self.client:
            raise RuntimeError('AWS SecretsManager client not available')
        new_value = new_value or _generate_random_secret()
        self.client.put_secret_value(SecretId=key, SecretString=new_value)
        s = Secret(key=key, value=new_value, metadata={'rotated': True}, created_at=datetime.utcnow())
        _log_access(key, 'aws', 'rotate', True, 'rotated via AWSSecretsManager')
        return s

    def audit_secret_access(self, key: str) -> List[AccessEvent]:
        # Prefer CloudTrail logs; fallback to local audit
        return _read_local_audit(key)


class AzureKeyVaultBackend(SecretsBackendBase):
    def __init__(self, vault_url: Optional[str] = None):
        try:
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.secrets import SecretClient

            credential = DefaultAzureCredential()
            vault_url = vault_url or os.environ.get('AZURE_KEYVAULT_URL')
            self.client = SecretClient(vault_url=vault_url, credential=credential)
        except Exception:
            self.client = None
            logger.exception('azure keyvault client init failed')

    def store_secret(self, key: str, value: str, metadata: Dict[str, Any]) -> None:
        if not self.client:
            raise RuntimeError('Azure Key Vault client not available')
        self.client.set_secret(key, value)

    def retrieve_secret(self, key: str) -> Secret:
        if not self.client:
            raise RuntimeError('Azure Key Vault client not available')
        try:
            sres = self.client.get_secret(key)
            s = Secret(key=key, value=sres.value, metadata={}, created_at=datetime.utcnow())
            _log_access(key, 'azure', 'retrieve', True, 'retrieved from Key Vault')
            return s
        except Exception as e:
            _log_access(key, 'azure', 'retrieve', False, str(e))
            raise

    def rotate_secret(self, key: str, new_value: Optional[str] = None) -> Secret:
        new_value = new_value or _generate_random_secret()
        self.store_secret(key, new_value, {'rotated_at': datetime.utcnow().isoformat()})
        s = Secret(key=key, value=new_value, metadata={'rotated': True}, created_at=datetime.utcnow())
        _log_access(key, 'azure', 'rotate', True, 'rotated via AzureKeyVault')
        return s

    def audit_secret_access(self, key: str) -> List[AccessEvent]:
        return _read_local_audit(key)


_AUDIT_LOG_PATH = os.environ.get('SECRETS_AUDIT_LOG', '/var/log/keycrypt/secrets_audit.log')


def _log_access(key: str, actor: str, action: str, success: bool, details: Optional[str] = None) -> None:
    ev = AccessEvent(key=key, actor=actor, action=action, timestamp=datetime.utcnow(), success=success, details=details)
    try:
        os.makedirs(os.path.dirname(_AUDIT_LOG_PATH), exist_ok=True)
        with open(_AUDIT_LOG_PATH, 'a') as f:
            f.write(json.dumps({'key': ev.key, 'actor': ev.actor, 'action': ev.action, 'timestamp': ev.timestamp.isoformat(), 'success': ev.success, 'details': ev.details}) + '\n')
    except Exception:
        logger.exception('failed to write audit log; printing to stdout')
        print(asdict(ev))


def _read_local_audit(key: str) -> List[AccessEvent]:
    events: List[AccessEvent] = []
    try:
        if not os.path.exists(_AUDIT_LOG_PATH):
            return []
        with open(_AUDIT_LOG_PATH, 'r') as f:
            for line in f:
                try:
                    j = json.loads(line)
                    if j.get('key') == key:
                        events.append(AccessEvent(key=j['key'], actor=j.get('actor', ''), action=j.get('action', ''), timestamp=datetime.fromisoformat(j['timestamp']), success=j.get('success', False), details=j.get('details')))
                except Exception:
                    continue
    except Exception:
        logger.exception('failed to read local audit log')
    return events


def _generate_random_secret(length: int = 32) -> str:
    return ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(length))


def initialize_secrets_backend(backend: str, **kwargs) -> SecretsBackendBase:
    b = backend.lower()
    if b == 'vault':
        url = kwargs.get('url') or os.environ.get('VAULT_ADDR')
        token = kwargs.get('token') or os.environ.get('VAULT_TOKEN')
        return VaultBackend(url=url, token=token, mount_point=kwargs.get('mount_point', 'secret'))
    if b in ('aws', 'aws_secretsmanager', 'secretsmanager'):
        return AWSSecretsManagerBackend(region_name=kwargs.get('region'))
    if b in ('azure', 'azure_keyvault', 'keyvault'):
        return AzureKeyVaultBackend(vault_url=kwargs.get('vault_url'))
    raise ValueError(f'Unsupported backend: {backend}')


def store_secret(backend: SecretsBackendBase, key: str, value: str, metadata: Optional[Dict[str, Any]] = None) -> None:
    metadata = metadata or {}
    backend.store_secret(key, value, metadata)
    _log_access(key, getattr(backend, '__class__', type(backend)).__name__, 'store', True, 'stored secret')


def retrieve_secret(backend: SecretsBackendBase, key: str) -> Secret:
    s = backend.retrieve_secret(key)
    _log_access(key, getattr(backend, '__class__', type(backend)).__name__, 'retrieve', True, 'retrieved secret')
    return s


def rotate_secret(backend: SecretsBackendBase, key: str, notify_consumers: bool = True) -> Secret:
    new = backend.rotate_secret(key)
    if notify_consumers:
        try:
            _trigger_k8s_rollout_for_secret(key)
        except Exception:
            logger.exception('failed to trigger k8s rollout after secret rotation')
    return new


def audit_secret_access(backend: SecretsBackendBase, key: str) -> List[AccessEvent]:
    return backend.audit_secret_access(key)


def _trigger_k8s_rollout_for_secret(secret_name: str) -> None:
    # Best-effort: annotate deployments/statefulsets that refer to the secret to restart
    try:
        from kubernetes import client, config

        try:
            config.load_incluster_config()
        except Exception:
            config.load_kube_config()
        api = client.AppsV1Api()
        # naive approach: patch all deployments with an annotation to trigger rollout
        ds = api.list_deployment_for_all_namespaces()
        for d in ds.items:
            mounts = json.dumps(d.spec.template.spec.volumes, default=str)
            if secret_name in mounts:
                name = d.metadata.name
                ns = d.metadata.namespace
                patch = {'spec': {'template': {'metadata': {'annotations': {'keycrypt/secret-rotated': datetime.utcnow().isoformat()}}}}}
                api.patch_namespaced_deployment(name, ns, patch)
    except Exception:
        # If kubernetes client is not available or fails, fallback to kubectl rollout restart if present
        if shutil.which('kubectl'):
            try:
                subprocess.run(['kubectl', 'rollout', 'restart', 'deployment', '--all', '-A'], check=True)
            except Exception:
                logger.exception('kubectl rollout restart failed')
        else:
            logger.warning('kubernetes client and kubectl unavailable; cannot trigger rollout')


def schedule_secret_rotation(key: str, interval_days: int = 90, python_exec: Optional[str] = None) -> None:
    """Install a cron entry that rotates `key` every `interval_days` by invoking this module.

    This function is a convenience helper for on-host cron. In Kubernetes, prefer CronJob resources.
    """
    python_exec = python_exec or shutil.which('python3') or shutil.which('python')
    if not python_exec:
        raise RuntimeError('Python executable not found')
    cron_expr = f"0 3 */{max(1, interval_days)} * *"
    cron_line = f"{cron_expr} {python_exec} -c \"from deployment.security.secrets_management import initialize_secrets_backend, rotate_secret; b=initialize_secrets_backend('vault'); rotate_secret(b, '{key}')\"  # keycrypt-rotate-{key}\n"
    res = subprocess.run(['crontab', '-l'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    existing = res.stdout if res.returncode == 0 else ''
    lines = [ln for ln in existing.splitlines() if f'keycrypt-rotate-{key}' not in ln]
    lines.append(cron_line.strip())
    new_cron = '\n'.join(lines) + '\n'
    p = subprocess.Popen(['crontab', '-'], stdin=subprocess.PIPE, text=True)
    p.communicate(new_cron)
    if p.returncode != 0:
        raise RuntimeError('Failed to install crontab for secret rotation')


def generate_csi_secretproviderclass_for_vault(secret_name: str, mount_path: str = '/mnt/secrets', name: str = 'vault-provider') -> str:
    """Return a YAML string for a SecretProviderClass using Vault CSI (example).

    This is a template; operators must fill in `vaultAddress` and authentication method.
    """
    tpl = f"""
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: {name}
spec:
  provider: vault
  parameters:
    vaultAddress: "https://vault.example.local"
    roleName: "keycrypt-app"
    objects: |
      - objectName: "{secret_name}"
        secretPath: "secret/data/{secret_name}"
    mountPath: "{mount_path}"
"""
    return tpl
