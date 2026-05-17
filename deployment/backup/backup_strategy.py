from __future__ import annotations

import hashlib
import json
import logging
import os
import shlex
import shutil
import subprocess
import tarfile
import tempfile
from dataclasses import dataclass
from datetime import datetime, date
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


@dataclass
class BackupResult:
    success: bool
    message: str
    backup_path: Optional[Path]
    timestamp: datetime
    size_bytes: Optional[int] = None


@dataclass
class ValidationResult:
    valid: bool
    errors: List[str]
    checksums: Dict[str, str]


@dataclass
class CronSchedule:
    cron_expression: str  # e.g. '0 2 * * *'
    user: Optional[str] = None


def _which(bin_name: str) -> Optional[str]:
    return shutil.which(bin_name)


def _run(cmd: List[str], capture: bool = True, env: Optional[Dict[str, str]] = None) -> subprocess.CompletedProcess:
    logger.debug('Running command: %s', ' '.join(shlex.quote(p) for p in cmd))
    return subprocess.run(cmd, stdout=subprocess.PIPE if capture else None, stderr=subprocess.PIPE if capture else None, env=env, text=True)


def _checksum_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()


def _collect_paths_for_keys() -> List[Path]:
    candidates = []
    home = Path.home()
    candidates += list((home / '.keycrypt' / 'keys').glob('**/*')) if (home / '.keycrypt' / 'keys').exists() else []
    candidates += list(Path('keys').glob('**/*')) if Path('keys').exists() else []
    candidates = [p for p in candidates if p.is_file()]
    return candidates


def _collect_paths_for_configs() -> List[Path]:
    candidates = []
    repo = Path.cwd()
    for p in ['config', 'configs', 'deployment/configs', 'deployment']:
        d = repo / p
        if d.exists():
            candidates += [x for x in d.rglob('*') if x.is_file()]
    # provider configs in src/providers
    prov = repo / 'src' / 'providers'
    if prov.exists():
        candidates += [x for x in prov.rglob('*') if x.is_file()]
    return candidates


def _collect_audit_logs(start_date: date, end_date: date) -> List[Path]:
    candidates: List[Path] = []
    # Common audit paths
    for base in [Path('/var/log/audit'), Path('deployment/audit_logs'), Path('logs/audit'), Path('audit')]:
        if base.exists():
            for p in base.rglob('*'):
                if not p.is_file():
                    continue
                mtime = datetime.fromtimestamp(p.stat().st_mtime).date()
                if start_date <= mtime <= end_date:
                    candidates.append(p)
    return candidates


def _create_tar(paths: List[Path], dest: Path, manifest_name: str = 'manifest.json') -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(dest, 'w:gz') as tar:
        manifest = {}
        for p in paths:
            arcname = p.relative_to(Path.cwd()) if p.is_relative_to(Path.cwd()) else p.name
            tar.add(p, arcname=str(arcname))
            manifest[str(arcname)] = _checksum_file(p)
        # add manifest as a file inside the tar
        with tempfile.NamedTemporaryFile('w', delete=False) as mf:
            json.dump({'generated': datetime.utcnow().isoformat(), 'files': manifest}, mf)
            mf.flush()
            tar.add(mf.name, arcname=manifest_name)
            os.unlink(mf.name)
    return dest


def _encrypt_with_gpg(src: Path, dest: Path, passphrase: Optional[str] = None) -> subprocess.CompletedProcess:
    gpg = _which('gpg')
    if not gpg:
        raise RuntimeError('gpg not available')
    cmd = [gpg, '--symmetric', '--cipher-algo', 'AES256', '--batch', '--yes', '-o', str(dest), str(src)]
    if passphrase:
        cmd[2:2] = ['--passphrase', passphrase]
    return _run(cmd, capture=True)


def _encrypt_with_aes_gcm(src: Path, dest: Path, key: bytes) -> None:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except Exception as e:
        raise RuntimeError('cryptography not available') from e
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    data = src.read_bytes()
    ct = aesgcm.encrypt(nonce, data, None)
    dest.write_bytes(nonce + ct)


def backup_encryption_keys(destination: str) -> BackupResult:
    """Back up key material. Keys are gathered from well-known locations and encrypted before storage.

    Destination can be a filesystem path or a restic/duplicity repository depending on environment.
    """
    timestamp = datetime.utcnow()
    dest = Path(destination)
    try:
        paths = _collect_paths_for_keys()
        if not paths:
            return BackupResult(False, 'No key files found to back up', None, timestamp)

        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            tar_path = td_path / f'key_backup_{timestamp.strftime("%Y%m%dT%H%M%SZ")}.tar.gz'
            _create_tar(paths, tar_path)

            # Prefer restic if configured
            if _which('restic'):
                repo = os.environ.get('RESTIC_REPOSITORY')
                pw = os.environ.get('RESTIC_PASSWORD')
                if not repo or not pw:
                    return BackupResult(False, 'RESTIC_REPOSITORY and RESTIC_PASSWORD must be set for restic backups', None, timestamp)
                env = os.environ.copy()
                env['RESTIC_PASSWORD'] = pw
                cmd = ['restic', '-r', repo, 'backup', str(tar_path), '--tag', 'key-backup']
                res = _run(cmd, env=env)
                if res.returncode == 0:
                    return BackupResult(True, res.stdout.strip(), Path(repo), timestamp)
                else:
                    return BackupResult(False, res.stderr.strip(), None, timestamp)

            # Prefer duplicity if available
            if _which('duplicity'):
                cmd = ['duplicity', str(tar_path), destination]
                res = _run(cmd)
                if res.returncode == 0:
                    return BackupResult(True, res.stdout.strip(), Path(destination), timestamp)
                else:
                    return BackupResult(False, res.stderr.strip(), None, timestamp)

            # Fallback: encrypt with GPG or AES and copy to destination path
            dest.mkdir(parents=True, exist_ok=True)
            encrypted = dest / (tar_path.name + '.gpg')
            if _which('gpg'):
                passphrase = os.environ.get('BACKUP_PASSPHRASE')
                res = _encrypt_with_gpg(tar_path, encrypted, passphrase)
                if res.returncode != 0:
                    return BackupResult(False, res.stderr.strip(), None, timestamp)
            else:
                key_b64 = os.environ.get('BACKUP_AES_KEY')
                if not key_b64:
                    return BackupResult(False, 'No BACKUP_AES_KEY set for AES fallback and gpg not available', None, timestamp)
                key = hashlib.sha256(key_b64.encode()).digest()
                _encrypt_with_aes_gcm(tar_path, encrypted, key)

            size = encrypted.stat().st_size
            return BackupResult(True, 'Encrypted backup created', encrypted, timestamp, size_bytes=size)
    except Exception as e:
        logger.exception('backup_encryption_keys failed')
        return BackupResult(False, str(e), None, timestamp)


def backup_configuration(destination: str) -> BackupResult:
    timestamp = datetime.utcnow()
    dest = Path(destination)
    try:
        paths = _collect_paths_for_configs()
        if not paths:
            return BackupResult(False, 'No configuration files found', None, timestamp)

        with tempfile.TemporaryDirectory() as td:
            tar_path = Path(td) / f'config_backup_{timestamp.strftime("%Y%m%dT%H%M%SZ")}.tar.gz'
            _create_tar(paths, tar_path)

            # Try restic/duplicity like keys
            if _which('restic'):
                repo = os.environ.get('RESTIC_REPOSITORY')
                pw = os.environ.get('RESTIC_PASSWORD')
                if not repo or not pw:
                    return BackupResult(False, 'RESTIC_REPOSITORY and RESTIC_PASSWORD must be set for restic backups', None, timestamp)
                env = os.environ.copy()
                env['RESTIC_PASSWORD'] = pw
                cmd = ['restic', '-r', repo, 'backup', str(tar_path), '--tag', 'config-backup']
                res = _run(cmd, env=env)
                if res.returncode == 0:
                    return BackupResult(True, res.stdout.strip(), Path(repo), timestamp)
                else:
                    return BackupResult(False, res.stderr.strip(), None, timestamp)

            if _which('duplicity'):
                cmd = ['duplicity', str(tar_path), destination]
                res = _run(cmd)
                if res.returncode == 0:
                    return BackupResult(True, res.stdout.strip(), Path(destination), timestamp)
                else:
                    return BackupResult(False, res.stderr.strip(), None, timestamp)

            # Fallback: gpg/AES
            dest.mkdir(parents=True, exist_ok=True)
            encrypted = dest / (tar_path.name + '.gpg')
            if _which('gpg'):
                passphrase = os.environ.get('BACKUP_PASSPHRASE')
                res = _encrypt_with_gpg(tar_path, encrypted, passphrase)
                if res.returncode != 0:
                    return BackupResult(False, res.stderr.strip(), None, timestamp)
            else:
                key_b64 = os.environ.get('BACKUP_AES_KEY')
                if not key_b64:
                    return BackupResult(False, 'No BACKUP_AES_KEY set for AES fallback and gpg not available', None, timestamp)
                key = hashlib.sha256(key_b64.encode()).digest()
                _encrypt_with_aes_gcm(tar_path, encrypted, key)

            size = encrypted.stat().st_size
            return BackupResult(True, 'Encrypted configuration backup created', encrypted, timestamp, size_bytes=size)
    except Exception as e:
        logger.exception('backup_configuration failed')
        return BackupResult(False, str(e), None, timestamp)


def backup_audit_logs(start_date: date, end_date: date, destination: str) -> BackupResult:
    timestamp = datetime.utcnow()
    try:
        paths = _collect_audit_logs(start_date, end_date)
        if not paths:
            return BackupResult(False, 'No audit logs found for given range', None, timestamp)

        with tempfile.TemporaryDirectory() as td:
            tar_path = Path(td) / f'audit_backup_{start_date.isoformat()}_{end_date.isoformat()}.tar.gz'
            _create_tar(paths, tar_path, manifest_name='audit_manifest.json')

            if _which('restic'):
                repo = os.environ.get('RESTIC_REPOSITORY')
                pw = os.environ.get('RESTIC_PASSWORD')
                if not repo or not pw:
                    return BackupResult(False, 'RESTIC_REPOSITORY and RESTIC_PASSWORD must be set for restic backups', None, timestamp)
                env = os.environ.copy()
                env['RESTIC_PASSWORD'] = pw
                cmd = ['restic', '-r', repo, 'backup', str(tar_path), '--tag', 'audit-backup']
                res = _run(cmd, env=env)
                if res.returncode == 0:
                    return BackupResult(True, res.stdout.strip(), Path(repo), timestamp)
                else:
                    return BackupResult(False, res.stderr.strip(), None, timestamp)

            if _which('duplicity'):
                cmd = ['duplicity', str(tar_path), destination]
                res = _run(cmd)
                if res.returncode == 0:
                    return BackupResult(True, res.stdout.strip(), Path(destination), timestamp)
                else:
                    return BackupResult(False, res.stderr.strip(), None, timestamp)

            dest = Path(destination)
            dest.mkdir(parents=True, exist_ok=True)
            encrypted = dest / (tar_path.name + '.gpg')
            if _which('gpg'):
                passphrase = os.environ.get('BACKUP_PASSPHRASE')
                res = _encrypt_with_gpg(tar_path, encrypted, passphrase)
                if res.returncode != 0:
                    return BackupResult(False, res.stderr.strip(), None, timestamp)
            else:
                key_b64 = os.environ.get('BACKUP_AES_KEY')
                if not key_b64:
                    return BackupResult(False, 'No BACKUP_AES_KEY set for AES fallback and gpg not available', None, timestamp)
                key = hashlib.sha256(key_b64.encode()).digest()
                _encrypt_with_aes_gcm(tar_path, encrypted, key)

            size = encrypted.stat().st_size
            return BackupResult(True, 'Encrypted audit backup created', encrypted, timestamp, size_bytes=size)
    except Exception as e:
        logger.exception('backup_audit_logs failed')
        return BackupResult(False, str(e), None, timestamp)


def verify_backup_integrity(backup_path: Path) -> ValidationResult:
    errors: List[str] = []
    checksums: Dict[str, str] = {}
    try:
        if _which('restic') and backup_path.exists() and backup_path.is_dir():
            # For restic repository, run `restic check`
            repo = str(backup_path)
            pw = os.environ.get('RESTIC_PASSWORD')
            env = os.environ.copy()
            if pw:
                env['RESTIC_PASSWORD'] = pw
            res = _run(['restic', '-r', repo, 'check'], env=env)
            if res.returncode == 0:
                return ValidationResult(True, [], {})
            else:
                return ValidationResult(False, [res.stderr.strip()], {})

        # If it's an encrypted file (.gpg) try to decrypt to temp and verify manifest
        if backup_path.exists() and backup_path.is_file():
            with tempfile.TemporaryDirectory() as td:
                td_p = Path(td)
                if str(backup_path).endswith('.gpg') and _which('gpg'):
                    out = td_p / 'decrypted.tar.gz'
                    cmd = ['gpg', '--batch', '--yes', '--output', str(out), '--decrypt', str(backup_path)]
                    pw = os.environ.get('BACKUP_PASSPHRASE')
                    if pw:
                        cmd[2:2] = ['--passphrase', pw]
                    res = _run(cmd)
                    if res.returncode != 0:
                        return ValidationResult(False, [res.stderr.strip()], {})
                    # inspect tar
                    with tarfile.open(out, 'r:gz') as tar:
                        try:
                            mf = tar.extractfile('manifest.json') or tar.extractfile('audit_manifest.json')
                            if not mf:
                                errors.append('manifest missing')
                                return ValidationResult(False, errors, {})
                            manifest = json.load(mf)
                            files = manifest.get('files', {})
                            for fname, expected in files.items():
                                try:
                                    f = tar.extractfile(fname)
                                    if not f:
                                        errors.append(f'missing file in archive: {fname}')
                                        continue
                                    data = f.read()
                                    actual = hashlib.sha256(data).hexdigest()
                                    checksums[fname] = actual
                                    if actual != expected:
                                        errors.append(f'checksum mismatch: {fname}')
                                except KeyError:
                                    errors.append(f'file not found in tar: {fname}')
                            return ValidationResult(len(errors) == 0, errors, checksums)
                        except Exception as e:
                            return ValidationResult(False, [str(e)], {})
                else:
                    # Assume plain tar.gz
                    with tarfile.open(str(backup_path), 'r:gz') as tar:
                        try:
                            mf = tar.extractfile('manifest.json') or tar.extractfile('audit_manifest.json')
                            if not mf:
                                errors.append('manifest missing')
                                return ValidationResult(False, errors, {})
                            manifest = json.load(mf)
                            files = manifest.get('files', {})
                            for fname, expected in files.items():
                                try:
                                    f = tar.extractfile(fname)
                                    if not f:
                                        errors.append(f'missing file in archive: {fname}')
                                        continue
                                    data = f.read()
                                    actual = hashlib.sha256(data).hexdigest()
                                    checksums[fname] = actual
                                    if actual != expected:
                                        errors.append(f'checksum mismatch: {fname}')
                                except KeyError:
                                    errors.append(f'file not found in tar: {fname}')
                            return ValidationResult(len(errors) == 0, errors, checksums)
                        except Exception as e:
                            return ValidationResult(False, [str(e)], {})

        return ValidationResult(False, ['backup path does not exist or unsupported format'], {})
    except Exception as e:
        logger.exception('verify_backup_integrity failed')
        return ValidationResult(False, [str(e)], {})


def schedule_backups(schedule: CronSchedule, python_exec: Optional[str] = None) -> None:
    """Install a cronjob for the current user to run scheduled backups.

    The cron will invoke a small Python one-liner which calls `run_scheduled_backup()` in this module.
    """
    python_exec = python_exec or shutil.which('python3') or shutil.which('python')
    if not python_exec:
        raise RuntimeError('Python executable not found for scheduling cron job')

    cron_line = f"{schedule.cron_expression} {python_exec} -c \"from deployment.backup.backup_strategy import run_scheduled_backup; run_scheduled_backup()\"  # keycrypt-backup\n"

    # read existing crontab
    res = _run(['crontab', '-l'])
    existing = res.stdout if res.returncode == 0 else ''
    if 'keycrypt-backup' in existing:
        logger.info('Existing keycrypt-backup cron detected, replacing')
        lines = [ln for ln in existing.splitlines() if 'keycrypt-backup' not in ln]
    else:
        lines = existing.splitlines() if existing else []
    lines.append(cron_line.strip())
    new_cron = '\n'.join(lines) + '\n'
    p = subprocess.Popen(['crontab', '-'], stdin=subprocess.PIPE, text=True)
    p.communicate(new_cron)
    if p.returncode != 0:
        raise RuntimeError('Failed to install crontab')
    logger.info('Cron installed: %s', schedule.cron_expression)


def run_scheduled_backup() -> None:
    """Entry point used by cron. Reads environment variables to determine what to back up.

    Expected env vars:
      - KEY_BACKUP_DEST
      - CONFIG_BACKUP_DEST
      - AUDIT_BACKUP_DEST
      - AUDIT_BACKUP_START
      - AUDIT_BACKUP_END
    """
    kb = os.environ.get('KEY_BACKUP_DEST')
    cb = os.environ.get('CONFIG_BACKUP_DEST')
    ab = os.environ.get('AUDIT_BACKUP_DEST')
    if kb:
        r = backup_encryption_keys(kb)
        logger.info('Key backup: %s', r)
    if cb:
        r = backup_configuration(cb)
        logger.info('Config backup: %s', r)
    if ab:
        s = os.environ.get('AUDIT_BACKUP_START')
        e = os.environ.get('AUDIT_BACKUP_END')
        try:
            start = date.fromisoformat(s) if s else date.today()
            end = date.fromisoformat(e) if e else date.today()
        except Exception:
            start = date.today()
            end = date.today()
        r = backup_audit_logs(start, end, ab)
        logger.info('Audit backup: %s', r)


if __name__ == '__main__':
    # simple CLI for manual invocation during debugging
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument('--keys-dest')
    ap.add_argument('--config-dest')
    ap.add_argument('--audit-start')
    ap.add_argument('--audit-end')
    ap.add_argument('--audit-dest')
    args = ap.parse_args()
    if args.keys_dest:
        print(backup_encryption_keys(args.keys_dest))
    if args.config_dest:
        print(backup_configuration(args.config_dest))
    if args.audit_dest:
        st = date.fromisoformat(args.audit_start) if args.audit_start else date.today()
        en = date.fromisoformat(args.audit_end) if args.audit_end else date.today()
        print(backup_audit_logs(st, en, args.audit_dest))
