from __future__ import annotations

import json
import logging
import os
import shlex
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Dict

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


@dataclass
class Certificate:
    id: str
    domain: str
    path: Path
    issued_at: Optional[datetime]
    expires_at: Optional[datetime]


@dataclass
class ExpiringCertificate:
    id: str
    domain: str
    expires_in_days: int
    expires_at: datetime


@dataclass
class RotationResult:
    success: bool
    details: Dict[str, str]


def _which(bin_name: str) -> Optional[str]:
    return shutil.which(bin_name)


def _run(cmd: List[str], capture: bool = True, env: Optional[Dict[str, str]] = None) -> subprocess.CompletedProcess:
    logger.debug('Running: %s', ' '.join(shlex.quote(c) for c in cmd))
    return subprocess.run(cmd, stdout=subprocess.PIPE if capture else None, stderr=subprocess.PIPE if capture else None, text=True, env=env)


def request_certificate(domain: str, validation_method: str = 'http', email: Optional[str] = None, private_ca: bool = False, ca_config: Optional[Dict] = None) -> Certificate:
    """Request a certificate for `domain`.

    validation_method: 'http', 'dns', or provider-specific (e.g., 'dns_cloudflare')
    If `private_ca` is True, use CFSSL (cfssl/cfssljson) and `ca_config` to request from a private CA.
    Otherwise attempts to use certbot (Let's Encrypt).
    """
    # Prefer certbot
    if not private_ca and _which('certbot'):
        webroot = os.environ.get('CERTBOT_WEBROOT', '/var/www/html')
        email_flag = ['--email', email] if email else ['--register-unsafely-without-email']
        validation_flags = []
        if validation_method == 'http':
            validation_flags = ['--webroot', '-w', webroot]
        elif validation_method.startswith('dns_'):
            # vendor-specific dns plugin
            plugin = validation_method.split('dns_', 1)[1]
            validation_flags = [f'--{plugin}']
        cmd = ['certbot', 'certonly', '--non-interactive', '--agree-tos', '-d', domain] + email_flag + validation_flags
        res = _run(cmd)
        if res.returncode != 0:
            raise RuntimeError(f'certbot failed: {res.stderr}')
        # locate cert path
        live = Path('/etc/letsencrypt/live') / domain
        cert = live / 'cert.pem'
        issued_at = None
        expires_at = None
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend

            cert_bytes = cert.read_bytes()
            cert_obj = x509.load_pem_x509_certificate(cert_bytes, default_backend())
            issued_at = cert_obj.not_valid_before
            expires_at = cert_obj.not_valid_after
        except Exception:
            logger.exception('failed to parse certificate for domain %s', domain)
        return Certificate(id=f'letsencrypt:{domain}', domain=domain, path=cert, issued_at=issued_at, expires_at=expires_at)

    # Private CA via cfssl
    if private_ca and _which('cfssl') and _which('cfssljson') and ca_config:
        with tempfile.TemporaryDirectory() as td:
            td_p = Path(td)
            csr = td_p / 'csr.json'
            csr.write_text(json.dumps(ca_config))
            # cfssl gencert -ca ca.pem -ca-key ca-key.pem -config=config.json csr.json | cfssljson -bare cert
            cmd = ['cfssl', 'gencert', '-']
            p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = p.communicate(json.dumps(ca_config))
            if p.returncode != 0:
                raise RuntimeError(f'cfssl gencert failed: {stderr}')
            # cfssljson step
            p2 = subprocess.Popen(['cfssljson', '-bare', 'cert'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=td)
            p2.communicate(stdout)
            # assume cert.pem output
            cert_path = td_p / 'cert.pem'
            dest = Path('/etc/pki/tls/certs')
            dest.mkdir(parents=True, exist_ok=True)
            target = dest / f'{domain}.pem'
            shutil.copyfile(cert_path, target)
            return Certificate(id=f'cfssl:{domain}', domain=domain, path=target, issued_at=datetime.utcnow(), expires_at=None)

    raise RuntimeError('No supported CA tool available (certbot or cfssl)')


def renew_certificate(cert_id: str) -> Certificate:
    """Renew certificate identified by cert_id.

    cert_id format: 'letsencrypt:domain' or 'cfssl:domain' or custom.
    """
    parts = cert_id.split(':', 1)
    if parts[0] == 'letsencrypt' and _which('certbot'):
        domain = parts[1]
        cmd = ['certbot', 'renew', '--cert-name', domain, '--non-interactive']
        res = _run(cmd)
        if res.returncode != 0:
            raise RuntimeError(f'certbot renew failed: {res.stderr}')
        live = Path('/etc/letsencrypt/live') / domain
        cert = live / 'cert.pem'
        issued_at = None
        expires_at = None
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            cert_bytes = cert.read_bytes()
            cert_obj = x509.load_pem_x509_certificate(cert_bytes, default_backend())
            issued_at = cert_obj.not_valid_before
            expires_at = cert_obj.not_valid_after
        except Exception:
            logger.exception('failed to parse renewed certificate')
        return Certificate(id=cert_id, domain=domain, path=cert, issued_at=issued_at, expires_at=expires_at)

    if parts[0] == 'cfssl' and _which('cfssl'):
        # CFSSL renewal will depend on private CA process; here we simply call request_certificate
        domain = parts[1]
        return request_certificate(domain, private_ca=True, ca_config={})

    raise RuntimeError('Unsupported cert_id or missing tooling')


def revoke_certificate(cert_id: str, reason: str = 'key-compromise') -> None:
    """Revoke certificate. For Let's Encrypt, use certbot revoke. For private CA, use cfssl revoke if available.
    """
    parts = cert_id.split(':', 1)
    if parts[0] == 'letsencrypt' and _which('certbot'):
        domain = parts[1]
        live = Path('/etc/letsencrypt/live') / domain
        cert = live / 'cert.pem'
        if not cert.exists():
            raise FileNotFoundError('certificate file not found')
        cmd = ['certbot', 'revoke', '--cert-path', str(cert), '--reason', reason, '--non-interactive']
        res = _run(cmd)
        if res.returncode != 0:
            raise RuntimeError(f'certbot revoke failed: {res.stderr}')
        return

    if parts[0] == 'cfssl' and _which('cfssl'):
        # CFSSL revoke flow varies by CA; operator must implement specific revoke API.
        raise RuntimeError('cfssl revoke flow not implemented — perform manual revocation')

    raise RuntimeError('Unsupported cert_id or missing tooling')


def _scan_cert_files(search_paths: Optional[List[Path]] = None) -> List[Certificate]:
    certs: List[Certificate] = []
    search_paths = search_paths or [Path('/etc/letsencrypt/live')]
    for base in search_paths:
        if not base.exists():
            continue
        for d in base.iterdir():
            certf = d / 'cert.pem'
            if certf.exists():
                try:
                    from cryptography import x509
                    from cryptography.hazmat.backends import default_backend

                    cert_bytes = certf.read_bytes()
                    cert_obj = x509.load_pem_x509_certificate(cert_bytes, default_backend())
                    certs.append(Certificate(id=f'letsencrypt:{d.name}', domain=d.name, path=certf, issued_at=cert_obj.not_valid_before, expires_at=cert_obj.not_valid_after))
                except Exception:
                    logger.exception('failed to parse cert at %s', certf)
    return certs


def monitor_certificate_expiry(days_threshold: int = 30) -> List[ExpiringCertificate]:
    """Checks certificates and returns those expiring within `days_threshold` days."""
    expiring: List[ExpiringCertificate] = []
    certs = _scan_cert_files()
    now = datetime.utcnow()
    for c in certs:
        if not c.expires_at:
            continue
        delta = c.expires_at - now
        days = int(delta.total_seconds() / 86400)
        if days <= days_threshold:
            expiring.append(ExpiringCertificate(id=c.id, domain=c.domain, expires_in_days=days, expires_at=c.expires_at))
    return expiring


def rotate_certificates(cert_ids: List[str], reload_commands: Optional[List[List[str]]] = None) -> RotationResult:
    """Rotate certificates and attempt zero-downtime reloads.

    reload_commands: list of shell commands (as lists) to run after renewing to reload services (e.g., nginx reload, kubectl rollout restart).
    """
    results: Dict[str, str] = {}
    for cid in cert_ids:
        try:
            cert = renew_certificate(cid)
            results[cid] = f'renewed, expires_at={cert.expires_at}'
        except Exception as e:
            logger.exception('failed to renew %s', cid)
            results[cid] = f'error: {e}'

    # Reload services
    if reload_commands:
        for cmd in reload_commands:
            try:
                res = _run(cmd, capture=False)
                if res.returncode != 0:
                    logger.warning('reload command failed: %s', cmd)
            except Exception:
                logger.exception('reload command execution failed: %s', cmd)

    success = all(not v.startswith('error:') for v in results.values())
    return RotationResult(success=success, details=results)


def schedule_renewals(cron_expr: str = '0 3 * * *', python_exec: Optional[str] = None, cert_names: Optional[List[str]] = None) -> None:
    """Install a cron job to run certificate expiry monitor and renewals periodically.

    Default: daily at 03:00. The cron job will call this module to renew certificates nearing expiry.
    """
    python_exec = python_exec or shutil.which('python3') or shutil.which('python')
    if not python_exec:
        raise RuntimeError('Python executable not found')
    certs_arg = ' '.join(cert_names) if cert_names else ''
    cron_line = f"{cron_expr} {python_exec} -c \"from deployment.security.certificate_manager import _renew_due_certs; _renew_due_certs()\"  # keycrypt-cert-renew\n"
    res = subprocess.run(['crontab', '-l'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    existing = res.stdout if res.returncode == 0 else ''
    lines = [ln for ln in existing.splitlines() if 'keycrypt-cert-renew' not in ln]
    lines.append(cron_line.strip())
    new_cron = '\n'.join(lines) + '\n'
    p = subprocess.Popen(['crontab', '-'], stdin=subprocess.PIPE, text=True)
    p.communicate(new_cron)
    if p.returncode != 0:
        raise RuntimeError('Failed to install cert renewal crontab')


def _renew_due_certs(days_before: int = 30) -> None:
    expiring = monitor_certificate_expiry(days_threshold=days_before)
    if not expiring:
        logger.info('No certificates expiring within %s days', days_before)
        return
    cert_ids = [e.id for e in expiring]
    logger.info('Certificates expiring soon: %s', cert_ids)
    rotate_certificates(cert_ids, reload_commands=[['systemctl', 'reload', 'nginx']])


if __name__ == '__main__':
    # Simple CLI to list expiring certs or renew
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument('--list-expiring', action='store_true')
    ap.add_argument('--renew-due', action='store_true')
    ap.add_argument('--days', type=int, default=30)
    args = ap.parse_args()
    if args.list_expiring:
        for e in monitor_certificate_expiry(days_threshold=args.days):
            print(e)
    if args.renew_due:
        _renew_due_certs(days_before=args.days)
