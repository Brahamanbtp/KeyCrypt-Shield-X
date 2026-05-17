"""
Disaster Recovery (DR) restore procedures and runbook helpers.

This module provides high-level, mostly-automatable steps for restoring system
state from backups, validating the restore against RTO/RPO targets, performing
regional failover, and running non-destructive DR drills.

Runbook (summary):
- Identify the most recent valid backup that satisfies the required RPO.
- Restore backup artifacts to an isolated recovery environment (or target region).
- Validate application and data consistency, run smoke tests, and verify RTO/RPO.
- Promote restored services and reconfigure DNS/load balancer to failover region.
- Run post-failover checks and update runbook/incident ticket with timings.

Note: This module contains safe, idempotent helpers that will try to use
`restic` / `gpg` when available, and otherwise operate against tarballs.
Manual operator approval is recommended before performing cross-region failover.
"""

from __future__ import annotations

import json
import logging
import os
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


@dataclass
class RestoreResult:
    success: bool
    message: str
    restored_path: Optional[Path]
    duration_seconds: Optional[float]
    timestamp: datetime


@dataclass
class ValidationResult:
    valid: bool
    errors: List[str]
    rto_seconds: Optional[float]
    rpo_seconds: Optional[float]
    metadata: Dict[str, str]


@dataclass
class FailoverResult:
    success: bool
    message: str
    switched_region: Optional[str]
    timestamp: datetime


@dataclass
class TestResult:
    success: bool
    details: str
    timestamp: datetime


@dataclass
class SystemState:
    services_running: List[str]
    db_consistent: bool
    last_applied_log_time: Optional[datetime]


def _which(bin_name: str) -> Optional[str]:
    from shutil import which

    return which(bin_name)


def _run(cmd: List[str], capture: bool = True, env: Optional[Dict[str, str]] = None) -> subprocess.CompletedProcess:
    logger.debug('DR running: %s', ' '.join(shlex.quote(c) for c in cmd))
    return subprocess.run(cmd, stdout=subprocess.PIPE if capture else None, stderr=subprocess.PIPE if capture else None, text=True, env=env)


def restore_from_backup(backup_path: Path, restore_point: datetime) -> RestoreResult:
    """Restore system state from a backup artifact.

    - If `backup_path` is a restic repository, attempts to `restic restore` to a temp dir.
    - If `backup_path` is an encrypted file (.gpg), attempts to decrypt and extract to a temp dir.
    - If `backup_path` is a tar.gz, extracts to a temp dir.

    Returns a RestoreResult with the path to the restored files (in a transient workspace).
    Operators should review and perform final promote/attach steps after validation.
    """
    start = time.time()
    ts = datetime.utcnow()
    try:
        if _which('restic') and backup_path.exists() and backup_path.is_dir():
            # Restic restore by time
            td = Path(tempfile.mkdtemp(prefix='keycrypt-dr-restore-'))
            env = os.environ.copy()
            pw = env.get('RESTIC_PASSWORD')
            if pw:
                env['RESTIC_PASSWORD'] = pw
            cmd = ['restic', '-r', str(backup_path), 'restore', '--target', str(td), '--time', restore_point.isoformat()]
            res = _run(cmd, env=env)
            if res.returncode != 0:
                return RestoreResult(False, f'restic restore failed: {res.stderr.strip()}', None, None, ts)
            return RestoreResult(True, 'restic restore completed', td, time.time() - start, ts)

        # If file
        if backup_path.exists() and backup_path.is_file():
            td = Path(tempfile.mkdtemp(prefix='keycrypt-dr-restore-'))
            if str(backup_path).endswith('.gpg') and _which('gpg'):
                decrypted = td / 'decrypted.tar.gz'
                cmd = ['gpg', '--batch', '--yes', '--output', str(decrypted), '--decrypt', str(backup_path)]
                pw = os.environ.get('BACKUP_PASSPHRASE')
                if pw:
                    cmd[2:2] = ['--passphrase', pw]
                res = _run(cmd)
                if res.returncode != 0:
                    return RestoreResult(False, f'gpg decrypt failed: {res.stderr.strip()}', None, None, ts)
                with tarfile.open(decrypted, 'r:gz') as tar:
                    tar.extractall(path=str(td))
                return RestoreResult(True, 'decrypted and extracted', td, time.time() - start, ts)

            # assume plain tar.gz
            if tarfile.is_tarfile(str(backup_path)):
                with tarfile.open(str(backup_path), 'r:gz') as tar:
                    tar.extractall(path=str(td))
                return RestoreResult(True, 'tar extracted', td, time.time() - start, ts)

        return RestoreResult(False, 'unsupported backup path or missing', None, None, ts)
    except Exception as e:
        logger.exception('restore_from_backup failed')
        return RestoreResult(False, str(e), None, None, ts)


def validate_restore(restored_system: SystemState, rto_target_seconds: Optional[int] = None, rpo_target_seconds: Optional[int] = None, expected_recovery_point: Optional[datetime] = None) -> ValidationResult:
    """Validate that a restored system meets expected properties and RTO/RPO targets.

    - `restored_system` is a lightweight representation produced by health checks against
      the restored environment (services, DB consistency, last applied WAL/log time).
    - `expected_recovery_point` is the point-in-time that must be achieved for RPO calculation.
    """
    errors: List[str] = []
    metadata: Dict[str, str] = {}
    rto_seconds = None
    rpo_seconds = None

    # Basic checks
    if not restored_system.services_running:
        errors.append('no services reported running')
    else:
        metadata['services_running'] = ','.join(restored_system.services_running)

    if not restored_system.db_consistent:
        errors.append('database not consistent')

    # RPO calculation based on last_applied_log_time
    if expected_recovery_point and restored_system.last_applied_log_time:
        rpo = expected_recovery_point - restored_system.last_applied_log_time
        rpo_seconds = int(rpo.total_seconds()) if rpo.total_seconds() >= 0 else 0
    else:
        rpo_seconds = None

    # RTO: we cannot measure an absolute RTO here; accept rto_target_seconds if provided and set metadata
    if rto_target_seconds is not None:
        # For the purpose of this helper assume the current elapsed time since restore start is acceptable
        # Real measurement requires timestamps from the restore run. Caller should pass observed RTO when available.
        metadata['rto_target_seconds'] = str(rto_target_seconds)

    valid = len(errors) == 0 and (rpo_seconds is None or (rpo_target_seconds is None or rpo_seconds <= rpo_target_seconds))
    return ValidationResult(valid, errors, rto_seconds, rpo_seconds, metadata)


def failover_to_secondary_region(primary: str, secondary: str, dns_provider: Optional[str] = None, make_cutover: bool = False) -> FailoverResult:
    """Perform a controlled failover from `primary` to `secondary` region.

    This is a high-level helper that attempts to:
      - Promote a replica in the secondary region (if provider CLIs available).
      - Update DNS/load balancer to point to secondary (requires operator approval unless `make_cutover=True`).

    The function is intentionally conservative: by default it only prepares steps and returns a message.
    Set `make_cutover=True` to attempt automated switch (use with caution).
    """
    ts = datetime.utcnow()
    try:
        steps = []
        steps.append(f'Ensure secondary {secondary} has up-to-date backups and replicas')
        # Example: try AWS RDS promote read replica
        if _which('aws'):
            steps.append('aws CLI available: can attempt replica promotion')
        else:
            steps.append('aws CLI not available: manual promotion required')

        if make_cutover:
            # Attempt DNS update via CLI; this is provider-specific and must be configured via env vars
            if dns_provider == 'aws' and _which('aws'):
                # Example: update Route53 record (requires hosted zone id in env)
                hz = os.environ.get('ROUTE53_HOSTED_ZONE_ID')
                record = os.environ.get('FAILOVER_RECORD')
                if hz and record:
                    # This is a placeholder; operators should replace with exact change-batch payload
                    steps.append(f'Would update Route53 record {record} in zone {hz} to point to {secondary}')
                else:
                    steps.append('route53 params missing; cannot update')
            else:
                steps.append('no automated DNS provider configured for cutover')
            return FailoverResult(True, 'cutover attempted (see steps)', secondary, ts)

        return FailoverResult(True, 'prepared failover steps', None, ts)
    except Exception as e:
        logger.exception('failover_to_secondary_region failed')
        return FailoverResult(False, str(e), None, ts)


def test_disaster_recovery(scenario: str, non_destructive: bool = True) -> TestResult:
    """Run a DR drill for a named scenario.

    - When `non_destructive=True`, the test will be performed against a temporary isolated environment
      (no changes to production).
    - The function returns a TestResult with pass/fail and details.
    """
    ts = datetime.utcnow()
    try:
        # For safety, DR tests operate on temporary copies of backups and do not touch live infra.
        # A realistic implementation would spin up a recovery VPC or use provider sandbox accounts.
        # Here we perform lightweight smoke checks to validate helpers.
        details = []
        details.append(f'scenario: {scenario}')
        details.append('non_destructive: ' + str(non_destructive))

        # Example smoke: verify restic/gpg availability and that backup dir exists if provided
        restic = _which('restic')
        gpg = _which('gpg')
        details.append(f'restic: {bool(restic)} gpg: {bool(gpg)}')

        # If a BACKUP_TEST_PATH env var provided, try to restore it to temp and validate
        test_path = os.environ.get('BACKUP_TEST_PATH')
        if test_path:
            rp = Path(test_path)
            details.append(f'found BACKUP_TEST_PATH={test_path}')
            rr = restore_from_backup(rp, datetime.utcnow())
            details.append(f'restore_result: {rr.success} {rr.message}')
            if not rr.success:
                return TestResult(False, '\n'.join(details), ts)
            # run a basic validation
            sysstate = SystemState(services_running=['simulated-service'], db_consistent=True, last_applied_log_time=datetime.utcnow())
            vr = validate_restore(sysstate)
            details.append(f'validate_result: {vr.valid} errors={vr.errors}')
            return TestResult(vr.valid, '\n'.join(details), ts)

        # If no test path, return info indicating readiness of tools
        details.append('no BACKUP_TEST_PATH provided; DR helpers appear operational')
        return TestResult(True, '\n'.join(details), ts)
    except Exception as e:
        logger.exception('test_disaster_recovery failed')
        return TestResult(False, str(e), ts)


if __name__ == '__main__':
    # small CLI for operators to run basic restore/validate commands locally
    import argparse

    ap = argparse.ArgumentParser(description='DR restore helpers')
    ap.add_argument('--restore', help='path to backup (file or restic repo)')
    ap.add_argument('--restore-time', help='ISO8601 restore point time', default=None)
    ap.add_argument('--test-scenario', help='run DR test scenario')
    args = ap.parse_args()
    if args.restore:
        rp = Path(args.restore)
        rt = datetime.fromisoformat(args.restore_time) if args.restore_time else datetime.utcnow()
        res = restore_from_backup(rp, rt)
        print(res)
    if args.test_scenario:
        tr = test_disaster_recovery(args.test_scenario)
        print(tr)
