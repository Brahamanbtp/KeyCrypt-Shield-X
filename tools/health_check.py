"""Comprehensive health check utilities for system diagnostics.

Provides checks for crypto providers, storage backends, key sources,
monitoring systems and dependencies. Offers a report generator and
an optional self-healing restart mechanism for known services.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Optional

try:
    import tomllib
except Exception:
    tomllib = None

try:
    import importlib.metadata as importlib_metadata
except Exception:
    importlib_metadata = None

try:
    import requests
except Exception:
    requests = None

import socket


@dataclass
class ProviderHealth:
    name: str
    healthy: bool
    details: str = ""
    action_taken: Optional[str] = None


@dataclass
class StorageHealth:
    name: str
    healthy: bool
    details: str = ""
    action_taken: Optional[str] = None


@dataclass
class KeySourceHealth:
    name: str
    healthy: bool
    details: str = ""
    action_taken: Optional[str] = None


@dataclass
class MonitoringHealth:
    name: str
    healthy: bool
    details: str = ""
    action_taken: Optional[str] = None


@dataclass
class DependencyHealth:
    package: str
    required: Optional[str]
    installed: Optional[str]
    healthy: bool
    details: str = ""


def _run_cmd(cmd: List[str], timeout: int = 10) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, text=True)
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except Exception as exc:
        return 255, "", str(exc)


def check_crypto_providers() -> List[ProviderHealth]:
    results: List[ProviderHealth] = []

    # Check for Python cryptography library
    try:
        import cryptography  # type: ignore

        h = ProviderHealth(name="cryptography", healthy=True, details=f"version={cryptography.__version__}")
    except Exception as exc:
        h = ProviderHealth(name="cryptography", healthy=False, details=str(exc))
    results.append(h)

    # Check for local provider modules under src/providers
    providers_dir = Path("src") / "providers"
    if providers_dir.exists() and providers_dir.is_dir():
        for child in sorted(providers_dir.iterdir()):
            if not child.is_dir():
                continue
            name = child.name
            try:
                # try import by module path if available
                mod_name = f"providers.{name}"
                __import__(mod_name)
                results.append(ProviderHealth(name=name, healthy=True, details="import OK"))
            except Exception:
                results.append(ProviderHealth(name=name, healthy=False, details="module present but import failed"))
    else:
        results.append(ProviderHealth(name="local_providers", healthy=False, details=str(providers_dir)))

    return results


def check_storage_backends() -> List[StorageHealth]:
    results: List[StorageHealth] = []

    # Local filesystem (key store)
    keys_dir = Path.home() / ".keycrypt" / "keys"
    try:
        keys_dir.mkdir(parents=True, exist_ok=True)
        test_file = keys_dir / ".hc_test"
        test_file.write_text("ok", encoding="utf-8")
        test_file.unlink(missing_ok=True)
        results.append(StorageHealth(name="local_filesystem", healthy=True, details=str(keys_dir)))
    except Exception as exc:
        results.append(StorageHealth(name="local_filesystem", healthy=False, details=str(exc)))

    # S3 (boto3)
    try:
        import boto3  # type: ignore

        try:
            client = boto3.client("s3")
            # avoid listing buckets if credentials missing; do quick call to get region instead
            client.list_buckets()
            results.append(StorageHealth(name="s3", healthy=True, details="list_buckets OK"))
        except Exception as exc:
            results.append(StorageHealth(name="s3", healthy=False, details=str(exc)))
    except Exception:
        results.append(StorageHealth(name="s3", healthy=False, details="boto3 not installed"))

    # Generic SQL driver presence check (psycopg2 / sqlite3)
    try:
        import sqlite3  # type: ignore

        results.append(StorageHealth(name="sqlite3", healthy=True, details=sqlite3.sqlite_version))
    except Exception as exc:
        results.append(StorageHealth(name="sqlite3", healthy=False, details=str(exc)))

    try:
        import psycopg2  # type: ignore

        results.append(StorageHealth(name="postgres_driver", healthy=True, details="psycopg2 present"))
    except Exception:
        results.append(StorageHealth(name="postgres_driver", healthy=False, details="psycopg2 not installed"))

    return results


def check_key_sources() -> List[KeySourceHealth]:
    results: List[KeySourceHealth] = []

    # AWS KMS
    try:
        import boto3  # type: ignore

        try:
            kms = boto3.client("kms")
            kms.list_keys(Limit=1)
            results.append(KeySourceHealth(name="aws_kms", healthy=True, details="list_keys OK"))
        except Exception as exc:
            results.append(KeySourceHealth(name="aws_kms", healthy=False, details=str(exc)))
    except Exception:
        results.append(KeySourceHealth(name="aws_kms", healthy=False, details="boto3 not installed"))

    # HSM: check for PKCS#11 Python bindings
    try:
        import pkcs11  # type: ignore

        results.append(KeySourceHealth(name="pkcs11_hsm", healthy=True, details="pkcs11 bindings present"))
    except Exception:
        results.append(KeySourceHealth(name="pkcs11_hsm", healthy=False, details="pkcs11 bindings not installed"))

    return results


def _http_check(url: str, timeout: int = 5) -> tuple[bool, str]:
    if requests is None:
        # fallback to socket-level check
        try:
            host = url.split("//")[-1].split(":")[0]
            port = int(url.split(":")[-1]) if ":" in url.split("//")[-1] else 80
            with socket.create_connection((host, port), timeout=timeout):
                return True, f"tcp {host}:{port} reachable"
        except Exception as exc:
            return False, str(exc)

    try:
        r = requests.get(url, timeout=timeout)
        if r.status_code < 400:
            return True, f"HTTP {r.status_code}"
        return False, f"HTTP {r.status_code}"
    except Exception as exc:
        return False, str(exc)


def check_monitoring_systems() -> List[MonitoringHealth]:
    results: List[MonitoringHealth] = []

    # Prometheus
    ok, details = _http_check("http://127.0.0.1:9090/-/ready")
    results.append(MonitoringHealth(name="prometheus", healthy=ok, details=details))

    # Grafana
    ok, details = _http_check("http://127.0.0.1:3000/api/health")
    results.append(MonitoringHealth(name="grafana", healthy=ok, details=details))

    # Logging (journald) presence
    code, out, err = _run_cmd(["which", "journalctl"], timeout=3)
    results.append(MonitoringHealth(name="journald", healthy=(code == 0), details=out or err))

    return results


def check_dependencies() -> List[DependencyHealth]:
    results: List[DependencyHealth] = []

    project_requires = {}
    pyproject = Path("pyproject.toml")
    if pyproject.exists() and tomllib is not None:
        try:
            with pyproject.open("rb") as fh:
                data = tomllib.load(fh)
            # Try poetry first
            poetry = data.get("tool", {}).get("poetry")
            if poetry and isinstance(poetry.get("dependencies"), dict):
                project_requires = poetry.get("dependencies", {})
            else:
                # PEP 621 [project]
                project_requires = data.get("project", {}).get("dependencies", [])
        except Exception:
            project_requires = {}

    # If we have a dict of dependencies (poetry), iterate keys; otherwise skip detailed checks
    if isinstance(project_requires, dict):
        for pkg, spec in project_requires.items():
            if pkg.lower() == "python":
                continue
            installed = None
            healthy = False
            details = ""
            if importlib_metadata is not None:
                try:
                    installed = importlib_metadata.version(pkg)
                    healthy = True
                except Exception as exc:
                    details = str(exc)
            results.append(DependencyHealth(package=pkg, required=str(spec), installed=installed, healthy=healthy, details=details))
    else:
        # Fallback: report a few core packages
        core_pkgs = ["click", "cryptography", "boto3", "requests"]
        for pkg in core_pkgs:
            installed = None
            healthy = False
            details = ""
            if importlib_metadata is not None:
                try:
                    installed = importlib_metadata.version(pkg)
                    healthy = True
                except Exception as exc:
                    details = str(exc)
            results.append(DependencyHealth(package=pkg, required=None, installed=installed, healthy=healthy, details=details))

    return results


def _attempt_restart(service_name: str) -> tuple[bool, str]:
    # Try systemctl
    if shutil.which("systemctl"):
        # map common service names
        mapping = {
            "prometheus": "prometheus",
            "grafana": "grafana-server",
            "journald": "systemd-journald",
        }
        svc = mapping.get(service_name)
        if svc:
            code, out, err = _run_cmd(["systemctl", "restart", svc], timeout=20)
            if code == 0:
                # give it a moment and check status
                time.sleep(2)
                code2, out2, err2 = _run_cmd(["systemctl", "is-active", svc], timeout=5)
                healthy = (code2 == 0 and out2.strip() == "active")
                return healthy, out2 or err2
            return False, err or out

    # Try docker
    if shutil.which("docker"):
        # try to find a container with service_name in its name
        code, out, err = _run_cmd(["docker", "ps", "--format", "{{.ID}} {{.Names}}"], timeout=10)
        if code == 0 and out:
            for line in out.splitlines():
                cid, name = line.split(maxsplit=1)
                if service_name in name:
                    ccode, cout, cerr = _run_cmd(["docker", "restart", cid], timeout=20)
                    return (ccode == 0), cout or cerr

    return False, "no-restart-mechanism"


def generate_report(report_path: Optional[Path] = None, auto_restart: bool = False) -> dict:
    report = {
        "crypto_providers": [asdict(x) for x in check_crypto_providers()],
        "storage_backends": [asdict(x) for x in check_storage_backends()],
        "key_sources": [asdict(x) for x in check_key_sources()],
        "monitoring": [asdict(x) for x in check_monitoring_systems()],
        "dependencies": [asdict(x) for x in check_dependencies()],
    }

    # self-heal attempts
    if auto_restart:
        actions = []
        for m in report["monitoring"]:
            if not m["healthy"]:
                ok, details = _attempt_restart(m["name"])
                actions.append({"name": m["name"], "restarted": ok, "details": details})
        report["auto_restart"] = actions

    if report_path:
        try:
            Path(report_path).write_text(json.dumps(report, indent=2), encoding="utf-8")
        except Exception:
            pass

    return report


if __name__ == "__main__":
    # Simple CLI runner
    import argparse

    parser = argparse.ArgumentParser(description="Run health checks and output JSON report")
    parser.add_argument("--report", "-o", help="Path to write JSON report", default=None)
    parser.add_argument("--auto-restart", action="store_true", help="Attempt auto-restart for failed components")
    args = parser.parse_args()
    rpt = generate_report(report_path=Path(args.report) if args.report else None, auto_restart=args.auto_restart)
    print(json.dumps(rpt, indent=2))
