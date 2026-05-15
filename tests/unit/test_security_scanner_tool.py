"""Unit tests for tools/security_scanner.py."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def _load_security_scanner_module():
    module_path = Path(__file__).resolve().parents[2] / "tools/security_scanner.py"
    spec = importlib.util.spec_from_file_location("security_scanner_tool", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load security_scanner module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_scan_for_hardcoded_secrets_detects_realistic_values(tmp_path: Path) -> None:
    module = _load_security_scanner_module()
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "app.py").write_text(
        'api_key = "AKIA1234567890ABCDEF"\npassword = "example123"\n',
        encoding="utf-8",
    )

    findings = module.scan_for_hardcoded_secrets(source_dir)

    assert findings
    assert any(item.secret_type == "aws_access_key" for item in findings)
    assert any(item.cvss_score >= 8.0 for item in findings)


def test_scan_for_sql_injection_and_command_injection(tmp_path: Path) -> None:
    module = _load_security_scanner_module()
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "app.py").write_text(
        """
import os
import subprocess


def run(user_query, user_command):
    cursor.execute(f\"SELECT * FROM users WHERE name = '{user_query}'\")
    os.system(user_command)
    subprocess.run(user_command, shell=True)
""",
        encoding="utf-8",
    )

    sql_findings = module.scan_for_sql_injection(source_dir)
    command_findings = module.scan_for_command_injection(source_dir)

    assert sql_findings
    assert any(item.cvss_score >= 8.0 for item in sql_findings)
    assert command_findings
    assert any(item.cvss_score >= 8.0 for item in command_findings)


def test_scan_dependencies_for_cves_uses_nvd_payload(tmp_path: Path, monkeypatch) -> None:
    module = _load_security_scanner_module()
    requirements_file = tmp_path / "requirements.txt"
    requirements_file.write_text("samplepkg==1.0.0\n", encoding="utf-8")

    def fake_fetch_nvd_json(package: str, version: str):
        assert package == "samplepkg"
        assert version == "1.0.0"
        return {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2026-1234",
                        "descriptions": [
                            {
                                "lang": "en",
                                "value": "samplepkg 1.0.0 allows remote code execution.",
                            }
                        ],
                        "references": [{"url": "https://example.invalid/cve-2026-1234"}],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 9.8,
                                        "baseSeverity": "CRITICAL",
                                    }
                                }
                            ]
                        },
                        "published": "2026-01-01T00:00:00.000",
                    }
                }
            ]
        }

    monkeypatch.setattr(module, "_fetch_nvd_json", fake_fetch_nvd_json)
    monkeypatch.setattr(module, "_run_safety_payload", lambda requirements: None)

    findings = module.scan_dependencies_for_cves(requirements_file)

    assert len(findings) == 1
    assert findings[0].cve_id == "CVE-2026-1234"
    assert findings[0].cvss_score == 9.8
    assert findings[0].severity == "critical"


def test_generate_security_audit_report_summarizes_findings(tmp_path: Path, monkeypatch) -> None:
    module = _load_security_scanner_module()
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    requirements_file = tmp_path / "requirements.txt"
    requirements_file.write_text("samplepkg==1.0.0\n", encoding="utf-8")

    monkeypatch.setattr(
        module,
        "scan_for_hardcoded_secrets",
        lambda source: [
            module.SecretLeak(
                file_path=source / "config.py",
                line_no=1,
                secret_type="github_token",
                matched_text="ghp_123",
                severity="critical",
                cvss_score=9.0,
                redaction_suggestion="Replace literal with [REDACTED]",
                remediation="Rotate secret",
            )
        ],
    )
    monkeypatch.setattr(
        module,
        "scan_for_sql_injection",
        lambda source: [
            module.SQLInjection(
                file_path=source / "db.py",
                line_no=2,
                snippet="cursor.execute(f'select ...')",
                reason="SQL query built with f-string",
                severity="high",
                cvss_score=8.9,
                remediation="Use parameterized queries",
            )
        ],
    )
    monkeypatch.setattr(
        module,
        "scan_for_command_injection",
        lambda source: [
            module.CommandInjection(
                file_path=source / "shell.py",
                line_no=3,
                snippet="os.system(user_input)",
                reason="Dynamic shell command construction",
                severity="high",
                cvss_score=9.0,
                remediation="Avoid shell execution",
            )
        ],
    )
    monkeypatch.setattr(
        module,
        "scan_dependencies_for_cves",
        lambda requirements: [
            module.CVE(
                package="samplepkg",
                installed_version="1.0.0",
                cve_id="CVE-2026-9999",
                description="Known issue",
                cvss_score=7.5,
                severity="high",
                published="2026-01-01T00:00:00.000",
                references=("https://example.invalid/cve",),
                remediation="Upgrade package",
            )
        ],
    )

    report = module.generate_security_audit_report(source_dir, requirements_file)

    assert report.startswith("# Security Audit Report")
    assert "Hardcoded secrets: 1" in report
    assert "SQL injection findings: 1" in report
    assert "Command injection findings: 1" in report
    assert "Dependency CVEs: 1" in report
    assert "Critical findings: 1" in report
    assert "CVE-2026-9999" in report
