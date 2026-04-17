#!/usr/bin/env python3
"""Security vulnerability scanner for source code and dependencies.

Capabilities:
- hardcoded secret detection using regex patterns
- SQL injection detection using AST heuristics and Bandit integration
- command injection detection using AST heuristics and Bandit integration
- dependency CVE lookup using the NIST NVD API
"""

from __future__ import annotations

import ast
import importlib.util
import json
import os
import re
import subprocess
import sys
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, List, Mapping


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

_BANDIT_ISSUE_CACHE: dict[Path, tuple["_BanditIssue", ...]] = {}

_SECRET_FILE_SUFFIXES = {
    ".py",
    ".env",
    ".ini",
    ".cfg",
    ".conf",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".txt",
    ".md",
}

_PLACEHOLDER_SECRET_VALUES = {
    "changeme",
    "change-me",
    "example",
    "example123",
    "dummy",
    "test",
    "password",
    "secret",
    "token",
    "your_api_key",
    "your-token",
    "replace_me",
}

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str], str, float], ...] = (
    (
        "aws_access_key",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "high",
        8.2,
    ),
    (
        "private_key_block",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)?PRIVATE KEY-----"),
        "critical",
        9.8,
    ),
    (
        "github_token",
        re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
        "critical",
        9.0,
    ),
    (
        "stripe_live_key",
        re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"),
        "critical",
        9.0,
    ),
    (
        "hardcoded_credential",
        re.compile(
            r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|token|private[_-]?key)\b"
            r"\s*[:=]\s*['\"][^'\"\n]{8,}['\"]"
        ),
        "high",
        7.5,
    ),
)

_BANDIT_SECRET_IDS = {"B105", "B106", "B107"}
_BANDIT_SQL_IDS = {"B608"}
_BANDIT_COMMAND_IDS = {"B602", "B603", "B604", "B605", "B606", "B607", "B609"}


@dataclass(frozen=True)
class SecretLeak:
    """Hardcoded secret finding."""

    file_path: Path
    line_no: int
    secret_type: str
    matched_text: str
    severity: str
    cvss_score: float
    source: str = "regex"


@dataclass(frozen=True)
class SQLInjection:
    """Potential SQL injection finding."""

    file_path: Path
    line_no: int
    snippet: str
    reason: str
    severity: str
    cvss_score: float
    source: str = "ast"


@dataclass(frozen=True)
class CommandInjection:
    """Potential command injection finding."""

    file_path: Path
    line_no: int
    snippet: str
    reason: str
    severity: str
    cvss_score: float
    source: str = "ast"


@dataclass(frozen=True)
class CVE:
    """Dependency CVE finding from NVD."""

    package: str
    installed_version: str
    cve_id: str
    description: str
    cvss_score: float
    severity: str
    published: str
    references: tuple[str, ...]


@dataclass(frozen=True)
class _BanditIssue:
    file_path: Path
    line_no: int
    test_id: str
    issue_text: str
    severity: str
    code: str


def _iter_source_files(source_dir: Path, *, suffixes: set[str]) -> list[Path]:
    if not source_dir.exists() or not source_dir.is_dir():
        raise FileNotFoundError(f"source_dir must be an existing directory: {source_dir}")

    return sorted(
        path
        for path in source_dir.rglob("*")
        if path.is_file() and path.suffix.lower() in suffixes
    )


def _iter_python_files(source_dir: Path) -> list[Path]:
    return _iter_source_files(source_dir, suffixes={".py"})


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _keyword_bool(node: ast.Call, key: str) -> bool:
    for keyword in node.keywords:
        if keyword.arg != key:
            continue
        if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, bool):
            return bool(keyword.value.value)
    return False


def _line_snippet(source_lines: list[str], line_no: int) -> str:
    if 1 <= line_no <= len(source_lines):
        return source_lines[line_no - 1].strip()
    return ""


def _severity_to_cvss(severity: str) -> float:
    mapping = {
        "critical": 9.8,
        "high": 8.8,
        "medium": 6.4,
        "low": 3.1,
        "unknown": 0.0,
    }
    return mapping.get(severity.lower(), 0.0)


def _normalize_severity(severity: str) -> str:
    value = severity.strip().lower()
    if value in {"critical", "high", "medium", "low"}:
        return value
    return "unknown"


def _quoted_value(text: str) -> str | None:
    match = re.search(r"['\"]([^'\"]+)['\"]", text)
    if match is None:
        return None
    return match.group(1)


def _canonicalize_package_name(value: str) -> str:
    return re.sub(r"-+", "-", value.strip().lower().replace("_", "-"))


def _parse_requirements(requirements_file: Path) -> list[tuple[str, str]]:
    if not requirements_file.exists() or not requirements_file.is_file():
        raise FileNotFoundError(f"requirements file not found: {requirements_file}")

    dependencies: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for raw_line in requirements_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-r", "--requirement", "-c", "--constraint")):
            continue

        no_comment = line.split("#", 1)[0].strip()
        if not no_comment:
            continue

        if "#egg=" in no_comment:
            name = _canonicalize_package_name(no_comment.split("#egg=", 1)[1].strip())
            item = (name, "")
            if item not in seen:
                dependencies.append(item)
                seen.add(item)
            continue

        spec = no_comment.split(";", 1)[0].strip()
        if " @ " in spec:
            spec = spec.split(" @ ", 1)[0].strip()

        if "[" in spec:
            spec = spec.split("[", 1)[0].strip()

        if "==" in spec:
            name, version = spec.split("==", 1)
        else:
            parts = re.split(r"[<>=!~\s]", spec, maxsplit=1)
            name = parts[0]
            version = ""

        normalized_name = _canonicalize_package_name(name)
        item = (normalized_name, version.strip())
        if normalized_name and item not in seen:
            dependencies.append(item)
            seen.add(item)

    return dependencies


def _parse_bandit_issues(payload: Any) -> tuple[_BanditIssue, ...]:
    if not isinstance(payload, dict):
        return tuple()

    raw_issues = payload.get("results")
    if not isinstance(raw_issues, list):
        return tuple()

    issues: list[_BanditIssue] = []
    for item in raw_issues:
        if not isinstance(item, dict):
            continue

        file_name = item.get("filename")
        line_no = item.get("line_number")
        test_id = str(item.get("test_id") or "")
        if not isinstance(file_name, str) or not file_name.strip() or not isinstance(line_no, int):
            continue

        issues.append(
            _BanditIssue(
                file_path=Path(file_name).expanduser().resolve(),
                line_no=int(line_no),
                test_id=test_id,
                issue_text=str(item.get("issue_text") or "Bandit issue"),
                severity=_normalize_severity(str(item.get("issue_severity") or "unknown")),
                code=str(item.get("code") or "").strip(),
            )
        )

    return tuple(issues)


def _extract_json_text(raw: str) -> Any | None:
    text = raw.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    for opener, closer in (("{", "}"), ("[", "]")):
        start = text.find(opener)
        end = text.rfind(closer)
        if start == -1 or end == -1 or start >= end:
            continue
        fragment = text[start : end + 1]
        try:
            return json.loads(fragment)
        except json.JSONDecodeError:
            continue

    return None


def _get_bandit_issues(source_dir: Path) -> tuple[_BanditIssue, ...]:
    resolved = Path(source_dir).expanduser().resolve()
    if resolved in _BANDIT_ISSUE_CACHE:
        return _BANDIT_ISSUE_CACHE[resolved]

    if importlib.util.find_spec("bandit") is None:
        _BANDIT_ISSUE_CACHE[resolved] = tuple()
        return tuple()

    command = [sys.executable, "-m", "bandit", "-r", str(resolved), "-f", "json", "-q"]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    payload = _extract_json_text((completed.stdout or "") + "\n" + (completed.stderr or ""))
    issues = _parse_bandit_issues(payload)
    _BANDIT_ISSUE_CACHE[resolved] = issues
    return issues


def _is_dynamic_expr(node: ast.AST | None) -> bool:
    if node is None:
        return False
    if isinstance(node, ast.Constant):
        return not isinstance(node.value, str)
    if isinstance(node, ast.List | ast.Tuple):
        return any(_is_dynamic_expr(item) for item in node.elts)
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            return True
        return True
    if isinstance(node, ast.Name | ast.Attribute | ast.Subscript):
        return True
    return False


def _sql_expr_risk(expr: ast.AST, *, has_parameters: bool) -> tuple[str, float, str] | None:
    if isinstance(expr, ast.JoinedStr):
        return "high", 9.1, "SQL query built with f-string"
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        return "high", 8.9, "SQL query built with string concatenation"
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Mod):
        return "high", 8.7, "SQL query built with %-formatting"
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr == "format":
        return "high", 8.6, "SQL query built with .format()"
    if isinstance(expr, ast.Name) and not has_parameters:
        return "medium", 6.8, "Variable SQL query passed without explicit parameter tuple"
    if _is_dynamic_expr(expr) and not has_parameters:
        return "medium", 6.5, "Dynamic SQL query argument"
    return None


def _command_expr_risk(expr: ast.AST | None) -> tuple[str, float, str]:
    if _is_dynamic_expr(expr):
        return "high", 9.0, "Dynamic shell command construction"
    return "medium", 6.5, "Shell command execution"


def _extract_cvss(cve_payload: Mapping[str, Any]) -> tuple[float, str]:
    metrics = cve_payload.get("metrics")
    if not isinstance(metrics, Mapping):
        return 0.0, "unknown"

    best_score = 0.0
    best_severity = "unknown"

    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key)
        if not isinstance(values, list):
            continue

        for item in values:
            if not isinstance(item, Mapping):
                continue
            cvss_data = item.get("cvssData")
            if not isinstance(cvss_data, Mapping):
                continue

            score_raw = cvss_data.get("baseScore")
            try:
                score = float(score_raw)
            except (TypeError, ValueError):
                continue

            severity = str(cvss_data.get("baseSeverity") or item.get("baseSeverity") or "unknown")
            if score >= best_score:
                best_score = score
                best_severity = _normalize_severity(severity)

    return best_score, best_severity


def _likely_nvd_match(package: str, version: str, description: str, references: Iterable[str]) -> bool:
    package_key = package.lower()
    blob = " ".join([description.lower(), *(item.lower() for item in references)])

    candidates = {
        package_key,
        package_key.replace("-", "_"),
        package_key.replace("-", " "),
        package_key.replace("-", ""),
    }

    if any(candidate and candidate in blob for candidate in candidates):
        return True
    if version and version in blob:
        return True
    return False


def _fetch_nvd_json(package: str, version: str) -> dict[str, Any] | None:
    keyword = f"{package} {version}".strip()
    query = urllib.parse.urlencode(
        {
            "keywordSearch": keyword,
            "resultsPerPage": 40,
        }
    )
    url = f"{NVD_API_URL}?{query}"

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "KeyCrypt-SecurityScanner/1.0",
            "Accept": "application/json",
        },
    )

    nvd_key = os.getenv("NVD_API_KEY", "").strip()
    if nvd_key:
        request.add_header("apiKey", nvd_key)

    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            payload = response.read().decode("utf-8", errors="ignore")
    except Exception:
        return None

    try:
        parsed = json.loads(payload)
    except json.JSONDecodeError:
        return None

    if not isinstance(parsed, dict):
        return None
    return parsed


def _parse_nvd_payload(package: str, version: str, payload: Mapping[str, Any]) -> list[CVE]:
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        return []

    findings: list[CVE] = []
    for item in vulnerabilities:
        if not isinstance(item, Mapping):
            continue
        cve = item.get("cve")
        if not isinstance(cve, Mapping):
            continue

        cve_id = str(cve.get("id") or "")
        descriptions = cve.get("descriptions")
        description = ""
        if isinstance(descriptions, list):
            for desc_item in descriptions:
                if not isinstance(desc_item, Mapping):
                    continue
                if str(desc_item.get("lang") or "").lower() != "en":
                    continue
                description = str(desc_item.get("value") or "")
                if description:
                    break
        if not description:
            description = "No description available"

        reference_urls: list[str] = []
        references = cve.get("references")
        if isinstance(references, list):
            for reference in references:
                if isinstance(reference, Mapping) and isinstance(reference.get("url"), str):
                    reference_urls.append(str(reference["url"]))

        if not _likely_nvd_match(package, version, description, reference_urls):
            continue

        cvss_score, severity = _extract_cvss(cve)
        published = str(cve.get("published") or "")

        findings.append(
            CVE(
                package=package,
                installed_version=version,
                cve_id=cve_id or "UNKNOWN-CVE",
                description=description,
                cvss_score=cvss_score,
                severity=severity,
                published=published,
                references=tuple(reference_urls),
            )
        )

    findings.sort(key=lambda item: (item.cvss_score, item.cve_id), reverse=True)
    return findings


def scan_for_hardcoded_secrets(source_dir: Path) -> List[SecretLeak]:
    """Detect potential hardcoded secrets in source files via regex and Bandit."""
    resolved_source = Path(source_dir).expanduser().resolve()
    findings: list[SecretLeak] = []

    for file_path in _iter_source_files(resolved_source, suffixes=_SECRET_FILE_SUFFIXES):
        lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        for line_no, line in enumerate(lines, start=1):
            for secret_type, pattern, severity, score in _SECRET_PATTERNS:
                for match in pattern.finditer(line):
                    matched_text = match.group(0).strip()
                    if secret_type == "hardcoded_credential":
                        candidate = _quoted_value(matched_text)
                        if candidate and candidate.strip().lower() in _PLACEHOLDER_SECRET_VALUES:
                            continue

                    findings.append(
                        SecretLeak(
                            file_path=file_path,
                            line_no=line_no,
                            secret_type=secret_type,
                            matched_text=matched_text,
                            severity=severity,
                            cvss_score=float(score),
                            source="regex",
                        )
                    )

    for issue in _get_bandit_issues(resolved_source):
        if issue.test_id not in _BANDIT_SECRET_IDS:
            continue
        findings.append(
            SecretLeak(
                file_path=issue.file_path,
                line_no=issue.line_no,
                secret_type=f"bandit_{issue.test_id.lower()}",
                matched_text=issue.issue_text,
                severity=issue.severity,
                cvss_score=_severity_to_cvss(issue.severity),
                source="bandit",
            )
        )

    deduped: dict[tuple[Path, int, str, str], SecretLeak] = {}
    for item in findings:
        key = (item.file_path, item.line_no, item.secret_type, item.source)
        if key not in deduped or item.cvss_score > deduped[key].cvss_score:
            deduped[key] = item

    ordered = sorted(
        deduped.values(),
        key=lambda item: (item.cvss_score, str(item.file_path), item.line_no),
        reverse=True,
    )
    return ordered


def scan_for_sql_injection(source_dir: Path) -> List[SQLInjection]:
    """Detect potential SQL injection vulnerabilities using AST + Bandit."""
    resolved_source = Path(source_dir).expanduser().resolve()
    findings: list[SQLInjection] = []

    for file_path in _iter_python_files(resolved_source):
        source = file_path.read_text(encoding="utf-8", errors="ignore")
        source_lines = source.splitlines()
        try:
            tree = ast.parse(source, filename=str(file_path))
        except SyntaxError:
            continue

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            call_name = _call_name(node.func).lower()
            if not (call_name.endswith("execute") or call_name.endswith("executemany")):
                continue
            if not node.args:
                continue

            has_parameters = len(node.args) > 1 or bool(node.keywords)
            risk = _sql_expr_risk(node.args[0], has_parameters=has_parameters)
            if risk is None:
                continue

            severity, score, reason = risk
            findings.append(
                SQLInjection(
                    file_path=file_path,
                    line_no=int(getattr(node, "lineno", 0)),
                    snippet=_line_snippet(source_lines, int(getattr(node, "lineno", 0))),
                    reason=reason,
                    severity=severity,
                    cvss_score=float(score),
                    source="ast",
                )
            )

    for issue in _get_bandit_issues(resolved_source):
        if issue.test_id not in _BANDIT_SQL_IDS:
            continue
        findings.append(
            SQLInjection(
                file_path=issue.file_path,
                line_no=issue.line_no,
                snippet=issue.code or issue.issue_text,
                reason=issue.issue_text,
                severity=issue.severity,
                cvss_score=_severity_to_cvss(issue.severity),
                source="bandit",
            )
        )

    deduped: dict[tuple[Path, int, str], SQLInjection] = {}
    for item in findings:
        key = (item.file_path, item.line_no, item.source)
        if key not in deduped or item.cvss_score > deduped[key].cvss_score:
            deduped[key] = item

    ordered = sorted(
        deduped.values(),
        key=lambda item: (item.cvss_score, str(item.file_path), item.line_no),
        reverse=True,
    )
    return ordered


def scan_for_command_injection(source_dir: Path) -> List[CommandInjection]:
    """Detect potential command injection vulnerabilities using AST + Bandit."""
    resolved_source = Path(source_dir).expanduser().resolve()
    findings: list[CommandInjection] = []

    shell_calls = {
        "os.system",
        "os.popen",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
    }
    subprocess_calls = {
        "subprocess.run",
        "subprocess.call",
        "subprocess.popen",
        "subprocess.check_call",
        "subprocess.check_output",
    }

    for file_path in _iter_python_files(resolved_source):
        source = file_path.read_text(encoding="utf-8", errors="ignore")
        source_lines = source.splitlines()
        try:
            tree = ast.parse(source, filename=str(file_path))
        except SyntaxError:
            continue

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            call_name = _call_name(node.func).lower()
            first_arg = node.args[0] if node.args else None

            if call_name in shell_calls:
                severity, score, reason = _command_expr_risk(first_arg)
                findings.append(
                    CommandInjection(
                        file_path=file_path,
                        line_no=int(getattr(node, "lineno", 0)),
                        snippet=_line_snippet(source_lines, int(getattr(node, "lineno", 0))),
                        reason=reason,
                        severity=severity,
                        cvss_score=float(score),
                        source="ast",
                    )
                )
                continue

            if call_name in subprocess_calls:
                shell_true = _keyword_bool(node, "shell")
                if shell_true:
                    dynamic = _is_dynamic_expr(first_arg)
                    severity = "high"
                    score = 9.8 if dynamic else 8.3
                    reason = (
                        "subprocess call uses shell=True with dynamic command"
                        if dynamic
                        else "subprocess call uses shell=True"
                    )
                    findings.append(
                        CommandInjection(
                            file_path=file_path,
                            line_no=int(getattr(node, "lineno", 0)),
                            snippet=_line_snippet(source_lines, int(getattr(node, "lineno", 0))),
                            reason=reason,
                            severity=severity,
                            cvss_score=float(score),
                            source="ast",
                        )
                    )
                elif _is_dynamic_expr(first_arg):
                    findings.append(
                        CommandInjection(
                            file_path=file_path,
                            line_no=int(getattr(node, "lineno", 0)),
                            snippet=_line_snippet(source_lines, int(getattr(node, "lineno", 0))),
                            reason="subprocess call receives dynamic command argument",
                            severity="medium",
                            cvss_score=6.2,
                            source="ast",
                        )
                    )

    for issue in _get_bandit_issues(resolved_source):
        if issue.test_id not in _BANDIT_COMMAND_IDS:
            continue
        findings.append(
            CommandInjection(
                file_path=issue.file_path,
                line_no=issue.line_no,
                snippet=issue.code or issue.issue_text,
                reason=issue.issue_text,
                severity=issue.severity,
                cvss_score=_severity_to_cvss(issue.severity),
                source="bandit",
            )
        )

    deduped: dict[tuple[Path, int, str], CommandInjection] = {}
    for item in findings:
        key = (item.file_path, item.line_no, item.source)
        if key not in deduped or item.cvss_score > deduped[key].cvss_score:
            deduped[key] = item

    ordered = sorted(
        deduped.values(),
        key=lambda item: (item.cvss_score, str(item.file_path), item.line_no),
        reverse=True,
    )
    return ordered


def scan_dependencies_for_cves(requirements_file: Path) -> List[CVE]:
    """Scan requirements for known CVEs using the NIST NVD API."""
    dependencies = _parse_requirements(Path(requirements_file).expanduser().resolve())

    findings: list[CVE] = []
    for package, version in dependencies:
        payload = _fetch_nvd_json(package, version)
        if payload is None:
            continue
        findings.extend(_parse_nvd_payload(package, version, payload))

    deduped: dict[tuple[str, str, str], CVE] = {}
    for item in findings:
        key = (item.package, item.installed_version, item.cve_id)
        if key not in deduped or item.cvss_score > deduped[key].cvss_score:
            deduped[key] = item

    ordered = sorted(
        deduped.values(),
        key=lambda item: (item.cvss_score, item.severity, item.cve_id),
        reverse=True,
    )
    return ordered


__all__ = [
    "CVE",
    "CommandInjection",
    "SQLInjection",
    "SecretLeak",
    "scan_dependencies_for_cves",
    "scan_for_command_injection",
    "scan_for_hardcoded_secrets",
    "scan_for_sql_injection",
]
