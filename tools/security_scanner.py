#!/usr/bin/env python3
"""Security vulnerability scanner for source code and dependencies.

Capabilities:
- hardcoded secret detection using regex patterns
- SQL injection detection using AST heuristics and Bandit integration
- command injection detection using AST heuristics and Bandit integration
- dependency CVE lookup using the NIST NVD API and optional safety fallback
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

_FAKE_SECRET_MARKERS = {
    "api_key_example",
    "dummy_password",
    "dummy_token",
    "github_token_example",
    "aws_key_example",
    "sk_test_fake_key",
    "fake_secret",
    "example_secret",
    "token_example",
    "password_example",
}

_REALISTIC_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
    re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"),
)

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
    redaction_suggestion: str
    remediation: str
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
    remediation: str
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
    remediation: str
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
    remediation: str


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


def is_fake_secret(value: str) -> bool:
    """Return True when a value is an intentionally fake placeholder.

    This helper enforces safe development/test practices by distinguishing
    example placeholders from realistic credential material.
    """
    normalized = value.strip().strip('"').strip("'").strip()
    if not normalized:
        return False

    lowered = normalized.lower()
    if lowered in _PLACEHOLDER_SECRET_VALUES:
        return True

    if lowered in _FAKE_SECRET_MARKERS:
        return True

    if lowered.startswith(("fake_", "dummy_", "example_", "test_")):
        return True

    if lowered.endswith(("_example", "_placeholder", "_dummy")):
        return True

    if lowered.startswith("sk_test_"):
        return True

    if all(char.isupper() or char.isdigit() or char == "_" for char in normalized) and (
        "EXAMPLE" in normalized or "DUMMY" in normalized
    ):
        return True

    return False


def _redact_secret(value: str) -> str:
    trimmed = value.strip()
    if not trimmed:
        return "[REDACTED]"
    if len(trimmed) <= 4:
        return "*" * len(trimmed)
    return f"{trimmed[:2]}{'*' * (len(trimmed) - 4)}{trimmed[-2:]}"


def _secret_remediation(secret_name: str) -> str:
    return (
        "Move secret material to environment variables or a secret manager. "
        f"Use os.getenv('{secret_name.upper()}') in code, rotate the exposed value, "
        "and avoid committing credentials to version control."
    )


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


def _run_safety_payload(requirements_file: Path) -> Any | None:
    if importlib.util.find_spec("safety") is None:
        return None

    commands = (
        [sys.executable, "-m", "safety", "check", "--json", "--file", str(requirements_file)],
        [sys.executable, "-m", "safety", "scan", "--output", "json", "--file", str(requirements_file)],
    )

    for command in commands:
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        payload = _extract_json_text((completed.stdout or "") + "\n" + (completed.stderr or ""))
        if payload is not None:
            return payload

    return None


def _parse_safety_payload(payload: Any) -> list[CVE]:
    if payload is None:
        return []

    if isinstance(payload, list):
        items = payload
    elif isinstance(payload, dict):
        if isinstance(payload.get("vulnerabilities"), list):
            items = payload["vulnerabilities"]
        elif isinstance(payload.get("results"), dict) and isinstance(
            payload["results"].get("vulnerabilities"), list
        ):
            items = payload["results"]["vulnerabilities"]
        else:
            items = []
    else:
        items = []

    findings: list[CVE] = []
    for item in items:
        if not isinstance(item, dict):
            continue

        package = _canonicalize_package_name(str(item.get("package_name") or item.get("package") or ""))
        version = str(item.get("installed_version") or item.get("analyzed_version") or "")
        cve_id = str(item.get("CVE") or item.get("cve") or item.get("vulnerability_id") or "UNKNOWN-CVE")
        description = str(item.get("advisory") or item.get("description") or "No advisory text")
        severity = _normalize_severity(str(item.get("severity") or "unknown"))
        cvss_score = _severity_to_cvss(severity)

        fixed_versions = item.get("fixed_versions")
        if isinstance(fixed_versions, list):
            fix_hint = ", ".join(str(version_item) for version_item in fixed_versions)
        elif isinstance(fixed_versions, str):
            fix_hint = fixed_versions
        else:
            fix_hint = "latest safe release"

        remediation = (
            f"Upgrade {package or 'dependency'} from {version or 'current version'} "
            f"to a non-vulnerable release ({fix_hint}) and re-run vulnerability scans."
        )

        findings.append(
            CVE(
                package=package,
                installed_version=version,
                cve_id=cve_id,
                description=description,
                cvss_score=cvss_score,
                severity=severity,
                published=str(item.get("published") or ""),
                references=tuple(),
                remediation=remediation,
            )
        )

    findings.sort(key=lambda entry: (entry.cvss_score, entry.cve_id), reverse=True)
    return findings


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
                remediation=(
                    f"Upgrade {package} to a patched version, pin secure ranges in requirements, "
                    "and verify fixes with a follow-up scan."
                ),
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

                    candidate = _quoted_value(matched_text) or matched_text
                    severity_value = severity
                    score_value = float(score)
                    if is_fake_secret(candidate):
                        severity_value = "low"
                        score_value = 1.0

                    # Realistic-looking secret patterns should always remain high severity.
                    if any(pattern_item.search(candidate) for pattern_item in _REALISTIC_SECRET_PATTERNS):
                        severity_value = severity
                        score_value = float(score)

                    redaction = _redact_secret(candidate)

                    env_name_match = re.search(
                        r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|token|private[_-]?key|access[_-]?key)\b",
                        line,
                    )
                    env_name = env_name_match.group(1) if env_name_match else "SECRET_VALUE"

                    findings.append(
                        SecretLeak(
                            file_path=file_path,
                            line_no=line_no,
                            secret_type=secret_type,
                            matched_text=matched_text,
                            severity=severity_value,
                            cvss_score=score_value,
                            redaction_suggestion=f"Replace literal with [REDACTED:{redaction}]",
                            remediation=_secret_remediation(env_name),
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
                redaction_suggestion="Replace detected literal with [REDACTED]",
                remediation=(
                    "Replace hardcoded secrets with environment variables and secret manager lookups "
                    "(for example, os.getenv('API_KEY'))."
                ),
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
                    remediation=(
                        "Use parameterized queries with placeholders and bound parameters; avoid "
                        "f-strings, concatenation, and .format() for SQL statements."
                    ),
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
                remediation=(
                    "Refactor database access to parameterized queries and enforce strict input "
                    "validation on query parameters."
                ),
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
                        remediation=(
                            "Avoid shell execution for user-controlled inputs. Use vetted allow-lists, "
                            "argument arrays, and subprocess calls with shell=False."
                        ),
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
                            remediation=(
                                "Set shell=False, pass argument lists, and validate command inputs with "
                                "strict allow-lists."
                            ),
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
                            remediation=(
                                "Avoid passing raw dynamic command strings. Build explicit argument lists "
                                "and validate each argument."
                            ),
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
                remediation=(
                    "Use subprocess with shell=False, sanitize inputs, and avoid command strings "
                    "constructed from untrusted data."
                ),
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
    """Scan requirements for known CVEs using NVD with optional safety fallback."""
    resolved_requirements = Path(requirements_file).expanduser().resolve()
    dependencies = _parse_requirements(resolved_requirements)

    findings: list[CVE] = []
    for package, version in dependencies:
        payload = _fetch_nvd_json(package, version)
        if payload is None:
            continue
        findings.extend(_parse_nvd_payload(package, version, payload))

    safety_payload = _run_safety_payload(resolved_requirements)
    findings.extend(_parse_safety_payload(safety_payload))

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
    "is_fake_secret",
    "scan_dependencies_for_cves",
    "scan_for_command_injection",
    "scan_for_hardcoded_secrets",
    "scan_for_sql_injection",
]
