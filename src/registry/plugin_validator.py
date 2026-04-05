"""Multi-layer security validator for plugins.

This module preserves plugin security validation and extends it with layered
checks across manifest integrity, signing, dependency safety, API
compatibility, static code analysis, sandbox testing, malware scanning, and
automated code-review checklist generation.
"""

from __future__ import annotations

import ast
import base64
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import ModuleType
from typing import Any, List, Literal, Mapping, Sequence

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from src.core import __version__ as _SYSTEM_VERSION
from src.registry.plugin_manifest import PluginManifest
from src.registry.plugin_sandbox import Plugin, PluginSandbox
from src.utils.logging import get_logger, log_security_event


logger = get_logger("src.registry.plugin_validator")


_SEMVER_PATTERN = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
_REQ_NAME_PATTERN = re.compile(r"^\s*([A-Za-z0-9_.-]+)")


@dataclass(frozen=True)
class Vulnerability:
    """Security issue identified during static validation."""

    code: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    title: str
    description: str
    recommendation: str
    line: int | None = None
    source: str | None = None


@dataclass(frozen=True)
class ChecklistItem:
    """Automated code review checklist item."""

    name: str
    passed: bool
    details: str = ""


@dataclass(frozen=True)
class MalwareScanResult:
    """Malware scan outcome for plugin filesystem contents."""

    clean: bool
    engine: str
    findings: list[str] = field(default_factory=list)
    message: str = ""


@dataclass(frozen=True)
class TestResult:
    """Sandbox execution result for plugin runtime behavior checks."""

    passed: bool
    violations: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ValidationResult:
    """Top-level plugin validation result."""

    is_valid: bool
    plugin_name: str
    manifest_valid: bool
    signature_valid: bool
    dependency_safe: bool
    api_compliant: bool
    permissions_ok: bool
    malware_scan: MalwareScanResult
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    checklist: list[ChecklistItem] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    sandbox_result: TestResult | None = None


class PluginValidator:
    """Plugin security validator with layered policy enforcement."""

    _DEFAULT_ALLOWED_PERMISSIONS = {
        "registry:read",
        "registry:register",
        "crypto:encrypt",
        "crypto:decrypt",
        "keys:read",
        "keys:rotate",
        "storage:read",
        "storage:write",
        "observability:emit",
        "policy:read",
    }
    _UNSAFE_PERMISSION_TOKENS = ("*", "admin", "root", "system", "shell", "exec")
    _UNSAFE_DEPENDENCIES = {
        "python-ldap",
        "easy_install",
    }

    def __init__(
        self,
        *,
        system_api_version: str = _SYSTEM_VERSION,
        require_code_signing: bool = False,
        trusted_signing_keys: Mapping[str, str | bytes] | None = None,
        allow_digest_signatures: bool = True,
        allowed_permissions: Sequence[str] | None = None,
        max_requested_permissions: int = 8,
        malware_scanning_enabled: bool = True,
        malware_scan_required: bool = False,
        malware_scan_command: Sequence[str] | None = None,
        malware_scan_timeout_seconds: int = 60,
        sandbox_whitelist_imports: Sequence[str] | None = None,
        actor_id: str = "plugin_validator",
    ) -> None:
        self._system_api_version = self._require_non_empty("system_api_version", system_api_version)
        self._require_code_signing = bool(require_code_signing)
        self._trusted_signing_keys = dict(trusted_signing_keys or {})
        self._allow_digest_signatures = bool(allow_digest_signatures)

        if max_requested_permissions <= 0:
            raise ValueError("max_requested_permissions must be > 0")
        self._max_requested_permissions = int(max_requested_permissions)

        allowed = allowed_permissions or tuple(sorted(self._DEFAULT_ALLOWED_PERMISSIONS))
        self._allowed_permissions = {self._require_non_empty("permission", item).lower() for item in allowed}

        self._malware_scanning_enabled = bool(malware_scanning_enabled)
        self._malware_scan_required = bool(malware_scan_required)

        default_scan_command = ("clamscan", "--no-summary", "--infected", "--recursive")
        selected_command = tuple(malware_scan_command or default_scan_command)
        if not selected_command:
            raise ValueError("malware_scan_command must not be empty")
        self._malware_scan_command = selected_command

        if malware_scan_timeout_seconds <= 0:
            raise ValueError("malware_scan_timeout_seconds must be > 0")
        self._malware_scan_timeout_seconds = int(malware_scan_timeout_seconds)

        default_whitelist = (
            "math",
            "json",
            "typing",
            "datetime",
            "collections",
            "itertools",
        )
        self._sandbox_whitelist_imports = [
            self._require_non_empty("whitelist import", item)
            for item in (sandbox_whitelist_imports or default_whitelist)
        ]
        self._actor_id = self._require_non_empty("actor_id", actor_id)

    def validate_plugin(self, plugin_path: Path) -> ValidationResult:
        """Validate plugin package with multi-layer security checks."""
        plugin_root, manifest_path = self._resolve_plugin_paths(plugin_path)
        plugin_name = plugin_root.name

        issues: list[str] = []
        warnings: list[str] = []
        vulnerabilities: list[Vulnerability] = []

        manifest_valid = False
        signature_valid = True
        dependency_safe = True
        api_compliant = True
        permissions_ok = True
        sandbox_result: TestResult | None = None

        manifest: PluginManifest | None = None
        try:
            manifest = PluginManifest.from_yaml(manifest_path)
            manifest_valid = True
            plugin_name = manifest.name
        except Exception as exc:
            issues.append(f"manifest schema validation failed: {exc}")

        if manifest is not None:
            signature_valid, signature_issue = self._validate_manifest_signature(manifest)
            if signature_issue:
                if signature_valid:
                    warnings.append(signature_issue)
                else:
                    issues.append(signature_issue)

            dependency_safe, dependency_issues, dependency_warnings, dependency_findings = self._check_dependencies(
                manifest.dependencies
            )
            issues.extend(dependency_issues)
            warnings.extend(dependency_warnings)
            vulnerabilities.extend(dependency_findings)

            api_compliant, api_issue = self._check_api_compatibility(manifest.api_version)
            if api_issue:
                issues.append(api_issue)

            permissions_ok = self.check_permissions(manifest, manifest.security.permissions)
            if not permissions_ok:
                issues.append("plugin requested excessive or unsafe permissions")

        for file_path in self._collect_python_files(plugin_root):
            try:
                source = file_path.read_text(encoding="utf-8")
            except Exception as exc:
                warnings.append(f"unable to read plugin file {file_path.name}: {exc}")
                continue

            for finding in self.scan_for_vulnerabilities(source):
                relative_source = str(file_path.relative_to(plugin_root))
                vulnerabilities.append(replace(finding, source=relative_source))

        malware_scan = self._run_malware_scan(plugin_root)
        if not malware_scan.clean:
            issues.append(
                "malware scan reported findings"
                if malware_scan.findings
                else "malware scanning failed"
            )

        plugin_instance = self._load_plugin_for_sandbox(plugin_root)
        if plugin_instance is not None:
            sandbox_result = self.sandbox_test(plugin_instance)
            if not sandbox_result.passed:
                issues.append("sandbox runtime test reported policy violations")
        else:
            warnings.append("sandbox test skipped: no plugin instance could be instantiated")

        has_critical = any(item.severity in {"CRITICAL", "HIGH"} for item in vulnerabilities)
        if has_critical:
            issues.append("static analysis found high-severity vulnerabilities")

        checklist = self._build_checklist(
            manifest_valid=manifest_valid,
            signature_valid=signature_valid,
            dependency_safe=dependency_safe,
            api_compliant=api_compliant,
            permissions_ok=permissions_ok,
            malware_scan=malware_scan,
            vulnerabilities=vulnerabilities,
            sandbox_result=sandbox_result,
        )

        is_valid = (
            manifest_valid
            and signature_valid
            and dependency_safe
            and api_compliant
            and permissions_ok
            and malware_scan.clean
            and not has_critical
            and (sandbox_result is None or sandbox_result.passed)
            and not issues
        )

        log_security_event(
            "plugin_validation_completed",
            severity="INFO" if is_valid else "WARNING",
            actor=self._actor_id,
            target=plugin_name,
            details={
                "valid": is_valid,
                "manifest_valid": manifest_valid,
                "signature_valid": signature_valid,
                "dependency_safe": dependency_safe,
                "api_compliant": api_compliant,
                "permissions_ok": permissions_ok,
                "malware_clean": malware_scan.clean,
                "vulnerability_count": len(vulnerabilities),
                "issue_count": len(issues),
            },
        )

        return ValidationResult(
            is_valid=is_valid,
            plugin_name=plugin_name,
            manifest_valid=manifest_valid,
            signature_valid=signature_valid,
            dependency_safe=dependency_safe,
            api_compliant=api_compliant,
            permissions_ok=permissions_ok,
            malware_scan=malware_scan,
            vulnerabilities=vulnerabilities,
            checklist=checklist,
            issues=issues,
            warnings=warnings,
            sandbox_result=sandbox_result,
        )

    def scan_for_vulnerabilities(self, plugin_code: str) -> List[Vulnerability]:
        """Run static analysis for common plugin security anti-patterns."""
        if not isinstance(plugin_code, str):
            raise TypeError("plugin_code must be a string")

        if not plugin_code.strip():
            return []

        findings: list[Vulnerability] = []

        try:
            tree = ast.parse(plugin_code)
            analyzer = _StaticSecurityAnalyzer(plugin_code)
            analyzer.visit(tree)
            findings.extend(analyzer.findings)
        except SyntaxError as exc:
            findings.append(
                Vulnerability(
                    code="PV-SYNTAX",
                    severity="HIGH",
                    title="Syntax error prevents deterministic review",
                    description=str(exc),
                    recommendation="Fix syntax errors before plugin deployment.",
                    line=getattr(exc, "lineno", None),
                )
            )

        for line_number, line in enumerate(plugin_code.splitlines(), start=1):
            stripped = line.strip()

            if _looks_like_hardcoded_secret(stripped):
                findings.append(
                    Vulnerability(
                        code="PV-SECRET-001",
                        severity="HIGH",
                        title="Potential hardcoded credential",
                        description="Code appears to contain a hardcoded secret-like value.",
                        recommendation="Move secrets to runtime-managed secret stores.",
                        line=line_number,
                    )
                )

            if "verify=False" in stripped and "requests." in stripped:
                findings.append(
                    Vulnerability(
                        code="PV-TLS-001",
                        severity="MEDIUM",
                        title="TLS certificate verification disabled",
                        description="Outgoing HTTP request disables TLS certificate validation.",
                        recommendation="Enable certificate verification and pin trust anchors.",
                        line=line_number,
                    )
                )

        return sorted(findings, key=lambda item: (_severity_rank(item.severity), item.line or 0))

    def check_permissions(self, plugin: Plugin, requested_permissions: List[str]) -> bool:
        """Validate plugin requested permissions for least-privilege policy."""
        if not isinstance(requested_permissions, list):
            raise TypeError("requested_permissions must be a list of strings")

        normalized: list[str] = []
        for raw in requested_permissions:
            if not isinstance(raw, str) or not raw.strip():
                return False
            value = raw.strip().lower()
            if value not in normalized:
                normalized.append(value)

        if len(normalized) > self._max_requested_permissions:
            return False

        for permission in normalized:
            if any(token in permission for token in self._UNSAFE_PERMISSION_TOKENS):
                return False

            if permission not in self._allowed_permissions and not self._permission_shape_allowed(permission):
                return False

        return True

    def sandbox_test(self, plugin: Plugin) -> TestResult:
        """Run plugin in a constrained sandbox and report policy violations."""
        start = time.perf_counter()
        violations: list[str] = []
        details: dict[str, Any] = {}

        try:
            sandbox = PluginSandbox(plugin, whitelist_imports=list(self._sandbox_whitelist_imports))

            entrypoint = self._sandbox_entrypoint(plugin)
            details["entrypoint"] = entrypoint

            if entrypoint is None:
                details["skipped"] = True
                details["reason"] = "no known sandbox test method found"
                return TestResult(
                    passed=True,
                    violations=[],
                    duration_seconds=time.perf_counter() - start,
                    details=details,
                )

            result = sandbox.execute(entrypoint)
            details["result_type"] = type(result).__name__

            if isinstance(result, bool):
                if not result:
                    violations.append("plugin sandbox self-test returned false")
            elif isinstance(result, Mapping):
                if result.get("passed") is False or result.get("ok") is False:
                    violations.append("plugin sandbox self-test reported failure")

                raw_violations = result.get("violations")
                if isinstance(raw_violations, list):
                    for item in raw_violations:
                        if isinstance(item, str) and item.strip():
                            violations.append(item.strip())
        except Exception as exc:
            violations.append(f"sandbox execution error: {exc}")

        return TestResult(
            passed=len(violations) == 0,
            violations=violations,
            duration_seconds=time.perf_counter() - start,
            details=details,
        )

    def _check_dependencies(
        self,
        dependencies: Sequence[str],
    ) -> tuple[bool, list[str], list[str], list[Vulnerability]]:
        issues: list[str] = []
        warnings: list[str] = []
        findings: list[Vulnerability] = []

        for requirement in dependencies:
            if not isinstance(requirement, str) or not requirement.strip():
                issues.append("dependency list contains non-string or empty entries")
                continue

            normalized = requirement.strip()
            lower = normalized.lower()

            name_match = _REQ_NAME_PATTERN.match(normalized)
            if name_match is None:
                issues.append(f"dependency has invalid format: {normalized}")
                findings.append(
                    Vulnerability(
                        code="PV-DEP-001",
                        severity="MEDIUM",
                        title="Invalid dependency specification",
                        description=f"Dependency requirement could not be parsed: {normalized}",
                        recommendation="Use standard PEP 508 requirement formatting.",
                    )
                )
                continue

            package_name = name_match.group(1).lower()
            if package_name in self._UNSAFE_DEPENDENCIES:
                issues.append(f"dependency denied by policy: {package_name}")
                findings.append(
                    Vulnerability(
                        code="PV-DEP-002",
                        severity="HIGH",
                        title="Dependency denied by policy",
                        description=f"Dependency is on internal deny-list: {package_name}",
                        recommendation="Replace with vetted alternatives.",
                    )
                )

            if any(token in lower for token in ("http://", "https://", "git+", "file://", "../", "..\\")):
                issues.append(f"dependency uses unsafe source reference: {normalized}")
                findings.append(
                    Vulnerability(
                        code="PV-DEP-003",
                        severity="HIGH",
                        title="Dependency uses non-vetted source",
                        description="Direct URL or local path dependencies bypass standard package trust controls.",
                        recommendation="Use signed packages from trusted registries.",
                    )
                )

            if not any(op in normalized for op in ("==", ">=", "<=", "~=", "<", ">")):
                warnings.append(f"dependency is not version constrained: {normalized}")

        return len(issues) == 0, issues, warnings, findings

    def _check_api_compatibility(self, plugin_api_version: str) -> tuple[bool, str | None]:
        plugin_version = self._require_non_empty("plugin_api_version", plugin_api_version)
        system_version = self._system_api_version

        plugin_semver = _parse_semver(plugin_version)
        system_semver = _parse_semver(system_version)

        if plugin_semver is not None and system_semver is not None:
            plugin_major, plugin_minor, _ = plugin_semver
            system_major, system_minor, _ = system_semver

            if plugin_major != system_major:
                return False, (
                    "plugin API major version is incompatible with system API version: "
                    f"plugin={plugin_version} system={system_version}"
                )

            if plugin_minor > system_minor:
                return False, (
                    "plugin requires newer API minor version than system provides: "
                    f"plugin={plugin_version} system={system_version}"
                )

            return True, None

        if plugin_version != system_version:
            return False, f"plugin API version mismatch: plugin={plugin_version} system={system_version}"

        return True, None

    def _validate_manifest_signature(self, manifest: PluginManifest) -> tuple[bool, str | None]:
        signature = manifest.security.signature.strip()
        if not signature:
            if self._require_code_signing:
                return False, "code signing is required but manifest signature is missing"
            return True, "signature missing; code signing is optional for this validator profile"

        payload = self._canonical_manifest_payload(manifest)
        trusted_key = self._resolve_trusted_key(manifest.name)

        if trusted_key is not None:
            try:
                public_key = self._parse_public_key(trusted_key)
                public_key.verify(base64.b64decode(signature), payload)
                return True, None
            except Exception:
                return False, "manifest signature verification failed against trusted public key"

        if not self._allow_digest_signatures:
            return False, "signature provided but no trusted key configured and digest signatures are disabled"

        expected = hashlib.sha256(payload).hexdigest()
        provided = signature.lower()
        if provided.startswith("sha256:"):
            provided = provided.split(":", 1)[1]

        if provided != expected:
            return False, "manifest digest signature mismatch"

        return True, None

    def _run_malware_scan(self, plugin_root: Path) -> MalwareScanResult:
        if not self._malware_scanning_enabled:
            return MalwareScanResult(
                clean=True,
                engine="disabled",
                findings=[],
                message="malware scanning disabled by policy",
            )

        command = [*self._malware_scan_command, str(plugin_root)]
        engine = self._malware_scan_command[0]

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=self._malware_scan_timeout_seconds,
            )
        except FileNotFoundError:
            message = f"malware scanner executable not found: {engine}"
            return MalwareScanResult(
                clean=not self._malware_scan_required,
                engine=engine,
                findings=[] if not self._malware_scan_required else [message],
                message=message,
            )
        except subprocess.TimeoutExpired:
            message = f"malware scanner timed out after {self._malware_scan_timeout_seconds}s"
            return MalwareScanResult(
                clean=not self._malware_scan_required,
                engine=engine,
                findings=[message] if self._malware_scan_required else [],
                message=message,
            )

        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        combined = f"{stdout}\n{stderr}".strip()

        if completed.returncode == 0:
            return MalwareScanResult(clean=True, engine=engine, findings=[], message="clean")

        if completed.returncode == 1:
            findings = [
                line.strip()
                for line in combined.splitlines()
                if "FOUND" in line.upper() or "infect" in line.lower()
            ]
            if not findings:
                findings = ["scanner reported malware indicators"]
            return MalwareScanResult(clean=False, engine=engine, findings=findings, message="malware detected")

        message = f"scanner execution error (exit={completed.returncode})"
        return MalwareScanResult(
            clean=not self._malware_scan_required,
            engine=engine,
            findings=[message] if self._malware_scan_required else [],
            message=message,
        )

    def _build_checklist(
        self,
        *,
        manifest_valid: bool,
        signature_valid: bool,
        dependency_safe: bool,
        api_compliant: bool,
        permissions_ok: bool,
        malware_scan: MalwareScanResult,
        vulnerabilities: Sequence[Vulnerability],
        sandbox_result: TestResult | None,
    ) -> list[ChecklistItem]:
        has_high = any(item.severity in {"HIGH", "CRITICAL"} for item in vulnerabilities)

        return [
            ChecklistItem(
                name="Manifest schema review",
                passed=manifest_valid,
                details="Manifest fields and structure validated.",
            ),
            ChecklistItem(
                name="Code signing verification",
                passed=signature_valid,
                details="Signature verified or accepted by configured policy.",
            ),
            ChecklistItem(
                name="Dependency safety review",
                passed=dependency_safe,
                details="Dependency sources and package policies evaluated.",
            ),
            ChecklistItem(
                name="Plugin API compatibility",
                passed=api_compliant,
                details="Plugin API version compared with system API.",
            ),
            ChecklistItem(
                name="Permission least-privilege",
                passed=permissions_ok,
                details="Requested permissions checked against policy bounds.",
            ),
            ChecklistItem(
                name="Static code review",
                passed=not has_high,
                details="High/critical findings must be zero.",
            ),
            ChecklistItem(
                name="Malware scan",
                passed=malware_scan.clean,
                details=malware_scan.message,
            ),
            ChecklistItem(
                name="Sandbox runtime test",
                passed=(sandbox_result is None or sandbox_result.passed),
                details="Plugin self-test executed in process isolation.",
            ),
        ]

    def _load_plugin_for_sandbox(self, plugin_root: Path) -> Plugin | None:
        plugin_file = plugin_root / "plugin.py"
        if not plugin_file.exists():
            return None

        module_name = f"_plugin_validator_{abs(hash(str(plugin_file)))}"
        module = self._load_module_from_file(module_name, plugin_file)

        factory = getattr(module, "create_plugin", None)
        if callable(factory):
            try:
                instance = factory()
                if instance is not None:
                    return instance
            except Exception:
                return None

        for candidate_name in ("Plugin", "MainPlugin", "KeyCryptPlugin"):
            cls = getattr(module, candidate_name, None)
            if cls is None or not isinstance(cls, type):
                continue
            try:
                return cls()
            except Exception:
                continue

        for _, cls in vars(module).items():
            if not isinstance(cls, type):
                continue
            if not cls.__name__.lower().endswith("plugin"):
                continue
            try:
                return cls()
            except Exception:
                continue

        return None

    @staticmethod
    def _collect_python_files(plugin_root: Path) -> list[Path]:
        files = [
            item
            for item in plugin_root.rglob("*.py")
            if "__pycache__" not in item.parts
        ]
        return sorted(files)

    @staticmethod
    def _resolve_plugin_paths(plugin_path: Path) -> tuple[Path, Path]:
        path = Path(plugin_path).expanduser().resolve()
        if not path.exists():
            raise FileNotFoundError(f"plugin path does not exist: {path}")

        if path.is_file():
            if path.name != "plugin.yaml":
                raise ValueError("plugin_path must be a plugin directory or plugin.yaml file")
            return path.parent, path

        manifest_path = path / "plugin.yaml"
        if not manifest_path.exists():
            raise FileNotFoundError(f"plugin manifest not found: {manifest_path}")

        return path, manifest_path

    @staticmethod
    def _canonical_manifest_payload(manifest: PluginManifest) -> bytes:
        payload = {
            "name": manifest.name,
            "version": manifest.version,
            "api_version": manifest.api_version,
            "author": manifest.author,
            "provides": [
                {
                    "interface": item.interface,
                    "implementation": item.implementation,
                }
                for item in manifest.provides
            ],
            "dependencies": list(manifest.dependencies),
            "security": {
                "permissions": list(manifest.security.permissions),
            },
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _resolve_trusted_key(self, plugin_name: str) -> str | bytes | None:
        if plugin_name in self._trusted_signing_keys:
            return self._trusted_signing_keys[plugin_name]
        normalized = plugin_name.strip().lower()
        return self._trusted_signing_keys.get(normalized)

    @staticmethod
    def _parse_public_key(value: str | bytes) -> Ed25519PublicKey:
        try:
            if isinstance(value, bytes):
                raw = value
                if raw.startswith(b"-----BEGIN"):
                    key = serialization.load_pem_public_key(raw)
                else:
                    key = Ed25519PublicKey.from_public_bytes(raw)
            elif isinstance(value, str):
                normalized = value.strip()
                if not normalized:
                    raise ValueError("public key cannot be empty")
                if normalized.startswith("-----BEGIN"):
                    key = serialization.load_pem_public_key(normalized.encode("utf-8"))
                else:
                    key = Ed25519PublicKey.from_public_bytes(base64.b64decode(normalized))
            else:
                raise TypeError("unsupported key type")
        except Exception as exc:
            raise ValueError("unable to parse trusted signing key") from exc

        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("trusted key must be Ed25519")
        return key

    def _permission_shape_allowed(self, permission: str) -> bool:
        match = re.fullmatch(r"([a-z0-9_-]+):([a-z0-9_-]+)", permission)
        if match is None:
            return False

        domain, action = match.groups()
        if domain in {"admin", "root", "system"}:
            return False
        if action in {"admin", "root", "exec", "shell"}:
            return False
        return True

    @staticmethod
    def _sandbox_entrypoint(plugin: Plugin) -> str | None:
        for candidate in ("self_test", "health_check", "validate", "run"):
            method = getattr(plugin, candidate, None)
            if callable(method):
                return candidate
        return None

    @staticmethod
    def _load_module_from_file(module_name: str, module_file: Path) -> ModuleType:
        try:
            cache_file = Path(importlib.util.cache_from_source(str(module_file)))
            if cache_file.exists():
                cache_file.unlink()
        except Exception:
            pass

        spec = importlib.util.spec_from_file_location(module_name, module_file)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"unable to load plugin module {module_name}")

        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        try:
            spec.loader.exec_module(module)
            return module
        except Exception:
            sys.modules.pop(module_name, None)
            raise

    @staticmethod
    def _require_non_empty(name: str, value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must be a non-empty string")
        return value.strip()


class _StaticSecurityAnalyzer(ast.NodeVisitor):
    def __init__(self, code: str) -> None:
        self.findings: list[Vulnerability] = []
        self._code = code

    def visit_Call(self, node: ast.Call) -> Any:
        call_name = _call_name(node.func)

        if call_name in {"eval", "exec"}:
            self._add(
                code="PV-CODE-001",
                severity="CRITICAL",
                title="Dynamic code execution",
                description=f"Call to {call_name} enables arbitrary code execution.",
                recommendation="Remove dynamic execution or sandbox untrusted expressions.",
                line=getattr(node, "lineno", None),
            )

        if call_name in {"os.system", "os.popen", "subprocess.call", "subprocess.Popen", "subprocess.run"}:
            shell_enabled = _keyword_bool(node, "shell")
            severity: Literal["HIGH", "MEDIUM"] = "HIGH" if shell_enabled else "MEDIUM"
            self._add(
                code="PV-CODE-002",
                severity=severity,
                title="Shell command execution",
                description=f"Call to {call_name} executes external commands.",
                recommendation="Use fixed command allow-lists and avoid shell=True.",
                line=getattr(node, "lineno", None),
            )

        if call_name in {"pickle.load", "pickle.loads", "dill.load", "dill.loads", "marshal.loads"}:
            self._add(
                code="PV-DESERIALIZE-001",
                severity="HIGH",
                title="Unsafe deserialization",
                description=f"Call to {call_name} may execute attacker-controlled payloads.",
                recommendation="Use safe serialization formats such as JSON with strict schemas.",
                line=getattr(node, "lineno", None),
            )

        if call_name == "yaml.load":
            if not _yaml_safe_loader(node):
                self._add(
                    code="PV-DESERIALIZE-002",
                    severity="HIGH",
                    title="Unsafe YAML loading",
                    description="yaml.load without SafeLoader can deserialize unsafe objects.",
                    recommendation="Use yaml.safe_load or pass Loader=yaml.SafeLoader.",
                    line=getattr(node, "lineno", None),
                )

        if call_name in {"hashlib.md5", "hashlib.sha1"}:
            self._add(
                code="PV-CRYPTO-001",
                severity="MEDIUM",
                title="Weak hash primitive",
                description=f"{call_name} is not appropriate for secure integrity checks.",
                recommendation="Use SHA-256 or stronger hash algorithms.",
                line=getattr(node, "lineno", None),
            )

        if call_name == "__import__":
            self._add(
                code="PV-IMPORT-001",
                severity="HIGH",
                title="Dynamic import usage",
                description="Dynamic imports can bypass policy-based module restrictions.",
                recommendation="Use static imports and explicit module allow-lists.",
                line=getattr(node, "lineno", None),
            )

        self.generic_visit(node)

    def _add(
        self,
        *,
        code: str,
        severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        title: str,
        description: str,
        recommendation: str,
        line: int | None,
    ) -> None:
        self.findings.append(
            Vulnerability(
                code=code,
                severity=severity,
                title=title,
                description=description,
                recommendation=recommendation,
                line=line,
            )
        )


def _parse_semver(version: str) -> tuple[int, int, int] | None:
    match = _SEMVER_PATTERN.fullmatch(version.strip())
    if match is None:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def _call_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        root = _call_name(node.value)
        if root:
            return f"{root}.{node.attr}"
        return node.attr
    return ""


def _keyword_bool(call: ast.Call, key: str) -> bool:
    for item in call.keywords:
        if item.arg != key:
            continue
        if isinstance(item.value, ast.Constant) and isinstance(item.value.value, bool):
            return bool(item.value.value)
    return False


def _yaml_safe_loader(call: ast.Call) -> bool:
    for item in call.keywords:
        if item.arg != "Loader":
            continue

        if isinstance(item.value, ast.Attribute):
            if item.value.attr == "SafeLoader":
                return True

        if isinstance(item.value, ast.Name):
            if item.value.id == "SafeLoader":
                return True

    return False


def _looks_like_hardcoded_secret(line: str) -> bool:
    pattern = re.compile(
        r"(?i)(password|passwd|secret|api[_-]?key|token|private[_-]?key)"
        r"\s*=\s*['\"][^'\"]{8,}['\"]"
    )
    return bool(pattern.search(line))


def _severity_rank(value: str) -> int:
    order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
    }
    return order.get(value, 99)


__all__ = [
    "Vulnerability",
    "ChecklistItem",
    "MalwareScanResult",
    "TestResult",
    "ValidationResult",
    "PluginValidator",
]
