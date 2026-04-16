#!/usr/bin/env python3
"""Dependency analysis tooling for Python projects.

Features:
- circular dependency detection for internal modules
- unused requirement detection against import usage
- CVE lookup integration via safety JSON output
- dependency graph visualization rendering (pydeps or DOT/SVG fallback)
"""

from __future__ import annotations

import ast
import json
import re
import shutil
import subprocess
import sys
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


REQUIREMENT_IMPORT_ALIASES: dict[str, set[str]] = {
    "pyyaml": {"yaml"},
    "python-jose": {"jose"},
    "python-multipart": {"multipart"},
    "dependency-injector": {"dependency_injector"},
    "psycopg2-binary": {"psycopg2"},
    "grpcio-tools": {"grpc_tools"},
    "liboqs-python": {"oqs"},
    "azure-storage-blob": {"azure"},
    "azure-keyvault-keys": {"azure"},
    "azure-identity": {"azure"},
    "google-cloud-storage": {"google"},
    "pytest-asyncio": {"pytest_asyncio"},
    "pytest-env": {"pytest_env"},
    "pytest-mock": {"pytest_mock"},
}


@dataclass(frozen=True)
class Cycle:
    """Circular dependency cycle."""

    modules: tuple[str, ...]

    @property
    def length(self) -> int:
        return len(self.modules)


@dataclass(frozen=True)
class Vulnerability:
    """Security vulnerability record from safety output."""

    package: str
    installed_version: str
    vulnerability_id: str
    advisory: str
    severity: str = "unknown"
    cve: str = ""
    fixed_versions: tuple[str, ...] = field(default_factory=tuple)
    affected_versions: str = ""


def _iter_python_files(source_dir: Path) -> list[Path]:
    if not source_dir.exists() or not source_dir.is_dir():
        raise FileNotFoundError(f"source_dir must be an existing directory: {source_dir}")

    return sorted(path for path in source_dir.rglob("*.py") if path.is_file())


def _module_name_for_file(file_path: Path, source_dir: Path) -> str:
    relative = file_path.resolve().relative_to(source_dir.resolve())
    if relative.name == "__init__.py":
        parts = relative.parts[:-1]
    else:
        parts = relative.with_suffix("").parts

    return ".".join(parts) if parts else source_dir.name


def _resolve_relative_import(current_module: str, module: str | None, level: int) -> str:
    if level <= 0:
        return module or ""

    package_parts = current_module.split(".")[:-1]
    trim = max(0, level - 1)
    if trim >= len(package_parts):
        resolved_parts: list[str] = []
    else:
        resolved_parts = package_parts[: len(package_parts) - trim]

    if module:
        resolved_parts.extend(module.split("."))

    return ".".join(part for part in resolved_parts if part)


def _closest_known_module(module_name: str, known_modules: set[str]) -> str | None:
    candidate = module_name
    while candidate:
        if candidate in known_modules:
            return candidate
        if "." not in candidate:
            break
        candidate = candidate.rsplit(".", 1)[0]
    return None


def _collect_graph_with_ast(source_dir: Path) -> dict[str, set[str]]:
    files = _iter_python_files(source_dir)
    module_for_file = {path: _module_name_for_file(path, source_dir) for path in files}
    known_modules = set(module_for_file.values())

    graph: dict[str, set[str]] = {module: set() for module in known_modules}

    for file_path, module_name in module_for_file.items():
        source = file_path.read_text(encoding="utf-8", errors="ignore")
        try:
            tree = ast.parse(source, filename=str(file_path))
        except SyntaxError:
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    resolved = _closest_known_module(alias.name, known_modules)
                    if resolved is not None and resolved != module_name:
                        graph[module_name].add(resolved)

            elif isinstance(node, ast.ImportFrom):
                base_module = _resolve_relative_import(module_name, node.module, node.level)
                resolved_base = _closest_known_module(base_module, known_modules)
                if resolved_base is not None and resolved_base != module_name:
                    graph[module_name].add(resolved_base)

                for alias in node.names:
                    if alias.name == "*":
                        continue
                    symbol_module = f"{base_module}.{alias.name}" if base_module else alias.name
                    resolved_symbol = _closest_known_module(symbol_module, known_modules)
                    if resolved_symbol is not None and resolved_symbol != module_name:
                        graph[module_name].add(resolved_symbol)

    return graph


def _collect_graph_with_modulegraph(source_dir: Path) -> dict[str, set[str]] | None:
    try:
        from modulegraph.modulegraph import ModuleGraph  # type: ignore
    except Exception:
        return None

    files = _iter_python_files(source_dir)
    module_for_file = {path: _module_name_for_file(path, source_dir) for path in files}
    known_modules = set(module_for_file.values())

    graph: dict[str, set[str]] = {module: set() for module in known_modules}

    try:
        module_graph = ModuleGraph()
        add_script = getattr(module_graph, "add_script", None)
        run_script = getattr(module_graph, "run_script", None)

        for file_path in files:
            if callable(run_script):
                run_script(str(file_path))
            elif callable(add_script):
                add_script(str(file_path))

        get_edges = getattr(module_graph, "get_edges", None)
        flatten = getattr(module_graph, "flatten", None)
        nodes = list(flatten()) if callable(flatten) else []

        if not nodes or not callable(get_edges):
            return None

        for node in nodes:
            identifier = getattr(node, "identifier", "")
            if not isinstance(identifier, str):
                continue
            source_module = _closest_known_module(identifier, known_modules)
            if source_module is None:
                continue

            _incoming, outgoing = get_edges(node)
            for target in outgoing:
                target_identifier = getattr(target, "identifier", "")
                if not isinstance(target_identifier, str):
                    continue
                target_module = _closest_known_module(target_identifier, known_modules)
                if target_module is not None and target_module != source_module:
                    graph[source_module].add(target_module)

    except Exception:
        return None

    has_edges = any(edges for edges in graph.values())
    return graph if has_edges else None


def _build_dependency_graph(source_dir: Path) -> dict[str, set[str]]:
    graph = _collect_graph_with_modulegraph(source_dir)
    if graph is not None:
        return graph
    return _collect_graph_with_ast(source_dir)


def _strongly_connected_components(graph: Mapping[str, set[str]]) -> list[list[str]]:
    index = 0
    stack: list[str] = []
    on_stack: set[str] = set()
    indexes: dict[str, int] = {}
    low_links: dict[str, int] = {}
    components: list[list[str]] = []

    def visit(node: str) -> None:
        nonlocal index
        indexes[node] = index
        low_links[node] = index
        index += 1

        stack.append(node)
        on_stack.add(node)

        for neighbor in sorted(graph.get(node, set())):
            if neighbor not in indexes:
                visit(neighbor)
                low_links[node] = min(low_links[node], low_links[neighbor])
            elif neighbor in on_stack:
                low_links[node] = min(low_links[node], indexes[neighbor])

        if low_links[node] == indexes[node]:
            component: list[str] = []
            while stack:
                member = stack.pop()
                on_stack.remove(member)
                component.append(member)
                if member == node:
                    break
            components.append(component)

    for module in sorted(graph.keys()):
        if module not in indexes:
            visit(module)

    return components


def _canonicalize_requirement_name(package_name: str) -> str:
    normalized = package_name.strip().lower().replace("_", "-")
    return re.sub(r"-+", "-", normalized)


def _extract_requirement_name(line: str) -> str | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    if stripped.startswith(("-r", "--requirement", "-c", "--constraint")):
        return None
    if stripped.startswith(("-e", "--editable")):
        stripped = stripped.split(maxsplit=1)[-1].strip()

    no_comment = stripped.split("#", 1)[0].strip()
    if not no_comment:
        return None

    if "#egg=" in no_comment:
        return _canonicalize_requirement_name(no_comment.split("#egg=", 1)[1].strip())

    spec = no_comment.split(";", 1)[0].strip()
    if " @ " in spec:
        spec = spec.split(" @ ", 1)[0].strip()

    if "[" in spec:
        spec = spec.split("[", 1)[0].strip()

    name = re.split(r"[<>=!~\s]", spec, maxsplit=1)[0].strip()
    if not name:
        return None

    return _canonicalize_requirement_name(name)


def _parse_requirements(requirements_file: Path) -> list[str]:
    if not requirements_file.exists() or not requirements_file.is_file():
        raise FileNotFoundError(f"requirements file not found: {requirements_file}")

    package_names: list[str] = []
    seen: set[str] = set()

    for line in requirements_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        name = _extract_requirement_name(line)
        if not name or name in seen:
            continue
        seen.add(name)
        package_names.append(name)

    return package_names


def _collect_import_roots(source_dir: Path) -> set[str]:
    imports: set[str] = set()
    for file_path in _iter_python_files(source_dir):
        source = file_path.read_text(encoding="utf-8", errors="ignore")
        try:
            tree = ast.parse(source, filename=str(file_path))
        except SyntaxError:
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name.split(".", 1)[0])
            elif isinstance(node, ast.ImportFrom):
                if node.level > 0:
                    continue
                if node.module:
                    imports.add(node.module.split(".", 1)[0])

    return {item for item in imports if item}


def _candidate_import_names(requirement_name: str) -> set[str]:
    canonical = _canonicalize_requirement_name(requirement_name)
    candidates = {
        canonical,
        canonical.replace("-", "_"),
        canonical.replace("-", ""),
    }

    if canonical.startswith("python-"):
        suffix = canonical.removeprefix("python-")
        candidates.add(suffix)
        candidates.add(suffix.replace("-", "_"))

    if canonical.endswith("-binary"):
        stripped = canonical.removesuffix("-binary")
        candidates.add(stripped)
        candidates.add(stripped.replace("-", "_"))

    if canonical.startswith("google-cloud-"):
        candidates.add("google")
    if canonical.startswith("azure-"):
        candidates.add("azure")

    candidates.update(REQUIREMENT_IMPORT_ALIASES.get(canonical, set()))
    return {item for item in candidates if item}


def _extract_json_payload(raw_text: str) -> Any | None:
    text = raw_text.strip()
    if not text:
        return None

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    for start_char, end_char in (("[", "]"), ("{", "}")):
        start = text.find(start_char)
        end = text.rfind(end_char)
        if start == -1 or end == -1 or start >= end:
            continue
        fragment = text[start : end + 1]
        try:
            return json.loads(fragment)
        except json.JSONDecodeError:
            continue

    return None


def _run_safety(requirements_file: Path) -> Any | None:
    commands = (
        [sys.executable, "-m", "safety", "check", "--json", "--file", str(requirements_file)],
        [sys.executable, "-m", "safety", "scan", "--output", "json", "--file", str(requirements_file)],
    )

    for command in commands:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )
        payload = _extract_json_payload((completed.stdout or "") + "\n" + (completed.stderr or ""))
        if payload is not None:
            return payload

    return None


def _coerce_fixed_versions(value: Any) -> tuple[str, ...]:
    if isinstance(value, list):
        return tuple(str(item) for item in value)
    if isinstance(value, str):
        parts = [part.strip() for part in value.split(",") if part.strip()]
        return tuple(parts)
    return tuple()


def _parse_safety_vulnerabilities(payload: Any) -> list[Vulnerability]:
    entries: list[Any]
    if isinstance(payload, list):
        entries = payload
    elif isinstance(payload, dict):
        if isinstance(payload.get("vulnerabilities"), list):
            entries = list(payload["vulnerabilities"])
        elif isinstance(payload.get("results"), dict) and isinstance(
            payload["results"].get("vulnerabilities"), list
        ):
            entries = list(payload["results"]["vulnerabilities"])
        else:
            entries = []
    else:
        entries = []

    vulnerabilities: list[Vulnerability] = []
    for item in entries:
        if isinstance(item, dict):
            package = str(item.get("package_name") or item.get("package") or "")
            version = str(item.get("installed_version") or item.get("analyzed_version") or "")
            vulnerability_id = str(
                item.get("vulnerability_id")
                or item.get("id")
                or item.get("advisory_id")
                or "unknown"
            )
            advisory = str(item.get("advisory") or item.get("description") or "No advisory text")
            severity = str(item.get("severity") or "unknown")
            cve = str(item.get("CVE") or item.get("cve") or "")
            fixed_versions = _coerce_fixed_versions(item.get("fixed_versions"))
            affected_versions = str(item.get("affected_versions") or "")
        elif isinstance(item, list):
            package = str(item[0]) if len(item) > 0 else ""
            version = str(item[1]) if len(item) > 1 else ""
            vulnerability_id = str(item[2]) if len(item) > 2 else "unknown"
            advisory = str(item[3]) if len(item) > 3 else "No advisory text"
            severity = "unknown"
            cve = ""
            fixed_versions = tuple()
            affected_versions = ""
        else:
            continue

        if not package:
            continue

        vulnerabilities.append(
            Vulnerability(
                package=package,
                installed_version=version,
                vulnerability_id=vulnerability_id,
                advisory=advisory,
                severity=severity,
                cve=cve,
                fixed_versions=fixed_versions,
                affected_versions=affected_versions,
            )
        )

    vulnerabilities.sort(key=lambda item: (item.package.lower(), item.vulnerability_id))
    return vulnerabilities


def _dependency_graph_to_dot(graph: Mapping[str, set[str]]) -> str:
    lines = [
        "digraph dependencies {",
        "  rankdir=LR;",
        "  node [shape=box, style=rounded];",
    ]

    for module in sorted(graph.keys()):
        if not graph[module]:
            lines.append(f'  "{module}";')
            continue
        for dependency in sorted(graph[module]):
            lines.append(f'  "{module}" -> "{dependency}";')

    lines.append("}")
    return "\n".join(lines) + "\n"


def _dependency_graph_to_mermaid(graph: Mapping[str, set[str]], *, edge_limit: int = 180) -> str:
    def node_id(name: str) -> str:
        return "n_" + re.sub(r"[^A-Za-z0-9_]", "_", name)

    lines = ["graph LR"]
    edge_count = 0

    for module in sorted(graph.keys()):
        dependencies = sorted(graph[module])
        if not dependencies:
            continue

        for dependency in dependencies:
            lines.append(
                f'    {node_id(module)}["{module}"] --> {node_id(dependency)}["{dependency}"]'
            )
            edge_count += 1
            if edge_count >= edge_limit:
                lines.append("    n_truncated[\"... graph truncated ...\"]")
                return "\n".join(lines)

    if edge_count == 0:
        lines.append("    n_empty[\"No internal import edges detected\"]")

    return "\n".join(lines)


def _discover_requirements_file(source_dir: Path) -> Path | None:
    search_roots = [source_dir.resolve(), source_dir.resolve().parent, PROJECT_ROOT.resolve()]
    candidates = ("requirements.txt", "requirements-dev.txt", "requirements-prod.txt")

    for root in search_roots:
        for name in candidates:
            candidate = root / name
            if candidate.exists() and candidate.is_file():
                return candidate

    return None


def _requirements_from_pyproject(source_dir: Path, output_dir: Path) -> Path | None:
    pyproject_candidates = [source_dir.resolve() / "pyproject.toml", PROJECT_ROOT.resolve() / "pyproject.toml"]

    pyproject_file = next(
        (candidate for candidate in pyproject_candidates if candidate.exists() and candidate.is_file()),
        None,
    )
    if pyproject_file is None:
        return None

    try:
        import tomllib

        payload = tomllib.loads(pyproject_file.read_text(encoding="utf-8"))
    except Exception:
        return None

    dependencies = payload.get("tool", {}).get("poetry", {}).get("dependencies", {})
    dev_dependencies = payload.get("tool", {}).get("poetry", {}).get("group", {}).get("dev", {}).get(
        "dependencies", {}
    )

    if not isinstance(dependencies, dict):
        dependencies = {}
    if not isinstance(dev_dependencies, dict):
        dev_dependencies = {}

    requirement_lines: list[str] = []
    for name in sorted({*dependencies.keys(), *dev_dependencies.keys()}):
        if str(name).lower() == "python":
            continue
        requirement_lines.append(str(name))

    if not requirement_lines:
        return None

    generated_file = output_dir / "requirements.generated.txt"
    generated_file.write_text("\n".join(requirement_lines) + "\n", encoding="utf-8")
    return generated_file


def analyze_circular_dependencies(source_dir: Path) -> List[Cycle]:
    """Detect circular import dependencies for a source directory."""
    graph = _build_dependency_graph(source_dir)
    components = _strongly_connected_components(graph)

    cycles: list[Cycle] = []
    for component in components:
        if len(component) > 1:
            cycles.append(Cycle(modules=tuple(sorted(component))))
            continue

        module = component[0]
        if module in graph.get(module, set()):
            cycles.append(Cycle(modules=(module,)))

    cycles.sort(key=lambda item: (-item.length, item.modules))
    return cycles


def analyze_unused_dependencies(requirements_file: Path, source_dir: Path) -> List[str]:
    """Find requirement packages that are not imported by source code."""
    packages = _parse_requirements(requirements_file)
    import_roots = {name.lower() for name in _collect_import_roots(source_dir)}

    unused: list[str] = []
    for package in packages:
        import_aliases = {alias.lower() for alias in _candidate_import_names(package)}
        if import_aliases.isdisjoint(import_roots):
            unused.append(package)

    return sorted(unused)


def analyze_security_vulnerabilities(requirements_file: Path) -> List[Vulnerability]:
    """Check requirement dependencies against known CVEs via safety."""
    if not requirements_file.exists() or not requirements_file.is_file():
        raise FileNotFoundError(f"requirements file not found: {requirements_file}")

    payload = _run_safety(requirements_file)
    if payload is None:
        return []

    return _parse_safety_vulnerabilities(payload)


def render_dependency_graph(source_dir: Path, output_dir: Path | None = None) -> Path:
    """Render dependency graph visualization for source directory.

    Rendering strategy:
    - pydeps SVG render when pydeps is available
    - DOT graph output fallback
    - DOT -> SVG conversion when graphviz dot is available
    """
    source_dir = Path(source_dir).expanduser().resolve()
    graph = _build_dependency_graph(source_dir)

    target_dir = (
        Path(output_dir).expanduser().resolve()
        if output_dir is not None
        else (source_dir.parent / ".dependency-analysis").resolve()
    )
    target_dir.mkdir(parents=True, exist_ok=True)

    pydeps_binary = shutil.which("pydeps")
    if pydeps_binary is not None:
        pydeps_svg = target_dir / "dependency_graph_pydeps.svg"
        command = [
            pydeps_binary,
            str(source_dir),
            "--noshow",
            "--output",
            str(pydeps_svg),
        ]
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        if completed.returncode == 0 and pydeps_svg.exists():
            return pydeps_svg

    dot_path = target_dir / "dependency_graph.dot"
    dot_path.write_text(_dependency_graph_to_dot(graph), encoding="utf-8")

    dot_binary = shutil.which("dot")
    if dot_binary is not None:
        svg_path = target_dir / "dependency_graph.svg"
        completed = subprocess.run(
            [dot_binary, "-Tsvg", str(dot_path), "-o", str(svg_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode == 0 and svg_path.exists():
            return svg_path

    return dot_path


def generate_dependency_report(source_dir: Path) -> str:
    """Generate a Markdown dependency analysis report with visualization."""
    source_dir = Path(source_dir).expanduser().resolve()
    graph = _build_dependency_graph(source_dir)
    cycles = analyze_circular_dependencies(source_dir)

    modules_count = len(graph)
    edge_count = sum(len(targets) for targets in graph.values())

    visualization_path = render_dependency_graph(source_dir)

    requirements_file = _discover_requirements_file(source_dir)
    generated_requirements = False
    if requirements_file is None:
        requirements_file = _requirements_from_pyproject(source_dir, visualization_path.parent)
        generated_requirements = requirements_file is not None

    if requirements_file is not None:
        unused_dependencies = analyze_unused_dependencies(requirements_file, source_dir)
        vulnerabilities = analyze_security_vulnerabilities(requirements_file)
        requirements_label = str(requirements_file)
        if generated_requirements:
            requirements_label += " (generated from pyproject.toml)"
    else:
        unused_dependencies = []
        vulnerabilities = []
        requirements_label = "not found"

    cycles_markdown = "\n".join(
        f"- {' -> '.join(cycle.modules)}" for cycle in cycles
    ) or "- None detected"

    unused_markdown = "\n".join(f"- {item}" for item in unused_dependencies) or "- None detected"

    vulnerabilities_markdown = (
        "\n".join(
            f"- {item.package} ({item.installed_version}): {item.vulnerability_id}"
            f" severity={item.severity}"
            for item in vulnerabilities
        )
        or "- None detected or safety unavailable"
    )

    mermaid = _dependency_graph_to_mermaid(graph)

    report = textwrap.dedent(
        f"""
        # Dependency Analysis Report

        Source directory: {source_dir}

        ## Summary

        - Modules analyzed: {modules_count}
        - Internal dependency edges: {edge_count}
        - Circular dependency groups: {len(cycles)}
        - Requirements source: {requirements_label}
        - Unused dependencies: {len(unused_dependencies)}
        - Vulnerabilities: {len(vulnerabilities)}
        - Visualization artifact: {visualization_path}

        ## Circular Dependencies

        {cycles_markdown}

        ## Unused Dependencies

        {unused_markdown}

        ## Security Vulnerabilities

        {vulnerabilities_markdown}

        ## Dependency Graph

        ```mermaid
        {mermaid}
        ```
        """
    ).strip()

    return report + "\n"


__all__ = [
    "Cycle",
    "Vulnerability",
    "analyze_circular_dependencies",
    "analyze_unused_dependencies",
    "analyze_security_vulnerabilities",
    "render_dependency_graph",
    "generate_dependency_report",
]
