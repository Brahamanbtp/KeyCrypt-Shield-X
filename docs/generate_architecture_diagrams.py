#!/usr/bin/env python3
"""Architecture diagram generator from Python code structure.

Capabilities:
- dependency graph analysis from import statements
- PlantUML component diagram generation with module clustering
- call-trace sequence diagram generation from discovered function calls
- optional PlantUML rendering to PNG artifacts
"""

from __future__ import annotations

import argparse
import ast
import os
import re
import shutil
import subprocess
import sys
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


@dataclass
class DependencyGraph:
    """Code dependency and call graph derived from source analysis."""

    source_dir: Path
    root_package: str
    modules: List[str]
    module_files: Dict[str, Path]
    dependencies: Dict[str, List[str]]
    reverse_dependencies: Dict[str, List[str]]
    external_dependencies: Dict[str, List[str]]
    clusters: Dict[str, List[str]]
    functions: Dict[str, List[str]]
    function_calls: Dict[str, List[str]]


@dataclass
class _CallRecord:
    kind: str
    value: str
    base: str | None = None
    attr: str | None = None


@dataclass
class _FunctionRecord:
    module: str
    qualname: str
    name: str
    class_name: str | None
    calls: List[_CallRecord] = field(default_factory=list)

    @property
    def full_name(self) -> str:
        return f"{self.module}.{self.qualname}"


@dataclass
class _ModuleAnalysis:
    module: str
    internal_imports: set[str] = field(default_factory=set)
    external_imports: set[str] = field(default_factory=set)
    imported_module_aliases: Dict[str, str] = field(default_factory=dict)
    imported_symbol_aliases: Dict[str, str] = field(default_factory=dict)
    functions: List[_FunctionRecord] = field(default_factory=list)


_LAST_ANALYZED_GRAPH: DependencyGraph | None = None


def _iter_python_files(source_dir: Path) -> List[Path]:
    if not source_dir.exists() or not source_dir.is_dir():
        raise FileNotFoundError(f"source_dir must be an existing directory: {source_dir}")
    return sorted(path for path in source_dir.rglob("*.py") if path.is_file())


def _module_name_for_file(file_path: Path, source_dir: Path, root_package: str) -> str:
    rel = file_path.resolve().relative_to(source_dir.resolve())
    if rel.name == "__init__.py":
        parts = rel.parts[:-1]
    else:
        parts = rel.with_suffix("").parts

    if not parts:
        return root_package

    return ".".join([root_package, *parts])


def _dotted_attr_path(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id

    if isinstance(node, ast.Attribute):
        parent = _dotted_attr_path(node.value)
        if parent is None:
            return None
        return f"{parent}.{node.attr}"

    return None


def _closest_known_module(module_name: str, known_modules: set[str]) -> str | None:
    candidate = module_name
    while candidate:
        if candidate in known_modules:
            return candidate
        if "." not in candidate:
            break
        candidate = candidate.rsplit(".", 1)[0]
    return None


def _resolve_import_from_module(current_module: str, module: str | None, level: int) -> str:
    if level <= 0:
        return module or ""

    current_parts = current_module.split(".")[:-1]
    parent_parts = current_parts[: max(0, len(current_parts) - (level - 1))]
    if module:
        parent_parts.extend(module.split("."))
    return ".".join(parent_parts)


def _external_root(module_name: str) -> str:
    return module_name.split(".", 1)[0]


class _ModuleAstAnalyzer(ast.NodeVisitor):
    def __init__(self, *, module: str, known_modules: set[str], root_package: str) -> None:
        self.module = module
        self.known_modules = known_modules
        self.root_package = root_package
        self.analysis = _ModuleAnalysis(module=module)
        self._scope_stack: List[str] = []
        self._class_stack: List[str] = []
        self._function_stack: List[_FunctionRecord] = []

    def visit_Import(self, node: ast.Import) -> Any:
        for alias in node.names:
            imported = alias.name
            local_module = _closest_known_module(imported, self.known_modules)
            if local_module is not None:
                self.analysis.internal_imports.add(local_module)
            else:
                self.analysis.external_imports.add(_external_root(imported))

            alias_name = alias.asname or imported.split(".", 1)[0]
            self.analysis.imported_module_aliases[alias_name] = imported

        return None

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        resolved_module = _resolve_import_from_module(self.module, node.module, node.level)
        if resolved_module:
            local_module = _closest_known_module(resolved_module, self.known_modules)
            if local_module is not None:
                self.analysis.internal_imports.add(local_module)
            else:
                self.analysis.external_imports.add(_external_root(resolved_module))

        for alias in node.names:
            if alias.name == "*":
                continue

            alias_name = alias.asname or alias.name
            full_symbol = f"{resolved_module}.{alias.name}" if resolved_module else alias.name
            self.analysis.imported_symbol_aliases[alias_name] = full_symbol

            local_symbol_module = _closest_known_module(full_symbol, self.known_modules)
            if local_symbol_module is not None:
                self.analysis.internal_imports.add(local_symbol_module)

            if resolved_module:
                self.analysis.imported_module_aliases.setdefault(alias_name, full_symbol)

        return None

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        self._scope_stack.append(node.name)
        self._class_stack.append(node.name)
        self.generic_visit(node)
        self._class_stack.pop()
        self._scope_stack.pop()
        return None

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        self._record_function(node, is_async=False)
        return None

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self._record_function(node, is_async=True)
        return None

    def visit_Call(self, node: ast.Call) -> Any:
        if not self._function_stack:
            self.generic_visit(node)
            return None

        current_fn = self._function_stack[-1]

        if isinstance(node.func, ast.Name):
            current_fn.calls.append(_CallRecord(kind="name", value=node.func.id))
        elif isinstance(node.func, ast.Attribute):
            path = _dotted_attr_path(node.func)
            if path:
                base = path.split(".", 1)[0]
                current_fn.calls.append(
                    _CallRecord(
                        kind="attr",
                        value=path,
                        base=base,
                        attr=node.func.attr,
                    )
                )
            else:
                current_fn.calls.append(
                    _CallRecord(
                        kind="attr",
                        value=node.func.attr,
                        base=None,
                        attr=node.func.attr,
                    )
                )

        self.generic_visit(node)
        return None

    def _record_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef, *, is_async: bool) -> None:
        _ = is_async
        qualname = ".".join([*self._scope_stack, node.name]) if self._scope_stack else node.name
        function_record = _FunctionRecord(
            module=self.module,
            qualname=qualname,
            name=node.name,
            class_name=self._class_stack[-1] if self._class_stack else None,
        )

        self.analysis.functions.append(function_record)
        self._function_stack.append(function_record)
        self._scope_stack.append(node.name)
        self.generic_visit(node)
        self._scope_stack.pop()
        self._function_stack.pop()


def _module_cluster(module_name: str, root_package: str) -> str:
    parts = module_name.split(".")
    if parts and parts[0] == root_package:
        parts = parts[1:]
    if not parts:
        return root_package
    return parts[0]


def _choose_function_candidate(candidate: str, known_functions: set[str]) -> str | None:
    if candidate in known_functions:
        return candidate

    suffix = f".{candidate}"
    matches = [name for name in known_functions if name.endswith(suffix)]
    if len(matches) == 1:
        return matches[0]

    return None


def _resolve_call_target(
    *,
    call: _CallRecord,
    function_record: _FunctionRecord,
    module_analysis: _ModuleAnalysis,
    known_functions: set[str],
    module_top_level_functions: Dict[str, Dict[str, str]],
    class_methods: Dict[str, Dict[str, Dict[str, str]]],
) -> str:
    module_name = function_record.module
    class_name = function_record.class_name

    if call.kind == "name":
        call_name = call.value

        if class_name and call_name in class_methods.get(module_name, {}).get(class_name, {}):
            return class_methods[module_name][class_name][call_name]

        if call_name in module_top_level_functions.get(module_name, {}):
            return module_top_level_functions[module_name][call_name]

        symbol_target = module_analysis.imported_symbol_aliases.get(call_name)
        if symbol_target:
            candidate = _choose_function_candidate(symbol_target, known_functions)
            if candidate is not None:
                return candidate

        maybe = _choose_function_candidate(call_name, known_functions)
        if maybe is not None:
            return maybe

        return f"external:{call_name}"

    base = call.base or ""
    attr = call.attr or call.value

    if base in {"self", "cls"} and class_name:
        method_target = class_methods.get(module_name, {}).get(class_name, {}).get(attr)
        if method_target:
            return method_target

    if base in module_analysis.imported_module_aliases:
        imported_module = module_analysis.imported_module_aliases[base]
        candidate = _choose_function_candidate(f"{imported_module}.{attr}", known_functions)
        if candidate is not None:
            return candidate

    if call.value:
        candidate = _choose_function_candidate(call.value, known_functions)
        if candidate is not None:
            return candidate

    return f"external:{call.value or attr}"


def analyze_dependencies(source_dir: Path) -> DependencyGraph:
    """Analyze import dependencies and build an internal dependency graph."""
    global _LAST_ANALYZED_GRAPH

    resolved_source = source_dir.resolve()
    root_package = resolved_source.name

    files = _iter_python_files(resolved_source)
    module_files: Dict[str, Path] = {}
    for file_path in files:
        module_name = _module_name_for_file(file_path, resolved_source, root_package)
        module_files[module_name] = file_path

    known_modules = set(module_files)

    analyses: Dict[str, _ModuleAnalysis] = {}
    dependencies_raw: Dict[str, set[str]] = defaultdict(set)
    external_raw: Dict[str, set[str]] = defaultdict(set)

    for module_name, file_path in sorted(module_files.items(), key=lambda item: item[0]):
        source = file_path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(source, filename=str(file_path))

        analyzer = _ModuleAstAnalyzer(
            module=module_name,
            known_modules=known_modules,
            root_package=root_package,
        )
        analyzer.visit(tree)

        analyses[module_name] = analyzer.analysis
        dependencies_raw[module_name].update(analyzer.analysis.internal_imports)
        external_raw[module_name].update(analyzer.analysis.external_imports)

    functions_by_module: Dict[str, List[str]] = defaultdict(list)
    module_top_level_functions: Dict[str, Dict[str, str]] = defaultdict(dict)
    class_methods: Dict[str, Dict[str, Dict[str, str]]] = defaultdict(lambda: defaultdict(dict))

    function_records: Dict[str, tuple[_FunctionRecord, _ModuleAnalysis]] = {}
    for module_name, analysis in analyses.items():
        for function_record in analysis.functions:
            full_name = function_record.full_name
            functions_by_module[module_name].append(full_name)
            function_records[full_name] = (function_record, analysis)

            if function_record.class_name is None and "." not in function_record.qualname:
                module_top_level_functions[module_name][function_record.name] = full_name

            if function_record.class_name is not None:
                class_methods[module_name][function_record.class_name][function_record.name] = full_name

    known_functions = set(function_records)

    function_calls_raw: Dict[str, set[str]] = defaultdict(set)
    for full_name, (function_record, module_analysis) in function_records.items():
        for call in function_record.calls:
            target = _resolve_call_target(
                call=call,
                function_record=function_record,
                module_analysis=module_analysis,
                known_functions=known_functions,
                module_top_level_functions=module_top_level_functions,
                class_methods=class_methods,
            )
            function_calls_raw[full_name].add(target)

    reverse_raw: Dict[str, set[str]] = defaultdict(set)
    for module_name, deps in dependencies_raw.items():
        for dep in deps:
            if dep == module_name:
                continue
            reverse_raw[dep].add(module_name)

    clusters_raw: Dict[str, set[str]] = defaultdict(set)
    for module_name in module_files:
        clusters_raw[_module_cluster(module_name, root_package)].add(module_name)

    graph = DependencyGraph(
        source_dir=resolved_source,
        root_package=root_package,
        modules=sorted(module_files),
        module_files={name: module_files[name] for name in sorted(module_files)},
        dependencies={
            name: sorted(dep for dep in dependencies_raw.get(name, set()) if dep != name)
            for name in sorted(module_files)
        },
        reverse_dependencies={
            name: sorted(reverse_raw.get(name, set()))
            for name in sorted(module_files)
        },
        external_dependencies={
            name: sorted(external_raw.get(name, set()))
            for name in sorted(module_files)
        },
        clusters={
            cluster: sorted(modules)
            for cluster, modules in sorted(clusters_raw.items(), key=lambda item: item[0])
        },
        functions={
            name: sorted(functions_by_module.get(name, []))
            for name in sorted(module_files)
        },
        function_calls={
            name: sorted(function_calls_raw.get(name, set()))
            for name in sorted(function_records)
        },
    )

    _LAST_ANALYZED_GRAPH = graph
    return graph


def _alias_map(items: Sequence[str], prefix: str) -> Dict[str, str]:
    return {item: f"{prefix}{index + 1}" for index, item in enumerate(sorted(items))}


def _display_module(module_name: str, root_package: str) -> str:
    if module_name.startswith(root_package + "."):
        return module_name[len(root_package) + 1 :]
    return module_name


def generate_component_diagram(graph: DependencyGraph) -> str:
    """Generate a PlantUML component diagram from dependency graph data."""
    lines: List[str] = [
        "@startuml",
        "title Architecture Component Diagram",
        "left to right direction",
        "skinparam componentStyle rectangle",
    ]

    module_aliases = _alias_map(graph.modules, "M")

    external_nodes: set[str] = set()
    for deps in graph.external_dependencies.values():
        external_nodes.update(deps)
    external_aliases = _alias_map(sorted(external_nodes), "E")

    for cluster_name, modules in sorted(graph.clusters.items(), key=lambda item: item[0]):
        cluster_alias = re.sub(r"[^A-Za-z0-9_]", "_", cluster_name)
        lines.append(f'package "{cluster_name}" as cluster_{cluster_alias} {{')
        for module_name in modules:
            alias = module_aliases[module_name]
            label = _display_module(module_name, graph.root_package)
            lines.append(f'  component "{label}" as {alias}')
        lines.append("}")

    if external_aliases:
        lines.append('package "external" {')
        for ext_name, alias in sorted(external_aliases.items(), key=lambda item: item[0]):
            lines.append(f'  component "{ext_name}" as {alias}')
        lines.append("}")

    emitted_edges: set[tuple[str, str, str]] = set()
    for module_name, deps in sorted(graph.dependencies.items(), key=lambda item: item[0]):
        source_alias = module_aliases[module_name]
        for dep in deps:
            if dep not in module_aliases:
                continue
            target_alias = module_aliases[dep]
            edge = (source_alias, target_alias, "-->")
            if edge in emitted_edges:
                continue
            emitted_edges.add(edge)
            lines.append(f"{source_alias} --> {target_alias}")

    for module_name, external_deps in sorted(graph.external_dependencies.items(), key=lambda item: item[0]):
        source_alias = module_aliases[module_name]
        for ext_name in external_deps:
            target_alias = external_aliases.get(ext_name)
            if target_alias is None:
                continue
            edge = (source_alias, target_alias, "..>")
            if edge in emitted_edges:
                continue
            emitted_edges.add(edge)
            lines.append(f"{source_alias} ..> {target_alias}")

    lines.append("@enduml")
    return "\n".join(lines)


def _resolve_operation_function(graph: DependencyGraph, operation: str) -> str:
    requested = operation.strip()
    if not requested:
        raise ValueError("operation must be a non-empty string")

    available = set(graph.function_calls)
    if requested in available:
        return requested

    normalized = requested.replace(":", ".")
    if normalized in available:
        return normalized

    suffix_matches = [name for name in available if name.endswith(f".{requested}")]
    if len(suffix_matches) == 1:
        return suffix_matches[0]

    normalized_suffix_matches = [name for name in available if name.endswith(f".{normalized}")]
    if len(normalized_suffix_matches) == 1:
        return normalized_suffix_matches[0]

    if suffix_matches:
        return sorted(suffix_matches)[0]
    if normalized_suffix_matches:
        return sorted(normalized_suffix_matches)[0]

    raise ValueError(f"operation not found in function call graph: {operation}")


def _display_participant(name: str, root_package: str) -> str:
    if name.startswith("external:"):
        return name.replace("external:", "ext.", 1)

    if name.startswith(root_package + "."):
        return name[len(root_package) + 1 :]

    return name


def generate_sequence_diagram(operation: str) -> str:
    """Trace function calls from an operation and emit PlantUML sequence text."""
    if _LAST_ANALYZED_GRAPH is None:
        raise RuntimeError("No analyzed graph found. Run analyze_dependencies() before sequence generation.")

    graph = _LAST_ANALYZED_GRAPH
    start_function = _resolve_operation_function(graph, operation)

    max_depth = 6
    max_edges = 80

    queue: deque[tuple[str, int]] = deque([(start_function, 0)])
    visited_functions: set[str] = {start_function}
    edges: List[tuple[str, str]] = []

    while queue and len(edges) < max_edges:
        caller, depth = queue.popleft()
        if depth >= max_depth:
            continue

        callees = graph.function_calls.get(caller, [])
        for callee in callees[:12]:
            edges.append((caller, callee))
            if callee in graph.function_calls and callee not in visited_functions:
                visited_functions.add(callee)
                queue.append((callee, depth + 1))

            if len(edges) >= max_edges:
                break

    participants: List[str] = [start_function]
    for caller, callee in edges:
        if caller not in participants:
            participants.append(caller)
        if callee not in participants:
            participants.append(callee)

    alias_map = {name: f"P{index + 1}" for index, name in enumerate(participants)}

    lines: List[str] = [
        "@startuml",
        f"title Sequence Diagram: {start_function}",
        "autonumber",
    ]

    for participant in participants:
        alias = alias_map[participant]
        label = _display_participant(participant, graph.root_package)
        lines.append(f'participant "{label}" as {alias}')

    if not edges:
        lines.append(f'{alias_map[start_function]} -> {alias_map[start_function]} : entrypoint')
    else:
        for caller, callee in edges:
            source = alias_map[caller]
            target = alias_map[callee]
            if callee.startswith("external:"):
                label = callee.replace("external:", "", 1)
            else:
                label = "call"
            lines.append(f"{source} -> {target} : {label}")

    lines.append("@enduml")
    return "\n".join(lines)


def render_diagrams(diagrams: List[str], output_dir: Path) -> None:
    """Write and render PlantUML diagrams to output directory."""
    if not diagrams:
        raise ValueError("diagrams must be non-empty")

    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    diagram_paths: List[Path] = []
    for index, diagram in enumerate(diagrams, start=1):
        path = output_dir / f"diagram_{index:02d}.puml"
        path.write_text(diagram.strip() + "\n", encoding="utf-8")
        diagram_paths.append(path)

    plantuml_bin = shutil.which("plantuml")
    if plantuml_bin:
        for diagram_path in diagram_paths:
            result = subprocess.run(
                [plantuml_bin, "-tpng", str(diagram_path)],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                message = (result.stderr or result.stdout or "plantuml render failed").strip()
                raise RuntimeError(f"PlantUML rendering failed for {diagram_path.name}: {message}")
        return

    jar_path = os.getenv("PLANTUML_JAR", "").strip()
    java_bin = shutil.which("java")
    if jar_path and java_bin:
        jar = Path(jar_path)
        if not jar.exists() or not jar.is_file():
            raise FileNotFoundError(f"PLANTUML_JAR does not exist: {jar}")

        for diagram_path in diagram_paths:
            result = subprocess.run(
                [java_bin, "-jar", str(jar), "-tpng", str(diagram_path)],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                message = (result.stderr or result.stdout or "plantuml jar render failed").strip()
                raise RuntimeError(f"PlantUML JAR rendering failed for {diagram_path.name}: {message}")
        return


def _default_operations(graph: DependencyGraph, limit: int = 3) -> List[str]:
    preferred = [
        name
        for name in graph.function_calls
        if any(token in name for token in ("encrypt", "decrypt", "generate", "load", "main"))
    ]
    if preferred:
        return sorted(preferred)[:limit]
    return sorted(graph.function_calls)[:limit]


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate architecture diagrams from source code")
    parser.add_argument(
        "--source-dir",
        type=Path,
        default=PROJECT_ROOT / "src",
        help="Directory containing Python source code",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=PROJECT_ROOT / "docs" / "architecture-diagrams",
        help="Directory for generated PlantUML/PNG artifacts",
    )
    parser.add_argument(
        "--operation",
        action="append",
        default=[],
        help="Operation/function to trace into a sequence diagram (repeatable)",
    )
    parser.add_argument(
        "--skip-render",
        action="store_true",
        help="Write .puml files only and skip PNG rendering",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()

    graph = analyze_dependencies(args.source_dir)
    diagrams: List[str] = [generate_component_diagram(graph)]

    operations = list(args.operation) if args.operation else _default_operations(graph)
    for operation in operations:
        try:
            diagrams.append(generate_sequence_diagram(operation))
        except ValueError:
            continue

    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.skip_render:
        for index, diagram in enumerate(diagrams, start=1):
            (output_dir / f"diagram_{index:02d}.puml").write_text(diagram.strip() + "\n", encoding="utf-8")
    else:
        render_diagrams(diagrams, output_dir)


if __name__ == "__main__":
    main()
