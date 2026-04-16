#!/usr/bin/env python3
"""Automatic API reference documentation generator.

Features:
- AST-based docstring extraction from Python modules
- Markdown API reference rendering with cross-references
- OpenAPI 3.x spec extraction from a FastAPI module
- Sphinx HTML documentation generation
"""

from __future__ import annotations

import argparse
import ast
import importlib
import importlib.util
import json
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


@dataclass
class FunctionDoc:
    """Structured documentation extracted for one function or method."""

    module: str
    file_path: Path
    qualname: str
    name: str
    signature: str
    docstring: str
    summary: str
    lineno: int
    is_async: bool = False
    calls: List[str] = field(default_factory=list)


def _get_jinja_environment() -> Any:
    try:
        from jinja2 import Environment, StrictUndefined
    except ModuleNotFoundError as exc:
        raise RuntimeError("Jinja2 is required. Install with: pip install jinja2") from exc

    return Environment(
        autoescape=False,
        trim_blocks=True,
        lstrip_blocks=True,
        undefined=StrictUndefined,
    )


def _iter_python_files(module_path: Path) -> List[Path]:
    if not module_path.exists():
        raise FileNotFoundError(f"module_path not found: {module_path}")

    if module_path.is_file():
        if module_path.suffix != ".py":
            raise ValueError(f"module_path file must be .py: {module_path}")
        return [module_path]

    return sorted(path for path in module_path.rglob("*.py") if path.is_file())


def _module_name_for_file(file_path: Path, root_dir: Path) -> str:
    relative = file_path.resolve().relative_to(root_dir.resolve())

    if relative.name == "__init__.py":
        parts = relative.parts[:-1]
    else:
        parts = relative.with_suffix("").parts

    if not parts:
        return file_path.stem

    return ".".join(parts)


def _format_arg(arg: ast.arg, default: ast.expr | None) -> str:
    rendered = arg.arg
    if arg.annotation is not None:
        rendered += f": {ast.unparse(arg.annotation)}"
    if default is not None:
        rendered += f" = {ast.unparse(default)}"
    return rendered


def _format_vararg(arg: ast.arg | None, prefix: str) -> str | None:
    if arg is None:
        return None
    rendered = f"{prefix}{arg.arg}"
    if arg.annotation is not None:
        rendered += f": {ast.unparse(arg.annotation)}"
    return rendered


def _format_signature(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    args = node.args
    rendered: List[str] = []

    positional = list(args.posonlyargs) + list(args.args)
    defaults = list(args.defaults)
    default_start = len(positional) - len(defaults)

    for index, arg in enumerate(positional):
        default = defaults[index - default_start] if index >= default_start else None
        rendered.append(_format_arg(arg, default))
        if index + 1 == len(args.posonlyargs):
            rendered.append("/")

    vararg = _format_vararg(args.vararg, "*")
    if vararg is not None:
        rendered.append(vararg)
    elif args.kwonlyargs:
        rendered.append("*")

    for kwonly_arg, kw_default in zip(args.kwonlyargs, args.kw_defaults):
        rendered.append(_format_arg(kwonly_arg, kw_default))

    kwarg = _format_vararg(args.kwarg, "**")
    if kwarg is not None:
        rendered.append(kwarg)

    signature = f"{node.name}({', '.join(part for part in rendered if part)})"
    if node.returns is not None:
        signature += f" -> {ast.unparse(node.returns)}"

    return signature


def _collect_call_names(node: ast.AST) -> List[str]:
    names: set[str] = set()
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue

        if isinstance(child.func, ast.Name):
            names.add(child.func.id)
        elif isinstance(child.func, ast.Attribute):
            names.add(child.func.attr)

    return sorted(names)


class _DocstringExtractor(ast.NodeVisitor):
    def __init__(self, *, module_name: str, file_path: Path) -> None:
        self.module_name = module_name
        self.file_path = file_path
        self.scope_stack: List[str] = []
        self.docs: List[FunctionDoc] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        self.scope_stack.append(node.name)
        self.generic_visit(node)
        self.scope_stack.pop()
        return None

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        self._record_function(node, is_async=False)
        self.scope_stack.append(node.name)
        self.generic_visit(node)
        self.scope_stack.pop()
        return None

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self._record_function(node, is_async=True)
        self.scope_stack.append(node.name)
        self.generic_visit(node)
        self.scope_stack.pop()
        return None

    def _record_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef, *, is_async: bool) -> None:
        docstring = ast.get_docstring(node, clean=True) or ""
        summary = docstring.splitlines()[0].strip() if docstring.strip() else "No docstring provided."
        qual_parts = [*self.scope_stack, node.name]
        qualname = ".".join(qual_parts)

        self.docs.append(
            FunctionDoc(
                module=self.module_name,
                file_path=self.file_path,
                qualname=qualname,
                name=node.name,
                signature=_format_signature(node),
                docstring=docstring,
                summary=summary,
                lineno=int(getattr(node, "lineno", 0)),
                is_async=is_async,
                calls=_collect_call_names(node),
            )
        )


def _slugify(value: str) -> str:
    lowered = value.lower()
    slug = re.sub(r"[^a-z0-9]+", "-", lowered).strip("-")
    return slug or "ref"


def _doc_id(doc: FunctionDoc) -> str:
    return f"{doc.module}.{doc.qualname}"


def _infer_related_function_qualnames(function_docs: Sequence[FunctionDoc]) -> Dict[str, List[str]]:
    by_name: Dict[str, List[FunctionDoc]] = defaultdict(list)
    for doc in function_docs:
        by_name[doc.name].append(doc)

    token_pattern = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
    related: Dict[str, List[str]] = {}

    for doc in function_docs:
        candidates: set[str] = set()

        for call_name in doc.calls:
            if call_name in by_name and call_name != doc.name:
                candidates.add(call_name)

        for token in token_pattern.findall(doc.docstring):
            if token in by_name and token != doc.name:
                candidates.add(token)

        prefix = doc.name.split("_", 1)[0]
        if len(prefix) >= 3:
            for other in function_docs:
                if other.qualname != doc.qualname and other.name.startswith(prefix):
                    candidates.add(other.name)

        resolved: List[str] = []
        for candidate_name in sorted(candidates):
            options = by_name.get(candidate_name, [])
            if not options:
                continue

            same_module = [item for item in options if item.module == doc.module]
            target = same_module[0] if same_module else options[0]
            resolved.append(_doc_id(target))

        related[_doc_id(doc)] = sorted(set(resolved))

    return related


def extract_docstrings(module_path: Path) -> List[FunctionDoc]:
    """Parse Python files and extract function/method docstrings.

    Args:
        module_path: Python file or directory of Python modules.

    Returns:
        List of extracted function documentation records.
    """
    files = _iter_python_files(module_path)
    root_dir = module_path if module_path.is_dir() else module_path.parent

    extracted: List[FunctionDoc] = []
    for file_path in files:
        try:
            source = file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            source = file_path.read_text(encoding="utf-8", errors="ignore")

        tree = ast.parse(source, filename=str(file_path))
        module_name = _module_name_for_file(file_path, root_dir)

        extractor = _DocstringExtractor(module_name=module_name, file_path=file_path)
        extractor.visit(tree)
        extracted.extend(extractor.docs)

    extracted.sort(key=lambda item: (item.module, item.qualname, item.lineno))
    return extracted


def generate_markdown_reference(function_docs: List[FunctionDoc]) -> str:
    """Convert extracted function docs into Markdown API reference text."""
    env = _get_jinja_environment()

    related_lookup = _infer_related_function_qualnames(function_docs)
    anchors = {
        _doc_id(doc): _slugify(f"{doc.module}-{doc.qualname}")
        for doc in function_docs
    }
    docs_by_qualname = {_doc_id(doc): doc for doc in function_docs}

    modules: Dict[str, List[dict[str, Any]]] = defaultdict(list)
    for doc in function_docs:
        doc_key = _doc_id(doc)
        related_links: List[dict[str, str]] = []
        for related_qualname in related_lookup.get(doc_key, []):
            target = docs_by_qualname.get(related_qualname)
            if target is None:
                continue
            related_links.append(
                {
                    "label": f"{target.module}.{target.qualname}",
                    "anchor": anchors[_doc_id(target)],
                }
            )

        modules[doc.module].append(
            {
                "module": doc.module,
                "qualname": doc.qualname,
                "signature": doc.signature,
                "summary": doc.summary,
                "docstring": doc.docstring,
                "lineno": doc.lineno,
                "is_async": doc.is_async,
                "file_path": str(doc.file_path),
                "anchor": anchors[doc_key],
                "related_links": related_links,
            }
        )

    ordered_modules = [
        {
            "name": module_name,
            "anchor": _slugify(f"module-{module_name}"),
            "functions": sorted(items, key=lambda item: (item["qualname"], item["lineno"])),
        }
        for module_name, items in sorted(modules.items(), key=lambda pair: pair[0])
    ]

    template = env.from_string(
        """
# API Reference

_Auto-generated by docs/generate_api_reference.py._

## Modules

{% for module in modules %}
- [{{ module.name }}](#{{ module.anchor }})
{% endfor %}

{% for module in modules %}
## <a id="{{ module.anchor }}"></a>{{ module.name }}

{% for fn in module.functions %}
### <a id="{{ fn.anchor }}"></a>`{{ fn.signature }}`

- Qualified Name: `{{ fn.module }}.{{ fn.qualname }}`
- Defined In: `{{ fn.file_path }}`:{{ fn.lineno }}
- Async: {{ "yes" if fn.is_async else "no" }}

{{ fn.summary }}

{% if fn.docstring %}
```text
{{ fn.docstring }}
```
{% endif %}

{% if fn.related_links %}
Related Functions:
{% for related in fn.related_links %}
- [{{ related.label }}](#{{ related.anchor }})
{% endfor %}
{% endif %}

{% endfor %}
{% endfor %}
""".strip()
    )

    return template.render(modules=ordered_modules)


def generate_openapi_spec(api_module: str) -> dict:
    """Generate an OpenAPI 3.x specification dictionary from a FastAPI module."""
    module = importlib.import_module(api_module)

    app = getattr(module, "app", None)
    if app is None:
        for value in vars(module).values():
            if value.__class__.__name__ == "FastAPI" and callable(getattr(value, "openapi", None)):
                app = value
                break

    if app is None:
        raise ValueError(f"No FastAPI app instance found in module '{api_module}'")

    openapi_method = getattr(app, "openapi", None)
    if not callable(openapi_method):
        raise TypeError(f"Resolved app in '{api_module}' does not expose openapi()")

    spec = openapi_method()
    if not isinstance(spec, dict):
        raise TypeError("openapi() returned a non-dictionary object")

    version = str(spec.get("openapi", ""))
    if not version.startswith("3."):
        raise ValueError(f"Expected OpenAPI 3.x spec, got '{version or 'unknown'}'")

    return spec


def _discover_python_modules(source_dir: Path) -> List[str]:
    modules: set[str] = set()

    for path in source_dir.rglob("*.py"):
        if not path.is_file():
            continue

        rel = path.relative_to(source_dir)
        if rel.name == "__init__.py":
            parts = rel.parts[:-1]
        else:
            parts = rel.with_suffix("").parts

        if not parts:
            continue

        if any(part.startswith(".") for part in parts):
            continue

        modules.add(".".join(parts))

    return sorted(modules)


def generate_sphinx_docs(source_dir: Path, output_dir: Path) -> None:
    """Generate Sphinx HTML documentation from Python source modules."""
    source_dir = source_dir.resolve()
    output_dir = output_dir.resolve()

    if not source_dir.exists() or not source_dir.is_dir():
        raise FileNotFoundError(f"source_dir must be an existing directory: {source_dir}")

    if importlib.util.find_spec("sphinx") is None:
        raise RuntimeError("Sphinx is required. Install with: pip install sphinx")

    modules = _discover_python_modules(source_dir)
    if not modules:
        raise ValueError(f"No Python modules found under source_dir: {source_dir}")

    env = _get_jinja_environment()

    sphinx_source = output_dir / "_sphinx_source"
    html_output = output_dir / "html"
    sphinx_source.mkdir(parents=True, exist_ok=True)
    html_output.mkdir(parents=True, exist_ok=True)

    conf_template = env.from_string(
        """
import os
import sys

sys.path.insert(0, r"{{ python_path }}")

project = "{{ project_name }}"
extensions = ["sphinx.ext.autodoc", "sphinx.ext.napoleon", "sphinx.ext.viewcode"]
templates_path = []
exclude_patterns = []
html_theme = "alabaster"
""".strip()
    )

    modules_template = env.from_string(
        """
API Modules
===========

{% for module in modules %}
{{ module }}
{{ "-" * module|length }}

.. automodule:: {{ module }}
   :members:
   :undoc-members:
   :show-inheritance:

{% endfor %}
""".strip()
    )

    index_template = env.from_string(
        """
{{ project_name }} API Documentation
===================================

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   modules
""".strip()
    )

    conf_text = conf_template.render(
        python_path=str(source_dir.parent),
        project_name=source_dir.name,
    )
    modules_text = modules_template.render(modules=modules)
    index_text = index_template.render(project_name=source_dir.name)

    (sphinx_source / "conf.py").write_text(conf_text + "\n", encoding="utf-8")
    (sphinx_source / "modules.rst").write_text(modules_text + "\n", encoding="utf-8")
    (sphinx_source / "index.rst").write_text(index_text + "\n", encoding="utf-8")

    command = [
        sys.executable,
        "-m",
        "sphinx",
        "-b",
        "html",
        str(sphinx_source),
        str(html_output),
    ]

    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        message = (result.stderr or result.stdout or "unknown sphinx build failure").strip()
        raise RuntimeError(f"Sphinx build failed: {message}")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate API reference artifacts")
    parser.add_argument(
        "--module-path",
        type=Path,
        default=PROJECT_ROOT / "src",
        help="Python file or directory to scan for docstrings",
    )
    parser.add_argument(
        "--markdown-output",
        type=Path,
        default=PROJECT_ROOT / "docs" / "api-reference.md",
        help="Output path for generated Markdown reference",
    )
    parser.add_argument(
        "--api-module",
        default="src.api.rest_api",
        help="Python module containing FastAPI app for OpenAPI extraction",
    )
    parser.add_argument(
        "--openapi-output",
        type=Path,
        default=PROJECT_ROOT / "docs" / "openapi.json",
        help="Output path for generated OpenAPI JSON",
    )
    parser.add_argument(
        "--sphinx-source",
        type=Path,
        default=PROJECT_ROOT / "src",
        help="Source directory used for Sphinx API docs",
    )
    parser.add_argument(
        "--sphinx-output",
        type=Path,
        default=PROJECT_ROOT / "docs" / "sphinx",
        help="Output directory for Sphinx artifacts",
    )
    parser.add_argument(
        "--skip-openapi",
        action="store_true",
        help="Skip OpenAPI generation",
    )
    parser.add_argument(
        "--skip-sphinx",
        action="store_true",
        help="Skip Sphinx generation",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()

    function_docs = extract_docstrings(args.module_path)
    markdown = generate_markdown_reference(function_docs)
    args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
    args.markdown_output.write_text(markdown + "\n", encoding="utf-8")

    if not args.skip_openapi:
        openapi_spec = generate_openapi_spec(args.api_module)
        args.openapi_output.parent.mkdir(parents=True, exist_ok=True)
        args.openapi_output.write_text(
            json.dumps(openapi_spec, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    if not args.skip_sphinx:
        generate_sphinx_docs(args.sphinx_source, args.sphinx_output)


if __name__ == "__main__":
    main()
