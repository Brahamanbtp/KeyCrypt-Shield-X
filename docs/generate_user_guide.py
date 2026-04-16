#!/usr/bin/env python3
"""User guide generator with tutorials, cookbook recipes, and troubleshooting.

This generator parses Python example files, then emits:
- step-by-step tutorial Markdown
- recipe-style cookbook Markdown
- troubleshooting guide Markdown

Formatting uses Jinja2 templates and Pygments syntax highlighting.
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


@dataclass
class Example:
    """One parsed example artifact."""

    title: str
    slug: str
    path: Path
    summary: str
    code: str
    highlighted_code: str
    imports: List[str] = field(default_factory=list)
    called_functions: List[str] = field(default_factory=list)
    steps: List[str] = field(default_factory=list)


@dataclass
class UseCase:
    """Cookbook recipe entry."""

    name: str
    problem: str
    solution: str
    steps: List[str]
    example_slug: str | None = None
    prerequisites: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


@dataclass
class Error:
    """Troubleshooting error entry."""

    code: str
    symptom: str
    likely_cause: str
    resolution_steps: List[str]
    related_examples: List[str] = field(default_factory=list)


class _ExampleAstAnalyzer(ast.NodeVisitor):
    def __init__(self) -> None:
        self.imports: set[str] = set()
        self.calls: set[str] = set()

    def visit_Import(self, node: ast.Import) -> Any:
        for alias in node.names:
            self.imports.add(alias.name)
        return None

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        if node.module:
            self.imports.add(node.module)
        return None

    def visit_Call(self, node: ast.Call) -> Any:
        if isinstance(node.func, ast.Name):
            self.calls.add(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            self.calls.add(node.func.attr)
        self.generic_visit(node)
        return None


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


def _pygments_highlight(code: str) -> tuple[str, str]:
    try:
        from pygments import highlight
        from pygments.formatters import HtmlFormatter
        from pygments.lexers import PythonLexer
    except ModuleNotFoundError as exc:
        raise RuntimeError("Pygments is required. Install with: pip install pygments") from exc

    formatter = HtmlFormatter(cssclass="codehilite", linenos=True)
    highlighted = highlight(code, PythonLexer(), formatter)
    css = formatter.get_style_defs(".codehilite")
    return highlighted, css


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or "example"


def _humanize_stem(stem: str) -> str:
    title = stem.replace("_", " ").replace("-", " ").strip()
    if not title:
        return "Example"
    return " ".join(part.capitalize() for part in title.split())


_STEP_PATTERN = re.compile(r"^\s*(?:[-*]|\d+[.)])\s+(?P<step>.+?)\s*$")


def _extract_steps_from_docstring(docstring: str) -> List[str]:
    if not docstring.strip():
        return []

    lines = docstring.splitlines()
    steps: List[str] = []
    in_steps_section = False

    for line in lines:
        stripped = line.strip()
        lowered = stripped.lower().rstrip(":")

        if lowered in {"steps", "step-by-step", "how to", "workflow"}:
            in_steps_section = True
            continue

        matched = _STEP_PATTERN.match(line)
        if matched and (in_steps_section or not steps):
            steps.append(matched.group("step").strip())
            continue

        if in_steps_section and stripped and not matched:
            # Stop once the explicit steps section ends.
            break

    return steps


def _extract_summary(docstring: str, fallback: str) -> str:
    if docstring.strip():
        for line in docstring.splitlines():
            stripped = line.strip()
            if stripped:
                return stripped
    return fallback


def _iter_example_files(examples_dir: Path) -> List[Path]:
    if not examples_dir.exists() or not examples_dir.is_dir():
        raise FileNotFoundError(f"examples_dir must be an existing directory: {examples_dir}")

    return sorted(
        path
        for path in examples_dir.rglob("*.py")
        if path.is_file() and path.name != "__init__.py"
    )


def extract_examples(examples_dir: Path) -> List[Example]:
    """Parse Python example files and extract structured example metadata."""
    examples: List[Example] = []

    for file_path in _iter_example_files(examples_dir):
        source = file_path.read_text(encoding="utf-8", errors="ignore")

        try:
            tree = ast.parse(source, filename=str(file_path))
        except SyntaxError:
            continue

        analyzer = _ExampleAstAnalyzer()
        analyzer.visit(tree)

        docstring = ast.get_docstring(tree, clean=True) or ""
        title = _extract_summary(docstring, _humanize_stem(file_path.stem))
        summary = _extract_summary(docstring, f"Usage example from {file_path.name}.")
        steps = _extract_steps_from_docstring(docstring)

        if not steps:
            relative_name = str(file_path.resolve().relative_to(PROJECT_ROOT.resolve()))
            steps = [
                f"Open and review {relative_name}",
                f"Run python {relative_name}",
                "Inspect output and adjust parameters for your environment",
            ]

        highlighted, _ = _pygments_highlight(source)

        examples.append(
            Example(
                title=title,
                slug=_slugify(file_path.stem),
                path=file_path,
                summary=summary,
                code=source,
                highlighted_code=highlighted,
                imports=sorted(analyzer.imports),
                called_functions=sorted(analyzer.calls),
                steps=steps,
            )
        )

    return examples


def generate_tutorial(examples: List[Example]) -> str:
    """Create step-by-step tutorial Markdown from parsed examples."""
    env = _get_jinja_environment()
    _, pygments_css = _pygments_highlight("print('hello')\n")

    template = env.from_string(
        """
# User Guide Tutorial

_Auto-generated by docs/generate_user_guide.py._

<style>
{{ pygments_css }}
</style>

## Table of Contents

{% for example in examples %}
- [{{ example.title }}](#{{ example.slug }})
{% endfor %}

{% for example in examples %}
## <a id="{{ example.slug }}"></a>{{ loop.index }}. {{ example.title }}

{{ example.summary }}

### Steps
{% for step in example.steps %}
{{ loop.index }}. {{ step }}
{% endfor %}

### Example Code

```python
{{ example.code }}
```

<details>
<summary>Syntax-highlighted view</summary>

{{ example.highlighted_code }}

</details>

{% if example.imports %}
### Imports
{% for imported in example.imports %}
- {{ imported }}
{% endfor %}
{% endif %}

{% if example.called_functions %}
### Called Functions
{% for call in example.called_functions %}
- {{ call }}
{% endfor %}
{% endif %}

{% endfor %}
""".strip()
    )

    ordered_examples = sorted(examples, key=lambda item: item.title.lower())
    return template.render(examples=ordered_examples, pygments_css=pygments_css)


def generate_cookbook(use_cases: List[UseCase]) -> str:
    """Generate recipe-style cookbook Markdown from use cases."""
    env = _get_jinja_environment()

    template = env.from_string(
        """
# User Guide Cookbook

_Auto-generated by docs/generate_user_guide.py._

## Recipes

{% for use_case in use_cases %}
## {{ use_case.name }}

### Problem
{{ use_case.problem }}

### Solution
{{ use_case.solution }}

### Recipe Steps
{% for step in use_case.steps %}
{{ loop.index }}. {{ step }}
{% endfor %}

{% if use_case.prerequisites %}
### Prerequisites
{% for item in use_case.prerequisites %}
- {{ item }}
{% endfor %}
{% endif %}

{% if use_case.notes %}
### Notes
{% for note in use_case.notes %}
- {{ note }}
{% endfor %}
{% endif %}

{% if use_case.example_slug %}
### Related Tutorial
- [Open tutorial example](user-guide-tutorial.md#{{ use_case.example_slug }})
{% endif %}

{% endfor %}
""".strip()
    )

    ordered_use_cases = sorted(use_cases, key=lambda item: item.name.lower())
    return template.render(use_cases=ordered_use_cases)


def generate_troubleshooting_guide(common_errors: List[Error]) -> str:
    """Generate troubleshooting guide Markdown from common error patterns."""
    env = _get_jinja_environment()

    template = env.from_string(
        """
# Troubleshooting Guide

_Auto-generated by docs/generate_user_guide.py._

## Error Index

| Code | Symptom | Likely Cause |
| --- | --- | --- |
{% for err in common_errors %}
| {{ err.code }} | {{ err.symptom }} | {{ err.likely_cause }} |
{% endfor %}

## Detailed Resolutions

{% for err in common_errors %}
## {{ err.code }}

### Symptom
{{ err.symptom }}

### Likely Cause
{{ err.likely_cause }}

### Resolution
{% for step in err.resolution_steps %}
{{ loop.index }}. {{ step }}
{% endfor %}

{% if err.related_examples %}
### Related Tutorial Examples
{% for slug in err.related_examples %}
- [{{ slug }}](user-guide-tutorial.md#{{ slug }})
{% endfor %}
{% endif %}

{% endfor %}
""".strip()
    )

    ordered_errors = sorted(common_errors, key=lambda item: item.code.lower())
    return template.render(common_errors=ordered_errors)


def _auto_use_cases_from_examples(examples: Sequence[Example]) -> List[UseCase]:
    use_cases: List[UseCase] = []
    for example in examples:
        top_import = example.imports[0] if example.imports else "project APIs"
        use_cases.append(
            UseCase(
                name=f"Run {example.title}",
                problem=f"Need to execute and adapt the {example.title.lower()} workflow.",
                solution="Use the example as a template, then apply environment-specific parameters.",
                steps=list(example.steps),
                example_slug=example.slug,
                prerequisites=[
                    "Install project dependencies",
                    f"Confirm access to {top_import}",
                ],
                notes=[
                    "Start with defaults before tuning advanced options.",
                    "Capture logs for reproducibility.",
                ],
            )
        )
    return use_cases


def _auto_errors_from_examples(examples: Sequence[Example]) -> List[Error]:
    slugs = [item.slug for item in examples]

    return [
        Error(
            code="UG-001",
            symptom="Example script fails to start",
            likely_cause="Missing dependencies or invalid Python environment",
            resolution_steps=[
                "Create and activate a compatible virtual environment",
                "Install dependencies from project configuration",
                "Re-run the example with verbose logging enabled",
            ],
            related_examples=slugs[:3],
        ),
        Error(
            code="UG-002",
            symptom="Authentication or key access fails",
            likely_cause="Missing credentials or unset runtime secrets",
            resolution_steps=[
                "Verify required environment variables are set",
                "Confirm key management service credentials are valid",
                "Retry with a minimal example to isolate configuration issues",
            ],
            related_examples=slugs[:3],
        ),
        Error(
            code="UG-003",
            symptom="Output does not match expected example behavior",
            likely_cause="Input format mismatch or changed defaults",
            resolution_steps=[
                "Validate input payload shape against the tutorial section",
                "Check release notes for parameter/default changes",
                "Run troubleshooting with debug logs and compare intermediate outputs",
            ],
            related_examples=slugs[3:6] if len(slugs) > 3 else slugs,
        ),
    ]


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content.strip() + "\n", encoding="utf-8")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate user guide artifacts from Python examples")
    parser.add_argument(
        "--examples-dir",
        type=Path,
        default=PROJECT_ROOT / "src" / "sdk",
        help="Directory containing Python example files",
    )
    parser.add_argument(
        "--tutorial-output",
        type=Path,
        default=PROJECT_ROOT / "docs" / "user-guide-tutorial.md",
        help="Output path for generated tutorial markdown",
    )
    parser.add_argument(
        "--cookbook-output",
        type=Path,
        default=PROJECT_ROOT / "docs" / "user-guide-cookbook.md",
        help="Output path for generated cookbook markdown",
    )
    parser.add_argument(
        "--troubleshooting-output",
        type=Path,
        default=PROJECT_ROOT / "docs" / "user-guide-troubleshooting.md",
        help="Output path for generated troubleshooting markdown",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()

    examples = extract_examples(args.examples_dir)
    if not examples:
        raise RuntimeError(f"No parseable examples found in: {args.examples_dir}")

    tutorial = generate_tutorial(examples)
    use_cases = _auto_use_cases_from_examples(examples)
    cookbook = generate_cookbook(use_cases)
    common_errors = _auto_errors_from_examples(examples)
    troubleshooting = generate_troubleshooting_guide(common_errors)

    _write_text(args.tutorial_output, tutorial)
    _write_text(args.cookbook_output, cookbook)
    _write_text(args.troubleshooting_output, troubleshooting)


if __name__ == "__main__":
    main()
