#!/usr/bin/env python3
"""Code generator for common development patterns.

This module provides reusable source-code generators for:
- provider skeletons that implement a target interface
- pytest suites with stubs for module functions
- REST API endpoint modules for common CRUD operations
- Alembic migration scripts from structured schema changes

All generators use Jinja2 templates and validate generated code with a
syntax check plus ruff linting (when ruff is available on PATH).
"""

from __future__ import annotations

import ast
import importlib
import inspect
import keyword
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, List, Sequence


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


DEFAULT_INTERFACE_MAP: dict[str, str] = {
    "CryptoProvider": "src.abstractions.crypto_provider.CryptoProvider",
    "KeyProvider": "src.abstractions.key_provider.KeyProvider",
    "StorageProvider": "src.abstractions.storage_provider.StorageProvider",
    "IntelligenceProvider": "src.abstractions.intelligence_provider.IntelligenceProvider",
}


@dataclass(frozen=True)
class ProviderMethodSpec:
    """Serializable provider method metadata for template rendering."""

    name: str
    signature: str
    is_async: bool
    doc_summary: str


@dataclass(frozen=True)
class TestFunctionSpec:
    """Describes a generated pytest stub target."""

    qualname: str
    test_name: str
    is_async: bool
    kind: str


@dataclass(frozen=True)
class SchemaColumn:
    """Column definition used by create-table schema changes."""

    name: str
    type_name: str
    nullable: bool = True
    default: str | None = None


@dataclass(frozen=True)
class SchemaChange:
    """Schema migration change descriptor.

    Supported operations:
    - create_table
    - drop_table
    - add_column
    - drop_column
    - alter_column
    - rename_column
    - rename_table
    """

    operation: str
    table: str
    column: str | None = None
    column_type: str | None = None
    nullable: bool | None = None
    default: str | None = None
    new_name: str | None = None
    columns: tuple[SchemaColumn, ...] = field(default_factory=tuple)


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


def _normalize_identifier(value: str, *, fallback: str) -> str:
    candidate = re.sub(r"[^A-Za-z0-9_]+", "_", value.strip())
    candidate = re.sub(r"_+", "_", candidate).strip("_")
    if not candidate:
        candidate = fallback
    if candidate[0].isdigit():
        candidate = f"n_{candidate}"
    if keyword.iskeyword(candidate):
        candidate = f"{candidate}_value"
    return candidate


def _to_pascal_case(value: str, *, suffix: str = "") -> str:
    parts = [part for part in re.split(r"[^A-Za-z0-9]+", value.strip()) if part]
    if not parts:
        base = "Generated"
    else:
        base = "".join(part[:1].upper() + part[1:] for part in parts)

    if suffix and not base.endswith(suffix):
        base = f"{base}{suffix}"

    if base[0].isdigit():
        base = f"Generated{base}"

    if keyword.iskeyword(base):
        base = f"{base}Model"

    return base


def _interface_import_parts(interface: str) -> tuple[str, str]:
    resolved = DEFAULT_INTERFACE_MAP.get(interface, interface)
    if "." not in resolved:
        raise ValueError(
            "interface must be a fully qualified symbol path or a known interface alias"
        )

    module_name, class_name = resolved.rsplit(".", 1)
    if not module_name or not class_name:
        raise ValueError(f"invalid interface path: {interface}")

    return module_name, class_name


def _resolve_interface(interface: str) -> tuple[str, type[Any]]:
    module_name, class_name = _interface_import_parts(interface)
    module = importlib.import_module(module_name)
    interface_cls = getattr(module, class_name, None)
    if interface_cls is None or not inspect.isclass(interface_cls):
        raise TypeError(f"interface class not found: {module_name}.{class_name}")
    return module_name, interface_cls


def _provider_methods(interface_cls: type[Any]) -> list[ProviderMethodSpec]:
    abstract_method_names = set(getattr(interface_cls, "__abstractmethods__", set()))
    methods: list[ProviderMethodSpec] = []

    for name, value in interface_cls.__dict__.items():
        if name not in abstract_method_names:
            continue
        if not inspect.isfunction(value):
            continue

        signature = str(inspect.signature(value))
        doc = inspect.getdoc(value) or "No docstring provided."
        summary = doc.splitlines()[0].strip() if doc.strip() else "No docstring provided."
        methods.append(
            ProviderMethodSpec(
                name=name,
                signature=signature,
                is_async=inspect.iscoroutinefunction(value),
                doc_summary=summary,
            )
        )

    methods.sort(key=lambda item: item.name)
    if not methods:
        raise ValueError(f"interface does not expose abstract methods: {interface_cls.__name__}")
    return methods


class _ModuleFunctionCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self._class_stack: list[str] = []
        self.functions: list[TestFunctionSpec] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        self._class_stack.append(node.name)
        self.generic_visit(node)
        self._class_stack.pop()
        return None

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        self._record(node, is_async=False)
        self.generic_visit(node)
        return None

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self._record(node, is_async=True)
        self.generic_visit(node)
        return None

    def _record(self, node: ast.FunctionDef | ast.AsyncFunctionDef, *, is_async: bool) -> None:
        if self._class_stack:
            class_name = self._class_stack[-1]
            qualname = f"{class_name}.{node.name}"
            test_name = _normalize_identifier(
                f"test_{class_name.lower()}_{node.name}",
                fallback="test_generated_method",
            )
            kind = "method"
        else:
            qualname = node.name
            test_name = _normalize_identifier(f"test_{node.name}", fallback="test_generated_function")
            kind = "function"

        self.functions.append(
            TestFunctionSpec(
                qualname=qualname,
                test_name=test_name,
                is_async=is_async,
                kind=kind,
            )
        )


def _safe_module_name(resource: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "_", resource.lower()).strip("_")
    return normalized or "resource"


def _sqlalchemy_type_expr(type_name: str) -> str:
    cleaned = type_name.strip()
    if not cleaned:
        raise ValueError("column type must be non-empty")
    if cleaned.startswith("sa."):
        return cleaned
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(\([^\n]*\))?", cleaned):
        return f"sa.{cleaned}"
    raise ValueError(f"unsupported SQLAlchemy type expression: {type_name}")


def _column_definition_expr(
    *,
    column: str,
    column_type: str,
    nullable: bool | None,
    default: str | None,
) -> str:
    args: list[str] = [repr(column), _sqlalchemy_type_expr(column_type)]
    if nullable is not None:
        args.append(f"nullable={nullable}")
    if default is not None:
        args.append(f"server_default={default}")
    return f"sa.Column({', '.join(args)})"


def _render_provider_template(
    *,
    interface_module: str,
    interface_name: str,
    class_name: str,
    methods: Sequence[ProviderMethodSpec],
) -> str:
    env = _get_jinja_environment()
    template = env.from_string(
    '''
from __future__ import annotations

import logging
from typing import Any, Mapping

from {{ interface_module }} import {{ interface_name }}


class {{ class_name }}({{ interface_name }}):
    """Generated provider skeleton implementing {{ interface_name }}."""

    def __init__(self, config: Mapping[str, Any] | None = None) -> None:
        self._logger = logging.getLogger(self.__class__.__name__)
        self._config = dict(config or {})

{% for method in methods %}    {% if method.is_async %}async {% endif %}def {{ method.name }}{{ method.signature }}:
        """{{ method.doc_summary }}"""
        # TODO: implement provider method behavior.
        raise NotImplementedError("TODO: implement {{ method.name }}")

{% endfor %}__all__ = ["{{ class_name }}"]
'''.strip()
    )
    return template.render(
        interface_module=interface_module,
        interface_name=interface_name,
        class_name=class_name,
        methods=methods,
    )


def _render_test_template(*, module_path: Path, functions: Sequence[TestFunctionSpec]) -> str:
    env = _get_jinja_environment()
    template = env.from_string(
    '''
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


TARGET_MODULE = Path(r"{{ module_path }}")


def _load_module():
    spec = importlib.util.spec_from_file_location("generated_target_module", TARGET_MODULE)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load module: {TARGET_MODULE}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


module = _load_module()


{% if functions %}{% for item in functions %}{% if item.is_async %}@pytest.mark.asyncio
async {% else %}{% endif %}def {{ item.test_name }}() -> None:
    """Auto-generated stub for {{ item.qualname }} ({{ item.kind }})."""
    target = getattr(module, "{{ item.qualname.split('.')[-1] }}", None)
    if target is None and "." in "{{ item.qualname }}":
        owner = getattr(module, "{{ item.qualname.split('.')[0] }}")
        target = getattr(owner, "{{ item.qualname.split('.')[-1] }}", None)
    assert target is not None
    pytest.skip("TODO: implement test inputs and assertions")


{% endfor %}{% else %}def test_module_imports() -> None:
    """Fallback test stub when no functions are discovered."""
    assert module is not None
    pytest.skip("No functions found in module; add custom tests as needed")
{% endif %}
'''.strip()
    )
    return template.render(module_path=str(module_path), functions=functions)


def _render_api_template(*, resource: str, operations: Sequence[str]) -> str:
    env = _get_jinja_environment()
    resource_slug = _safe_module_name(resource)
    model_name = _to_pascal_case(resource, suffix="Resource")
    tag_name = resource_slug.replace("_", " ").title()

    supported = {
        "create": "create",
        "list": "list",
        "retrieve": "retrieve",
        "read": "retrieve",
        "get": "retrieve",
        "update": "update",
        "patch": "patch",
        "delete": "delete",
    }

    normalized_ops: list[str] = []
    for op in operations:
        key = op.strip().lower()
        if key not in supported:
            raise ValueError(f"unsupported operation: {op}")
        canonical = supported[key]
        if canonical not in normalized_ops:
            normalized_ops.append(canonical)

    if not normalized_ops:
        raise ValueError("operations must contain at least one supported operation")

    template = env.from_string(
        '''
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Response, status
from pydantic import BaseModel, Field


router = APIRouter(prefix="/{{ resource_slug }}", tags=["{{ tag_name }}"])


class {{ model_name }}CreateRequest(BaseModel):
    payload: dict[str, Any] = Field(default_factory=dict)


class {{ model_name }}UpdateRequest(BaseModel):
    payload: dict[str, Any] = Field(default_factory=dict)


class {{ model_name }}Response(BaseModel):
    id: str
    payload: dict[str, Any] = Field(default_factory=dict)


_STORE: dict[str, {{ model_name }}Response] = {}


{% if "create" in operations %}@router.post("", response_model={{ model_name }}Response, status_code=status.HTTP_201_CREATED)
def create_{{ resource_slug }}(body: {{ model_name }}CreateRequest) -> {{ model_name }}Response:
    resource_id = str(len(_STORE) + 1)
    record = {{ model_name }}Response(id=resource_id, payload=dict(body.payload))
    _STORE[resource_id] = record
    return record


{% endif %}{% if "list" in operations %}@router.get("", response_model=list[{{ model_name }}Response])
def list_{{ resource_slug }}() -> list[{{ model_name }}Response]:
    return sorted(_STORE.values(), key=lambda item: item.id)


{% endif %}{% if "retrieve" in operations %}@router.get("/{item_id}", response_model={{ model_name }}Response)
def get_{{ resource_slug }}(item_id: str) -> {{ model_name }}Response:
    record = _STORE.get(item_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found")
    return record


{% endif %}{% if "update" in operations %}@router.put("/{item_id}", response_model={{ model_name }}Response)
def update_{{ resource_slug }}(item_id: str, body: {{ model_name }}UpdateRequest) -> {{ model_name }}Response:
    record = _STORE.get(item_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found")
    updated = record.model_copy(update={"payload": dict(body.payload)})
    _STORE[item_id] = updated
    return updated


{% endif %}{% if "patch" in operations %}@router.patch("/{item_id}", response_model={{ model_name }}Response)
def patch_{{ resource_slug }}(item_id: str, body: {{ model_name }}UpdateRequest) -> {{ model_name }}Response:
    record = _STORE.get(item_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found")
    merged = dict(record.payload)
    merged.update(body.payload)
    patched = record.model_copy(update={"payload": merged})
    _STORE[item_id] = patched
    return patched


{% endif %}{% if "delete" in operations %}@router.delete("/{item_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_{{ resource_slug }}(item_id: str) -> Response:
    if item_id not in _STORE:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found")
    del _STORE[item_id]
    return Response(status_code=status.HTTP_204_NO_CONTENT)


{% endif %}__all__ = ["router"]
'''.strip()
    )
    return template.render(
        resource_slug=resource_slug,
        model_name=model_name,
        operations=tuple(normalized_ops),
        tag_name=tag_name,
    )


def _iter_migration_lines(changes: Sequence[SchemaChange]) -> tuple[list[str], list[str]]:
    upgrade_lines: list[str] = []
    downgrade_lines: list[str] = []

    for index, change in enumerate(changes, start=1):
        op = change.operation.strip().lower()
        table = _normalize_identifier(change.table, fallback=f"table_{index}")

        if op == "create_table":
            columns = list(change.columns)
            if not columns:
                columns = [SchemaColumn(name="id", type_name="Integer", nullable=False)]

            column_lines = [
                _column_definition_expr(
                    column=_normalize_identifier(col.name, fallback=f"column_{idx}"),
                    column_type=col.type_name,
                    nullable=col.nullable,
                    default=col.default,
                )
                for idx, col in enumerate(columns, start=1)
            ]
            joined = ",\n        ".join(column_lines)
            upgrade_lines.append(f'op.create_table("{table}",\n        {joined}\n    )')
            downgrade_lines.insert(0, f'op.drop_table("{table}")')
            continue

        if op == "drop_table":
            upgrade_lines.append(f'op.drop_table("{table}")')
            downgrade_lines.insert(
                0,
                f'# TODO: restore dropped table "{table}" with original schema before downgrade runs',
            )
            continue

        if op == "add_column":
            if not change.column or not change.column_type:
                raise ValueError("add_column requires column and column_type")
            column_name = _normalize_identifier(change.column, fallback="column")
            column_expr = _column_definition_expr(
                column=column_name,
                column_type=change.column_type,
                nullable=change.nullable,
                default=change.default,
            )
            upgrade_lines.append(f'op.add_column("{table}", {column_expr})')
            downgrade_lines.insert(0, f'op.drop_column("{table}", "{column_name}")')
            continue

        if op == "drop_column":
            if not change.column:
                raise ValueError("drop_column requires column")
            column_name = _normalize_identifier(change.column, fallback="column")
            upgrade_lines.append(f'op.drop_column("{table}", "{column_name}")')
            if change.column_type:
                column_expr = _column_definition_expr(
                    column=column_name,
                    column_type=change.column_type,
                    nullable=change.nullable,
                    default=change.default,
                )
                downgrade_lines.insert(0, f'op.add_column("{table}", {column_expr})')
            else:
                downgrade_lines.insert(
                    0,
                    f'# TODO: add dropped column "{column_name}" back to "{table}" in downgrade',
                )
            continue

        if op == "alter_column":
            if not change.column:
                raise ValueError("alter_column requires column")
            column_name = _normalize_identifier(change.column, fallback="column")
            kwargs: list[str] = []
            if change.column_type:
                kwargs.append(f"type_={_sqlalchemy_type_expr(change.column_type)}")
            if change.nullable is not None:
                kwargs.append(f"nullable={change.nullable}")
            if change.default is not None:
                kwargs.append(f"server_default={change.default}")
            if not kwargs:
                raise ValueError("alter_column requires at least one of column_type, nullable, default")
            upgrade_lines.append(
                f'op.alter_column("{table}", "{column_name}", {", ".join(kwargs)})'
            )
            downgrade_lines.insert(
                0,
                f'# TODO: define inverse alter_column operation for "{table}.{column_name}"',
            )
            continue

        if op == "rename_column":
            if not change.column or not change.new_name:
                raise ValueError("rename_column requires column and new_name")
            old_name = _normalize_identifier(change.column, fallback="old_column")
            new_name = _normalize_identifier(change.new_name, fallback="new_column")
            upgrade_lines.append(
                f'op.alter_column("{table}", "{old_name}", new_column_name="{new_name}")'
            )
            downgrade_lines.insert(
                0,
                f'op.alter_column("{table}", "{new_name}", new_column_name="{old_name}")',
            )
            continue

        if op == "rename_table":
            if not change.new_name:
                raise ValueError("rename_table requires new_name")
            new_table = _normalize_identifier(change.new_name, fallback="renamed_table")
            upgrade_lines.append(f'op.rename_table("{table}", "{new_table}")')
            downgrade_lines.insert(0, f'op.rename_table("{new_table}", "{table}")')
            continue

        raise ValueError(f"unsupported schema change operation: {change.operation}")

    return upgrade_lines, downgrade_lines


def _render_migration_template(changes: Sequence[SchemaChange]) -> str:
    env = _get_jinja_environment()
    upgrade_lines, downgrade_lines = _iter_migration_lines(changes)

    template = env.from_string(
        '''
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "TODO_REVISION_ID"
down_revision = "TODO_PREVIOUS_REVISION"
branch_labels = None
depends_on = None


def upgrade() -> None:
{% if upgrade_lines %}{% for line in upgrade_lines %}    {{ line }}
{% endfor %}{% else %}    pass
{% endif %}


def downgrade() -> None:
{% if downgrade_lines %}{% for line in downgrade_lines %}    {{ line }}
{% endfor %}{% else %}    pass
{% endif %}
'''.strip()
    )
    return template.render(upgrade_lines=upgrade_lines, downgrade_lines=downgrade_lines)


def validate_generated_code(code: str, *, filename: str = "generated.py") -> None:
    """Validate generated source code syntax and lint compliance.

    Validation sequence:
    1. Parse with ``ast.parse`` to ensure Python syntax correctness.
    2. Run ``ruff check`` against stdin when ruff is available.
    """
    if not isinstance(code, str) or not code.strip():
        raise ValueError("generated code must be a non-empty string")

    try:
        ast.parse(code, filename=filename)
    except SyntaxError as exc:
        raise ValueError(f"generated code is syntactically invalid: {exc}") from exc

    ruff_binary = shutil.which("ruff")
    if ruff_binary is None:
        return

    process = subprocess.run(
        [ruff_binary, "check", "--quiet", "--stdin-filename", filename, "-"],
        input=code,
        capture_output=True,
        text=True,
        check=False,
    )
    if process.returncode != 0:
        details = (process.stdout + process.stderr).strip() or "ruff reported lint errors"
        raise ValueError(f"generated code failed lint validation: {details}")


def generate_provider(interface: str, name: str) -> str:
    """Generate provider skeleton code implementing the requested interface."""
    if not interface.strip():
        raise ValueError("interface must be non-empty")
    if not name.strip():
        raise ValueError("name must be non-empty")

    interface_module, interface_cls = _resolve_interface(interface)
    methods = _provider_methods(interface_cls)

    class_name = _to_pascal_case(name, suffix="Provider")
    code = _render_provider_template(
        interface_module=interface_module,
        interface_name=interface_cls.__name__,
        class_name=class_name,
        methods=methods,
    )
    validate_generated_code(code, filename=f"{class_name.lower()}.py")
    return code


def generate_test_suite(module_path: Path) -> str:
    """Generate a pytest module with stubs for all discovered functions."""
    module_file = Path(module_path).expanduser().resolve()
    if not module_file.exists() or not module_file.is_file():
        raise FileNotFoundError(f"module path does not exist: {module_path}")
    if module_file.suffix != ".py":
        raise ValueError(f"module path must point to a .py file: {module_path}")

    source = module_file.read_text(encoding="utf-8", errors="ignore")
    tree = ast.parse(source, filename=str(module_file))
    collector = _ModuleFunctionCollector()
    collector.visit(tree)

    rendered = _render_test_template(module_path=module_file, functions=collector.functions)
    test_file_name = f"test_{_normalize_identifier(module_file.stem, fallback='module')}.py"
    validate_generated_code(rendered, filename=test_file_name)
    return rendered


def generate_api_endpoint(resource: str, operations: List[str]) -> str:
    """Generate REST API endpoint code for a resource and operations list."""
    if not resource.strip():
        raise ValueError("resource must be non-empty")
    if not isinstance(operations, list):
        raise TypeError("operations must be a list of operation names")

    rendered = _render_api_template(resource=resource, operations=operations)
    endpoint_file = f"{_safe_module_name(resource)}_endpoint.py"
    validate_generated_code(rendered, filename=endpoint_file)
    return rendered


def generate_migration_script(changes: List[SchemaChange]) -> str:
    """Generate an Alembic-style migration script from schema changes."""
    if not isinstance(changes, list):
        raise TypeError("changes must be a list of SchemaChange")
    if any(not isinstance(change, SchemaChange) for change in changes):
        raise TypeError("all items in changes must be SchemaChange instances")

    rendered = _render_migration_template(changes)
    validate_generated_code(rendered, filename="migration.py")
    return rendered


__all__ = [
    "SchemaChange",
    "SchemaColumn",
    "generate_provider",
    "generate_test_suite",
    "generate_api_endpoint",
    "generate_migration_script",
    "validate_generated_code",
]
