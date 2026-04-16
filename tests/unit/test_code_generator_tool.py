"""Unit tests for tools/code_generator.py."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def _load_code_generator_module():
    module_path = Path(__file__).resolve().parents[2] / "tools/code_generator.py"
    spec = importlib.util.spec_from_file_location("code_generator_tool", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load code_generator module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_generate_provider_builds_key_provider_skeleton() -> None:
    module = _load_code_generator_module()

    generated = module.generate_provider("KeyProvider", "acme key")

    assert "class AcmeKeyProvider(KeyProvider):" in generated
    assert "def get_key(" in generated
    assert "def generate_key(" in generated
    assert "def rotate_key(" in generated
    assert "def list_keys(" in generated


def test_generate_test_suite_collects_functions_and_methods(tmp_path: Path) -> None:
    module = _load_code_generator_module()

    target = tmp_path / "sample_module.py"
    target.write_text(
        """
def top_level(x: int) -> int:
    return x + 1


class Worker:
    def execute(self, value: str) -> str:
        return value


async def async_fn(name: str) -> str:
    return name
""".strip()
        + "\n",
        encoding="utf-8",
    )

    generated = module.generate_test_suite(target)

    assert "def test_top_level() -> None:" in generated
    assert "def test_worker_execute() -> None:" in generated
    assert "async def test_async_fn() -> None:" in generated


def test_generate_api_endpoint_builds_requested_operations() -> None:
    module = _load_code_generator_module()

    generated = module.generate_api_endpoint(
        resource="audit event",
        operations=["create", "list", "retrieve", "update", "delete"],
    )

    assert "router = APIRouter(prefix=\"/audit_event\"" in generated
    assert "def create_audit_event(" in generated
    assert "def list_audit_event() -> list[AuditEventResourceResponse]:" in generated
    assert "def get_audit_event(item_id: str) -> AuditEventResourceResponse:" in generated
    assert "def update_audit_event(item_id: str, body: AuditEventResourceUpdateRequest)" in generated
    assert "def delete_audit_event(item_id: str) -> Response:" in generated


def test_generate_migration_script_renders_upgrade_and_downgrade() -> None:
    module = _load_code_generator_module()

    change = module.SchemaChange(
        operation="add_column",
        table="audit_logs",
        column="trace_id",
        column_type="String(64)",
        nullable=False,
    )
    generated = module.generate_migration_script([change])

    assert 'op.add_column("audit_logs", sa.Column(\'trace_id\', sa.String(64), nullable=False))' in generated
    assert 'op.drop_column("audit_logs", "trace_id")' in generated


def test_validation_rejects_invalid_python_source() -> None:
    module = _load_code_generator_module()

    with pytest.raises(ValueError):
        module.validate_generated_code("def bad(:\n    pass\n", filename="broken.py")
