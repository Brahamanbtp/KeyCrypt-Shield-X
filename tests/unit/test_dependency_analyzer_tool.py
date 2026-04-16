"""Unit tests for tools/dependency_analyzer.py."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def _load_dependency_analyzer_module():
    module_path = Path(__file__).resolve().parents[2] / "tools/dependency_analyzer.py"
    spec = importlib.util.spec_from_file_location("dependency_analyzer_tool", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load dependency_analyzer module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_analyze_circular_dependencies_detects_cycle(tmp_path: Path) -> None:
    module = _load_dependency_analyzer_module()

    source_dir = tmp_path / "src"
    source_dir.mkdir()

    (source_dir / "a.py").write_text("import b\n", encoding="utf-8")
    (source_dir / "b.py").write_text("import c\n", encoding="utf-8")
    (source_dir / "c.py").write_text("import a\n", encoding="utf-8")

    cycles = module.analyze_circular_dependencies(source_dir)

    assert cycles
    assert any(set(cycle.modules) == {"a", "b", "c"} for cycle in cycles)


def test_analyze_unused_dependencies_handles_common_aliases(tmp_path: Path) -> None:
    module = _load_dependency_analyzer_module()

    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "main.py").write_text(
        "import requests\nimport yaml\n",
        encoding="utf-8",
    )

    requirements_file = tmp_path / "requirements.txt"
    requirements_file.write_text(
        "\n".join(
            [
                "requests==2.31.0",
                "PyYAML==6.0.2",
                "unused-package==1.0.0",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    unused = module.analyze_unused_dependencies(requirements_file, source_dir)

    assert "unused-package" in unused
    assert "requests" not in unused
    assert "pyyaml" not in unused


def test_analyze_security_vulnerabilities_parses_safety_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_dependency_analyzer_module()

    requirements_file = tmp_path / "requirements.txt"
    requirements_file.write_text("requests==2.0.0\n", encoding="utf-8")

    payload = [
        {
            "package_name": "requests",
            "installed_version": "2.0.0",
            "vulnerability_id": "12345",
            "advisory": "Example advisory",
            "severity": "high",
            "CVE": "CVE-2024-0001",
            "fixed_versions": ["2.31.0"],
        }
    ]

    def _fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=1,
            stdout=json.dumps(payload),
            stderr="",
        )

    monkeypatch.setattr(module.subprocess, "run", _fake_run)

    findings = module.analyze_security_vulnerabilities(requirements_file)

    assert len(findings) == 1
    assert findings[0].package == "requests"
    assert findings[0].vulnerability_id == "12345"
    assert findings[0].severity == "high"
    assert findings[0].cve == "CVE-2024-0001"


def test_render_dependency_graph_falls_back_to_dot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_dependency_analyzer_module()

    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "a.py").write_text("import b\n", encoding="utf-8")
    (source_dir / "b.py").write_text("\n", encoding="utf-8")

    monkeypatch.setattr(module.shutil, "which", lambda _name: None)

    graph_path = module.render_dependency_graph(source_dir)

    assert graph_path.exists()
    assert graph_path.suffix == ".dot"
    assert "digraph dependencies" in graph_path.read_text(encoding="utf-8")


def test_generate_dependency_report_includes_graph_and_sections(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_dependency_analyzer_module()

    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "x.py").write_text("import y\n", encoding="utf-8")
    (source_dir / "y.py").write_text("import x\n", encoding="utf-8")

    monkeypatch.setattr(module.shutil, "which", lambda _name: None)

    report = module.generate_dependency_report(source_dir)

    assert "# Dependency Analysis Report" in report
    assert "## Circular Dependencies" in report
    assert "x -> y" in report or "y -> x" in report
    assert "## Dependency Graph" in report
