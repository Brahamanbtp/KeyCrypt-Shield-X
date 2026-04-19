"""Unit tests for ci_cd/release_automation.py."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def _load_release_automation_module():
    module_path = Path(__file__).resolve().parents[2] / "ci_cd/release_automation.py"
    spec = importlib.util.spec_from_file_location("release_automation_tool", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load release_automation module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _write_minimal_project_layout(root: Path) -> None:
    (root / "src/core").mkdir(parents=True, exist_ok=True)
    (root / "src/api").mkdir(parents=True, exist_ok=True)
    (root / "src/cli").mkdir(parents=True, exist_ok=True)
    (root / "src").joinpath("__init__.py").write_text("\n", encoding="utf-8")
    (root / "src/cli/main.py").write_text("def main() -> None:\n    return None\n", encoding="utf-8")

    (root / "pyproject.toml").write_text(
        """
[tool.poetry]
name = "keycrypt-shield-x"
version = "0.1.0"
""".strip()
        + "\n",
        encoding="utf-8",
    )
    (root / "setup.py").write_text(
        'setup(name="keycrypt-shield-x", version="0.1.0")\n',
        encoding="utf-8",
    )
    (root / "src/core/__init__.py").write_text(
        '__version__ = "0.1.0"\n',
        encoding="utf-8",
    )
    (root / "src/api/rest_api.py").write_text(
        'app = None\nversion="0.1.0"\n',
        encoding="utf-8",
    )


def test_prepare_release_updates_versions_and_changelog(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_release_automation_module()
    _write_minimal_project_layout(tmp_path)

    monkeypatch.setattr(module, "_project_root", lambda: tmp_path)
    monkeypatch.setattr(module, "_latest_git_tag", lambda _root: "v0.1.0")
    monkeypatch.setattr(module, "generate_changelog", lambda _from, _to: "### Features\n- add release automation")

    result = module.prepare_release("1.2.3")

    assert result.version == "1.2.3"
    assert result.previous_version == "0.1.0"
    assert (tmp_path / "pyproject.toml").read_text(encoding="utf-8").find('version = "1.2.3"') != -1
    assert (tmp_path / "setup.py").read_text(encoding="utf-8").find('version="1.2.3"') != -1
    assert (tmp_path / "src/core/__init__.py").read_text(encoding="utf-8").find('__version__ = "1.2.3"') != -1
    assert (tmp_path / "CHANGELOG.md").exists()
    assert "## [1.2.3]" in (tmp_path / "CHANGELOG.md").read_text(encoding="utf-8")


def test_generate_changelog_groups_conventional_commit_subjects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_release_automation_module()
    monkeypatch.setattr(module, "_project_root", lambda: tmp_path)

    def _fake_run(command, *, cwd):
        _ = (command, cwd)
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=(
                "feat(api): add release endpoint\n"
                "fix(ci): handle flaky tests\n"
                "docs: update release notes guide\n"
                "refactor(core): simplify parser\n"
                "random uncategorized message\n"
            ),
            stderr="",
        )

    monkeypatch.setattr(module, "_run_command", _fake_run)

    changelog = module.generate_changelog("v0.1.0", "HEAD")

    assert "### Features" in changelog
    assert "### Fixes" in changelog
    assert "### Documentation" in changelog
    assert "### Refactoring" in changelog
    assert "### Other" in changelog


def test_build_artifacts_creates_wheel_docker_and_binary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_release_automation_module()
    _write_minimal_project_layout(tmp_path)
    (tmp_path / "deployment/docker").mkdir(parents=True, exist_ok=True)
    (tmp_path / "deployment/docker/Dockerfile").write_text("FROM python:3.12-slim\n", encoding="utf-8")

    monkeypatch.setattr(module, "_project_root", lambda: tmp_path)
    monkeypatch.setattr(module, "shutil_which", lambda cmd: "/usr/bin/docker" if cmd == "docker" else None)

    def _fake_run(command, *, cwd):
        _ = cwd
        if command[:3] == [sys.executable, "-m", "build"]:
            dist = tmp_path / "dist"
            dist.mkdir(parents=True, exist_ok=True)
            (dist / "keycrypt_shield_x-1.0.0-py3-none-any.whl").write_bytes(b"wheel")
        if command[:3] == [sys.executable, "-m", "zipapp"]:
            output_index = command.index("-o") + 1
            output_path = Path(command[output_index])
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(b"binary")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(module, "_run_command", _fake_run)

    artifacts = module.build_artifacts(["wheel", "docker", "binary"])

    kinds = {item.artifact_type for item in artifacts}
    assert "wheel" in kinds
    assert "docker_image" in kinds
    assert "binary" in kinds
    assert any(item.path and item.path.suffix == ".whl" for item in artifacts)
    assert any(item.reference and item.reference.startswith("keycrypt-shield-x:") for item in artifacts)


def test_sign_artifacts_writes_signature_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_release_automation_module()
    monkeypatch.setattr(module, "_project_root", lambda: tmp_path)
    monkeypatch.setattr(module, "shutil_which", lambda _cmd: "/usr/bin/gpg")

    artifact_path = tmp_path / "dist" / "artifact.whl"
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    artifact_path.write_bytes(b"content")

    signing_key = tmp_path / "signing.asc"
    signing_key.write_text("dummy-key", encoding="utf-8")

    artifact = module.Artifact(
        name=artifact_path.name,
        artifact_type="wheel",
        platform="python",
        version="1.0.0",
        path=artifact_path,
    )

    def _fake_run(command, *, cwd):
        _ = cwd
        if "--detach-sign" in command:
            out_path = Path(command[command.index("--output") + 1])
            out_path.write_text("signature", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(module, "_run_command", _fake_run)

    module.sign_artifacts([artifact], signing_key)

    assert artifact.signature_path is not None
    assert artifact.signature_path.exists()


def test_publish_release_invokes_twine_github_and_docker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_release_automation_module()
    _write_minimal_project_layout(tmp_path)
    monkeypatch.setattr(module, "_project_root", lambda: tmp_path)

    wheel_path = tmp_path / "dist" / "pkg-1.0.0-py3-none-any.whl"
    wheel_path.parent.mkdir(parents=True, exist_ok=True)
    wheel_path.write_bytes(b"wheel")

    binary_path = tmp_path / "dist" / "bin" / "keycrypt-shield-x.pyz"
    binary_path.parent.mkdir(parents=True, exist_ok=True)
    binary_path.write_bytes(b"binary")

    artifacts = [
        module.Artifact(
            name=wheel_path.name,
            artifact_type="wheel",
            platform="python",
            version="1.0.0",
            path=wheel_path,
        ),
        module.Artifact(
            name="keycrypt-shield-x:1.0.0",
            artifact_type="docker_image",
            platform="docker",
            version="1.0.0",
            reference="keycrypt-shield-x:1.0.0",
        ),
        module.Artifact(
            name=binary_path.name,
            artifact_type="binary",
            platform="python",
            version="1.0.0",
            path=binary_path,
        ),
    ]

    monkeypatch.setattr(module, "shutil_which", lambda _cmd: "/usr/bin/fake")

    executed_commands: list[list[str]] = []

    def _fake_run(command, *, cwd):
        _ = cwd
        executed_commands.append(list(command))
        return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

    monkeypatch.setattr(module, "_run_command", _fake_run)

    monkeypatch.setenv("GITHUB_TOKEN", "token")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")

    class _Response:
        def __init__(self, status_code: int, payload: dict[str, str]):
            self.status_code = status_code
            self._payload = payload
            self.text = ""
            self.content = b"{}"

        def json(self):
            return self._payload

    def _fake_post(url, headers, json=None, data=None, timeout=0):
        _ = (headers, json, data, timeout)
        if url.endswith("/releases"):
            return _Response(
                201,
                {
                    "html_url": "https://github.example/release/1",
                    "upload_url": "https://uploads.github.example/assets{?name,label}",
                },
            )
        return _Response(201, {"browser_download_url": "https://github.example/asset.bin"})

    monkeypatch.setattr(module.requests, "post", _fake_post)

    release = module.publish_release(artifacts, "release notes")

    assert release.pypi_uploaded is True
    assert release.github_release_url == "https://github.example/release/1"
    assert release.docker_pushed == ("keycrypt-shield-x:1.0.0",)
    assert release.published_assets
    assert any(command[0] == "twine" for command in executed_commands)
    assert any(command[0:2] == ["docker", "push"] for command in executed_commands)


def test_validate_semantic_version_rejects_invalid_values() -> None:
    module = _load_release_automation_module()

    with pytest.raises(ValueError):
        module.validate_semantic_version("1")
    with pytest.raises(ValueError):
        module.validate_semantic_version("1.2")
    with pytest.raises(ValueError):
        module.validate_semantic_version("v1.2.3")
