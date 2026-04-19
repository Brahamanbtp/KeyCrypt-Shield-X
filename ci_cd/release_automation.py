#!/usr/bin/env python3
"""Release automation for KeyCrypt.

Capabilities:
- prepare release metadata and version files
- build wheel/docker/binary artifacts
- sign artifacts with GPG
- publish artifacts to PyPI, GitHub Releases, and Docker Hub
- generate changelog from git commit history
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any, Iterable, List
from urllib.parse import quote

import requests


_SEMVER_PATTERN = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)

_CONVENTIONAL_SUBJECT_PATTERN = re.compile(
    r"^(?P<type>feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)"
    r"(?:\([^)]+\))?(?:!)?:\s*(?P<description>.+)$"
)


@dataclass(frozen=True)
class ReleasePreparation:
    """Release preparation output metadata."""

    version: str
    previous_version: str
    from_tag: str
    to_ref: str
    updated_files: tuple[Path, ...]
    changelog: str
    changelog_path: Path


@dataclass
class Artifact:
    """Build artifact descriptor."""

    name: str
    artifact_type: str
    platform: str
    version: str
    path: Path | None = None
    reference: str | None = None
    sha256: str | None = None
    signature_path: Path | None = None


@dataclass(frozen=True)
class Release:
    """Published release metadata."""

    version: str
    pypi_uploaded: bool
    github_release_url: str | None
    docker_pushed: tuple[str, ...]
    published_assets: tuple[str, ...]
    release_notes: str
    release_targets: tuple[str, ...] = field(default_factory=tuple)


def prepare_release(version: str) -> ReleasePreparation:
    """Prepare release by validating version, updating files, and changelog generation."""
    normalized = validate_semantic_version(version)
    project_root = _project_root()

    previous_version = _read_project_version(project_root)
    updated_files: list[Path] = []

    for file_path, updater in _version_updaters(project_root).items():
        if updater(file_path, normalized):
            updated_files.append(file_path)

    from_tag = _latest_git_tag(project_root)
    to_ref = "HEAD"
    changelog = generate_changelog(from_tag, to_ref)

    changelog_path = project_root / "CHANGELOG.md"
    _write_changelog_entry(changelog_path, normalized, changelog)
    if changelog_path not in updated_files:
        updated_files.append(changelog_path)

    return ReleasePreparation(
        version=normalized,
        previous_version=previous_version,
        from_tag=from_tag,
        to_ref=to_ref,
        updated_files=tuple(updated_files),
        changelog=changelog,
        changelog_path=changelog_path,
    )


def build_artifacts(platforms: List[str]) -> List[Artifact]:
    """Build release artifacts for requested platform/build targets."""
    if not isinstance(platforms, list):
        raise TypeError("platforms must be a list")
    if not platforms:
        return []

    project_root = _project_root()
    version = _read_project_version(project_root)
    artifacts: list[Artifact] = []

    for raw_target in platforms:
        target = str(raw_target).strip().lower()
        if not target:
            continue

        if target in {"wheel", "wheels", "python", "pypi"}:
            artifacts.extend(_build_wheel_artifacts(project_root, version))
        elif target in {"docker", "container", "image"} or target.startswith("docker") or "/" in target:
            artifacts.append(_build_docker_artifact(project_root, version, target))
        elif target in {"binary", "bin", "executable", "pyz"}:
            artifacts.append(_build_binary_artifact(project_root, version))
        else:
            raise ValueError(f"unsupported artifact platform/build target: {raw_target!r}")

    return artifacts


def sign_artifacts(artifacts: List[Artifact], signing_key: Path) -> None:
    """Sign file-based artifacts using GPG."""
    key_path = Path(signing_key).expanduser().resolve()
    if not key_path.exists() or not key_path.is_file():
        raise FileNotFoundError(f"signing key file not found: {key_path}")

    if shutil_which("gpg") is None:
        raise RuntimeError("gpg is required for artifact signing but was not found on PATH")

    project_root = _project_root()
    import_result = _run_command(["gpg", "--batch", "--import", str(key_path)], cwd=project_root)
    if import_result.returncode != 0:
        raise RuntimeError(f"failed to import GPG key: {import_result.stderr.strip()}")

    for artifact in artifacts:
        if artifact.path is None:
            continue
        file_path = Path(artifact.path).expanduser().resolve()
        if not file_path.exists() or not file_path.is_file():
            continue

        signature_path = file_path.with_suffix(file_path.suffix + ".asc")
        sign_result = _run_command(
            [
                "gpg",
                "--batch",
                "--yes",
                "--armor",
                "--detach-sign",
                "--output",
                str(signature_path),
                str(file_path),
            ],
            cwd=project_root,
        )
        if sign_result.returncode != 0:
            raise RuntimeError(
                f"failed to sign artifact {file_path.name}: {sign_result.stderr.strip()}"
            )

        artifact.signature_path = signature_path


def publish_release(artifacts: List[Artifact], release_notes: str) -> Release:
    """Publish release artifacts to configured release destinations."""
    project_root = _project_root()
    version = _infer_release_version(artifacts, project_root)

    wheel_paths = [
        str(item.path)
        for item in artifacts
        if item.artifact_type in {"wheel", "sdist"} and item.path is not None
    ]
    docker_refs = [item.reference for item in artifacts if item.artifact_type == "docker_image" and item.reference]

    pypi_uploaded = False
    if wheel_paths:
        if shutil_which("twine") is None:
            raise RuntimeError("twine is required to publish Python artifacts to PyPI")
        upload_result = _run_command(["twine", "upload", *wheel_paths], cwd=project_root)
        if upload_result.returncode != 0:
            raise RuntimeError(f"PyPI upload failed: {upload_result.stderr.strip()}")
        pypi_uploaded = True

    docker_pushed: list[str] = []
    if docker_refs:
        if shutil_which("docker") is None:
            raise RuntimeError("docker is required to publish Docker image artifacts")
        for reference in docker_refs:
            push_result = _run_command(["docker", "push", reference], cwd=project_root)
            if push_result.returncode != 0:
                raise RuntimeError(f"Docker push failed for {reference}: {push_result.stderr.strip()}")
            docker_pushed.append(reference)

    github_release_url: str | None = None
    published_assets: list[str] = []
    github_token = os.getenv("GITHUB_TOKEN", "").strip()
    github_repo = os.getenv("GITHUB_REPOSITORY", "").strip()

    if github_token and github_repo:
        release_payload = _create_or_get_github_release(
            repository=github_repo,
            token=github_token,
            version=version,
            release_notes=release_notes,
        )
        github_release_url = str(release_payload.get("html_url") or "").strip() or None
        upload_url = str(release_payload.get("upload_url") or "").split("{", 1)[0].strip()

        if upload_url:
            for artifact in artifacts:
                if artifact.path is None:
                    continue
                file_path = Path(artifact.path).expanduser().resolve()
                if not file_path.exists() or not file_path.is_file():
                    continue

                with file_path.open("rb") as handle:
                    response = requests.post(
                        f"{upload_url}?name={quote(file_path.name)}",
                        headers={
                            "Authorization": f"Bearer {github_token}",
                            "Accept": "application/vnd.github+json",
                            "Content-Type": "application/octet-stream",
                        },
                        data=handle.read(),
                        timeout=120,
                    )

                if response.status_code not in {200, 201}:
                    raise RuntimeError(
                        "GitHub asset upload failed for "
                        f"{file_path.name}: HTTP {response.status_code} {response.text}"
                    )

                payload = response.json() if response.content else {}
                published_assets.append(str(payload.get("browser_download_url") or file_path.name))

    targets: list[str] = []
    if pypi_uploaded:
        targets.append("pypi")
    if github_release_url:
        targets.append("github")
    if docker_pushed:
        targets.append("dockerhub")

    return Release(
        version=version,
        pypi_uploaded=pypi_uploaded,
        github_release_url=github_release_url,
        docker_pushed=tuple(docker_pushed),
        published_assets=tuple(published_assets),
        release_notes=release_notes,
        release_targets=tuple(targets),
    )


def generate_changelog(from_tag: str, to_tag: str) -> str:
    """Generate markdown changelog from git commit subjects between refs."""
    project_root = _project_root()
    range_spec = _git_range_spec(from_tag, to_tag)

    command = ["git", "log", "--pretty=format:%s"]
    if range_spec:
        command.append(range_spec)

    result = _run_command(command, cwd=project_root)
    if result.returncode != 0:
        raise RuntimeError(f"failed to generate changelog: {result.stderr.strip()}")

    subjects = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not subjects:
        return "- No changes recorded."

    sections: dict[str, list[str]] = {
        "Features": [],
        "Fixes": [],
        "Performance": [],
        "Refactoring": [],
        "Documentation": [],
        "Tests": [],
        "Build & CI": [],
        "Other": [],
    }

    for subject in subjects:
        category, description = _categorize_commit_subject(subject)
        sections[category].append(description)

    lines: list[str] = []
    for heading, items in sections.items():
        if not items:
            continue
        lines.append(f"### {heading}")
        for item in items:
            lines.append(f"- {item}")
        lines.append("")

    rendered = "\n".join(lines).strip()
    return rendered if rendered else "- No changes recorded."


def validate_semantic_version(version: str) -> str:
    """Validate semantic version and return normalized version string."""
    candidate = version.strip()
    if _SEMVER_PATTERN.fullmatch(candidate) is None:
        raise ValueError(
            "version must follow semantic versioning (for example: 1.2.3, 1.2.3-rc.1)"
        )
    return candidate


def _version_updaters(project_root: Path) -> dict[Path, Any]:
    return {
        project_root / "pyproject.toml": _update_pyproject_version,
        project_root / "setup.py": _update_setup_version,
        project_root / "src/core/__init__.py": _update_core_version,
        project_root / "src/api/rest_api.py": _update_rest_api_version,
    }


def _update_pyproject_version(path: Path, version: str) -> bool:
    if not path.exists() or not path.is_file():
        return False

    text = path.read_text(encoding="utf-8")
    pattern = re.compile(r"(\[tool\.poetry\][\s\S]*?^version\s*=\s*)\"[^\"]+\"", re.MULTILINE)
    updated, count = pattern.subn(lambda match: f'{match.group(1)}"{version}"', text, count=1)
    if count == 0 or updated == text:
        return False

    path.write_text(updated, encoding="utf-8")
    return True


def _update_setup_version(path: Path, version: str) -> bool:
    return _replace_file_regex(path, r'(version\s*=\s*)"[^"]+"', rf'\1"{version}"')


def _update_core_version(path: Path, version: str) -> bool:
    return _replace_file_regex(path, r'(?m)^__version__\s*=\s*"[^"]+"', f'__version__ = "{version}"')


def _update_rest_api_version(path: Path, version: str) -> bool:
    return _replace_file_regex(path, r'(?m)^(\s*version\s*=\s*)"[^"]+"', rf'\1"{version}"')


def _replace_file_regex(path: Path, pattern: str, replacement: str) -> bool:
    if not path.exists() or not path.is_file():
        return False

    text = path.read_text(encoding="utf-8")
    updated, count = re.subn(pattern, replacement, text, count=1)
    if count == 0 or updated == text:
        return False

    path.write_text(updated, encoding="utf-8")
    return True


def _read_project_version(project_root: Path) -> str:
    pyproject = project_root / "pyproject.toml"
    if pyproject.exists() and pyproject.is_file():
        text = pyproject.read_text(encoding="utf-8")
        match = re.search(r"\[tool\.poetry\][\s\S]*?^version\s*=\s*\"([^\"]+)\"", text, re.MULTILINE)
        if match:
            return match.group(1).strip()

    core_init = project_root / "src/core/__init__.py"
    if core_init.exists() and core_init.is_file():
        text = core_init.read_text(encoding="utf-8")
        match = re.search(r"^__version__\s*=\s*\"([^\"]+)\"", text, re.MULTILINE)
        if match:
            return match.group(1).strip()

    raise RuntimeError("unable to determine current project version")


def _latest_git_tag(project_root: Path) -> str:
    result = _run_command(["git", "describe", "--tags", "--abbrev=0"], cwd=project_root)
    if result.returncode != 0:
        return ""
    return result.stdout.strip()


def _write_changelog_entry(changelog_path: Path, version: str, body: str) -> None:
    heading = f"## [{version}] - {date.today().isoformat()}"
    entry = f"{heading}\n\n{body.strip()}\n"

    if changelog_path.exists() and changelog_path.is_file():
        existing = changelog_path.read_text(encoding="utf-8")
    else:
        existing = "# Changelog\n\n"

    if existing.startswith("# Changelog"):
        lines = existing.splitlines()
        header = lines[0]
        remainder = "\n".join(lines[1:]).lstrip("\n")
        new_content = f"{header}\n\n{entry}\n{remainder}".rstrip() + "\n"
    else:
        new_content = f"# Changelog\n\n{entry}\n{existing}".rstrip() + "\n"

    changelog_path.write_text(new_content, encoding="utf-8")


def _git_range_spec(from_tag: str, to_tag: str) -> str:
    left = from_tag.strip()
    right = to_tag.strip()
    if left and right:
        return f"{left}..{right}"
    if right:
        return right
    if left:
        return left
    return ""


def _categorize_commit_subject(subject: str) -> tuple[str, str]:
    match = _CONVENTIONAL_SUBJECT_PATTERN.fullmatch(subject.strip())
    if match is None:
        return "Other", subject.strip()

    commit_type = match.group("type")
    description = match.group("description").strip()
    mapping = {
        "feat": "Features",
        "fix": "Fixes",
        "perf": "Performance",
        "refactor": "Refactoring",
        "docs": "Documentation",
        "test": "Tests",
        "build": "Build & CI",
        "ci": "Build & CI",
        "style": "Other",
        "chore": "Other",
        "revert": "Other",
    }
    return mapping.get(commit_type, "Other"), description


def _build_wheel_artifacts(project_root: Path, version: str) -> list[Artifact]:
    dist_dir = project_root / "dist"
    dist_dir.mkdir(parents=True, exist_ok=True)

    build_result = _run_command([sys.executable, "-m", "build", "--wheel"], cwd=project_root)
    if build_result.returncode != 0:
        setup_py = project_root / "setup.py"
        if not setup_py.exists():
            raise RuntimeError(f"wheel build failed: {build_result.stderr.strip()}")
        fallback = _run_command([sys.executable, "setup.py", "bdist_wheel"], cwd=project_root)
        if fallback.returncode != 0:
            raise RuntimeError(
                "wheel build failed using both python -m build and setup.py bdist_wheel"
            )

    wheel_paths = sorted(dist_dir.glob("*.whl"), key=lambda item: item.stat().st_mtime)
    if not wheel_paths:
        raise RuntimeError("wheel build completed but no .whl artifacts were produced")

    artifacts: list[Artifact] = []
    for path in wheel_paths:
        artifacts.append(
            Artifact(
                name=path.name,
                artifact_type="wheel",
                platform="python",
                version=version,
                path=path,
                sha256=_sha256_file(path),
            )
        )
    return artifacts


def _build_docker_artifact(project_root: Path, version: str, target: str) -> Artifact:
    if shutil_which("docker") is None:
        raise RuntimeError("docker is required for Docker image builds")

    dockerfile = project_root / "deployment/docker/Dockerfile"
    if not dockerfile.exists() or not dockerfile.is_file():
        dockerfile = project_root / "Dockerfile"

    platform = "linux/amd64" if target in {"docker", "container", "image"} else target
    tag_suffix = "" if platform in {"docker", "container", "image", "linux/amd64"} else f"-{platform.replace('/', '-') }"
    tag = f"keycrypt-shield-x:{version}{tag_suffix}"

    command = ["docker", "build", "-t", tag]
    if platform not in {"docker", "container", "image"}:
        command.extend(["--platform", platform])
    if dockerfile.exists():
        command.extend(["-f", str(dockerfile)])
    command.append(str(project_root))

    result = _run_command(command, cwd=project_root)
    if result.returncode != 0:
        raise RuntimeError(f"docker build failed for {platform}: {result.stderr.strip()}")

    return Artifact(
        name=tag,
        artifact_type="docker_image",
        platform=platform,
        version=version,
        reference=tag,
    )


def _build_binary_artifact(project_root: Path, version: str) -> Artifact:
    dist_dir = project_root / "dist" / "bin"
    dist_dir.mkdir(parents=True, exist_ok=True)

    if shutil_which("pyinstaller") is not None:
        command = [
            "pyinstaller",
            "--onefile",
            "src/cli/main.py",
            "--name",
            "keycrypt-shield-x",
            "--distpath",
            str(dist_dir),
            "--workpath",
            str(project_root / "build" / "pyinstaller"),
        ]
        result = _run_command(command, cwd=project_root)
        if result.returncode != 0:
            raise RuntimeError(f"pyinstaller binary build failed: {result.stderr.strip()}")

        candidates = sorted(dist_dir.glob("keycrypt-shield-x*"))
        if not candidates:
            raise RuntimeError("pyinstaller completed without producing a binary artifact")
        binary_path = candidates[0]
    else:
        binary_path = dist_dir / "keycrypt-shield-x.pyz"
        result = _run_command(
            [
                sys.executable,
                "-m",
                "zipapp",
                "src",
                "-o",
                str(binary_path),
                "-m",
                "src.cli.main:main",
            ],
            cwd=project_root,
        )
        if result.returncode != 0:
            raise RuntimeError(f"zipapp binary build failed: {result.stderr.strip()}")

    return Artifact(
        name=binary_path.name,
        artifact_type="binary",
        platform="python",
        version=version,
        path=binary_path,
        sha256=_sha256_file(binary_path),
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _infer_release_version(artifacts: Iterable[Artifact], project_root: Path) -> str:
    for artifact in artifacts:
        if artifact.version:
            return artifact.version
    return _read_project_version(project_root)


def _create_or_get_github_release(
    *,
    repository: str,
    token: str,
    version: str,
    release_notes: str,
) -> dict[str, Any]:
    tag_name = f"v{version}"
    url = f"https://api.github.com/repos/{repository}/releases"
    response = requests.post(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
        },
        json={
            "tag_name": tag_name,
            "name": tag_name,
            "body": release_notes,
            "draft": False,
            "prerelease": "-" in version,
        },
        timeout=30,
    )

    if response.status_code in {200, 201}:
        return response.json()

    if response.status_code == 422:
        existing = requests.get(
            f"https://api.github.com/repos/{repository}/releases/tags/{quote(tag_name)}",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
            },
            timeout=30,
        )
        if existing.status_code in {200, 201}:
            return existing.json()

    raise RuntimeError(
        f"GitHub release publication failed: HTTP {response.status_code} {response.text}"
    )


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _run_command(command: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        check=False,
    )


def shutil_which(command: str) -> str | None:
    from shutil import which

    return which(command)


__all__ = [
    "Artifact",
    "Release",
    "ReleasePreparation",
    "build_artifacts",
    "generate_changelog",
    "prepare_release",
    "publish_release",
    "sign_artifacts",
    "validate_semantic_version",
]
