"""Unit tests for src.registry.plugin_repository."""

from __future__ import annotations

import json
import socketserver
import subprocess
import sys
import threading
from contextlib import contextmanager
from http.server import SimpleHTTPRequestHandler
from pathlib import Path
from typing import Iterator

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.registry.plugin_repository import PluginMetadata, PluginRepository, RepositorySource


def _manifest_payload(name: str, version: str, *, api_version: str = "0.1.0", author: str = "tests") -> dict:
    return {
        "name": name,
        "version": version,
        "api_version": api_version,
        "author": author,
        "provides": [],
        "dependencies": [],
        "security": {
            "permissions": ["registry:read"],
            "signature": "",
        },
    }


def _write_plugin_package(root: Path, *, name: str, version: str, rel_path: str) -> Path:
    package_dir = root / rel_path
    package_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = package_dir / "plugin.yaml"
    manifest_path.write_text(
        json.dumps(_manifest_payload(name, version), indent=2),
        encoding="utf-8",
    )
    return package_dir


def _catalog_entry(
    *,
    name: str,
    version: str,
    official: bool,
    package_path: str | None = None,
    download_url: str | None = None,
    tags: list[str] | None = None,
    reviews: list[dict] | None = None,
    dependencies: list[str] | None = None,
) -> dict:
    payload = {
        "name": name,
        "version": version,
        "author": "tests",
        "description": f"{name} description",
        "api_version": "0.1.0",
        "official": official,
        "tags": tags or ["crypto"],
        "reviews": reviews or [],
        "dependencies": dependencies or [],
    }
    if package_path is not None:
        payload["package_path"] = package_path
    if download_url is not None:
        payload["download_url"] = download_url
    return payload


def _write_catalog(root: Path, entries: list[dict]) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "catalog.json").write_text(
        json.dumps({"plugins": entries}, indent=2),
        encoding="utf-8",
    )


@contextmanager
def _serve_directory(directory: Path) -> Iterator[str]:
    class _Handler(SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(directory), **kwargs)

        def log_message(self, format, *args):
            return

    with socketserver.TCPServer(("127.0.0.1", 0), _Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            host, port = server.server_address
            yield f"http://{host}:{port}"
        finally:
            server.shutdown()
            thread.join(timeout=3)


def test_search_and_list_across_local_http_and_git_sources(tmp_path: Path) -> None:
    local_root = tmp_path / "local-catalog"
    _write_plugin_package(local_root, name="official-local-plugin", version="1.0.0", rel_path="packages/official/1.0.0")
    _write_catalog(
        local_root,
        [
            _catalog_entry(
                name="official-local-plugin",
                version="1.0.0",
                official=True,
                package_path="packages/official/1.0.0",
                tags=["crypto", "official"],
                reviews=[
                    {"reviewer": "alice", "rating": 5, "comment": "excellent", "created_at": 10.0},
                    {"reviewer": "bob", "rating": 4, "comment": "solid", "created_at": 11.0},
                ],
            )
        ],
    )

    git_root = tmp_path / "git-catalog"
    git_root.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init"], cwd=git_root, capture_output=True, text=True, check=True)
    _write_plugin_package(git_root, name="community-git-plugin", version="1.0.0", rel_path="packages/community/1.0.0")
    _write_plugin_package(git_root, name="community-git-plugin", version="1.1.0", rel_path="packages/community/1.1.0")
    _write_catalog(
        git_root,
        [
            _catalog_entry(
                name="community-git-plugin",
                version="1.0.0",
                official=False,
                package_path="packages/community/1.0.0",
                tags=["crypto", "community"],
                reviews=[{"reviewer": "eve", "rating": 3, "comment": "ok", "created_at": 8.0}],
            ),
            _catalog_entry(
                name="community-git-plugin",
                version="1.1.0",
                official=False,
                package_path="packages/community/1.1.0",
                tags=["crypto", "community"],
                reviews=[{"reviewer": "mike", "rating": 5, "comment": "great", "created_at": 12.0}],
            ),
        ],
    )

    http_root = tmp_path / "http-catalog"
    with _serve_directory(http_root) as base_url:
        _write_catalog(
            http_root,
            [
                _catalog_entry(
                    name="community-http-plugin",
                    version="0.2.0",
                    official=False,
                    download_url=f"{base_url}/community-http-plugin-0.2.0.pkg",
                    tags=["community", "streaming"],
                    reviews=[{"reviewer": "sam", "rating": 4, "comment": "nice", "created_at": 9.0}],
                )
            ],
        )
        (http_root / "community-http-plugin-0.2.0.pkg").write_bytes(b"http-plugin-package")

        repository = PluginRepository(
            sources=[
                RepositorySource(name="official-local", kind="local", location=str(local_root), official=True),
                RepositorySource(name="community-http", kind="http", location=f"{base_url}/catalog.json", official=False),
                RepositorySource(name="community-git", kind="git", location=str(git_root), official=False),
            ],
            refresh_git_on_read=False,
        )

        all_matches = repository.search_plugins("plugin", {})
        assert {item.name for item in all_matches} == {
            "official-local-plugin",
            "community-git-plugin",
            "community-http-plugin",
        }

        official = repository.list_official_plugins()
        assert [item.name for item in official] == ["official-local-plugin"]

        community = repository.list_community_plugins()
        community_names = {item.name for item in community}
        assert community_names == {"community-git-plugin", "community-http-plugin"}

        details = repository.get_plugin_details("community-git-plugin")
        assert details.metadata.version == "1.1.0"
        assert details.available_versions == ("1.1.0", "1.0.0")
        assert len(details.reviews) >= 2


def test_download_plugin_from_local_source(tmp_path: Path) -> None:
    local_root = tmp_path / "local-download"
    _write_plugin_package(local_root, name="download-local-plugin", version="1.0.0", rel_path="packages/local/1.0.0")
    _write_catalog(
        local_root,
        [
            _catalog_entry(
                name="download-local-plugin",
                version="1.0.0",
                official=True,
                package_path="packages/local/1.0.0",
            )
        ],
    )

    repository = PluginRepository(
        sources=[RepositorySource(name="local", kind="local", location=str(local_root), official=True)],
        refresh_git_on_read=False,
    )

    output = repository.download_plugin("download-local-plugin", "1.0.0", tmp_path / "downloads")
    assert output.exists()
    assert (output / "plugin.yaml").exists()


def test_download_plugin_from_http_source(tmp_path: Path) -> None:
    http_root = tmp_path / "http-download"
    http_root.mkdir(parents=True, exist_ok=True)

    with _serve_directory(http_root) as base_url:
        package_path = http_root / "download-http-plugin-2.0.0.pkg"
        package_path.write_bytes(b"binary-http-package")

        _write_catalog(
            http_root,
            [
                _catalog_entry(
                    name="download-http-plugin",
                    version="2.0.0",
                    official=False,
                    download_url=f"{base_url}/{package_path.name}",
                    tags=["community"],
                )
            ],
        )

        repository = PluginRepository(
            sources=[RepositorySource(name="http", kind="http", location=f"{base_url}/catalog.json", official=False)]
        )

        output = repository.download_plugin("download-http-plugin", "2.0.0", tmp_path / "downloads-http")
        assert output.exists()
        assert output.read_bytes() == b"binary-http-package"


def test_publish_plugin_to_local_catalog(tmp_path: Path) -> None:
    local_root = tmp_path / "publish-catalog"
    local_root.mkdir(parents=True, exist_ok=True)

    plugin_dir = tmp_path / "plugin-to-publish"
    plugin_dir.mkdir(parents=True, exist_ok=True)
    (plugin_dir / "plugin.yaml").write_text(
        json.dumps(_manifest_payload("published-plugin", "3.1.0"), indent=2),
        encoding="utf-8",
    )

    repository = PluginRepository(
        sources=[RepositorySource(name="publish-local", kind="local", location=str(local_root), official=False)],
        refresh_git_on_read=False,
    )

    metadata = PluginMetadata(
        name="published-plugin",
        version="3.1.0",
        author="publisher",
        description="published via test",
        api_version="0.1.0",
        official=False,
        source_name="publish-local",
        source_kind="local",
        tags=("community",),
        download_url=None,
        package_ref=None,
        average_rating=0.0,
        review_count=0,
    )

    repository.publish_plugin(plugin_dir, metadata)

    published_manifest = local_root / "published-plugin" / "3.1.0" / "plugin.yaml"
    assert published_manifest.exists()

    search = repository.search_plugins("published", {})
    assert len(search) == 1
    assert search[0].name == "published-plugin"
    assert search[0].version == "3.1.0"


def test_update_notifications_include_newer_versions(tmp_path: Path) -> None:
    local_root = tmp_path / "updates-catalog"
    _write_plugin_package(local_root, name="updatable-plugin", version="1.0.0", rel_path="packages/updatable/1.0.0")
    _write_plugin_package(local_root, name="updatable-plugin", version="1.2.0", rel_path="packages/updatable/1.2.0")
    _write_catalog(
        local_root,
        [
            _catalog_entry(
                name="updatable-plugin",
                version="1.0.0",
                official=False,
                package_path="packages/updatable/1.0.0",
            ),
            _catalog_entry(
                name="updatable-plugin",
                version="1.2.0",
                official=False,
                package_path="packages/updatable/1.2.0",
            ),
        ],
    )

    repository = PluginRepository(
        sources=[RepositorySource(name="updates", kind="local", location=str(local_root), official=False)],
        refresh_git_on_read=False,
    )

    notifications = repository.get_update_notifications(
        {
            "updatable-plugin": "1.0.0",
            "already-latest": "9.9.9",
        }
    )

    assert len(notifications) == 1
    assert notifications[0].plugin_name == "updatable-plugin"
    assert notifications[0].current_version == "1.0.0"
    assert notifications[0].latest_version == "1.2.0"
