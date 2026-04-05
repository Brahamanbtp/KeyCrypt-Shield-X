"""Centralized plugin repository for discovery and distribution.

This module preserves plugin discovery/distribution and extends it with a
multi-source catalog covering local directories, remote HTTP indexes, and Git
repositories.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, List, Literal, Mapping, Sequence

from src.registry.plugin_manifest import PluginManifest
from src.utils.logging import get_logger, log_security_event


logger = get_logger("src.registry.plugin_repository")


_SEMVER_PATTERN = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)


@dataclass(frozen=True)
class RepositorySource:
    """Repository source definition used for plugin catalog ingestion."""

    name: str
    kind: Literal["local", "http", "git"]
    location: str
    official: bool = False
    branch: str = "main"
    headers: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class PluginReview:
    """Community review attached to a plugin."""

    reviewer: str
    rating: int
    comment: str = ""
    created_at: float = field(default_factory=time.time)


@dataclass(frozen=True)
class PluginMetadata:
    """Search/list metadata for a plugin version in the repository catalog."""

    name: str
    version: str
    author: str
    description: str
    api_version: str
    official: bool
    source_name: str
    source_kind: Literal["local", "http", "git"]
    tags: tuple[str, ...] = field(default_factory=tuple)
    download_url: str | None = None
    package_ref: str | None = None
    average_rating: float = 0.0
    review_count: int = 0
    published_at: float | None = None
    updated_at: float | None = None


@dataclass(frozen=True)
class PluginDetails:
    """Expanded plugin details with versions, reviews, and manifest context."""

    metadata: PluginMetadata
    available_versions: tuple[str, ...] = field(default_factory=tuple)
    reviews: tuple[PluginReview, ...] = field(default_factory=tuple)
    dependencies: tuple[str, ...] = field(default_factory=tuple)
    capabilities: tuple[str, ...] = field(default_factory=tuple)
    manifest: PluginManifest | None = None


@dataclass(frozen=True)
class UpdateNotification:
    """Notification emitted when a newer plugin version is available."""

    plugin_name: str
    current_version: str
    latest_version: str
    source_name: str
    message: str


class PluginRepository:
    """Centralized plugin catalog manager with multi-source aggregation."""

    def __init__(
        self,
        *,
        sources: Sequence[RepositorySource],
        cache_dir: Path | None = None,
        http_timeout_seconds: int = 10,
        refresh_git_on_read: bool = True,
        actor_id: str = "plugin_repository",
    ) -> None:
        if not isinstance(sources, Sequence) or not sources:
            raise ValueError("sources must be a non-empty sequence")

        parsed_sources: list[RepositorySource] = []
        for source in sources:
            if not isinstance(source, RepositorySource):
                raise TypeError("all sources must be RepositorySource instances")
            parsed_sources.append(source)

        if http_timeout_seconds <= 0:
            raise ValueError("http_timeout_seconds must be > 0")

        self._sources = tuple(parsed_sources)
        self._http_timeout_seconds = int(http_timeout_seconds)
        self._refresh_git_on_read = bool(refresh_git_on_read)
        self._actor_id = self._require_non_empty("actor_id", actor_id)

        base_cache = cache_dir or (Path(tempfile.gettempdir()) / "keycrypt-plugin-repository")
        self._cache_dir = base_cache.expanduser().resolve()
        self._cache_dir.mkdir(parents=True, exist_ok=True)

    def search_plugins(self, query: str, filters: dict) -> List[PluginMetadata]:
        """Search plugin catalog entries by text query and structured filters."""
        if not isinstance(query, str):
            raise TypeError("query must be a string")
        if not isinstance(filters, dict):
            raise TypeError("filters must be a dictionary")

        all_details = self._collect_plugin_details()
        latest = self._latest_by_plugin(all_details)

        normalized_query = query.strip().lower()
        results: list[PluginMetadata] = []

        for metadata in latest:
            if normalized_query and not self._matches_query(metadata, normalized_query):
                continue
            if not self._matches_filters(metadata, filters):
                continue
            results.append(metadata)

        results.sort(key=self._metadata_sort_key)
        return results

    def list_official_plugins(self) -> List[PluginMetadata]:
        """List latest versions of official plugins."""
        return self.search_plugins("", {"official": True})

    def list_community_plugins(self) -> List[PluginMetadata]:
        """List latest versions of community plugins."""
        return self.search_plugins("", {"official": False})

    def get_plugin_details(self, plugin_name: str) -> PluginDetails:
        """Return details for the latest version of the named plugin."""
        normalized_name = self._normalize_plugin_name(plugin_name)
        entries = [item for item in self._collect_plugin_details() if item.metadata.name.lower() == normalized_name]
        if not entries:
            raise KeyError(f"plugin not found in repository catalog: {plugin_name}")

        entries.sort(key=lambda item: self._version_sort_key(item.metadata.version), reverse=True)
        latest = entries[0]

        versions = sorted(
            {item.metadata.version for item in entries},
            key=self._version_sort_key,
            reverse=True,
        )

        reviews: list[PluginReview] = []
        for item in entries:
            reviews.extend(item.reviews)
        reviews.sort(key=lambda item: item.created_at, reverse=True)

        return PluginDetails(
            metadata=latest.metadata,
            available_versions=tuple(versions),
            reviews=tuple(reviews),
            dependencies=latest.dependencies,
            capabilities=latest.capabilities,
            manifest=latest.manifest,
        )

    def download_plugin(self, plugin_name: str, version: str, dest: Path) -> Path:
        """Download or materialize a plugin version into destination path."""
        normalized_name = self._normalize_plugin_name(plugin_name)
        normalized_version = self._require_non_empty("version", version)
        destination = Path(dest).expanduser().resolve()
        destination.mkdir(parents=True, exist_ok=True)

        candidates = [
            item
            for item in self._collect_plugin_details()
            if item.metadata.name.lower() == normalized_name and item.metadata.version == normalized_version
        ]
        if not candidates:
            raise KeyError(f"plugin version not found: {plugin_name}@{version}")

        candidate = candidates[0]
        metadata = candidate.metadata

        output_path: Path
        if metadata.source_kind == "http":
            if not metadata.download_url:
                raise ValueError(
                    f"plugin {metadata.name}@{metadata.version} does not expose a downloadable URL"
                )

            parsed = urllib.parse.urlparse(metadata.download_url)
            file_name = Path(parsed.path).name or f"{metadata.name}-{metadata.version}.plugin"
            output_path = destination / file_name
            self._download_http_file(metadata.download_url, output_path, headers={})
        else:
            source_path = self._resolve_local_package_path(candidate)
            if source_path is None or not source_path.exists():
                raise FileNotFoundError(
                    f"plugin package path does not exist for {metadata.name}@{metadata.version}"
                )

            output_path = destination / f"{metadata.name}-{metadata.version}"
            if source_path.is_file():
                output_path = destination / source_path.name
                shutil.copy2(source_path, output_path)
            else:
                if output_path.exists():
                    shutil.rmtree(output_path)
                shutil.copytree(source_path, output_path)

        log_security_event(
            "plugin_downloaded",
            severity="INFO",
            actor=self._actor_id,
            target=metadata.name,
            details={
                "plugin": metadata.name,
                "version": metadata.version,
                "source": metadata.source_name,
                "destination": str(output_path),
            },
        )
        return output_path

    def publish_plugin(self, plugin_path: Path, metadata: PluginMetadata) -> None:
        """Publish plugin metadata and package to first writable catalog source."""
        if not isinstance(metadata, PluginMetadata):
            raise TypeError("metadata must be PluginMetadata")

        source_plugin_path = Path(plugin_path).expanduser().resolve()
        if not source_plugin_path.exists():
            raise FileNotFoundError(f"plugin_path does not exist: {source_plugin_path}")

        manifest_path = source_plugin_path / "plugin.yaml"
        if not manifest_path.exists():
            raise FileNotFoundError(f"plugin manifest not found at publish path: {manifest_path}")

        PluginManifest.from_yaml(manifest_path)

        target_source = self._first_writable_source()
        if target_source is None:
            raise RuntimeError("no writable repository source configured (local/git required)")

        target_root = self._source_root_path(target_source)
        target_root.mkdir(parents=True, exist_ok=True)

        version_folder = target_root / metadata.name / metadata.version
        if version_folder.exists():
            shutil.rmtree(version_folder)
        shutil.copytree(source_plugin_path, version_folder)

        relative_path = str(version_folder.relative_to(target_root))

        catalog_path = target_root / "catalog.json"
        catalog_payload = self._read_catalog_json(catalog_path)
        plugins_raw = catalog_payload.setdefault("plugins", [])
        if not isinstance(plugins_raw, list):
            raise ValueError(f"catalog.json is invalid in source {target_source.name}")

        record = {
            "name": metadata.name,
            "version": metadata.version,
            "author": metadata.author,
            "description": metadata.description,
            "api_version": metadata.api_version,
            "official": bool(metadata.official),
            "tags": list(metadata.tags),
            "package_path": relative_path,
            "reviews": [],
            "published_at": metadata.published_at or time.time(),
            "updated_at": time.time(),
        }

        updated_plugins: list[dict[str, Any]] = []
        for item in plugins_raw:
            if not isinstance(item, dict):
                continue
            same_entry = (
                str(item.get("name", "")).strip().lower() == metadata.name.strip().lower()
                and str(item.get("version", "")).strip() == metadata.version
            )
            if same_entry:
                continue
            updated_plugins.append(item)
        updated_plugins.append(record)

        catalog_payload["plugins"] = updated_plugins
        self._write_catalog_json(catalog_path, catalog_payload)

        log_security_event(
            "plugin_published",
            severity="INFO",
            actor=self._actor_id,
            target=metadata.name,
            details={
                "plugin": metadata.name,
                "version": metadata.version,
                "source": target_source.name,
                "path": str(version_folder),
            },
        )

    def get_update_notifications(self, installed_plugins: Mapping[str, str]) -> list[UpdateNotification]:
        """Return update notifications for installed plugin versions."""
        if not isinstance(installed_plugins, Mapping):
            raise TypeError("installed_plugins must be a mapping of plugin_name -> version")

        latest_by_name = {
            item.name.lower(): item
            for item in self._latest_by_plugin(self._collect_plugin_details())
        }

        notifications: list[UpdateNotification] = []
        for raw_name, raw_version in installed_plugins.items():
            if not isinstance(raw_name, str) or not raw_name.strip():
                continue
            if not isinstance(raw_version, str) or not raw_version.strip():
                continue

            normalized_name = raw_name.strip().lower()
            latest = latest_by_name.get(normalized_name)
            if latest is None:
                continue

            if self._version_sort_key(latest.version) <= self._version_sort_key(raw_version.strip()):
                continue

            notifications.append(
                UpdateNotification(
                    plugin_name=latest.name,
                    current_version=raw_version.strip(),
                    latest_version=latest.version,
                    source_name=latest.source_name,
                    message=(
                        f"Update available for {latest.name}: "
                        f"{raw_version.strip()} -> {latest.version}"
                    ),
                )
            )

        notifications.sort(key=lambda item: (item.plugin_name.lower(), self._version_sort_key(item.latest_version)))
        return notifications

    def _collect_plugin_details(self) -> list[PluginDetails]:
        collected: list[PluginDetails] = []

        for source in self._sources:
            try:
                if source.kind == "local":
                    collected.extend(self._load_local_source(source))
                elif source.kind == "http":
                    collected.extend(self._load_http_source(source))
                elif source.kind == "git":
                    collected.extend(self._load_git_source(source))
                else:
                    raise ValueError(f"unsupported source kind: {source.kind}")
            except Exception as exc:
                logger.warning(
                    "plugin repository source read failed source=%s kind=%s error=%s",
                    source.name,
                    source.kind,
                    exc,
                )

        return collected

    def _load_local_source(self, source: RepositorySource) -> list[PluginDetails]:
        root = Path(source.location).expanduser().resolve()
        if not root.exists():
            return []

        catalog_path = root / "catalog.json"
        if catalog_path.exists():
            payload = self._read_catalog_json(catalog_path)
            return self._plugin_details_from_catalog_payload(payload, source, root)

        details: list[PluginDetails] = []
        for manifest_path in sorted(root.rglob("plugin.yaml")):
            try:
                manifest = PluginManifest.from_yaml(manifest_path)
            except Exception:
                continue

            package_root = manifest_path.parent
            metadata = PluginMetadata(
                name=manifest.name,
                version=manifest.version,
                author=manifest.author,
                description="",
                api_version=manifest.api_version,
                official=bool(source.official),
                source_name=source.name,
                source_kind=source.kind,
                tags=tuple(),
                download_url=None,
                package_ref=str(package_root),
                average_rating=0.0,
                review_count=0,
                published_at=None,
                updated_at=None,
            )
            details.append(
                PluginDetails(
                    metadata=metadata,
                    available_versions=(manifest.version,),
                    reviews=tuple(),
                    dependencies=tuple(manifest.dependencies),
                    capabilities=tuple(item.interface for item in manifest.provides),
                    manifest=manifest,
                )
            )

        return details

    def _load_http_source(self, source: RepositorySource) -> list[PluginDetails]:
        request = urllib.request.Request(source.location)
        for header_key, header_value in source.headers.items():
            request.add_header(header_key, header_value)

        try:
            with urllib.request.urlopen(request, timeout=self._http_timeout_seconds) as response:
                charset = response.headers.get_content_charset("utf-8")
                body = response.read().decode(charset)
        except urllib.error.URLError:
            return []

        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            return []

        return self._plugin_details_from_catalog_payload(payload, source, base_path=None)

    def _load_git_source(self, source: RepositorySource) -> list[PluginDetails]:
        checkout_path = self._ensure_git_checkout(source)
        catalog_path = checkout_path / "catalog.json"
        if catalog_path.exists():
            payload = self._read_catalog_json(catalog_path)
            return self._plugin_details_from_catalog_payload(payload, source, checkout_path)

        # Fallback to manifest scan when catalog index is absent.
        local_source = RepositorySource(
            name=source.name,
            kind="local",
            location=str(checkout_path),
            official=source.official,
            branch=source.branch,
            headers=dict(source.headers),
        )
        return self._load_local_source(local_source)

    def _plugin_details_from_catalog_payload(
        self,
        payload: Any,
        source: RepositorySource,
        base_path: Path | None,
    ) -> list[PluginDetails]:
        if isinstance(payload, dict):
            plugins_raw = payload.get("plugins", [])
        else:
            plugins_raw = payload

        if not isinstance(plugins_raw, list):
            return []

        details: list[PluginDetails] = []
        for entry in plugins_raw:
            if not isinstance(entry, dict):
                continue

            try:
                metadata, reviews, dependencies, capabilities, manifest = self._parse_plugin_entry(
                    entry,
                    source,
                    base_path,
                )
            except Exception:
                continue

            details.append(
                PluginDetails(
                    metadata=metadata,
                    available_versions=(metadata.version,),
                    reviews=reviews,
                    dependencies=dependencies,
                    capabilities=capabilities,
                    manifest=manifest,
                )
            )

        return details

    def _parse_plugin_entry(
        self,
        entry: dict[str, Any],
        source: RepositorySource,
        base_path: Path | None,
    ) -> tuple[PluginMetadata, tuple[PluginReview, ...], tuple[str, ...], tuple[str, ...], PluginManifest | None]:
        name = self._require_non_empty("name", str(entry.get("name", "")))
        version = self._require_non_empty("version", str(entry.get("version", "")))
        author = self._require_non_empty("author", str(entry.get("author", "unknown")))

        description = str(entry.get("description", "")).strip()
        api_version = str(entry.get("api_version", "")).strip() or version

        tags_raw = entry.get("tags", [])
        tags = self._normalize_tags(tags_raw)

        download_url = entry.get("download_url")
        if not isinstance(download_url, str) or not download_url.strip():
            download_url = None

        package_ref = entry.get("package_path")
        if not isinstance(package_ref, str) or not package_ref.strip():
            package_ref = entry.get("package_ref")
        if not isinstance(package_ref, str) or not package_ref.strip():
            package_ref = None

        dependencies_raw = entry.get("dependencies", [])
        dependencies = self._normalize_text_list(dependencies_raw)

        capabilities_raw = entry.get("capabilities", [])
        capabilities = self._normalize_text_list(capabilities_raw)

        reviews = self._parse_reviews(entry.get("reviews", []))
        average_rating, review_count = self._rating_summary(reviews)

        published_at = self._optional_float(entry.get("published_at"))
        updated_at = self._optional_float(entry.get("updated_at"))

        manifest: PluginManifest | None = None
        if base_path is not None:
            manifest_path = self._resolve_manifest_path(base_path, package_ref)
            if manifest_path is not None and manifest_path.exists():
                try:
                    manifest = PluginManifest.from_yaml(manifest_path)
                    dependencies = tuple(manifest.dependencies)
                    capabilities = tuple(item.interface for item in manifest.provides)
                    api_version = manifest.api_version
                except Exception:
                    manifest = None

        metadata = PluginMetadata(
            name=name,
            version=version,
            author=author,
            description=description,
            api_version=api_version,
            official=bool(entry.get("official", source.official)),
            source_name=source.name,
            source_kind=source.kind,
            tags=tags,
            download_url=download_url,
            package_ref=package_ref,
            average_rating=average_rating,
            review_count=review_count,
            published_at=published_at,
            updated_at=updated_at,
        )

        return metadata, reviews, dependencies, capabilities, manifest

    def _ensure_git_checkout(self, source: RepositorySource) -> Path:
        location_path = Path(source.location).expanduser()
        if location_path.exists() and (location_path / ".git").exists():
            if self._refresh_git_on_read:
                self._git_run(["pull", "--ff-only"], cwd=location_path.resolve(), check=False)
            return location_path.resolve()

        cache_key = hashlib.sha256(f"{source.name}:{source.location}".encode("utf-8")).hexdigest()[:16]
        checkout = self._cache_dir / f"git-{cache_key}"

        if checkout.exists() and (checkout / ".git").exists():
            if self._refresh_git_on_read:
                self._git_run(["pull", "--ff-only"], cwd=checkout, check=False)
            return checkout

        checkout.parent.mkdir(parents=True, exist_ok=True)
        if checkout.exists():
            shutil.rmtree(checkout)

        self._git_run(["clone", "--depth", "1", "--branch", source.branch, source.location, str(checkout)], cwd=None)
        return checkout

    def _first_writable_source(self) -> RepositorySource | None:
        for source in self._sources:
            if source.kind in {"local", "git"}:
                return source
        return None

    def _source_root_path(self, source: RepositorySource) -> Path:
        if source.kind == "local":
            return Path(source.location).expanduser().resolve()
        if source.kind == "git":
            return self._ensure_git_checkout(source)
        raise ValueError("HTTP sources are read-only for publishing")

    def _resolve_local_package_path(self, details: PluginDetails) -> Path | None:
        source = next((item for item in self._sources if item.name == details.metadata.source_name), None)
        if source is None:
            return None

        if details.metadata.package_ref is None:
            return None

        package_ref = Path(details.metadata.package_ref)
        if package_ref.is_absolute():
            return package_ref

        if source.kind == "local":
            root = Path(source.location).expanduser().resolve()
        elif source.kind == "git":
            root = self._ensure_git_checkout(source)
        else:
            return None

        return (root / package_ref).resolve()

    @staticmethod
    def _resolve_manifest_path(base_path: Path, package_ref: str | None) -> Path | None:
        if package_ref:
            candidate = (base_path / package_ref).resolve()
            if candidate.is_file() and candidate.name == "plugin.yaml":
                return candidate
            if candidate.is_dir():
                return candidate / "plugin.yaml"

        fallback = base_path / "plugin.yaml"
        if fallback.exists():
            return fallback

        return None

    @staticmethod
    def _download_http_file(url: str, destination: Path, headers: Mapping[str, str]) -> None:
        request = urllib.request.Request(url)
        for key, value in headers.items():
            request.add_header(key, value)

        with urllib.request.urlopen(request, timeout=30) as response:
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open("wb") as handle:
                shutil.copyfileobj(response, handle)

    @staticmethod
    def _read_catalog_json(path: Path) -> dict[str, Any]:
        if not path.exists():
            return {"plugins": []}

        raw = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            return dict(raw)
        if isinstance(raw, list):
            return {"plugins": raw}
        raise ValueError(f"invalid catalog JSON structure at {path}")

    @staticmethod
    def _write_catalog_json(path: Path, payload: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    @staticmethod
    def _parse_reviews(raw: Any) -> tuple[PluginReview, ...]:
        if not isinstance(raw, list):
            return tuple()

        reviews: list[PluginReview] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            reviewer = str(item.get("reviewer", "anonymous")).strip() or "anonymous"
            rating_value = item.get("rating", 0)
            try:
                rating = int(rating_value)
            except Exception:
                continue
            if rating < 1 or rating > 5:
                continue

            comment = str(item.get("comment", "")).strip()
            created_at = item.get("created_at", time.time())
            try:
                created = float(created_at)
            except Exception:
                created = time.time()

            reviews.append(
                PluginReview(
                    reviewer=reviewer,
                    rating=rating,
                    comment=comment,
                    created_at=created,
                )
            )

        reviews.sort(key=lambda item: item.created_at, reverse=True)
        return tuple(reviews)

    @staticmethod
    def _rating_summary(reviews: Sequence[PluginReview]) -> tuple[float, int]:
        if not reviews:
            return 0.0, 0

        total = sum(item.rating for item in reviews)
        count = len(reviews)
        average = round(total / count, 2)
        return average, count

    @staticmethod
    def _normalize_tags(raw: Any) -> tuple[str, ...]:
        return PluginRepository._normalize_text_list(raw)

    @staticmethod
    def _normalize_text_list(raw: Any) -> tuple[str, ...]:
        if not isinstance(raw, list):
            return tuple()

        normalized: list[str] = []
        for item in raw:
            if not isinstance(item, str):
                continue
            value = item.strip()
            if not value:
                continue
            if value not in normalized:
                normalized.append(value)
        return tuple(normalized)

    @staticmethod
    def _optional_float(value: Any) -> float | None:
        if value is None:
            return None
        try:
            return float(value)
        except Exception:
            return None

    @staticmethod
    def _latest_by_plugin(details: Sequence[PluginDetails]) -> list[PluginMetadata]:
        best: dict[str, PluginMetadata] = {}
        for item in details:
            metadata = item.metadata
            key = metadata.name.lower()
            existing = best.get(key)
            if existing is None or PluginRepository._version_sort_key(metadata.version) > PluginRepository._version_sort_key(existing.version):
                best[key] = metadata

        return sorted(best.values(), key=PluginRepository._metadata_sort_key)

    @staticmethod
    def _matches_query(metadata: PluginMetadata, normalized_query: str) -> bool:
        haystack = " ".join(
            [
                metadata.name,
                metadata.version,
                metadata.author,
                metadata.description,
                metadata.api_version,
                " ".join(metadata.tags),
            ]
        ).lower()
        return normalized_query in haystack

    @staticmethod
    def _matches_filters(metadata: PluginMetadata, filters: dict[str, Any]) -> bool:
        for key, value in filters.items():
            if key == "official":
                if bool(metadata.official) != bool(value):
                    return False
            elif key == "source_kind":
                if str(value).strip().lower() != metadata.source_kind:
                    return False
            elif key == "source_name":
                if str(value).strip().lower() != metadata.source_name.lower():
                    return False
            elif key == "author":
                if str(value).strip().lower() != metadata.author.lower():
                    return False
            elif key == "tag":
                tag = str(value).strip().lower()
                if tag not in {item.lower() for item in metadata.tags}:
                    return False
            elif key == "min_rating":
                try:
                    minimum = float(value)
                except Exception:
                    return False
                if metadata.average_rating < minimum:
                    return False
            elif key == "api_version":
                if str(value).strip() != metadata.api_version:
                    return False
            elif key == "name":
                if str(value).strip().lower() != metadata.name.lower():
                    return False
            elif key == "version":
                if str(value).strip() != metadata.version:
                    return False

        return True

    @staticmethod
    def _metadata_sort_key(metadata: PluginMetadata) -> tuple[Any, ...]:
        return (
            -metadata.average_rating,
            -metadata.review_count,
            metadata.name.lower(),
            PluginRepository._version_sort_key(metadata.version),
        )

    @staticmethod
    def _version_sort_key(version: str) -> tuple[int, int, int, int, str]:
        normalized = version.strip()
        match = _SEMVER_PATTERN.fullmatch(normalized)
        if match is None:
            return (0, 0, 0, 0, normalized)
        return (1, int(match.group(1)), int(match.group(2)), int(match.group(3)), "")

    @staticmethod
    def _git_run(args: Sequence[str], cwd: Path | None, *, check: bool = True) -> subprocess.CompletedProcess[str]:
        command = ["git", *args]
        completed = subprocess.run(
            command,
            cwd=str(cwd) if cwd is not None else None,
            capture_output=True,
            text=True,
            check=False,
        )
        if check and completed.returncode != 0:
            stderr = completed.stderr.strip() if completed.stderr else ""
            raise RuntimeError(f"git command failed: {' '.join(command)}: {stderr}")
        return completed

    @staticmethod
    def _normalize_plugin_name(plugin_name: str) -> str:
        value = plugin_name.strip().lower()
        if not value:
            raise ValueError("plugin_name must be a non-empty string")
        return value

    @staticmethod
    def _require_non_empty(name: str, value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must be a non-empty string")
        return value.strip()


__all__ = [
    "RepositorySource",
    "PluginReview",
    "PluginMetadata",
    "PluginDetails",
    "UpdateNotification",
    "PluginRepository",
]
