#!/usr/bin/env python3
"""Interactive plugin scaffolding generator for KeyCrypt.

This development tool prompts plugin authors for core metadata and generates a
ready-to-edit plugin scaffold using Jinja2 templates.

Generated artifacts:
- plugin.yaml manifest
- provider.py implementation skeleton
- README.md usage guide
- tests/test_provider.py test template

The generator performs post-generation validation by parsing the manifest and
validating the generated provider class against known provider interfaces.
"""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import keyword
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jinja2 import BaseLoader, Environment, StrictUndefined

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.registry.plugin_manifest import PluginManifest
from src.registry.provider_registry import ProviderRegistry


@dataclass(frozen=True)
class MethodSpec:
    name: str
    signature: str
    docstring: str
    todo_steps: tuple[str, ...]
    is_async: bool = False


@dataclass(frozen=True)
class InterfaceSpec:
    key: str
    title: str
    base_class: str
    interface_symbol: str
    import_line: str
    alias_lines: tuple[str, ...]
    methods: tuple[MethodSpec, ...]
    default_permissions: tuple[str, ...]
    placeholder_call: str
    placeholder_async: bool


@dataclass(frozen=True)
class ConfigParam:
    name: str
    type_name: str
    required: bool
    description: str
    has_default: bool
    default_value: Any | None


@dataclass(frozen=True)
class ConfigParamRender:
    name: str
    safe_name: str
    type_name: str
    required: bool
    description: str
    has_default: bool
    default_literal: str
    default_yaml: str
    validator_expression: str | None
    type_description: str


@dataclass(frozen=True)
class PluginRequest:
    plugin_name: str
    plugin_slug: str
    class_name: str
    description: str
    author: str
    version: str
    api_version: str
    interface: InterfaceSpec
    dependencies: tuple[str, ...]
    config_params: tuple[ConfigParam, ...]
    output_dir: Path


@dataclass(frozen=True)
class GeneratedPaths:
    plugin_dir: Path
    manifest_path: Path
    provider_path: Path
    readme_path: Path
    tests_path: Path


@dataclass(frozen=True)
class ValidationReport:
    passed: bool
    errors: tuple[str, ...]
    warnings: tuple[str, ...]


INTERFACE_SPECS: tuple[InterfaceSpec, ...] = (
    InterfaceSpec(
        key="crypto",
        title="CryptoProvider",
        base_class="CryptoProvider",
        interface_symbol="src.abstractions.crypto_provider.CryptoProvider",
        import_line="from src.abstractions.crypto_provider import CryptoProvider",
        alias_lines=(
            "EncryptionContext = Any",
            "DecryptionContext = Any",
        ),
        methods=(
            MethodSpec(
                name="encrypt",
                signature="(self, plaintext: bytes, context: EncryptionContext) -> bytes",
                docstring="Encrypt plaintext bytes using provider-specific semantics.",
                todo_steps=(
                    "Validate plaintext and context fields.",
                    "Resolve key/nonce/associated-data from context.",
                    "Run encryption and return serialized ciphertext.",
                ),
            ),
            MethodSpec(
                name="decrypt",
                signature="(self, ciphertext: bytes, context: DecryptionContext) -> bytes",
                docstring="Decrypt ciphertext bytes using provider-specific semantics.",
                todo_steps=(
                    "Validate ciphertext and required context values.",
                    "Parse ciphertext envelope/metadata as needed.",
                    "Run decryption and integrity verification.",
                ),
            ),
            MethodSpec(
                name="get_algorithm_name",
                signature="(self) -> str",
                docstring="Return stable algorithm identifier for routing and policy.",
                todo_steps=(
                    "Return a non-empty algorithm label, for example AES-GCM-256.",
                ),
            ),
            MethodSpec(
                name="get_security_level",
                signature="(self) -> int",
                docstring="Return numeric security level used by policy engines.",
                todo_steps=(
                    "Return a positive integer mapped to your policy scale.",
                ),
            ),
        ),
        default_permissions=(
            "crypto:encrypt",
            "crypto:decrypt",
        ),
        placeholder_call='provider.encrypt(b"example", {"key": b"change-me"})',
        placeholder_async=False,
    ),
    InterfaceSpec(
        key="key",
        title="KeyProvider",
        base_class="KeyProvider",
        interface_symbol="src.abstractions.key_provider.KeyProvider",
        import_line=(
            "from src.abstractions.key_provider import "
            "KeyFilter, KeyGenerationParams, KeyMaterial, KeyMetadata, KeyProvider"
        ),
        alias_lines=(),
        methods=(
            MethodSpec(
                name="get_key",
                signature="(self, key_id: str) -> KeyMaterial",
                docstring="Retrieve key material for the given key identifier.",
                todo_steps=(
                    "Validate key_id and normalize provider identifier.",
                    "Fetch key material/metadata from your backend.",
                    "Return a populated KeyMaterial instance.",
                ),
            ),
            MethodSpec(
                name="generate_key",
                signature="(self, params: KeyGenerationParams) -> str",
                docstring="Generate a new key and return its provider identifier.",
                todo_steps=(
                    "Validate generation parameters.",
                    "Create key in provider backend.",
                    "Return the new stable key identifier.",
                ),
            ),
            MethodSpec(
                name="rotate_key",
                signature="(self, key_id: str) -> str",
                docstring="Rotate an existing key and return replacement identifier.",
                todo_steps=(
                    "Validate key_id and backend rotation policy.",
                    "Rotate key material/version in backend.",
                    "Return active replacement identifier.",
                ),
            ),
            MethodSpec(
                name="list_keys",
                signature="(self, filter: Optional[KeyFilter]) -> List[KeyMetadata]",
                docstring="List key metadata records matching optional filter.",
                todo_steps=(
                    "Fetch key list from backend.",
                    "Apply optional filter constraints.",
                    "Return List[KeyMetadata] records.",
                ),
            ),
        ),
        default_permissions=(
            "keys:read",
            "keys:rotate",
        ),
        placeholder_call="provider.generate_key(None)",
        placeholder_async=False,
    ),
    InterfaceSpec(
        key="storage",
        title="StorageProvider",
        base_class="StorageProvider",
        interface_symbol="src.abstractions.storage_provider.StorageProvider",
        import_line="from src.abstractions.storage_provider import StorageProvider",
        alias_lines=(),
        methods=(
            MethodSpec(
                name="write",
                signature="(self, data: bytes, metadata: dict[str, Any]) -> str",
                docstring="Persist an object payload and return object identifier.",
                todo_steps=(
                    "Validate payload bytes and metadata dictionary.",
                    "Write object bytes to backend storage.",
                    "Return stable object identifier.",
                ),
                is_async=True,
            ),
            MethodSpec(
                name="read",
                signature="(self, object_id: str) -> Tuple[bytes, dict[str, Any]]",
                docstring="Read object payload and metadata by identifier.",
                todo_steps=(
                    "Validate object identifier.",
                    "Read data and metadata from backend.",
                    "Return (data, metadata) tuple.",
                ),
                is_async=True,
            ),
            MethodSpec(
                name="delete",
                signature="(self, object_id: str) -> bool",
                docstring="Delete object and return whether it existed.",
                todo_steps=(
                    "Validate object identifier.",
                    "Delete object in backend (idempotent where possible).",
                    "Return True if deleted, False if missing.",
                ),
                is_async=True,
            ),
            MethodSpec(
                name="list_objects",
                signature="(self, prefix: str) -> AsyncIterator[str]",
                docstring="Asynchronously iterate object ids matching a prefix.",
                todo_steps=(
                    "Validate prefix input.",
                    "Query backend for matching object identifiers.",
                    "Yield matching identifiers as an async iterator.",
                ),
                is_async=True,
            ),
        ),
        default_permissions=(
            "storage:read",
            "storage:write",
        ),
        placeholder_call='provider.write(b"example", {})',
        placeholder_async=True,
    ),
    InterfaceSpec(
        key="intelligence",
        title="IntelligenceProvider",
        base_class="IntelligenceProvider",
        interface_symbol="src.abstractions.intelligence_provider.IntelligenceProvider",
        import_line=(
            "from src.abstractions.intelligence_provider import "
            "AlgorithmRecommendation, AnomalyScore, DataProfile, "
            "IntelligenceProvider, RiskScore, SecurityContext, SecurityEvent"
        ),
        alias_lines=(),
        methods=(
            MethodSpec(
                name="predict_risk",
                signature="(self, context: SecurityContext) -> RiskScore",
                docstring="Predict normalized risk for supplied security context.",
                todo_steps=(
                    "Validate context features and constraints.",
                    "Run model or rule-based risk computation.",
                    "Return a RiskScore in range [0.0, 1.0].",
                ),
            ),
            MethodSpec(
                name="detect_anomaly",
                signature="(self, event: SecurityEvent) -> AnomalyScore",
                docstring="Score event anomalousness using provider logic.",
                todo_steps=(
                    "Validate event payload and feature vector.",
                    "Compute anomaly score and threshold decision.",
                    "Return AnomalyScore result object.",
                ),
            ),
            MethodSpec(
                name="suggest_algorithm",
                signature="(self, data_profile: DataProfile) -> AlgorithmRecommendation",
                docstring="Recommend cryptographic algorithm for data profile.",
                todo_steps=(
                    "Validate profile constraints and compliance tags.",
                    "Run recommendation strategy or model.",
                    "Return AlgorithmRecommendation object.",
                ),
            ),
        ),
        default_permissions=(
            "policy:read",
            "observability:emit",
        ),
        placeholder_call="provider.predict_risk(None)",
        placeholder_async=False,
    ),
)


TYPE_SPECS: dict[str, dict[str, str | None]] = {
    "str": {
        "annotation": "str",
        "validator": "isinstance(VALUE, str)",
        "description": "a string",
    },
    "int": {
        "annotation": "int",
        "validator": "isinstance(VALUE, int) and not isinstance(VALUE, bool)",
        "description": "an integer",
    },
    "float": {
        "annotation": "float",
        "validator": "isinstance(VALUE, (int, float)) and not isinstance(VALUE, bool)",
        "description": "a float",
    },
    "bool": {
        "annotation": "bool",
        "validator": "isinstance(VALUE, bool)",
        "description": "a boolean",
    },
    "dict": {
        "annotation": "dict[str, Any]",
        "validator": "isinstance(VALUE, dict)",
        "description": "a dictionary",
    },
    "list": {
        "annotation": "list[Any]",
        "validator": "isinstance(VALUE, list)",
        "description": "a list",
    },
    "any": {
        "annotation": "Any",
        "validator": None,
        "description": "any value",
    },
}


MANIFEST_TEMPLATE = """name: \"{{ manifest_name }}\"
version: \"{{ version }}\"
api_version: \"{{ api_version }}\"
author: \"{{ author }}\"
description: \"{{ description }}\"
provides:
  - interface: \"{{ interface.interface_symbol }}\"
    implementation: \"{{ implementation_symbol }}\"
{% if dependencies %}dependencies:
{% for dependency in dependencies %}  - \"{{ dependency }}\"
{% endfor %}{% else %}dependencies: []
{% endif %}{% if config_params %}configuration:
{% for item in config_params %}  - name: \"{{ item.name }}\"
    type: \"{{ item.type_name }}\"
    required: {{ "true" if item.required else "false" }}
{% if item.has_default %}    default: {{ item.default_yaml }}
{% endif %}    description: \"{{ item.description }}\"
{% endfor %}{% else %}configuration: []
{% endif %}security:
  permissions:
{% if interface.default_permissions %}{% for permission in interface.default_permissions %}    - \"{{ permission }}\"
{% endfor %}{% else %}    []
{% endif %}  signature: \"\"
"""


PROVIDER_TEMPLATE = """\"\"\"Generated provider scaffold for {{ plugin_name }}.

This file is intentionally a scaffold and contains TODO markers for developers.

STEP-BY-STEP:
1. Update `PROVIDER_NAME` and `PROVIDER_VERSION` if needed.
2. Implement each required interface method.
3. Replace placeholder errors with real backend integrations.
4. Add robust validation, security checks, and tests.
\"\"\"

from __future__ import annotations

import logging
from typing import Any, AsyncIterator, List, Mapping, Optional, Tuple

{{ interface.import_line }}
{% for alias_line in interface.alias_lines %}{{ alias_line }}
{% endfor %}

class {{ class_name }}({{ interface.base_class }}):
    \"\"\"Provider scaffold implementing {{ interface.title }}.\"\"\"

    PROVIDER_NAME = \"{{ provider_name }}\"
    PROVIDER_VERSION = \"{{ version }}\"

    def __init__(self, config: Mapping[str, Any] | None = None) -> None:
        \"\"\"Initialize provider and load runtime configuration.\"\"\"
        self._logger = logging.getLogger(self.__class__.__name__)
        self._config = self._load_config(config)
        self._logger.info("Initialized provider scaffold: %s", self.PROVIDER_NAME)

    def _load_config(self, config: Mapping[str, Any] | None) -> dict[str, Any]:
        \"\"\"Normalize and validate plugin configuration parameters.\"\"\"
        raw = dict(config or {})
        resolved: dict[str, Any] = {}
        _missing = object()
{% if config_params %}{% for param in config_params %}        raw_{{ param.safe_name }} = raw.get("{{ param.name }}", _missing)
        if raw_{{ param.safe_name }} is _missing:
{% if param.required %}            raise ValueError("Missing required configuration: {{ param.name }}")
{% elif param.has_default %}            value_{{ param.safe_name }} = {{ param.default_literal }}
{% else %}            value_{{ param.safe_name }} = None
{% endif %}        else:
            value_{{ param.safe_name }} = raw_{{ param.safe_name }}
{% if param.validator_expression %}        if value_{{ param.safe_name }} is not None and not ({{ param.validator_expression }}):
            raise TypeError("config.{{ param.name }} must be {{ param.type_description }}")
{% endif %}        resolved["{{ param.name }}"] = value_{{ param.safe_name }}

{% endfor %}{% else %}        # No explicit config parameters were requested during generation.
        # Add provider-specific configuration keys here as needed.
{% endif %}        return resolved

{% for method in interface.methods %}    {% if method.is_async %}async {% endif %}def {{ method.name }}{{ method.signature }}:
        \"\"\"{{ method.docstring }}\"\"\"
{% for step in method.todo_steps %}        # TODO {{ loop.index }}: {{ step }}
{% endfor %}        self._logger.debug("TODO implementation reached: {{ method.name }}")
        try:
            raise NotImplementedError("TODO: implement {{ method.name }}")
        except NotImplementedError:
            raise
        except Exception as exc:
            self._logger.exception("Provider method failed: {{ method.name }}")
            raise RuntimeError("{{ method.name }} failed: {exc}") from exc

{% endfor %}__all__ = ["{{ class_name }}"]
"""


README_TEMPLATE = """# {{ plugin_name }}

{{ description }}

This plugin scaffold was generated automatically and is intended as a quick-start
reference for implementing {{ interface.title }}.

## Generated Files

- plugin.yaml: Plugin metadata and provider declaration.
- provider.py: Provider class scaffold with TODO sections.
- tests/test_provider.py: Starter test template.

## Configuration Parameters

{% if config_params %}| Name | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
{% for item in config_params %}| {{ item.name }} | {{ item.type_name }} | {{ "yes" if item.required else "no" }} | {{ item.default_literal if item.has_default else "(none)" }} | {{ item.description }} |
{% endfor %}{% else %}No configuration parameters were captured during generation.
{% endif %}

## Dependencies

{% if dependencies %}{% for dependency in dependencies %}- {{ dependency }}
{% endfor %}{% else %}No additional plugin dependencies were provided.
{% endif %}

## Next Steps

1. Implement all TODO-marked methods in provider.py.
2. Replace placeholder exceptions with real backend logic.
3. Expand tests and run pytest for your plugin package.
4. Validate plugin.yaml and provider class before publishing.
"""


TEST_TEMPLATE = """\"\"\"Starter tests for generated provider scaffold.\"\"\"

from __future__ import annotations

import asyncio
import importlib.util
from pathlib import Path

import pytest


def _load_provider_class():
    plugin_root = Path(__file__).resolve().parents[1]
    provider_path = plugin_root / "provider.py"

    spec = importlib.util.spec_from_file_location("generated_provider_module", provider_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load generated provider module")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.{{ class_name }}


def test_provider_can_be_instantiated() -> None:
    provider_class = _load_provider_class()
    provider = provider_class(config={{ sample_config }})

    assert provider is not None
    assert provider.PROVIDER_NAME == "{{ provider_name }}"


def test_placeholder_method_raises_not_implemented() -> None:
    provider_class = _load_provider_class()
    provider = provider_class(config={{ sample_config }})

    with pytest.raises(NotImplementedError):
{% if interface.placeholder_async %}        asyncio.run({{ interface.placeholder_call }})
{% else %}        {{ interface.placeholder_call }}
{% endif %}
"""


def build_environment() -> Environment:
    return Environment(
        loader=BaseLoader(),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )


def to_snake_case(value: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9]+", "_", value.strip()).strip("_").lower()
    normalized = re.sub(r"_+", "_", normalized)
    if not normalized:
        normalized = "plugin"
    if normalized[0].isdigit():
        normalized = f"plugin_{normalized}"
    if keyword.iskeyword(normalized):
        normalized = f"{normalized}_plugin"
    if not normalized.endswith("_provider"):
        normalized = f"{normalized}_provider"
    return normalized


def to_pascal_case(value: str) -> str:
    parts = [part for part in re.split(r"[^A-Za-z0-9]+", value) if part]
    if not parts:
        return "GeneratedProvider"
    candidate = "".join(part[:1].upper() + part[1:] for part in parts)
    if not candidate.endswith("Provider"):
        candidate = f"{candidate}Provider"
    return candidate


def normalize_class_name(value: str, *, fallback: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_]", "", value.strip())
    if not cleaned:
        return fallback

    if cleaned[0].isdigit():
        cleaned = f"Generated{cleaned}"

    parts = [part for part in cleaned.split("_") if part]
    if not parts:
        return fallback

    candidate = "".join(part[:1].upper() + part[1:] for part in parts)
    if keyword.iskeyword(candidate):
        candidate = f"{candidate}Provider"
    if not candidate.endswith("Provider"):
        candidate = f"{candidate}Provider"
    return candidate


def safe_variable_name(name: str) -> str:
    candidate = re.sub(r"[^A-Za-z0-9_]", "_", name)
    candidate = re.sub(r"_+", "_", candidate).strip("_")
    if not candidate:
        candidate = "param"
    if candidate[0].isdigit():
        candidate = f"p_{candidate}"
    if keyword.iskeyword(candidate):
        candidate = f"{candidate}_value"
    return candidate


def prompt_text(prompt: str, *, default: str | None = None, required: bool = False) -> str:
    while True:
        suffix = f" [{default}]" if default is not None else ""
        value = input(f"{prompt}{suffix}: ").strip()
        if value:
            return value
        if default is not None:
            return default
        if not required:
            return ""
        print("Value is required.")


def prompt_yes_no(prompt: str, *, default: bool = False) -> bool:
    options = "Y/n" if default else "y/N"
    while True:
        raw = input(f"{prompt} [{options}]: ").strip().lower()
        if not raw:
            return default
        if raw in {"y", "yes"}:
            return True
        if raw in {"n", "no"}:
            return False
        print("Please answer yes or no.")


def choose_interface() -> InterfaceSpec:
    print("\nChoose an interface to scaffold:")
    for index, spec in enumerate(INTERFACE_SPECS, start=1):
        print(f"  {index}. {spec.title}")

    while True:
        raw = input("Selection (number): ").strip()
        try:
            choice = int(raw)
        except ValueError:
            print("Please enter a number from the list.")
            continue

        if 1 <= choice <= len(INTERFACE_SPECS):
            return INTERFACE_SPECS[choice - 1]
        print("Selection is out of range.")


def choose_type_name() -> str:
    keys = list(TYPE_SPECS.keys())
    print("Available parameter types:")
    for index, key in enumerate(keys, start=1):
        print(f"  {index}. {key}")

    while True:
        raw = input("Type selection (number): ").strip()
        try:
            choice = int(raw)
        except ValueError:
            print("Please enter a number from the list.")
            continue

        if 1 <= choice <= len(keys):
            return keys[choice - 1]
        print("Selection is out of range.")


def parse_default_value(raw: str, type_name: str) -> Any:
    text = raw.strip()
    if type_name == "str":
        return text
    if type_name == "int":
        return int(text)
    if type_name == "float":
        return float(text)
    if type_name == "bool":
        lowered = text.lower()
        if lowered in {"true", "t", "1", "yes", "y"}:
            return True
        if lowered in {"false", "f", "0", "no", "n"}:
            return False
        raise ValueError("bool default must be true/false")
    if type_name == "dict":
        try:
            value = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError("dict default must be valid JSON object") from exc
        if not isinstance(value, dict):
            raise ValueError("dict default must be a JSON object")
        return value
    if type_name == "list":
        try:
            value = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError("list default must be valid JSON array") from exc
        if not isinstance(value, list):
            raise ValueError("list default must be a JSON array")
        return value
    return text


def prompt_config_params() -> tuple[ConfigParam, ...]:
    print("\nConfiguration parameters")
    print("Add as many parameters as needed; leave empty to finish.")

    params: list[ConfigParam] = []
    seen_names: set[str] = set()

    while True:
        if not prompt_yes_no("Add a configuration parameter?", default=False):
            break

        while True:
            name = prompt_text("Parameter name", required=True)
            if name in seen_names:
                print("Parameter already exists; choose a unique name.")
                continue
            break

        type_name = choose_type_name()
        required = prompt_yes_no("Required parameter?", default=True)
        description = prompt_text("Description", default="")

        has_default = False
        default_value: Any | None = None
        if not required:
            default_raw = prompt_text(
                "Default value (leave blank for none)",
                default="",
            )
            if default_raw != "":
                try:
                    default_value = parse_default_value(default_raw, type_name)
                    has_default = True
                except ValueError as exc:
                    print(f"Invalid default value: {exc}")
                    continue

        params.append(
            ConfigParam(
                name=name,
                type_name=type_name,
                required=required,
                description=description,
                has_default=has_default,
                default_value=default_value,
            )
        )
        seen_names.add(name)

    return tuple(params)


def prompt_dependencies() -> tuple[str, ...]:
    raw = prompt_text(
        "\nDependencies (comma-separated, e.g. hvac>=2.0.0)",
        default="",
    )
    if not raw:
        return tuple()

    dependencies: list[str] = []
    for item in raw.split(","):
        dep = item.strip()
        if dep and dep not in dependencies:
            dependencies.append(dep)
    return tuple(dependencies)


def collect_request(output_root: Path) -> PluginRequest:
    print("Interactive Plugin Generator\n")

    plugin_name = prompt_text("Plugin display name", required=True)
    description = prompt_text("Plugin description", required=True)
    interface = choose_interface()

    default_slug = to_snake_case(plugin_name)
    plugin_slug = prompt_text("Plugin folder/module name", default=default_slug)
    plugin_slug = to_snake_case(plugin_slug)

    default_class_name = to_pascal_case(plugin_slug)
    class_name_input = prompt_text("Provider class name", default=default_class_name)
    class_name = normalize_class_name(class_name_input, fallback=default_class_name)
    if class_name != class_name_input.strip():
        print(f"Normalized provider class name to: {class_name}")

    author = prompt_text("Author", default="Plugin Developer")
    version = prompt_text("Plugin version", default="0.1.0")
    api_version = prompt_text("API version", default="v1")

    dependencies = prompt_dependencies()
    config_params = prompt_config_params()

    output_dir = output_root / plugin_slug

    return PluginRequest(
        plugin_name=plugin_name,
        plugin_slug=plugin_slug,
        class_name=class_name,
        description=description,
        author=author,
        version=version,
        api_version=api_version,
        interface=interface,
        dependencies=dependencies,
        config_params=config_params,
        output_dir=output_dir,
    )


def as_render_config(params: tuple[ConfigParam, ...]) -> tuple[ConfigParamRender, ...]:
    rendered: list[ConfigParamRender] = []

    for param in params:
        type_spec = TYPE_SPECS[param.type_name]
        validator = type_spec["validator"]
        if validator is not None:
            validator = validator.replace("VALUE", f"value_{safe_variable_name(param.name)}")

        default_literal = repr(param.default_value) if param.has_default else "None"
        default_yaml = json.dumps(param.default_value) if param.has_default else "null"

        rendered.append(
            ConfigParamRender(
                name=param.name,
                safe_name=safe_variable_name(param.name),
                type_name=param.type_name,
                required=param.required,
                description=param.description,
                has_default=param.has_default,
                default_literal=default_literal,
                default_yaml=default_yaml,
                validator_expression=validator,
                type_description=str(type_spec["description"]),
            )
        )

    return tuple(rendered)


def sample_config_literal(params: tuple[ConfigParam, ...]) -> str:
    sample: dict[str, Any] = {}

    for param in params:
        if param.has_default:
            sample[param.name] = param.default_value
            continue

        if not param.required:
            continue

        if param.type_name == "str":
            sample[param.name] = "change-me"
        elif param.type_name == "int":
            sample[param.name] = 1
        elif param.type_name == "float":
            sample[param.name] = 1.0
        elif param.type_name == "bool":
            sample[param.name] = False
        elif param.type_name == "dict":
            sample[param.name] = {}
        elif param.type_name == "list":
            sample[param.name] = []
        else:
            sample[param.name] = "change-me"

    return repr(sample)


def ensure_output_path(output_dir: Path) -> None:
    if output_dir.exists() and any(output_dir.iterdir()):
        overwrite = prompt_yes_no(
            f"Output directory already exists and is not empty: {output_dir}. Overwrite files?",
            default=False,
        )
        if not overwrite:
            raise RuntimeError("Generation aborted by user")

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "tests").mkdir(parents=True, exist_ok=True)


def render_templates(request: PluginRequest) -> GeneratedPaths:
    env = build_environment()
    config_render = as_render_config(request.config_params)

    provider_name = request.plugin_slug.replace("_", "-")
    manifest_name = provider_name
    implementation_symbol = f"{request.plugin_slug}.provider.{request.class_name}"

    context = {
        "plugin_name": request.plugin_name,
        "provider_name": provider_name,
        "manifest_name": manifest_name,
        "class_name": request.class_name,
        "description": request.description,
        "author": request.author,
        "version": request.version,
        "api_version": request.api_version,
        "interface": request.interface,
        "dependencies": request.dependencies,
        "config_params": config_render,
        "implementation_symbol": implementation_symbol,
        "sample_config": sample_config_literal(request.config_params),
    }

    manifest_text = env.from_string(MANIFEST_TEMPLATE).render(**context)
    provider_text = env.from_string(PROVIDER_TEMPLATE).render(**context)
    readme_text = env.from_string(README_TEMPLATE).render(**context)
    tests_text = env.from_string(TEST_TEMPLATE).render(**context)

    manifest_path = request.output_dir / "plugin.yaml"
    provider_path = request.output_dir / "provider.py"
    readme_path = request.output_dir / "README.md"
    tests_path = request.output_dir / "tests" / "test_provider.py"

    manifest_path.write_text(manifest_text, encoding="utf-8")
    provider_path.write_text(provider_text, encoding="utf-8")
    readme_path.write_text(readme_text, encoding="utf-8")
    tests_path.write_text(tests_text, encoding="utf-8")

    return GeneratedPaths(
        plugin_dir=request.output_dir,
        manifest_path=manifest_path,
        provider_path=provider_path,
        readme_path=readme_path,
        tests_path=tests_path,
    )


def validate_generated_plugin(paths: GeneratedPaths, request: PluginRequest) -> ValidationReport:
    errors: list[str] = []
    warnings: list[str] = []

    for required_path in (paths.manifest_path, paths.provider_path, paths.readme_path, paths.tests_path):
        if not required_path.exists():
            errors.append(f"missing generated file: {required_path}")

    manifest: PluginManifest | None = None
    try:
        manifest = PluginManifest.from_yaml(paths.manifest_path)
    except Exception as exc:
        errors.append(f"manifest validation failed: {exc}")

    if manifest is not None:
        if not manifest.provides:
            errors.append("manifest.provides must contain at least one provider declaration")
        else:
            declaration = manifest.provides[0]
            if declaration.interface != request.interface.interface_symbol:
                errors.append(
                    "manifest interface mismatch: "
                    f"expected {request.interface.interface_symbol}, got {declaration.interface}"
                )

        if manifest.api_version != request.api_version:
            warnings.append(
                f"manifest api_version differs from requested value: {manifest.api_version}"
            )

    try:
        spec = importlib.util.spec_from_file_location(
            f"generated_plugin_{request.plugin_slug}",
            paths.provider_path,
        )
        if spec is None or spec.loader is None:
            raise RuntimeError("unable to load provider module spec")

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except Exception as exc:
        errors.append(f"failed to import generated provider module: {exc}")
        return ValidationReport(False, tuple(errors), tuple(warnings))

    provider_class = getattr(module, request.class_name, None)
    if not inspect.isclass(provider_class):
        errors.append(f"provider class not found: {request.class_name}")
        return ValidationReport(False, tuple(errors), tuple(warnings))

    registry = ProviderRegistry()
    validation = registry.validate_provider(provider_class)
    if not validation.is_valid:
        for item in validation.errors:
            errors.append(f"provider validation: {item}")

    if validation.interface is None:
        errors.append("provider validation: unable to resolve interface")
    elif validation.interface.__name__ != request.interface.base_class:
        errors.append(
            "provider validation: interface mismatch "
            f"(expected {request.interface.base_class}, got {validation.interface.__name__})"
        )

    return ValidationReport(not errors, tuple(errors), tuple(warnings))


def print_summary(paths: GeneratedPaths, report: ValidationReport) -> None:
    print("\nGenerated plugin scaffold:")
    print(f"- {paths.manifest_path}")
    print(f"- {paths.provider_path}")
    print(f"- {paths.readme_path}")
    print(f"- {paths.tests_path}")

    print("\nValidation results:")
    if report.passed:
        print("- PASS: generated plugin scaffold is valid.")
    else:
        print("- FAIL: generated scaffold has validation issues.")
        for issue in report.errors:
            print(f"  - {issue}")

    if report.warnings:
        print("\nWarnings:")
        for warning in report.warnings:
            print(f"- {warning}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Interactive KeyCrypt plugin generator")
    parser.add_argument(
        "--output-root",
        default=str(REPO_ROOT / "plugins" / "community"),
        help="Directory where the generated plugin folder will be created",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output_root = Path(args.output_root).expanduser().resolve()
    output_root.mkdir(parents=True, exist_ok=True)

    try:
        request = collect_request(output_root)
        ensure_output_path(request.output_dir)
        paths = render_templates(request)
        report = validate_generated_plugin(paths, request)
    except KeyboardInterrupt:
        print("\nGeneration cancelled.")
        return 130
    except Exception as exc:
        print(f"\nGeneration failed: {exc}")
        return 1

    print_summary(paths, report)
    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
