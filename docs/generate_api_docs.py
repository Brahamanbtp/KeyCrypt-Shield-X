#!/usr/bin/env python3
"""Generate API reference artifacts from the FastAPI application."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    from fastapi.routing import APIRoute
except ModuleNotFoundError as exc:
    raise SystemExit(
        "Missing dependency: fastapi. Install with: pip install fastapi"
    ) from exc

try:
    from jinja2 import Environment
except ModuleNotFoundError as exc:
    raise SystemExit(
        "Missing dependency: jinja2. Install with: pip install jinja2"
    ) from exc

try:
    from src.api.rest_api import app
except ModuleNotFoundError as exc:
    raise SystemExit(
        "Unable to import FastAPI app due to missing dependency: "
        f"{exc.name}. Install project dependencies, then rerun this script."
    ) from exc


DEFAULT_BASE_URL = "http://localhost:8000"


MARKDOWN_TEMPLATE = """
# {{ title }}

{{ description }}

- Version: `{{ version }}`
- Base URL: `{{ base_url }}`

## Authentication

Protected endpoints require:

```http
Authorization: Bearer <token>
```

Use `POST /auth/token` to obtain a JWT.

## Endpoints
{% for endpoint in endpoints %}
### {{ endpoint.method }} {{ endpoint.path }}

- Tags: {{ endpoint.tags | join(", ") if endpoint.tags else "none" }}
- Operation ID: `{{ endpoint.operation_id }}`
- Authentication: {{ "Required" if endpoint.auth_required else "Not required" }}

{% if endpoint.summary %}{{ endpoint.summary }}{% endif %}
{% if endpoint.description %}
{{ endpoint.description }}
{% endif %}

#### Request Schema

{% if endpoint.request_schema %}
```json
{{ endpoint.request_schema | tojson(indent=2) }}
```
{% else %}
_No request body._
{% endif %}

#### Response Schemas

{% for response in endpoint.responses %}
Status `{{ response.status }}`:
{% if response.schema %}
```json
{{ response.schema | tojson(indent=2) }}
```
{% else %}
_No JSON schema._
{% endif %}
{% endfor %}

#### Example Request

```bash
{{ endpoint.curl_example }}
```

#### Example Response

```json
{{ endpoint.example_response | tojson(indent=2) }}
```

{% endfor %}
""".strip()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate API docs from FastAPI OpenAPI metadata")
    parser.add_argument(
        "--output-markdown",
        default="docs/api-reference.md",
        help="Path for generated Markdown API reference",
    )
    parser.add_argument(
        "--output-openapi",
        default="docs/openapi.json",
        help="Path for generated OpenAPI JSON",
    )
    parser.add_argument(
        "--output-postman",
        default="docs/postman-collection.json",
        help="Path for generated Postman collection JSON",
    )
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help="Base URL used in generated curl and Postman examples",
    )
    return parser.parse_args()


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def dereference_schema(schema: dict[str, Any] | None, components: dict[str, Any]) -> dict[str, Any] | None:
    if schema is None:
        return None

    if "$ref" in schema:
        ref = schema["$ref"]
        ref_name = ref.rsplit("/", 1)[-1]
        resolved = components.get("schemas", {}).get(ref_name)
        if isinstance(resolved, dict):
            return dereference_schema(resolved, components)
        return None

    if "allOf" in schema:
        merged: dict[str, Any] = {"type": "object", "properties": {}}
        required: list[str] = []
        for item in schema.get("allOf", []):
            resolved = dereference_schema(item, components) or {}
            merged["properties"].update(resolved.get("properties", {}))
            required.extend(resolved.get("required", []))
        if required:
            merged["required"] = sorted(set(required))
        return merged

    if "oneOf" in schema:
        first = schema.get("oneOf", [{}])[0]
        return dereference_schema(first, components)

    if "anyOf" in schema:
        first = schema.get("anyOf", [{}])[0]
        return dereference_schema(first, components)

    if schema.get("type") == "array" and isinstance(schema.get("items"), dict):
        items = dereference_schema(schema["items"], components)
        return {**schema, "items": items}

    if schema.get("type") == "object" and isinstance(schema.get("properties"), dict):
        props = {
            key: dereference_schema(value, components) if isinstance(value, dict) else value
            for key, value in schema["properties"].items()
        }
        return {**schema, "properties": props}

    return schema


def schema_example(schema: dict[str, Any] | None, components: dict[str, Any]) -> Any:
    if schema is None:
        return {"message": "No schema available"}

    resolved = dereference_schema(schema, components)
    if not resolved:
        return {"message": "No schema available"}

    if "example" in resolved:
        return resolved["example"]

    schema_type = resolved.get("type")

    if schema_type == "object":
        properties = resolved.get("properties", {})
        output: dict[str, Any] = {}
        for key, value in properties.items():
            if isinstance(value, dict):
                output[key] = schema_example(value, components)
            else:
                output[key] = "string"
        return output

    if schema_type == "array":
        item_schema = resolved.get("items") if isinstance(resolved.get("items"), dict) else None
        return [schema_example(item_schema, components)]

    if schema_type == "integer":
        return 0

    if schema_type == "number":
        return 0.0

    if schema_type == "boolean":
        return True

    if schema_type == "string":
        enum_values = resolved.get("enum")
        if isinstance(enum_values, list) and enum_values:
            return enum_values[0]
        fmt = resolved.get("format")
        if fmt == "date-time":
            return "2026-01-01T00:00:00Z"
        if fmt == "uuid":
            return "00000000-0000-0000-0000-000000000000"
        return "string"

    return {"message": "No schema available"}


def route_operation(openapi: dict[str, Any], path: str, method: str) -> dict[str, Any]:
    return openapi.get("paths", {}).get(path, {}).get(method.lower(), {})


def request_schema(operation: dict[str, Any], components: dict[str, Any]) -> dict[str, Any] | None:
    request_body = operation.get("requestBody", {})
    content = request_body.get("content", {})

    json_schema = content.get("application/json", {}).get("schema")
    if isinstance(json_schema, dict):
        return dereference_schema(json_schema, components)

    form_schema = content.get("multipart/form-data", {}).get("schema")
    if isinstance(form_schema, dict):
        return dereference_schema(form_schema, components)

    return None


def response_schemas(operation: dict[str, Any], components: dict[str, Any]) -> list[dict[str, Any]]:
    responses = operation.get("responses", {})
    output: list[dict[str, Any]] = []

    for status, metadata in responses.items():
        content = metadata.get("content", {}) if isinstance(metadata, dict) else {}
        json_schema = content.get("application/json", {}).get("schema")
        schema = dereference_schema(json_schema, components) if isinstance(json_schema, dict) else None
        output.append({"status": status, "schema": schema})

    return output


def detect_auth_required(operation: dict[str, Any]) -> bool:
    if operation.get("security"):
        return True

    responses = operation.get("responses", {})
    return "401" in responses or "403" in responses


def curl_example(method: str, path: str, base_url: str, auth_required: bool, body: Any) -> str:
    lines = [f"curl -X {method} '{base_url}{path}'"]

    headers = ["-H 'accept: application/json'"]
    if auth_required:
        headers.append("-H 'Authorization: Bearer <token>'")

    if body is not None:
        headers.append("-H 'Content-Type: application/json'")

    lines.extend(headers)

    if body is not None:
        payload = json.dumps(body, indent=2)
        lines.append(f"-d '{payload}'")

    return " \\\n  ".join(lines)


def postman_url(base_url: str, path: str) -> dict[str, Any]:
    raw = f"{{{{base_url}}}}{path}"
    cleaned = path.lstrip("/")
    path_parts = cleaned.split("/") if cleaned else []
    return {
        "raw": raw,
        "host": ["{{base_url}}"],
        "path": path_parts,
    }


def build_endpoint_records(openapi: dict[str, Any], base_url: str) -> list[dict[str, Any]]:
    components = openapi.get("components", {})
    endpoints: list[dict[str, Any]] = []

    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue

        methods = sorted(m for m in route.methods if m not in {"HEAD", "OPTIONS"})
        for method in methods:
            operation = route_operation(openapi, route.path, method)
            req_schema = request_schema(operation, components)
            req_example = schema_example(req_schema, components) if req_schema else None
            responses = response_schemas(operation, components)

            preferred = next((r for r in responses if str(r["status"]).startswith("2")), None)
            if preferred and isinstance(preferred.get("schema"), dict):
                example_response = schema_example(preferred["schema"], components)
            else:
                example_response = {"message": "No example response available"}

            auth_required = detect_auth_required(operation)

            endpoints.append(
                {
                    "method": method,
                    "path": route.path,
                    "tags": operation.get("tags", []),
                    "summary": operation.get("summary", ""),
                    "description": operation.get("description", ""),
                    "operation_id": operation.get("operationId", route.name),
                    "auth_required": auth_required,
                    "request_schema": req_schema,
                    "request_example": req_example,
                    "responses": responses,
                    "example_response": example_response,
                    "curl_example": curl_example(
                        method,
                        route.path,
                        base_url,
                        auth_required,
                        req_example,
                    ),
                }
            )

    endpoints.sort(key=lambda item: (item["path"], item["method"]))
    return endpoints


def render_markdown(openapi: dict[str, Any], endpoints: list[dict[str, Any]], base_url: str) -> str:
    env = Environment(autoescape=False)
    template = env.from_string(MARKDOWN_TEMPLATE)
    return template.render(
        title=openapi.get("info", {}).get("title", "API Reference"),
        description=openapi.get("info", {}).get("description", ""),
        version=openapi.get("info", {}).get("version", "0.0.0"),
        base_url=base_url,
        endpoints=endpoints,
    )


def build_postman_collection(openapi: dict[str, Any], endpoints: list[dict[str, Any]]) -> dict[str, Any]:
    postman_items: list[dict[str, Any]] = []

    for endpoint in endpoints:
        headers = [{"key": "accept", "value": "application/json"}]
        if endpoint["auth_required"]:
            headers.append({"key": "Authorization", "value": "Bearer <token>"})

        body: dict[str, Any] | None = None
        if endpoint["request_example"] is not None:
            headers.append({"key": "Content-Type", "value": "application/json"})
            body = {
                "mode": "raw",
                "raw": json.dumps(endpoint["request_example"], indent=2),
                "options": {"raw": {"language": "json"}},
            }

        postman_item: dict[str, Any] = {
            "name": f"{endpoint['method']} {endpoint['path']}",
            "request": {
                "method": endpoint["method"],
                "header": headers,
                "url": postman_url("{{base_url}}", endpoint["path"]),
                "description": endpoint["description"] or endpoint["summary"],
            },
            "response": [
                {
                    "name": "Example Response",
                    "status": "OK",
                    "code": 200,
                    "_postman_previewlanguage": "json",
                    "body": json.dumps(endpoint["example_response"], indent=2),
                }
            ],
        }

        if body is not None:
            postman_item["request"]["body"] = body

        postman_items.append(postman_item)

    info = openapi.get("info", {})
    collection = {
        "info": {
            "name": info.get("title", "API Collection"),
            "description": info.get("description", ""),
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
            "version": info.get("version", "1.0.0"),
        },
        "item": postman_items,
        "variable": [{"key": "base_url", "value": DEFAULT_BASE_URL}],
    }
    return collection


def write_json(path: Path, data: dict[str, Any]) -> None:
    ensure_parent(path)
    path.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def write_markdown(path: Path, markdown: str) -> None:
    ensure_parent(path)
    path.write_text(markdown + "\n", encoding="utf-8")


def main() -> None:
    args = parse_args()

    markdown_path = Path(args.output_markdown)
    openapi_path = Path(args.output_openapi)
    postman_path = Path(args.output_postman)

    openapi = app.openapi()
    endpoints = build_endpoint_records(openapi, args.base_url)

    markdown = render_markdown(openapi, endpoints, args.base_url)
    collection = build_postman_collection(openapi, endpoints)

    write_json(openapi_path, openapi)
    write_markdown(markdown_path, markdown)
    write_json(postman_path, collection)

    print(f"Generated OpenAPI JSON: {openapi_path}")
    print(f"Generated Markdown docs: {markdown_path}")
    print(f"Generated Postman collection: {postman_path}")
    print(f"Discovered endpoints: {len(endpoints)}")


if __name__ == "__main__":
    main()
