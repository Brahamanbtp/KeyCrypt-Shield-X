#!/usr/bin/env python3
"""CI/CD pipeline generator for multiple platforms.

This module provides Jinja2-templated pipeline generation for:
- GitHub Actions
- GitLab CI
- Jenkins Declarative Pipeline
- Azure DevOps Pipelines
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Mapping


@dataclass(frozen=True)
class PipelineStage:
    """Single test/deploy stage definition."""

    name: str
    commands: tuple[str, ...]
    image: str | None = None
    environment: str | None = None
    needs: tuple[str, ...] = tuple()
    condition: str | None = None


@dataclass(frozen=True)
class SecurityScanConfig:
    """Security scan configuration."""

    enabled: bool = True
    tools: tuple[str, ...] = ("bandit", "safety")
    commands: tuple[str, ...] = tuple()
    allow_failure: bool = False


@dataclass(frozen=True)
class ArtifactPublishingConfig:
    """Artifact publishing configuration."""

    enabled: bool = True
    artifact_name: str = "build-artifacts"
    paths: tuple[str, ...] = ("dist/**",)
    retention_days: int = 7


@dataclass(frozen=True)
class PipelineConfig:
    """Cross-platform pipeline configuration."""

    pipeline_name: str = "KeyCrypt CI"
    python_version: str = "3.11"
    test_stages: tuple[PipelineStage, ...] = field(
        default_factory=lambda: (
            PipelineStage(name="unit", commands=("pytest -q tests/unit",)),
        )
    )
    deploy_stages: tuple[PipelineStage, ...] = field(default_factory=tuple)
    security_scans: SecurityScanConfig = field(default_factory=SecurityScanConfig)
    artifact_publishing: ArtifactPublishingConfig = field(default_factory=ArtifactPublishingConfig)
    push_branches: tuple[str, ...] = ("main",)
    pull_request_branches: tuple[str, ...] = ("main",)
    bootstrap_commands: tuple[str, ...] = ("python -m pip install --upgrade pip",)
    install_command: str = "pip install -e ."
    runner: str = "ubuntu-latest"
    additional_env: Mapping[str, str] = field(default_factory=dict)


_DEFAULT_SECURITY_TOOL_COMMANDS: dict[str, str] = {
    "bandit": "bandit -r src",
    "safety": "safety check",
    "pip-audit": "pip-audit",
    "trivy": "trivy fs .",
}


def generate_github_actions_workflow(config: PipelineConfig) -> str:
    """Generate a GitHub Actions workflow YAML string."""
    context = _build_context(config)
    template = _jinja_env().from_string(_GITHUB_ACTIONS_TEMPLATE)
    return template.render(**context).strip() + "\n"


def generate_gitlab_ci_pipeline(config: PipelineConfig) -> str:
    """Generate a GitLab CI YAML string."""
    context = _build_context(config)
    template = _jinja_env().from_string(_GITLAB_CI_TEMPLATE)
    return template.render(**context).strip() + "\n"


def generate_jenkins_pipeline(config: PipelineConfig) -> str:
    """Generate a Jenkins declarative pipeline string."""
    context = _build_context(config)
    template = _jinja_env().from_string(_JENKINS_TEMPLATE)
    return template.render(**context).strip() + "\n"


def generate_azure_devops_pipeline(config: PipelineConfig) -> str:
    """Generate an Azure DevOps pipeline YAML string."""
    context = _build_context(config)
    template = _jinja_env().from_string(_AZURE_DEVOPS_TEMPLATE)
    return template.render(**context).strip() + "\n"


def _jinja_env() -> Any:
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


def _build_context(config: PipelineConfig) -> dict[str, Any]:
    if not isinstance(config, PipelineConfig):
        raise TypeError("config must be a PipelineConfig")

    if not config.test_stages:
        raise ValueError("PipelineConfig.test_stages must include at least one stage")

    test_stages = [_stage_context(stage, prefix="test") for stage in config.test_stages]
    deploy_stages = [_stage_context(stage, prefix="deploy") for stage in config.deploy_stages]
    security_commands = _security_commands(config.security_scans)

    test_job_ids = [item["job_id"] for item in test_stages]
    security_job_id = "security_scan"
    artifact_job_id = "publish_artifacts"

    deploy_default_needs = list(test_job_ids)
    if config.security_scans.enabled and security_commands:
        deploy_default_needs.append(security_job_id)
    if config.artifact_publishing.enabled:
        deploy_default_needs.append(artifact_job_id)

    for stage in deploy_stages:
        if stage["needs"]:
            stage["resolved_needs"] = [_slugify(item) for item in stage["needs"]]
        else:
            stage["resolved_needs"] = list(deploy_default_needs)

    env_items = [
        {"key": str(key), "value": str(value)}
        for key, value in sorted(config.additional_env.items(), key=lambda item: item[0])
    ]

    return {
        "pipeline_name": config.pipeline_name,
        "python_version": config.python_version,
        "test_stages": test_stages,
        "deploy_stages": deploy_stages,
        "security_enabled": bool(config.security_scans.enabled and security_commands),
        "security_commands": security_commands,
        "security_allow_failure": config.security_scans.allow_failure,
        "artifact_enabled": config.artifact_publishing.enabled,
        "artifact_name": config.artifact_publishing.artifact_name,
        "artifact_paths": list(config.artifact_publishing.paths),
        "artifact_retention_days": config.artifact_publishing.retention_days,
        "push_branches": list(config.push_branches),
        "pull_request_branches": list(config.pull_request_branches),
        "bootstrap_commands": list(config.bootstrap_commands),
        "install_command": config.install_command,
        "runner": config.runner,
        "env_items": env_items,
        "test_job_ids": test_job_ids,
        "security_job_id": security_job_id,
        "artifact_job_id": artifact_job_id,
    }


def _stage_context(stage: PipelineStage, *, prefix: str) -> dict[str, Any]:
    if not isinstance(stage, PipelineStage):
        raise TypeError("stage entries must be PipelineStage instances")
    if not stage.commands:
        raise ValueError(f"stage '{stage.name}' must contain at least one command")

    return {
        "name": stage.name,
        "job_id": f"{prefix}_{_slugify(stage.name)}",
        "commands": list(stage.commands),
        "image": stage.image,
        "environment": stage.environment,
        "needs": list(stage.needs),
        "condition": stage.condition,
    }


def _security_commands(config: SecurityScanConfig) -> list[str]:
    if config.commands:
        return [item for item in config.commands if item.strip()]

    resolved: list[str] = []
    for tool in config.tools:
        command = _DEFAULT_SECURITY_TOOL_COMMANDS.get(tool.strip().lower())
        if command:
            resolved.append(command)
    return resolved


def _slugify(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_]+", "_", value.strip())
    cleaned = re.sub(r"_+", "_", cleaned).strip("_")
    if not cleaned:
        return "stage"
    if cleaned[0].isdigit():
        return f"stage_{cleaned}"
    return cleaned.lower()


_GITHUB_ACTIONS_TEMPLATE = """
name: {{ pipeline_name }}

on:
  push:
    branches:
{% for branch in push_branches %}
      - {{ branch }}
{% endfor %}
  pull_request:
    branches:
{% for branch in pull_request_branches %}
      - {{ branch }}
{% endfor %}

jobs:
{% for stage in test_stages %}
  {{ stage.job_id }}:
    name: Test / {{ stage.name }}
    runs-on: {{ runner }}
{% if env_items %}
    env:
{% for item in env_items %}
      {{ item.key }}: "{{ item.value }}"
{% endfor %}
{% endif %}
{% if stage.condition %}
    if: ${{ '{{' }} {{ stage.condition }} {{ '}}' }}
{% endif %}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "{{ python_version }}"
{% for command in bootstrap_commands %}
      - name: Bootstrap {{ loop.index }}
        run: {{ command }}
{% endfor %}
      - name: Install dependencies
        run: {{ install_command }}
{% for command in stage.commands %}
      - name: {{ stage.name }} step {{ loop.index }}
        run: {{ command }}
{% endfor %}
{% endfor %}
{% if security_enabled %}
  {{ security_job_id }}:
    name: Security Scans
    runs-on: {{ runner }}
    needs:
{% for job_id in test_job_ids %}
      - {{ job_id }}
{% endfor %}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "{{ python_version }}"
{% for command in bootstrap_commands %}
      - name: Bootstrap {{ loop.index }}
        run: {{ command }}
{% endfor %}
      - name: Install dependencies
        run: {{ install_command }}
{% for command in security_commands %}
      - name: Security step {{ loop.index }}
        run: {{ command }}
{% endfor %}
{% endif %}
{% if artifact_enabled %}
  {{ artifact_job_id }}:
    name: Publish Artifacts
    runs-on: {{ runner }}
    needs:
{% for job_id in test_job_ids %}
      - {{ job_id }}
{% endfor %}
{% if security_enabled %}
      - {{ security_job_id }}
{% endif %}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/upload-artifact@v4
        with:
          name: {{ artifact_name }}
          retention-days: {{ artifact_retention_days }}
          path: |
{% for path in artifact_paths %}
            {{ path }}
{% endfor %}
{% endif %}
{% for stage in deploy_stages %}
  {{ stage.job_id }}:
    name: Deploy / {{ stage.name }}
    runs-on: {{ runner }}
{% if stage.resolved_needs %}
    needs:
{% for dependency in stage.resolved_needs %}
      - {{ dependency }}
{% endfor %}
{% endif %}
{% if stage.environment %}
    environment: {{ stage.environment }}
{% endif %}
{% if stage.condition %}
    if: ${{ '{{' }} {{ stage.condition }} {{ '}}' }}
{% endif %}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "{{ python_version }}"
{% for command in stage.commands %}
      - name: Deploy step {{ loop.index }}
        run: {{ command }}
{% endfor %}
{% endfor %}
"""


_GITLAB_CI_TEMPLATE = """
stages:
  - test
{% if security_enabled %}
  - security
{% endif %}
{% if artifact_enabled %}
  - artifacts
{% endif %}
{% if deploy_stages %}
  - deploy
{% endif %}

variables:
  PYTHON_VERSION: "{{ python_version }}"
{% for item in env_items %}
  {{ item.key }}: "{{ item.value }}"
{% endfor %}

{% for stage in test_stages %}
{{ stage.job_id }}:
  stage: test
  image: {{ stage.image or ("python:" ~ python_version) }}
  script:
{% for command in bootstrap_commands %}
    - {{ command }}
{% endfor %}
    - {{ install_command }}
{% for command in stage.commands %}
    - {{ command }}
{% endfor %}
{% endfor %}

{% if security_enabled %}
{{ security_job_id }}:
  stage: security
  image: python:{{ python_version }}
{% if security_allow_failure %}
  allow_failure: true
{% endif %}
  script:
{% for command in bootstrap_commands %}
    - {{ command }}
{% endfor %}
    - {{ install_command }}
{% for command in security_commands %}
    - {{ command }}
{% endfor %}
{% endif %}

{% if artifact_enabled %}
{{ artifact_job_id }}:
  stage: artifacts
  image: python:{{ python_version }}
  script:
    - echo "Publishing artifacts"
  artifacts:
    name: "{{ artifact_name }}"
    expire_in: "{{ artifact_retention_days }} days"
    paths:
{% for path in artifact_paths %}
      - {{ path }}
{% endfor %}
{% endif %}

{% for stage in deploy_stages %}
{{ stage.job_id }}:
  stage: deploy
  image: {{ stage.image or ("python:" ~ python_version) }}
{% if stage.resolved_needs %}
  needs:
{% for dependency in stage.resolved_needs %}
    - {{ dependency }}
{% endfor %}
{% endif %}
{% if stage.environment %}
  environment:
    name: {{ stage.environment }}
{% endif %}
  script:
{% for command in stage.commands %}
    - {{ command }}
{% endfor %}
{% endfor %}
"""


_JENKINS_TEMPLATE = """
pipeline {
  agent any

{% if env_items %}
  environment {
{% for item in env_items %}
    {{ item.key }} = '{{ item.value }}'
{% endfor %}
  }
{% endif %}

  stages {
{% for stage in test_stages %}
    stage('Test: {{ stage.name }}') {
      steps {
{% for command in bootstrap_commands %}
        sh '{{ command }}'
{% endfor %}
        sh '{{ install_command }}'
{% for command in stage.commands %}
        sh '{{ command }}'
{% endfor %}
      }
    }
{% endfor %}
{% if security_enabled %}
    stage('Security Scans') {
      steps {
{% for command in security_commands %}
        sh '{{ command }}'
{% endfor %}
      }
    }
{% endif %}
{% for stage in deploy_stages %}
    stage('Deploy: {{ stage.name }}') {
      steps {
{% for command in stage.commands %}
        sh '{{ command }}'
{% endfor %}
      }
    }
{% endfor %}
  }

{% if artifact_enabled %}
  post {
    always {
      archiveArtifacts artifacts: '{% for path in artifact_paths %}{{ path }}{% if not loop.last %},{% endif %}{% endfor %}', allowEmptyArchive: true
    }
  }
{% endif %}
}
"""


_AZURE_DEVOPS_TEMPLATE = """
trigger:
  branches:
    include:
{% for branch in push_branches %}
      - {{ branch }}
{% endfor %}

pr:
  branches:
    include:
{% for branch in pull_request_branches %}
      - {{ branch }}
{% endfor %}

variables:
  PYTHON_VERSION: "{{ python_version }}"
{% for item in env_items %}
  {{ item.key }}: "{{ item.value }}"
{% endfor %}

stages:
- stage: Test
  displayName: Test
  jobs:
{% for stage in test_stages %}
  - job: {{ stage.job_id }}
    displayName: "Test / {{ stage.name }}"
    pool:
      vmImage: "{{ runner }}"
    steps:
      - checkout: self
      - task: UsePythonVersion@0
        inputs:
          versionSpec: "{{ python_version }}"
{% for command in bootstrap_commands %}
      - script: {{ command }}
        displayName: "Bootstrap {{ loop.index }}"
{% endfor %}
      - script: {{ install_command }}
        displayName: Install dependencies
{% for command in stage.commands %}
      - script: {{ command }}
        displayName: "{{ stage.name }} step {{ loop.index }}"
{% endfor %}
{% endfor %}

{% if security_enabled %}
- stage: Security
  displayName: Security Scans
  dependsOn: Test
  jobs:
  - job: {{ security_job_id }}
    pool:
      vmImage: "{{ runner }}"
{% if security_allow_failure %}
    continueOnError: true
{% endif %}
    steps:
      - checkout: self
{% for command in security_commands %}
      - script: {{ command }}
        displayName: "Security step {{ loop.index }}"
{% endfor %}
{% endif %}

{% if artifact_enabled %}
- stage: Artifacts
  displayName: Publish Artifacts
  dependsOn:
    - Test
{% if security_enabled %}
    - Security
{% endif %}
  jobs:
  - job: {{ artifact_job_id }}
    pool:
      vmImage: "{{ runner }}"
    steps:
      - task: PublishBuildArtifacts@1
        inputs:
          PathtoPublish: "{{ artifact_paths[0] if artifact_paths else '.' }}"
          ArtifactName: "{{ artifact_name }}"
{% endif %}

{% if deploy_stages %}
- stage: Deploy
  displayName: Deploy
  dependsOn:
    - Test
{% if security_enabled %}
    - Security
{% endif %}
{% if artifact_enabled %}
    - Artifacts
{% endif %}
  jobs:
{% for stage in deploy_stages %}
  - job: {{ stage.job_id }}
    displayName: "Deploy / {{ stage.name }}"
    pool:
      vmImage: "{{ runner }}"
{% if stage.condition %}
    condition: {{ stage.condition }}
{% endif %}
    steps:
      - checkout: self
{% for command in stage.commands %}
      - script: {{ command }}
        displayName: "Deploy step {{ loop.index }}"
{% endfor %}
{% endfor %}
{% endif %}
"""


__all__ = [
    "ArtifactPublishingConfig",
    "PipelineConfig",
    "PipelineStage",
    "SecurityScanConfig",
    "generate_azure_devops_pipeline",
    "generate_github_actions_workflow",
    "generate_gitlab_ci_pipeline",
    "generate_jenkins_pipeline",
]
