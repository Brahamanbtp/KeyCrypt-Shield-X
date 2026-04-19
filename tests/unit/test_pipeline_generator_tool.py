"""Unit tests for ci_cd/pipeline_generator.py."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def _load_pipeline_generator_module():
    module_path = Path(__file__).resolve().parents[2] / "ci_cd/pipeline_generator.py"
    spec = importlib.util.spec_from_file_location("pipeline_generator_tool", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load pipeline_generator module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _build_config(module):
    return module.PipelineConfig(
        pipeline_name="KeyCrypt Multi CI",
        python_version="3.12",
        test_stages=(
            module.PipelineStage(
                name="unit",
                commands=("pytest -q tests/unit",),
            ),
            module.PipelineStage(
                name="integration",
                commands=("pytest -q tests/integration",),
                condition="github.ref == 'refs/heads/main'",
            ),
        ),
        deploy_stages=(
            module.PipelineStage(
                name="production",
                commands=("echo deploy",),
                environment="production",
            ),
        ),
        security_scans=module.SecurityScanConfig(
            enabled=True,
            commands=("bandit -r src", "safety check"),
            allow_failure=False,
        ),
        artifact_publishing=module.ArtifactPublishingConfig(
            enabled=True,
            artifact_name="build-output",
            paths=("dist/**", "coverage.xml"),
            retention_days=14,
        ),
        additional_env={
            "KEYCRYPT_ENV": "ci",
            "KEYCRYPT_FEATURE": "pipeline",
        },
    )


def test_generate_github_actions_workflow_contains_expected_jobs() -> None:
    module = _load_pipeline_generator_module()
    config = _build_config(module)

    rendered = module.generate_github_actions_workflow(config)

    assert "name: KeyCrypt Multi CI" in rendered
    assert "test_unit:" in rendered
    assert "test_integration:" in rendered
    assert "security_scan:" in rendered
    assert "publish_artifacts:" in rendered
    assert "deploy_production:" in rendered
    assert "uses: actions/upload-artifact@v4" in rendered
    assert "bandit -r src" in rendered
    assert "retention-days: 14" in rendered


def test_generate_gitlab_ci_pipeline_contains_stages_and_artifacts() -> None:
    module = _load_pipeline_generator_module()
    config = _build_config(module)

    rendered = module.generate_gitlab_ci_pipeline(config)

    assert "stages:" in rendered
    assert "- test" in rendered
    assert "- security" in rendered
    assert "- artifacts" in rendered
    assert "- deploy" in rendered
    assert "security_scan:" in rendered
    assert "expire_in: \"14 days\"" in rendered
    assert "deploy_production:" in rendered


def test_generate_jenkins_pipeline_contains_stage_blocks() -> None:
    module = _load_pipeline_generator_module()
    config = _build_config(module)

    rendered = module.generate_jenkins_pipeline(config)

    assert "pipeline {" in rendered
    assert "stage('Test: unit')" in rendered
    assert "stage('Security Scans')" in rendered
    assert "stage('Deploy: production')" in rendered
    assert "archiveArtifacts artifacts:" in rendered


def test_generate_azure_devops_pipeline_contains_expected_sections() -> None:
    module = _load_pipeline_generator_module()
    config = _build_config(module)

    rendered = module.generate_azure_devops_pipeline(config)

    assert "trigger:" in rendered
    assert "pr:" in rendered
    assert "- stage: Test" in rendered
    assert "- stage: Security" in rendered
    assert "- stage: Artifacts" in rendered
    assert "- stage: Deploy" in rendered
    assert "UsePythonVersion@0" in rendered
    assert "PublishBuildArtifacts@1" in rendered


def test_generate_github_actions_uses_default_security_commands_when_unspecified() -> None:
    module = _load_pipeline_generator_module()

    config = module.PipelineConfig(
        test_stages=(module.PipelineStage(name="unit", commands=("pytest -q",)),),
        security_scans=module.SecurityScanConfig(enabled=True, tools=("bandit", "safety"), commands=tuple()),
    )

    rendered = module.generate_github_actions_workflow(config)

    assert "bandit -r src" in rendered
    assert "safety check" in rendered
