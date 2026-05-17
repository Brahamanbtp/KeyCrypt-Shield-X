from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple


@dataclass
class ConfigurationSet:
    cloud: str
    environment: str
    kubernetes: Dict[str, Any] = field(default_factory=dict)
    infrastructure: Dict[str, Any] = field(default_factory=dict)
    env_vars: Dict[str, str] = field(default_factory=dict)


@dataclass
class ValidationReport:
    ok: bool
    findings: List[Tuple[str, str]] = field(default_factory=list)

    def add(self, ok: bool, message: str) -> None:
        self.findings.append(("PASS" if ok else "FAIL", message))
        if not ok:
            self.ok = False


def _base_template() -> Dict[str, Any]:
    return {
        "service": {
            "replicas": 3,
            "resources": {"requests": {"cpu": "250m", "memory": "256Mi"}, "limits": {"cpu": "500m", "memory": "512Mi"}},
            "livenessProbe": {"path": "/healthz", "port": 8080},
            "readinessProbe": {"path": "/ready", "port": 8080},
        },
        "autoscaling": {"enabled": True, "minReplicas": 2, "maxReplicas": 10, "targetCPUUtilizationPercentage": 60},
        "network": {"ingress": True, "egress": "restricted", "networkPolicy": True},
        "storage": {"class": "standard", "size": "20Gi", "encrypted": True},
        "monitoring": {"prometheus": True, "logs": "centralized"},
        "backup": {"enabled": True, "schedule": "daily"},
    }


def _cloud_overrides(cloud: str) -> Dict[str, Any]:
    cloud = cloud.lower()
    if cloud == "aws":
        return {
            "infrastructure": {"provider": "aws", "instance_type": "m6i.large", "use_spot": False, "kms": True},
            "storage": {"class": "gp3", "encrypted": True},
        }
    if cloud == "azure":
        return {
            "infrastructure": {"provider": "azure", "instance_type": "Standard_D2s_v3", "use_spot": False, "key_vault": True},
            "storage": {"class": "managed-premium", "encrypted": True},
        }
    if cloud == "gcp":
        return {
            "infrastructure": {"provider": "gcp", "instance_type": "n2-standard-2", "preemptible": False, "kms": True},
            "storage": {"class": "pd-ssd", "encrypted": True},
        }
    return {"infrastructure": {"provider": cloud}}


def _environment_overrides(environment: str) -> Dict[str, Any]:
    env = environment.lower()
    if env == "dev":
        return {"service": {"replicas": 1}, "autoscaling": {"enabled": False}, "monitoring": {"prometheus": False}}
    if env == "staging":
        return {"service": {"replicas": 2}, "autoscaling": {"minReplicas": 1, "maxReplicas": 5}}
    if env == "prod":
        return {"service": {"replicas": 5}, "autoscaling": {"minReplicas": 3, "maxReplicas": 20}}
    return {}


def generate_production_config(environment: str, cloud: str) -> ConfigurationSet:
    """Generate production-ready configuration set for the given environment and cloud."""
    base = _base_template()
    cloud_over = _cloud_overrides(cloud)
    env_over = _environment_overrides(environment)

    # Merge dictionaries (shallow for simplicity)
    merged = copy.deepcopy(base)
    # apply cloud overrides
    for k, v in cloud_over.items():
        if isinstance(v, dict):
            merged.setdefault(k, {}).update(v)
        else:
            merged[k] = v
    # apply environment overrides
    for k, v in env_over.items():
        if isinstance(v, dict):
            merged.setdefault(k, {}).update(v)
        else:
            merged[k] = v

    infra = merged.pop("infrastructure", cloud_over.get("infrastructure", {}))

    config = ConfigurationSet(cloud=cloud, environment=environment, kubernetes=merged, infrastructure=infra, env_vars={"ENVIRONMENT": environment.upper()})
    return config


def optimize_for_performance(config: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(config)
    svc = out.setdefault("service", {})
    svc["replicas"] = max(svc.get("replicas", 1), 6)
    svc["resources"] = {"requests": {"cpu": "500m", "memory": "1Gi"}, "limits": {"cpu": "2", "memory": "4Gi"}}
    out.setdefault("autoscaling", {}).update({"enabled": True, "minReplicas": 3, "maxReplicas": 50, "targetCPUUtilizationPercentage": 70})
    out.setdefault("network", {})["throughputOptimized"] = True
    out.setdefault("storage", {})["iops"] = "high"
    return out


def optimize_for_cost(config: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(config)
    svc = out.setdefault("service", {})
    svc["replicas"] = max(1, int(svc.get("replicas", 1)))
    svc["resources"] = {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"cpu": "250m", "memory": "256Mi"}}
    autos = out.setdefault("autoscaling", {})
    autos.update({"enabled": True, "minReplicas": 1, "maxReplicas": 5, "targetCPUUtilizationPercentage": 60})
    infra = out.setdefault("infrastructure", {})
    # prefer cheaper instance types or preemptible/spot
    infra["use_spot"] = True
    infra.setdefault("instance_type", "t3.small")
    out.setdefault("storage", {})["class"] = out.get("storage", {}).get("class", "standard")
    return out


def optimize_for_security(config: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(config)
    out.setdefault("storage", {})["encrypted"] = True
    out.setdefault("network", {})["networkPolicy"] = True
    out.setdefault("service", {})["securityContext"] = {"runAsNonRoot": True, "readOnlyRootFilesystem": True}
    out.setdefault("secrets", {})["encryptionAtRest"] = True
    out.setdefault("monitoring", {})["audit_logs"] = True
    out.setdefault("backup", {})["encrypted"] = True
    return out


def validate_production_readiness(config: Dict[str, Any]) -> ValidationReport:
    report = ValidationReport(ok=True)
    svc = config.get("service", {})
    replicas = svc.get("replicas", 0)
    report.add(replicas >= 2, f"replicas >=2 (found {replicas})")
    resources = svc.get("resources")
    report.add(resources is not None and "limits" in resources and "requests" in resources, "resource limits/requests configured")
    report.add(bool(svc.get("livenessProbe")), "liveness probe configured")
    report.add(bool(svc.get("readinessProbe")), "readiness probe configured")
    storage = config.get("storage", {})
    report.add(storage.get("encrypted", False), "storage encryption enabled")
    autos = config.get("autoscaling", {})
    report.add(autos.get("enabled", False), "autoscaling enabled")
    monitoring = config.get("monitoring", {})
    report.add(bool(monitoring.get("prometheus") or monitoring.get("logs")), "monitoring/logging configured")
    backup = config.get("backup", {})
    report.add(bool(backup.get("enabled") and backup.get("schedule")), "backup configured")
    return report


def templates_for_pattern(pattern: str) -> Dict[str, Any]:
    pattern = pattern.lower()
    if pattern == "web-service":
        return {
            "replicas": 3,
            "resources": {"requests": {"cpu": "200m", "memory": "256Mi"}},
            "autoscaling": {"minReplicas": 2, "maxReplicas": 10},
        }
    if pattern == "batch-job":
        return {"replicas": 1, "resources": {"requests": {"cpu": "500m", "memory": "1Gi"}}, "autoscaling": {"enabled": False}}
    return {}


if __name__ == "__main__":
    # Quick demo: generate prod config for AWS and validate
    cfg = generate_production_config("prod", "aws")
    print("Kubernetes config:\n", json.dumps(cfg.kubernetes, indent=2))
    perf = optimize_for_performance(cfg.kubernetes)
    print("Performance tuned sample:\n", json.dumps(perf, indent=2))
    val = validate_production_readiness(perf)
    print("Validation OK:", val.ok)
