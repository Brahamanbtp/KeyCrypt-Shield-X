"""Structured logging utilities for KeyCrypt Shield X."""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from loguru import logger


DEFAULT_FORMAT = (
    "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
    "<level>{level: <8}</level> | "
    "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
    "<level>{message}</level>"
)

SECURITY_FORMAT = (
    "<red>{time:YYYY-MM-DD HH:mm:ss.SSS}</red> | "
    "<level>SECURITY-{level: <8}</level> | "
    "<yellow>{extra[event_type]}</yellow> | "
    "actor={extra[actor]} target={extra[target]} details={extra[details]}"
)


def _is_at_least_level(level_name: str, minimum_level_name: str) -> bool:
    return logger.level(level_name).no >= logger.level(minimum_level_name).no


def _module_level_filter(module_name: str, min_level: str):
    module_name = module_name.strip()
    min_level = min_level.upper().strip()

    def _filter(record: dict[str, Any]) -> bool:
        record_module = record["name"] or ""
        return record_module.startswith(module_name) and _is_at_least_level(record["level"].name, min_level)

    return _filter


def _default_filter(module_levels: dict[str, str]):
    normalized = {name.strip(): level.upper().strip() for name, level in module_levels.items()}

    def _filter(record: dict[str, Any]) -> bool:
        record_module = record["name"] or ""
        for module_name, min_level in normalized.items():
            if record_module.startswith(module_name):
                return _is_at_least_level(record["level"].name, min_level)
        return True

    return _filter


def configure_logging(
    environment: str = "development",
    log_dir: str | Path = "logs",
    module_levels: dict[str, str] | None = None,
    app_level: str = "INFO",
) -> None:
    """Configure Loguru for development or production use.

    Args:
        environment: development enables colored console logs, production writes JSON logs.
        log_dir: Directory used for rotating log files.
        module_levels: Per-module minimum levels, for example {"src.core": "DEBUG"}.
        app_level: Fallback minimum level when no module override exists.
    """
    env = environment.lower().strip()
    logs_path = Path(log_dir)
    logs_path.mkdir(parents=True, exist_ok=True)

    module_levels = module_levels or {}
    default_filter = _default_filter(module_levels)

    logger.remove()

    logger.add(
        logs_path / "app.log",
        level=app_level.upper(),
        rotation="10 MB",
        retention="5 files",
        compression="zip",
        serialize=True,
        enqueue=True,
        backtrace=False,
        diagnose=False,
        filter=default_filter,
    )

    logger.add(
        logs_path / "security.log",
        level="INFO",
        rotation="10 MB",
        retention="5 files",
        compression="zip",
        serialize=True,
        enqueue=True,
        backtrace=False,
        diagnose=False,
        filter=lambda record: bool(record["extra"].get("security_event")),
    )

    if env == "production":
        logger.add(
            sys.stdout,
            level=app_level.upper(),
            serialize=True,
            enqueue=True,
            backtrace=False,
            diagnose=False,
            filter=default_filter,
        )
    else:
        logger.add(
            sys.stdout,
            level=app_level.upper(),
            format=DEFAULT_FORMAT,
            colorize=True,
            enqueue=True,
            backtrace=True,
            diagnose=False,
            filter=default_filter,
        )

    for module_name, min_level in module_levels.items():
        logger.add(
            logs_path / f"{module_name.replace('.', '_')}.log",
            level=min_level.upper().strip(),
            rotation="10 MB",
            retention="5 files",
            compression="zip",
            serialize=True,
            enqueue=True,
            backtrace=False,
            diagnose=False,
            filter=_module_level_filter(module_name, min_level),
        )


def get_logger(name: str):
    """Return a module-scoped logger."""
    return logger.bind(module=name)


def log_security_event(
    event_type: str,
    *,
    severity: str = "WARNING",
    actor: str = "unknown",
    target: str = "unknown",
    details: str | dict[str, Any] = "",
) -> None:
    """Write a security-specific event with strongly structured metadata."""
    detail_value = json.dumps(details, separators=(",", ":")) if isinstance(details, dict) else str(details)

    security_logger = logger.bind(
        security_event=True,
        event_type=event_type,
        actor=actor,
        target=target,
        details=detail_value,
        ts=datetime.now(UTC).isoformat(),
    )

    security_logger.log(severity.upper(), SECURITY_FORMAT)


def log_performance_metric(
    metric_name: str,
    value: float,
    *,
    unit: str = "ms",
    component: str = "core",
    extra: dict[str, Any] | None = None,
) -> None:
    """Record structured performance metrics for observability pipelines."""
    payload: dict[str, Any] = {
        "metric_name": metric_name,
        "value": value,
        "unit": unit,
        "component": component,
        "timestamp": datetime.now(UTC).isoformat(),
    }
    if extra:
        payload.update(extra)

    logger.bind(performance_metric=True, **payload).info(
        "performance metric recorded: {metric_name}={value}{unit}",
        metric_name=metric_name,
        value=value,
        unit=unit,
    )


__all__ = [
    "configure_logging",
    "get_logger",
    "log_security_event",
    "log_performance_metric",
]
