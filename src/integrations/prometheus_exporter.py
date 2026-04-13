"""Prometheus metrics exporter for KeyCrypt.

This integration module exposes required KeyCrypt metrics and supports plugin
metric registration against a shared CollectorRegistry.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence


try:  # pragma: no cover - optional dependency boundary
    from prometheus_client import Counter, Gauge, Histogram, REGISTRY, CollectorRegistry, start_http_server
except Exception as exc:  # pragma: no cover - optional dependency boundary
    Counter = None  # type: ignore[assignment]
    Gauge = None  # type: ignore[assignment]
    Histogram = None  # type: ignore[assignment]
    CollectorRegistry = None  # type: ignore[assignment]
    REGISTRY = None  # type: ignore[assignment]
    start_http_server = None  # type: ignore[assignment]
    _PROMETHEUS_IMPORT_ERROR = exc
else:
    _PROMETHEUS_IMPORT_ERROR = None


class PrometheusExporterError(RuntimeError):
    """Raised when Prometheus exporter setup or operations fail."""


@dataclass(frozen=True)
class _MetricNames:
    encryptions_total: str = "keycrypt_encryptions_total"
    decryptions_total: str = "keycrypt_decryptions_total"
    encryption_duration_seconds: str = "keycrypt_encryption_duration_seconds"
    key_rotations_total: str = "keycrypt_key_rotations_total"
    active_keys: str = "keycrypt_active_keys"
    security_state: str = "keycrypt_security_state"


class PrometheusExporter:
    """Prometheus metrics exporter with custom plugin metric support."""

    METRICS_PATH = "/metrics"
    SECURITY_STATES = ("LOW", "NORMAL", "ELEVATED", "CRITICAL")

    def __init__(
        self,
        *,
        registry: Any | None = None,
        histogram_buckets: Sequence[float] | None = None,
        server_starter: Callable[..., Any] | None = None,
    ) -> None:
        self._ensure_prometheus_available()

        if registry is not None:
            self.registry = registry
        elif CollectorRegistry is not None:
            self.registry = CollectorRegistry(auto_describe=True)
        else:
            self.registry = REGISTRY

        self._server_starter = server_starter or start_http_server
        self._server_handle: Any | None = None

        names = _MetricNames()
        buckets = tuple(histogram_buckets) if histogram_buckets is not None else (
            0.0005,
            0.001,
            0.0025,
            0.005,
            0.01,
            0.025,
            0.05,
            0.1,
            0.25,
            0.5,
            1.0,
            2.5,
            5.0,
            10.0,
        )

        self.keycrypt_encryptions_total = Counter(
            names.encryptions_total,
            "Total number of successful encryption operations.",
            registry=self.registry,
        )
        self.keycrypt_decryptions_total = Counter(
            names.decryptions_total,
            "Total number of successful decryption operations.",
            registry=self.registry,
        )
        self.keycrypt_encryption_duration_seconds = Histogram(
            names.encryption_duration_seconds,
            "Encryption operation duration in seconds.",
            buckets=buckets,
            registry=self.registry,
        )
        self.keycrypt_key_rotations_total = Counter(
            names.key_rotations_total,
            "Total number of key rotation operations.",
            registry=self.registry,
        )
        self.keycrypt_active_keys = Gauge(
            names.active_keys,
            "Number of active cryptographic keys.",
            registry=self.registry,
        )
        self.keycrypt_security_state = Gauge(
            names.security_state,
            "Security state marker, 1 for active state and 0 otherwise.",
            labelnames=("state", "source"),
            registry=self.registry,
        )

        self._custom_metrics: dict[str, Any] = {}

        for state in self.SECURITY_STATES:
            self.keycrypt_security_state.labels(state=state, source="system").set(0)

    @property
    def metrics_path(self) -> str:
        return self.METRICS_PATH

    def start_http_server(self, port: int = 8000, addr: str = "0.0.0.0") -> Any:
        """Start Prometheus HTTP endpoint (exposes /metrics)."""
        if self._server_starter is None:
            raise PrometheusExporterError("start_http_server backend is unavailable")
        if int(port) <= 0:
            raise ValueError("port must be > 0")
        if not isinstance(addr, str) or not addr.strip():
            raise ValueError("addr must be a non-empty string")

        self._server_handle = self._server_starter(int(port), addr=addr.strip(), registry=self.registry)
        return self._server_handle

    def record_encryption(self, duration_seconds: float, amount: int = 1) -> None:
        """Increment encryption counter and observe duration histogram."""
        normalized_amount = self._validate_positive_int("amount", amount)
        normalized_duration = self._validate_non_negative_float("duration_seconds", duration_seconds)

        self.keycrypt_encryptions_total.inc(normalized_amount)
        self.keycrypt_encryption_duration_seconds.observe(normalized_duration)

    def record_decryption(self, amount: int = 1) -> None:
        """Increment decryption counter."""
        self.keycrypt_decryptions_total.inc(self._validate_positive_int("amount", amount))

    def record_key_rotation(self, amount: int = 1) -> None:
        """Increment key rotation counter."""
        self.keycrypt_key_rotations_total.inc(self._validate_positive_int("amount", amount))

    def set_active_keys(self, value: int) -> None:
        """Set gauge for active key count."""
        self.keycrypt_active_keys.set(self._validate_non_negative_int("value", value))

    def set_security_state(self, state: str, *, source: str = "system") -> None:
        """Set one security state active for the given source label."""
        normalized_state = self._normalize_state(state)
        normalized_source = self._validate_non_empty("source", source)

        for existing in self.SECURITY_STATES:
            self.keycrypt_security_state.labels(state=existing, source=normalized_source).set(0)
        self.keycrypt_security_state.labels(state=normalized_state, source=normalized_source).set(1)

    def register_custom_metric(self, name: str, collector: Any) -> Any:
        """Register one custom metric collector for plugin integrations."""
        key = self._validate_non_empty("name", name)
        if collector is None:
            raise ValueError("collector is required")
        if key in self._custom_metrics:
            raise ValueError(f"custom metric already registered: {key}")

        self._register_collector_if_needed(collector)
        self._custom_metrics[key] = collector
        return collector

    def register_plugin_metrics(self, plugin_name: str, factory: Callable[[Any], Any]) -> list[Any]:
        """Allow plugin factory to add one or many custom metrics."""
        normalized_plugin = self._validate_non_empty("plugin_name", plugin_name)
        if not callable(factory):
            raise TypeError("factory must be callable")

        produced = factory(self.registry)
        registered: list[Any] = []

        if produced is None:
            return registered

        if isinstance(produced, Mapping):
            for metric_name, collector in produced.items():
                key = f"{normalized_plugin}:{self._validate_non_empty('metric_name', str(metric_name))}"
                registered.append(self.register_custom_metric(key, collector))
            return registered

        if isinstance(produced, (list, tuple, set)):
            for idx, collector in enumerate(produced):
                key = f"{normalized_plugin}:metric_{idx + 1}"
                registered.append(self.register_custom_metric(key, collector))
            return registered

        key = f"{normalized_plugin}:metric"
        registered.append(self.register_custom_metric(key, produced))
        return registered

    def _register_collector_if_needed(self, collector: Any) -> None:
        register = getattr(self.registry, "register", None)
        if not callable(register):
            return

        try:
            register(collector)
        except ValueError as exc:
            # Collectors created with registry=self.registry are already registered.
            if "Duplicated timeseries" not in str(exc):
                raise

    @classmethod
    def _ensure_prometheus_available(cls) -> None:
        if Counter is None or Gauge is None or Histogram is None:
            raise PrometheusExporterError(
                "prometheus_client is unavailable"
                + ("" if _PROMETHEUS_IMPORT_ERROR is None else f" (import error: {_PROMETHEUS_IMPORT_ERROR})")
            )

    @staticmethod
    def _validate_positive_int(field_name: str, value: int) -> int:
        normalized = int(value)
        if normalized <= 0:
            raise ValueError(f"{field_name} must be > 0")
        return normalized

    @staticmethod
    def _validate_non_negative_int(field_name: str, value: int) -> int:
        normalized = int(value)
        if normalized < 0:
            raise ValueError(f"{field_name} must be >= 0")
        return normalized

    @staticmethod
    def _validate_non_negative_float(field_name: str, value: float) -> float:
        normalized = float(value)
        if normalized < 0:
            raise ValueError(f"{field_name} must be >= 0")
        return normalized

    @classmethod
    def _normalize_state(cls, state: str) -> str:
        normalized = cls._validate_non_empty("state", state).upper()
        if normalized not in cls.SECURITY_STATES:
            raise ValueError(f"state must be one of: {', '.join(cls.SECURITY_STATES)}")
        return normalized

    @staticmethod
    def _validate_non_empty(field_name: str, value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field_name} must be a non-empty string")
        return value.strip()


_DEFAULT_EXPORTER: PrometheusExporter | None = None


def get_prometheus_exporter() -> PrometheusExporter:
    """Return a process-wide default Prometheus exporter instance."""
    global _DEFAULT_EXPORTER

    if _DEFAULT_EXPORTER is None:
        _DEFAULT_EXPORTER = PrometheusExporter()
    return _DEFAULT_EXPORTER


def start_prometheus_exporter(port: int = 8000, addr: str = "0.0.0.0") -> PrometheusExporter:
    """Initialize and start the default exporter HTTP endpoint."""
    exporter = get_prometheus_exporter()
    exporter.start_http_server(port=port, addr=addr)
    return exporter


__all__ = [
    "PrometheusExporter",
    "PrometheusExporterError",
    "get_prometheus_exporter",
    "start_prometheus_exporter",
]
