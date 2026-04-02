"""Method-level dependency injection decorators for provider interfaces.

This module offers non-invasive decorators that resolve providers from the
orchestration DI container and inject them into function parameters.
"""

from __future__ import annotations

import inspect
import threading
from functools import wraps
from types import UnionType
from typing import Any, Callable, ParamSpec, TypeVar, get_args, get_origin, get_type_hints

from src.abstractions.crypto_provider import CryptoProvider
from src.abstractions.key_provider import KeyProvider
from src.abstractions.storage_provider import StorageProvider
from src.orchestration.dependency_container import CoreContainer


P = ParamSpec("P")
R = TypeVar("R")


_CONTAINER_LOCK = threading.RLock()
_DEFAULT_CONTAINER: CoreContainer | None = None


_PROVIDER_RESOLUTION = {
    CryptoProvider: {
        "container_attr": "crypto_provider",
        "preferred_params": ("provider", "crypto_provider", "crypto"),
    },
    KeyProvider: {
        "container_attr": "key_provider",
        "preferred_params": ("provider", "key_provider", "key"),
    },
    StorageProvider: {
        "container_attr": "storage_provider",
        "preferred_params": ("provider", "storage_provider", "storage"),
    },
}


def inject_crypto_provider(func: Callable[P, R]) -> Callable[P, R]:
    """Inject a CryptoProvider instance into the decorated function.

    The target parameter is detected by annotation first, then by preferred
    parameter names.
    """
    return _decorate_with_single_provider(func, CryptoProvider)


def inject_key_provider(func: Callable[P, R]) -> Callable[P, R]:
    """Inject a KeyProvider instance into the decorated function."""
    return _decorate_with_single_provider(func, KeyProvider)


def inject_storage_provider(func: Callable[P, R]) -> Callable[P, R]:
    """Inject a StorageProvider instance into the decorated function."""
    return _decorate_with_single_provider(func, StorageProvider)


def inject_all_providers(func: Callable[P, R]) -> Callable[P, R]:
    """Inject all provider types referenced by function parameters.

    This decorator scans the function signature and annotations for parameters
    matching CryptoProvider, KeyProvider, and StorageProvider, and injects the
    missing values from the default DI container.
    """
    signature = inspect.signature(func)
    type_hints = _safe_get_type_hints(func)

    plans: list[tuple[type[Any], str, Any]] = []

    for interface in (CryptoProvider, KeyProvider, StorageProvider):
        found = _resolve_parameter_for_interface(func, signature, type_hints, interface, required=False)
        if found is None:
            continue
        param_name, annotation = found
        plans.append((interface, param_name, annotation))

    if not plans:
        raise TypeError(
            "inject_all_providers requires at least one parameter annotated as "
            "CryptoProvider, KeyProvider, or StorageProvider"
        )

    if inspect.iscoroutinefunction(func):

        @wraps(func)
        async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            bound_names = _bound_argument_names(signature, args, kwargs)
            mutable_kwargs = dict(kwargs)

            for interface, param_name, annotation in plans:
                if param_name in bound_names or param_name in mutable_kwargs:
                    continue

                instance = _resolve_provider_instance(interface)
                _ensure_annotation_match(func, param_name, annotation, instance, interface)
                mutable_kwargs[param_name] = instance

            return await func(*args, **mutable_kwargs)

        return async_wrapper

    @wraps(func)
    def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        bound_names = _bound_argument_names(signature, args, kwargs)
        mutable_kwargs = dict(kwargs)

        for interface, param_name, annotation in plans:
            if param_name in bound_names or param_name in mutable_kwargs:
                continue

            instance = _resolve_provider_instance(interface)
            _ensure_annotation_match(func, param_name, annotation, instance, interface)
            mutable_kwargs[param_name] = instance

        return func(*args, **mutable_kwargs)

    return sync_wrapper


def set_injection_container(container: CoreContainer) -> None:
    """Set the default container used by injection decorators.

    This helper is useful for tests and environment-specific wiring.
    """
    global _DEFAULT_CONTAINER
    if container is None:
        raise ValueError("container must not be None")

    with _CONTAINER_LOCK:
        _DEFAULT_CONTAINER = container


def reset_injection_container() -> None:
    """Reset injection decorators to use a fresh default CoreContainer."""
    global _DEFAULT_CONTAINER
    with _CONTAINER_LOCK:
        _DEFAULT_CONTAINER = None


def _decorate_with_single_provider(func: Callable[P, R], interface: type[Any]) -> Callable[P, R]:
    signature = inspect.signature(func)
    type_hints = _safe_get_type_hints(func)

    resolved = _resolve_parameter_for_interface(func, signature, type_hints, interface, required=True)
    if resolved is None:
        raise TypeError("internal error: required parameter resolution unexpectedly failed")

    param_name, annotation = resolved

    if inspect.iscoroutinefunction(func):

        @wraps(func)
        async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            bound_names = _bound_argument_names(signature, args, kwargs)
            if param_name in bound_names or param_name in kwargs:
                return await func(*args, **kwargs)

            instance = _resolve_provider_instance(interface)
            _ensure_annotation_match(func, param_name, annotation, instance, interface)

            mutable_kwargs = dict(kwargs)
            mutable_kwargs[param_name] = instance
            return await func(*args, **mutable_kwargs)

        return async_wrapper

    @wraps(func)
    def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        bound_names = _bound_argument_names(signature, args, kwargs)
        if param_name in bound_names or param_name in kwargs:
            return func(*args, **kwargs)

        instance = _resolve_provider_instance(interface)
        _ensure_annotation_match(func, param_name, annotation, instance, interface)

        mutable_kwargs = dict(kwargs)
        mutable_kwargs[param_name] = instance
        return func(*args, **mutable_kwargs)

    return sync_wrapper


def _resolve_parameter_for_interface(
    func: Callable[..., Any],
    signature: inspect.Signature,
    type_hints: dict[str, Any],
    interface: type[Any],
    *,
    required: bool,
) -> tuple[str, Any] | None:
    settings = _PROVIDER_RESOLUTION[interface]
    preferred_params = settings["preferred_params"]

    for name, param in signature.parameters.items():
        annotation = type_hints.get(name, param.annotation)
        if _annotation_references_interface(annotation, interface):
            return name, annotation

    for candidate in preferred_params:
        if candidate in signature.parameters:
            param = signature.parameters[candidate]
            return candidate, type_hints.get(candidate, param.annotation)

    if required:
        raise TypeError(
            f"{func.__name__} must declare a parameter for {interface.__name__} "
            f"(annotation or preferred names: {', '.join(preferred_params)})"
        )

    return None


def _resolve_provider_instance(interface: type[Any]) -> Any:
    container = _get_default_container()
    attr_name = _PROVIDER_RESOLUTION[interface]["container_attr"]

    factory = getattr(container, attr_name, None)
    if factory is None:
        raise RuntimeError(f"container does not expose provider '{attr_name}'")

    instance = factory()
    if not isinstance(instance, interface):
        raise TypeError(
            f"resolved provider from '{attr_name}' is not a {interface.__name__}: "
            f"{type(instance).__name__}"
        )

    return instance


def _ensure_annotation_match(
    func: Callable[..., Any],
    param_name: str,
    annotation: Any,
    value: Any,
    interface: type[Any],
) -> None:
    if annotation is inspect.Signature.empty:
        return

    if not _value_matches_annotation(value, annotation, interface):
        raise TypeError(
            "injected value type does not match annotation for "
            f"{func.__name__} parameter '{param_name}': annotation={annotation!r}, "
            f"value_type={type(value).__name__}"
        )


def _value_matches_annotation(value: Any, annotation: Any, interface: type[Any]) -> bool:
    if annotation is Any:
        return True

    if isinstance(annotation, str):
        normalized = annotation.replace(" ", "")
        if interface.__name__ in normalized:
            return isinstance(value, interface)
        return True

    if inspect.isclass(annotation):
        return isinstance(value, annotation)

    origin = get_origin(annotation)
    args = get_args(annotation)

    if origin in (UnionType,):
        return any(_value_matches_annotation(value, arg, interface) for arg in args)

    if origin is None and args:
        return any(_value_matches_annotation(value, arg, interface) for arg in args)

    if origin is not None and args:
        return any(_value_matches_annotation(value, arg, interface) for arg in args)

    return isinstance(value, interface)


def _annotation_references_interface(annotation: Any, interface: type[Any]) -> bool:
    if annotation is inspect.Signature.empty:
        return False

    if annotation is interface:
        return True

    if annotation is Any:
        return False

    if isinstance(annotation, str):
        normalized = annotation.replace(" ", "")
        return (
            normalized == interface.__name__
            or normalized.endswith(f".{interface.__name__}")
            or interface.__name__ in normalized
        )

    if inspect.isclass(annotation):
        try:
            return issubclass(annotation, interface)
        except TypeError:
            return False

    origin = get_origin(annotation)
    args = get_args(annotation)

    if origin is None and args:
        return any(_annotation_references_interface(arg, interface) for arg in args)

    if origin is not None:
        return any(_annotation_references_interface(arg, interface) for arg in args)

    return False


def _safe_get_type_hints(func: Callable[..., Any]) -> dict[str, Any]:
    try:
        return get_type_hints(func)
    except Exception:
        return dict(getattr(func, "__annotations__", {}))


def _bound_argument_names(
    signature: inspect.Signature,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> set[str]:
    try:
        bound = signature.bind_partial(*args, **kwargs)
        return set(bound.arguments.keys())
    except TypeError:
        return set(kwargs.keys())


def _get_default_container() -> CoreContainer:
    global _DEFAULT_CONTAINER

    with _CONTAINER_LOCK:
        if _DEFAULT_CONTAINER is None:
            _DEFAULT_CONTAINER = CoreContainer()
        return _DEFAULT_CONTAINER


__all__: list[str] = [
    "inject_crypto_provider",
    "inject_key_provider",
    "inject_storage_provider",
    "inject_all_providers",
    "set_injection_container",
    "reset_injection_container",
]
