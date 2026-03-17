"""Core cryptographic engine for KeyCrypt Shield X.

This module is the primary entry point for the platform's security engine,
exposing cryptographic orchestration, key lifecycle controls, security state
management, and runtime configuration primitives.
"""

from importlib import import_module
from typing import Any

__version__ = "0.1.0"

__all__ = [
    "CryptoEngine",
    "KeyManager",
    "SecurityStates",
    "Config",
    "__version__",
]


_EXPORT_MAP = {
    "CryptoEngine": ("crypto_engine", "CryptoEngine"),
    "KeyManager": ("key_manager", "KeyManager"),
    "SecurityStates": ("security_states", "SecurityStates"),
    "Config": ("config", "Config"),
}


def __getattr__(name: str) -> Any:
    if name not in _EXPORT_MAP:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    module_name, symbol_name = _EXPORT_MAP[name]
    module = import_module(f".{module_name}", __name__)
    return getattr(module, symbol_name)
