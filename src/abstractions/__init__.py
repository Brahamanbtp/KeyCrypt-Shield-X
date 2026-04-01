"""Provider abstraction layer for KeyCrypt Shield X.

This package defines stable interfaces that decouple orchestration logic from
concrete implementations. Providers can be backed by local modules, external
services, hardware systems, or future pluggable adapters while exposing a
consistent API surface.
"""

from __future__ import annotations

from abc import ABC

from .crypto_provider import CryptoProvider
from .intelligence_provider import IntelligenceProvider
from .key_provider import KeyProvider
from .storage_provider import StorageProvider


class DeletionProvider(ABC):
    """Stub abstraction for secure deletion providers.

    This placeholder is exported to stabilize the public API. Concrete
    interface methods will be introduced in a future iteration.
    """


__all__: list[str] = [
    "CryptoProvider",
    "KeyProvider",
    "StorageProvider",
    "IntelligenceProvider",
    "DeletionProvider",
]
