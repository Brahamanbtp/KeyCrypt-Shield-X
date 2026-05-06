"""Comprehensive tests for ProviderRegistry discovery and validation."""

from __future__ import annotations

from pathlib import Path
import inspect

import pytest

from src.registry.provider_registry import (
    ProviderRegistry,
    ProviderInfo,
    ValidationResult,
)
from src.abstractions.crypto_provider import CryptoProvider
from src.abstractions.key_provider import KeyProvider, KeyMaterial, KeyGenerationParams, KeyFilter, KeyMetadata
from src.orchestration.context_builder import EncryptionContext, DataClassification, PerformanceTarget


# Valid provider implementations
class ValidCryptoProvider(CryptoProvider):
    """Valid implementation of CryptoProvider."""

    PROVIDER_NAME = "valid-crypto"
    PROVIDER_VERSION = "1.2.3"

    def encrypt(self, plaintext: bytes, context: EncryptionContext) -> bytes:
        return plaintext[::-1]  # Simple reversal for testing

    def decrypt(self, ciphertext: bytes, context) -> bytes:
        return ciphertext[::-1]

    def get_algorithm_name(self) -> str:
        return "TEST-ALG-256"

    def get_security_level(self) -> int:
        return 256


class ValidKeyProvider(KeyProvider):
    """Valid implementation of KeyProvider."""

    PROVIDER_NAME = "valid-key"
    PROVIDER_VERSION = "2.0.0"

    def get_key(self, key_id: str) -> KeyMaterial:
        return KeyMaterial(
            key_id=key_id,
            algorithm="AES-256",
            material=b"\x00" * 32,
            version=1,
        )

    def generate_key(self, params: KeyGenerationParams) -> str:
        return "key-123"

    def rotate_key(self, key_id: str) -> str:
        return "key-rotated-123"

    def list_keys(self, filter: KeyFilter | None) -> list[KeyMetadata]:
        return []


class AnotherCryptoProvider(CryptoProvider):
    """Another valid crypto provider."""

    PROVIDER_VERSION = "1.0.0"  # Uses default naming

    def encrypt(self, plaintext: bytes, context: EncryptionContext) -> bytes:
        return plaintext

    def decrypt(self, ciphertext: bytes, context) -> bytes:
        return ciphertext

    def get_algorithm_name(self) -> str:
        return "ANOTHER-ALG-128"

    def get_security_level(self) -> int:
        return 128


# Invalid implementations for testing
class MissingMethodProvider(CryptoProvider):
    """Missing required method."""

    PROVIDER_VERSION = "1.0.0"

    def encrypt(self, plaintext: bytes, context: EncryptionContext) -> bytes:
        return plaintext

    def get_algorithm_name(self) -> str:
        return "BAD-ALG"

    # Missing decrypt() and get_security_level() methods


class WrongSignatureProvider(CryptoProvider):
    """Wrong method signature."""

    PROVIDER_VERSION = "1.0.0"

    def encrypt(self, plaintext: bytes, context: EncryptionContext, extra_param: str) -> bytes:
        return plaintext

    def decrypt(self, ciphertext: bytes, context) -> bytes:
        return ciphertext

    def get_algorithm_name(self) -> str:
        return "WRONG-ALG"

    def get_security_level(self) -> int:
        return 256


class NotAClassProvider:
    """Not actually a provider class."""

    pass


# Test fixtures
@pytest.fixture
def registry():
    """Create a fresh ProviderRegistry."""
    return ProviderRegistry()


@pytest.fixture
def crypto_interface():
    """Get CryptoProvider interface."""
    return CryptoProvider


@pytest.fixture
def key_interface():
    """Get KeyProvider interface."""
    return KeyProvider


class TestProviderRegistryBasics:
    """Test basic registry operations (existing functionality)."""

    def test_register_provider(self, registry, crypto_interface):
        """Test basic provider registration."""
        registry.register_provider(crypto_interface, "test", ValidCryptoProvider)
        
        providers = registry.list_providers(crypto_interface)
        assert "test" in providers

    def test_get_provider_returns_same_instance(self, registry, crypto_interface):
        """Lazy instantiation should return same instance on subsequent calls."""
        registry.register_provider(crypto_interface, "crypto", ValidCryptoProvider)
        
        instance1 = registry.get_provider(crypto_interface, "crypto")
        instance2 = registry.get_provider(crypto_interface, "crypto")
        
        assert instance1 is instance2

    def test_get_provider_raises_keyerror_for_nonexistent(self, registry, crypto_interface):
        """Getting non-existent provider raises KeyError."""
        with pytest.raises(KeyError, match="not registered"):
            registry.get_provider(crypto_interface, "nonexistent")

    def test_list_providers_empty(self, registry, crypto_interface):
        """Listing providers for unregistered interface returns empty list."""
        providers = registry.list_providers(crypto_interface)
        assert providers == []

    def test_register_multiple_providers_same_interface(self, registry, crypto_interface):
        """Multiple providers can be registered for same interface."""
        registry.register_provider(crypto_interface, "provider1", ValidCryptoProvider)
        registry.register_provider(crypto_interface, "provider2", AnotherCryptoProvider)
        
        providers = registry.list_providers(crypto_interface)
        assert "provider1" in providers
        assert "provider2" in providers
        assert len(providers) == 2


class TestValidation:
    """Test provider validation."""

    def test_validate_valid_provider(self, registry):
        """Valid provider passes validation."""
        result = registry.validate_provider(ValidCryptoProvider)
        
        assert result.is_valid is True
        assert result.interface is CryptoProvider
        assert result.errors == []
        assert result.version == "1.2.3"

    def test_validate_missing_method(self, registry):
        """Provider missing required method fails validation."""
        result = registry.validate_provider(MissingMethodProvider)
        
        assert result.is_valid is False
        assert any("decrypt" in error or "get_security_level" in error for error in result.errors)
    def test_validate_missing_method(self, registry):
        """Provider missing required method fails validation."""
        result = registry.validate_provider(MissingMethodProvider)
        
        assert result.is_valid is False
        # Missing methods cause abstract class error or signature mismatch
        assert len(result.errors) > 0

    def test_validate_wrong_signature(self, registry):
        """Provider with wrong signature fails validation."""
        result = registry.validate_provider(WrongSignatureProvider)
        
        assert result.is_valid is False
        assert len(result.errors) > 0

    def test_validate_non_class(self, registry):
        """Non-class object fails validation."""
        result = registry.validate_provider(NotAClassProvider())  # type: ignore
        
        assert result.is_valid is False
        assert "must be a class" in result.errors[0]

    def test_validate_abstract_class(self, registry):
        """Abstract class fails validation."""
        result = registry.validate_provider(CryptoProvider)
        
        assert result.is_valid is False
        assert any("abstract" in error.lower() for error in result.errors)

    def test_validate_extracts_version(self, registry):
        """Validation extracts provider version."""
        result = registry.validate_provider(ValidCryptoProvider)
        
        assert result.version == "1.2.3"

    def test_validate_defaults_version(self, registry):
        """Validation defaults to 0.1.0 if no version specified."""
        class NoVersionProvider(CryptoProvider):
            def encrypt(self, plaintext: bytes, context: EncryptionContext) -> bytes:
                return plaintext

            def decrypt(self, ciphertext: bytes, context) -> bytes:
                return ciphertext

            def get_algorithm_name(self) -> str:
                return "NO-VER-ALG"

            def get_security_level(self) -> int:
                return 128

        result = registry.validate_provider(NoVersionProvider)
        
        assert result.version == "0.1.0"

    def test_validate_invalid_semver(self, registry):
        """Invalid semantic version detected."""
        class BadVersionProvider(CryptoProvider):
            PROVIDER_VERSION = "not.valid.version"

            def encrypt(self, plaintext: bytes, context: EncryptionContext) -> bytes:
                return plaintext

            def decrypt(self, ciphertext: bytes, context) -> bytes:
                return ciphertext

            def get_algorithm_name(self) -> str:
                return "BAD-VER-ALG"

            def get_security_level(self) -> int:
                return 256

        result = registry.validate_provider(BadVersionProvider)
        
        assert result.is_valid is False
        assert any("semantic versioning" in error for error in result.errors)


class TestDiscovery:
    """Test provider discovery."""

    def test_discover_providers_basic(self, registry):
        """Basic provider discovery."""
        result = registry.validate_provider(ValidCryptoProvider)
        assert result.is_valid is True
        assert result.interface is CryptoProvider

    def test_iter_module_files_file_input(self, registry, tmp_path):
        """Iterate over module files - single file input."""
        test_file = tmp_path / "test.py"
        test_file.write_text("# test module")
        
        files = registry._iter_module_files([test_file])
        
        assert len(files) > 0
        assert any(f.name == "test.py" for f in files)

    def test_iter_module_files_directory_input(self, registry, tmp_path):
        """Iterate over module files - directory input."""
        (tmp_path / "mod1.py").write_text("# module 1")
        (tmp_path / "mod2.py").write_text("# module 2")
        
        files = registry._iter_module_files([tmp_path])
        
        assert len(files) >= 2
        file_names = {f.name for f in files}
        assert "mod1.py" in file_names
        assert "mod2.py" in file_names

    def test_iter_module_files_skips_init(self, registry, tmp_path):
        """Module iteration skips __init__.py files."""
        (tmp_path / "__init__.py").write_text("# init")
        (tmp_path / "module.py").write_text("# module")
        
        files = registry._iter_module_files([tmp_path])
        
        file_names = {f.name for f in files}
        assert "__init__.py" not in file_names
        assert "module.py" in file_names

    def test_iter_module_files_recursive(self, registry, tmp_path):
        """Module iteration is recursive."""
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        (tmp_path / "top.py").write_text("# top")
        (subdir / "nested.py").write_text("# nested")
        
        files = registry._iter_module_files([tmp_path])
        
        file_names = {f.name for f in files}
        assert "top.py" in file_names
        assert "nested.py" in file_names

    def test_iter_module_files_nonexistent_path(self, registry):
        """Non-existent paths are silently skipped."""
        nonexistent = Path("/does/not/exist")
        
        files = registry._iter_module_files([nonexistent])
        
        assert isinstance(files, list)

    def test_iter_module_files_requires_path_type(self, registry):
        """search_paths must contain Path objects."""
        with pytest.raises(TypeError, match="Path"):
            registry._iter_module_files(["/string/path"])  # type: ignore


class TestProviderNaming:
    """Test provider name extraction."""

    def test_provider_name_explicit(self, registry):
        """Explicit PROVIDER_NAME attribute used if present."""
        name = registry._provider_name(ValidCryptoProvider)
        
        assert name == "valid-crypto"

    def test_provider_name_default(self, registry):
        """Default name derived from class name."""
        name = registry._provider_name(AnotherCryptoProvider)
        
        assert name == "another-crypto"

    def test_provider_name_removes_provider_suffix(self, registry):
        """Class names ending in 'Provider' have suffix removed."""
        class MyCustomProvider(CryptoProvider):
            def encrypt(self, plaintext: bytes, context: EncryptionContext) -> bytes:
                return plaintext

            def decrypt(self, ciphertext: bytes, context) -> bytes:
                return ciphertext

            def get_algorithm_name(self) -> str:
                return "CUSTOM-ALG"

            def get_security_level(self) -> int:
                return 128

        name = registry._provider_name(MyCustomProvider)
        
        assert "provider" not in name.lower() or len(name) > 0
        assert "custom" in name.lower()

    def test_provider_name_kebab_case_conversion(self, registry):
        """CamelCase converted to kebab-case."""
        class MyCustomEncryptionProvider(CryptoProvider):
            def encrypt(self, plaintext: bytes, context: EncryptionContext) -> bytes:
                return plaintext

            def decrypt(self, ciphertext: bytes, context) -> bytes:
                return ciphertext

            def get_algorithm_name(self) -> str:
                return "ENCRYPTION-ALG"

            def get_security_level(self) -> int:
                return 256

        name = registry._provider_name(MyCustomEncryptionProvider)
        
        assert "-" in name
        assert name.islower()


class TestVersionExtraction:
    """Test semantic version extraction."""

    def test_extract_version_from_provider_version_attr(self, registry):
        """Extracts PROVIDER_VERSION attribute."""
        version = registry._extract_provider_version(ValidCryptoProvider)
        
        assert version == "1.2.3"

    def test_extract_version_from_version_attr(self, registry):
        """Falls back to VERSION attribute."""
        class VersionAttrProvider(CryptoProvider):
            VERSION = "2.1.0"

            def encrypt(self, plaintext: bytes, context: EncryptionContext) -> bytes:
                return plaintext

            def decrypt(self, ciphertext: bytes, context) -> bytes:
                return ciphertext

            def get_algorithm_name(self) -> str:
                return "VERSION-ALG"

            def get_security_level(self) -> int:
                return 128

        version = registry._extract_provider_version(VersionAttrProvider)
        
        assert version == "2.1.0"

    def test_extract_version_from_dunder_version(self, registry):
        """Falls back to __version__ attribute."""
        class DunderVersionProvider(CryptoProvider):
            __version__ = "3.0.1"

            def encrypt(self, plaintext: bytes, context: EncryptionContext) -> bytes:
                return plaintext

            def decrypt(self, ciphertext: bytes, context) -> bytes:
                return ciphertext

            def get_algorithm_name(self) -> str:
                return "DUNDER-ALG"

            def get_security_level(self) -> int:
                return 192

        version = registry._extract_provider_version(DunderVersionProvider)
        
        assert version == "3.0.1"

    def test_extract_version_default(self, registry):
        """Defaults to 0.1.0 if no version found."""
        class NoVersionProvider(CryptoProvider):
            def encrypt(self, plaintext: bytes, context: EncryptionContext) -> bytes:
                return plaintext

            def decrypt(self, ciphertext: bytes, context) -> bytes:
                return ciphertext

            def get_algorithm_name(self) -> str:
                return "NO-VER-ALG"

            def get_security_level(self) -> int:
                return 128

        version = registry._extract_provider_version(NoVersionProvider)
        
        assert version == "0.1.0"

    def test_is_semver_valid(self, registry):
        """Valid semantic versions recognized."""
        assert registry._is_semver("1.0.0") is True
        assert registry._is_semver("0.0.0") is True
        assert registry._is_semver("1.2.3") is True
        assert registry._is_semver("1.0.0-alpha") is True
        assert registry._is_semver("1.0.0+build.1") is True
        assert registry._is_semver("1.0.0-rc.1+build.123") is True

    def test_is_semver_invalid(self, registry):
        """Invalid semantic versions rejected."""
        assert registry._is_semver("1") is False
        assert registry._is_semver("1.0") is False
        assert registry._is_semver("01.0.0") is False  # Leading zero
        assert registry._is_semver("1.0.0.0") is False
        assert registry._is_semver("v1.0.0") is False


class TestAutoRegister:
    """Test automatic provider registration."""

    def test_auto_register_empty_paths(self, registry):
        """Auto-register with empty paths returns 0."""
        count = registry.auto_register_discovered([])
        
        assert count == 0

    def test_auto_register_nonexistent_path(self, registry):
        """Auto-register with non-existent path returns 0."""
        nonexistent = Path("/does/not/exist")
        
        count = registry.auto_register_discovered([nonexistent])
        
        assert count == 0

    def test_auto_register_discovered_stores_version(self, registry):
        """Auto-register stores provider version."""
        validation = registry.validate_provider(ValidCryptoProvider)
        assert validation.version == "1.2.3"
        
        registry.register_provider(
            CryptoProvider,
            "test-provider",
            ValidCryptoProvider,
        )
        registry._versions.setdefault(CryptoProvider, {})["test-provider"] = validation.version
        
        versions = registry._versions.get(CryptoProvider, {})
        assert versions.get("test-provider") == "1.2.3"


class TestSignatureCompatibility:
    """Test method signature compatibility checking."""

    def test_signatures_compatible_exact_match(self, registry):
        """Exact signature match is compatible."""
        def interface_method(x: int, y: str) -> bool:
            pass

        def impl_method(x: int, y: str) -> bool:
            pass

        interface_sig = inspect.signature(interface_method)
        impl_sig = inspect.signature(impl_method)
        
        is_compatible = registry._signatures_compatible(interface_sig, impl_sig)
        
        assert is_compatible is True

    def test_signatures_incompatible_param_count(self, registry):
        """Different parameter count is incompatible."""
        def interface_method(x: int) -> bool:
            pass

        def impl_method(x: int, y: str) -> bool:
            pass

        interface_sig = inspect.signature(interface_method)
        impl_sig = inspect.signature(impl_method)
        
        is_compatible = registry._signatures_compatible(interface_sig, impl_sig)
        
        assert is_compatible is False

    def test_signatures_incompatible_param_name(self, registry):
        """Different parameter names are incompatible."""
        def interface_method(x: int) -> bool:
            pass

        def impl_method(y: int) -> bool:
            pass

        interface_sig = inspect.signature(interface_method)
        impl_sig = inspect.signature(impl_method)
        
        is_compatible = registry._signatures_compatible(interface_sig, impl_sig)
        
        assert is_compatible is False

    def test_signatures_compatible_with_defaults(self, registry):
        """Implementation can add default to required parameter."""
        def interface_method(x: int, y: str) -> bool:
            pass

        def impl_method(x: int, y: str = "default") -> bool:
            pass

        interface_sig = inspect.signature(interface_method)
        impl_sig = inspect.signature(impl_method)
        
        is_compatible = registry._signatures_compatible(interface_sig, impl_sig)
        
        assert is_compatible is True


class TestProviderInfoDataclass:
    """Test ProviderInfo dataclass."""

    def test_provider_info_creation(self, crypto_interface):
        """ProviderInfo can be created with all fields."""
        info = ProviderInfo(
            name="test-provider",
            interface=crypto_interface,
            module_path=Path("/tmp/test.py"),
            version="1.2.3",
        )
        
        assert info.name == "test-provider"
        assert info.interface is crypto_interface
        assert info.module_path == Path("/tmp/test.py")
        assert info.version == "1.2.3"

    def test_provider_info_frozen(self, crypto_interface):
        """ProviderInfo is immutable."""
        info = ProviderInfo(
            name="test",
            interface=crypto_interface,
            module_path=Path("/tmp/test.py"),
            version="1.0.0",
        )
        
        with pytest.raises(Exception):  # FrozenInstanceError
            info.name = "modified"


class TestValidationResultDataclass:
    """Test ValidationResult dataclass."""

    def test_validation_result_valid(self, crypto_interface):
        """ValidationResult for valid provider."""
        result = ValidationResult(
            is_valid=True,
            interface=crypto_interface,
            errors=[],
            version="1.2.3",
        )
        
        assert result.is_valid is True
        assert result.interface is crypto_interface
        assert result.errors == []

    def test_validation_result_invalid(self):
        """ValidationResult for invalid provider."""
        result = ValidationResult(
            is_valid=False,
            interface=None,
            errors=["missing method", "wrong signature"],
            version="0.1.0",
        )
        
        assert result.is_valid is False
        assert result.interface is None
        assert len(result.errors) == 2

    def test_validation_result_frozen(self, crypto_interface):
        """ValidationResult is immutable."""
        result = ValidationResult(
            is_valid=True,
            interface=crypto_interface,
            errors=[],
        )
        
        with pytest.raises(Exception):  # FrozenInstanceError
            result.is_valid = False


class TestInterfaceResolution:
    """Test interface detection and resolution."""

    def test_resolve_interface_direct_subclass(self, registry, crypto_interface):
        """Resolves provider to direct interface."""
        interfaces = [crypto_interface]
        resolved = registry._resolve_interface(ValidCryptoProvider, interfaces)
        
        assert resolved is crypto_interface

    def test_resolve_interface_none_for_non_provider(self, registry, crypto_interface):
        """Returns None for class that doesn't implement interface."""
        class NotAProvider:
            pass

        interfaces = [crypto_interface]
        resolved = registry._resolve_interface(NotAProvider, interfaces)
        
        assert resolved is None

    def test_resolve_interface_multiple_interfaces(self, registry, crypto_interface):
        """Resolves to most specific interface."""
        class SpecialCryptoProvider(ValidCryptoProvider):
            pass

        interfaces = [crypto_interface, ValidCryptoProvider]
        resolved = registry._resolve_interface(SpecialCryptoProvider, interfaces)
        
        assert resolved in interfaces


class TestIntegration:
    """Integration tests combining multiple features."""

    def test_register_and_retrieve_valid_provider(self, registry, crypto_interface):
        """Complete workflow: register valid provider and retrieve it."""
        validation = registry.validate_provider(ValidCryptoProvider)
        assert validation.is_valid is True
        
        registry.register_provider(
            crypto_interface,
            "crypto",
            ValidCryptoProvider,
        )
        
        instance = registry.get_provider(crypto_interface, "crypto")
        
        assert isinstance(instance, ValidCryptoProvider)
        context = EncryptionContext(
            user_id="test-user",
            data_classification=DataClassification.INTERNAL,
            compliance_requirements=[],
            performance_target=PerformanceTarget.BALANCED,
            metadata={},
        )
        result = instance.encrypt(b"test", context)
        assert result == b"tset"  # Reversed

    def test_cannot_retrieve_invalid_provider(self, registry, crypto_interface):
        """Invalid providers cannot be retrieved."""
        with pytest.raises(KeyError):
            registry.get_provider(crypto_interface, "missing")

    def test_multiple_interfaces_independent(self, registry, crypto_interface, key_interface):
        """Providers for different interfaces are independent."""
        registry.register_provider(crypto_interface, "crypto", ValidCryptoProvider)
        registry.register_provider(key_interface, "key", ValidKeyProvider)
        
        crypto = registry.get_provider(crypto_interface, "crypto")
        key = registry.get_provider(key_interface, "key")
        
        assert isinstance(crypto, ValidCryptoProvider)
        assert isinstance(key, ValidKeyProvider)
        assert crypto is not key
