"""Unit tests for injection decorators module."""
from __future__ import annotations

import asyncio
import pytest

from src.abstractions.crypto_provider import CryptoProvider
from src.abstractions.key_provider import KeyProvider
from src.abstractions.storage_provider import StorageProvider
from src.orchestration.dependency_container import CoreContainer
from src.orchestration.injection_decorators import (
    inject_all_providers,
    inject_crypto_provider,
    inject_key_provider,
    inject_storage_provider,
    reset_injection_container,
    set_injection_container,
)


class TestInjectCryptoProvider:
    """Tests for @inject_crypto_provider decorator."""

    def test_inject_crypto_provider_with_provider_param(self):
        """Test injection into 'provider' parameter."""
        @inject_crypto_provider
        def my_func(provider: CryptoProvider):
            return provider

        result = my_func()
        assert isinstance(result, CryptoProvider)

    def test_inject_crypto_provider_with_crypto_provider_param(self):
        """Test injection into 'crypto_provider' parameter."""
        @inject_crypto_provider
        def my_func(crypto_provider: CryptoProvider):
            return crypto_provider

        result = my_func()
        assert isinstance(result, CryptoProvider)

    def test_inject_crypto_provider_with_crypto_param(self):
        """Test injection into 'crypto' parameter."""
        @inject_crypto_provider
        def my_func(crypto: CryptoProvider):
            return crypto

        result = my_func()
        assert isinstance(result, CryptoProvider)

    def test_inject_crypto_provider_skip_if_provided(self):
        """Test that injection is skipped if already provided."""
        @inject_crypto_provider
        def my_func(provider: CryptoProvider):
            return provider

        custom_provider = object()
        result = my_func(provider=custom_provider)
        assert result is custom_provider

    def test_inject_crypto_provider_missing_parameter_raises(self):
        """Test that missing target parameter raises TypeError at decoration time."""
        with pytest.raises(TypeError, match="must declare a parameter"):
            @inject_crypto_provider
            def my_func():
                pass

    def test_inject_crypto_provider_wrong_annotation_raises(self):
        """Test that wrong annotation raises TypeError at runtime."""
        @inject_crypto_provider
        def my_func(provider: KeyProvider):
            pass

        with pytest.raises(TypeError, match="injected value type does not match annotation"):
            my_func()

    @pytest.mark.asyncio
    async def test_inject_crypto_provider_async(self):
        """Test injection into async function."""
        @inject_crypto_provider
        async def my_func(provider: CryptoProvider):
            await asyncio.sleep(0)
            return provider

        result = await my_func()
        assert isinstance(result, CryptoProvider)

    def test_inject_crypto_provider_preserves_function_metadata(self):
        """Test that decorator preserves function metadata."""
        @inject_crypto_provider
        def my_func(provider: CryptoProvider):
            """My docstring."""
            return provider

        assert my_func.__name__ == "my_func"
        assert "My docstring" in my_func.__doc__


class TestInjectKeyProvider:
    """Tests for @inject_key_provider decorator."""

    def test_inject_key_provider_with_provider_param(self):
        """Test injection into 'provider' parameter."""
        @inject_key_provider
        def my_func(provider: KeyProvider):
            return provider

        result = my_func()
        assert isinstance(result, KeyProvider)

    def test_inject_key_provider_with_key_provider_param(self):
        """Test injection into 'key_provider' parameter."""
        @inject_key_provider
        def my_func(key_provider: KeyProvider):
            return key_provider

        result = my_func()
        assert isinstance(result, KeyProvider)

    def test_inject_key_provider_with_key_param(self):
        """Test injection into 'key' parameter."""
        @inject_key_provider
        def my_func(key: KeyProvider):
            return key

        result = my_func()
        assert isinstance(result, KeyProvider)

    def test_inject_key_provider_skip_if_provided(self):
        """Test that injection is skipped if already provided."""
        @inject_key_provider
        def my_func(provider: KeyProvider):
            return provider

        custom_provider = object()
        result = my_func(provider=custom_provider)
        assert result is custom_provider

    def test_inject_key_provider_missing_parameter_raises(self):
        """Test that missing target parameter raises TypeError at decoration time."""
        with pytest.raises(TypeError, match="must declare a parameter"):
            @inject_key_provider
            def my_func():
                pass

    @pytest.mark.asyncio
    async def test_inject_key_provider_async(self):
        """Test injection into async function."""
        @inject_key_provider
        async def my_func(provider: KeyProvider):
            await asyncio.sleep(0)
            return provider

        result = await my_func()
        assert isinstance(result, KeyProvider)


class TestInjectStorageProvider:
    """Tests for @inject_storage_provider decorator."""

    def test_inject_storage_provider_with_provider_param(self):
        """Test injection into 'provider' parameter."""
        @inject_storage_provider
        def my_func(provider: StorageProvider):
            return provider

        result = my_func()
        assert isinstance(result, StorageProvider)

    def test_inject_storage_provider_with_storage_provider_param(self):
        """Test injection into 'storage_provider' parameter."""
        @inject_storage_provider
        def my_func(storage_provider: StorageProvider):
            return storage_provider

        result = my_func()
        assert isinstance(result, StorageProvider)

    def test_inject_storage_provider_with_storage_param(self):
        """Test injection into 'storage' parameter."""
        @inject_storage_provider
        def my_func(storage: StorageProvider):
            return storage

        result = my_func()
        assert isinstance(result, StorageProvider)

    def test_inject_storage_provider_skip_if_provided(self):
        """Test that injection is skipped if already provided."""
        @inject_storage_provider
        def my_func(provider: StorageProvider):
            return provider

        custom_provider = object()
        result = my_func(provider=custom_provider)
        assert result is custom_provider

    def test_inject_storage_provider_missing_parameter_raises(self):
        """Test that missing target parameter raises TypeError at decoration time."""
        with pytest.raises(TypeError, match="must declare a parameter"):
            @inject_storage_provider
            def my_func():
                pass

    @pytest.mark.asyncio
    async def test_inject_storage_provider_async(self):
        """Test injection into async function."""
        @inject_storage_provider
        async def my_func(provider: StorageProvider):
            await asyncio.sleep(0)
            return provider

        result = await my_func()
        assert isinstance(result, StorageProvider)


class TestInjectAllProviders:
    """Tests for @inject_all_providers decorator."""

    def test_inject_all_providers_with_primary_names(self):
        """Test injection with primary parameter names."""
        @inject_all_providers
        def my_func(
            crypto_provider: CryptoProvider,
            key_provider: KeyProvider,
            storage_provider: StorageProvider,
        ):
            return crypto_provider, key_provider, storage_provider

        crypto, key, storage = my_func()
        assert isinstance(crypto, CryptoProvider)
        assert isinstance(key, KeyProvider)
        assert isinstance(storage, StorageProvider)

    def test_inject_all_providers_with_secondary_names(self):
        """Test injection with secondary parameter names."""
        @inject_all_providers
        def my_func(crypto: CryptoProvider, key: KeyProvider, storage: StorageProvider):
            return crypto, key, storage

        crypto, key, storage = my_func()
        assert isinstance(crypto, CryptoProvider)
        assert isinstance(key, KeyProvider)
        assert isinstance(storage, StorageProvider)

    def test_inject_all_providers_partial_injection(self):
        """Test injection of only available providers."""
        @inject_all_providers
        def my_func(crypto_provider: CryptoProvider, key_provider: KeyProvider):
            return crypto_provider, key_provider

        crypto, key = my_func()
        assert isinstance(crypto, CryptoProvider)
        assert isinstance(key, KeyProvider)

    def test_inject_all_providers_skip_if_provided(self):
        """Test that injection is skipped for provided parameters."""
        @inject_all_providers
        def my_func(
            crypto_provider: CryptoProvider,
            key_provider: KeyProvider,
            storage_provider: StorageProvider,
        ):
            return crypto_provider, key_provider, storage_provider

        custom_crypto = object()
        crypto, key, storage = my_func(crypto_provider=custom_crypto)
        assert crypto is custom_crypto
        assert isinstance(key, KeyProvider)
        assert isinstance(storage, StorageProvider)

    def test_inject_all_providers_no_providers_raises(self):
        """Test that no matching parameters raises TypeError at decoration time."""
        with pytest.raises(TypeError, match="at least one parameter"):
            @inject_all_providers
            def my_func():
                pass

    def test_inject_all_providers_preserves_function_metadata(self):
        """Test that decorator preserves function metadata."""
        @inject_all_providers
        def my_func(
            crypto_provider: CryptoProvider,
            key_provider: KeyProvider,
            storage_provider: StorageProvider,
        ):
            """My docstring."""
            return crypto_provider, key_provider, storage_provider

        assert my_func.__name__ == "my_func"
        assert "My docstring" in my_func.__doc__

    @pytest.mark.asyncio
    async def test_inject_all_providers_async(self):
        """Test injection into async function."""
        @inject_all_providers
        async def my_func(
            crypto_provider: CryptoProvider,
            key_provider: KeyProvider,
            storage_provider: StorageProvider,
        ):
            await asyncio.sleep(0)
            return crypto_provider, key_provider, storage_provider

        crypto, key, storage = await my_func()
        assert isinstance(crypto, CryptoProvider)
        assert isinstance(key, KeyProvider)
        assert isinstance(storage, StorageProvider)


class TestContainerManagement:
    """Tests for container management functions."""

    def test_set_injection_container(self):
        """Test setting a custom injection container."""
        reset_injection_container()

        custom_container = CoreContainer()

        @inject_crypto_provider
        def my_func(provider: CryptoProvider):
            return provider

        set_injection_container(custom_container)
        result = my_func()

        assert isinstance(result, CryptoProvider)
        reset_injection_container()

    def test_set_injection_container_none_raises(self):
        """Test that setting None container raises ValueError."""
        with pytest.raises(ValueError, match="must not be None"):
            set_injection_container(None)

    def test_reset_injection_container(self):
        """Test resetting injection container."""
        reset_injection_container()

        @inject_crypto_provider
        def my_func(provider: CryptoProvider):
            return provider

        # Should work with default container
        result1 = my_func()
        assert isinstance(result1, CryptoProvider)

        # Reset should create new default container
        reset_injection_container()
        result2 = my_func()
        assert isinstance(result2, CryptoProvider)


class TestDecoratorsWithExtraArguments:
    """Tests for decorators with additional function arguments."""

    def test_inject_crypto_provider_with_args(self):
        """Test injection with additional positional arguments."""
        @inject_crypto_provider
        def my_func(a, b, provider: CryptoProvider):
            return a, b, provider

        result_a, result_b, result_provider = my_func(1, 2)
        assert result_a == 1
        assert result_b == 2
        assert isinstance(result_provider, CryptoProvider)

    def test_inject_crypto_provider_with_kwargs(self):
        """Test injection with additional keyword arguments."""
        @inject_crypto_provider
        def my_func(a, b=None, provider: CryptoProvider = None):
            return a, b, provider

        result_a, result_b, result_provider = my_func(1, b=2)
        assert result_a == 1
        assert result_b == 2
        assert isinstance(result_provider, CryptoProvider)

    def test_inject_all_providers_with_args(self):
        """Test all-providers injection with additional arguments."""
        @inject_all_providers
        def my_func(
            a,
            b,
            crypto_provider: CryptoProvider,
            key_provider: KeyProvider,
        ):
            return a, b, crypto_provider, key_provider

        a, b, crypto, key = my_func(1, 2)
        assert a == 1
        assert b == 2
        assert isinstance(crypto, CryptoProvider)
        assert isinstance(key, KeyProvider)


class TestAnnotationVariations:
    """Tests for various annotation patterns."""

    def test_inject_with_no_annotation(self):
        """Test that injection works even without type annotation."""
        @inject_crypto_provider
        def my_func(provider):
            return provider

        result = my_func()
        assert isinstance(result, CryptoProvider)

    def test_inject_with_string_annotation(self):
        """Test that string annotations are handled gracefully."""
        @inject_crypto_provider
        def my_func(provider: "CryptoProvider"):
            return provider

        result = my_func()
        assert isinstance(result, CryptoProvider)
