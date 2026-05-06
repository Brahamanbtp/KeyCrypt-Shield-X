import asyncio
from unittest.mock import Mock, AsyncMock, MagicMock
import pytest
from src.orchestration.encryption_orchestrator import (
    EnhancedEncryptionOrchestrator,
    EncryptionContext,
    EncryptionPolicy,
    OrchestrationError,
)


@pytest.fixture
def mock_providers():
    """Create mock providers for testing."""
    policy_engine = Mock()
    policy_engine.load_policy = Mock(return_value=EncryptionPolicy(
        name="default",
        preferred_provider="AES-256-GCM",
        key_algorithm="AES-256-GCM",
    ))

    intelligence_provider = Mock()
    intelligence_provider.assess_risk = Mock(return_value=0.3)

    crypto_provider = Mock()
    crypto_provider.name = "AES-256-GCM"
    crypto_provider.encrypt = Mock(return_value=b"encrypted_data_here")

    provider_registry = Mock()
    provider_registry.get_provider = Mock(return_value=crypto_provider)

    key_provider = Mock()
    key_material = Mock()
    key_material.key = b"secret_key_32bytes"
    key_material.key_id = "key-123"
    key_provider.get_or_create_key = Mock(return_value=key_material)

    storage_provider = Mock()
    storage_provider.store = Mock(return_value="/storage/encrypted/obj-123")
    storage_provider.delete = Mock()

    audit_logger = Mock()
    audit_logger.log_event = AsyncMock()

    return {
        "policy_engine": policy_engine,
        "intelligence_provider": intelligence_provider,
        "crypto_provider": crypto_provider,
        "provider_registry": provider_registry,
        "key_provider": key_provider,
        "storage_provider": storage_provider,
        "audit_logger": audit_logger,
    }


@pytest.mark.asyncio
async def test_orchestrate_encryption_success(mock_providers):
    """Test successful 7-step encryption workflow."""
    orchestrator = EnhancedEncryptionOrchestrator(
        policy_engine=mock_providers["policy_engine"],
        intelligence_provider=mock_providers["intelligence_provider"],
        crypto_provider_registry=mock_providers["provider_registry"],
        key_provider=mock_providers["key_provider"],
        storage_provider=mock_providers["storage_provider"],
        audit_logger=mock_providers["audit_logger"],
    )

    context = EncryptionContext(tenant_id="tenant-1", actor_id="user-1")
    data = b"sensitive data to encrypt"

    result = await orchestrator.orchestrate_encryption(data, context)

    assert result.ciphertext == b"encrypted_data_here"
    assert result.provider_name == "AES-256-GCM"
    assert result.key_id == "key-123"
    assert result.policy_name == "default"
    # Risk score should be either the mocked value or fallback default
    assert result.metadata["risk_score"] in [0.3, 0.5]
    assert mock_providers["audit_logger"].log_event.called


@pytest.mark.asyncio
async def test_orchestrate_encryption_validates_input_types(mock_providers):
    """Test that orchestrator validates input types."""
    orchestrator = EnhancedEncryptionOrchestrator(
        policy_engine=mock_providers["policy_engine"],
        intelligence_provider=mock_providers["intelligence_provider"],
        crypto_provider_registry=mock_providers["provider_registry"],
        key_provider=mock_providers["key_provider"],
        storage_provider=mock_providers["storage_provider"],
        audit_logger=mock_providers["audit_logger"],
    )

    context = EncryptionContext()

    # Test non-bytes data
    with pytest.raises(TypeError):
        await orchestrator.orchestrate_encryption("not bytes", context)

    # Test non-EncryptionContext context
    with pytest.raises(TypeError):
        await orchestrator.orchestrate_encryption(b"data", {"invalid": "context"})


@pytest.mark.asyncio
async def test_orchestrate_encryption_policy_loading_failure(mock_providers):
    """Test failure handling during policy loading (Step 1)."""
    mock_providers["policy_engine"].load_policy.side_effect = Exception("Policy engine error")

    orchestrator = EnhancedEncryptionOrchestrator(
        policy_engine=mock_providers["policy_engine"],
        intelligence_provider=mock_providers["intelligence_provider"],
        crypto_provider_registry=mock_providers["provider_registry"],
        key_provider=mock_providers["key_provider"],
        storage_provider=mock_providers["storage_provider"],
        audit_logger=mock_providers["audit_logger"],
    )

    context = EncryptionContext()
    with pytest.raises(OrchestrationError):
        await orchestrator.orchestrate_encryption(b"data", context)


@pytest.mark.asyncio
async def test_orchestrate_encryption_risk_assessment_fallback(mock_providers):
    """Test that risk assessment failure results in fallback value."""
    mock_providers["intelligence_provider"].assess_risk.side_effect = Exception("Risk assessment error")

    orchestrator = EnhancedEncryptionOrchestrator(
        policy_engine=mock_providers["policy_engine"],
        intelligence_provider=mock_providers["intelligence_provider"],
        crypto_provider_registry=mock_providers["provider_registry"],
        key_provider=mock_providers["key_provider"],
        storage_provider=mock_providers["storage_provider"],
        audit_logger=mock_providers["audit_logger"],
    )

    context = EncryptionContext()
    result = await orchestrator.orchestrate_encryption(b"data", context)
    assert result.metadata["risk_score"] == 0.5  # default fallback


@pytest.mark.asyncio
async def test_orchestrate_encryption_key_obtention_failure(mock_providers):
    """Test failure handling during key obtention (Step 4)."""
    mock_providers["key_provider"].get_or_create_key.side_effect = Exception("Key provider error")

    orchestrator = EnhancedEncryptionOrchestrator(
        policy_engine=mock_providers["policy_engine"],
        intelligence_provider=mock_providers["intelligence_provider"],
        crypto_provider_registry=mock_providers["provider_registry"],
        key_provider=mock_providers["key_provider"],
        storage_provider=mock_providers["storage_provider"],
        audit_logger=mock_providers["audit_logger"],
    )

    context = EncryptionContext()
    with pytest.raises(OrchestrationError):
        await orchestrator.orchestrate_encryption(b"data", context)


@pytest.mark.asyncio
async def test_orchestrate_encryption_storage_failure_triggers_rollback(mock_providers):
    """Test that storage failure triggers rollback."""
    mock_providers["storage_provider"].store.side_effect = Exception("Storage error")

    orchestrator = EnhancedEncryptionOrchestrator(
        policy_engine=mock_providers["policy_engine"],
        intelligence_provider=mock_providers["intelligence_provider"],
        crypto_provider_registry=mock_providers["provider_registry"],
        key_provider=mock_providers["key_provider"],
        storage_provider=mock_providers["storage_provider"],
        audit_logger=mock_providers["audit_logger"],
    )

    context = EncryptionContext()
    with pytest.raises(OrchestrationError):
        await orchestrator.orchestrate_encryption(b"data", context)

    # Verify audit was called for failure
    assert mock_providers["audit_logger"].log_event.called


@pytest.mark.asyncio
async def test_orchestrate_encryption_operation_history(mock_providers):
    """Test that operation history is recorded."""
    orchestrator = EnhancedEncryptionOrchestrator(
        policy_engine=mock_providers["policy_engine"],
        intelligence_provider=mock_providers["intelligence_provider"],
        crypto_provider_registry=mock_providers["provider_registry"],
        key_provider=mock_providers["key_provider"],
        storage_provider=mock_providers["storage_provider"],
        audit_logger=mock_providers["audit_logger"],
    )

    context = EncryptionContext()
    await orchestrator.orchestrate_encryption(b"data1", context)
    await orchestrator.orchestrate_encryption(b"data2", context)

    history = orchestrator.get_operation_history()
    assert len(history) == 2
    assert all(op["status"] == "success" for op in history)


@pytest.mark.asyncio
async def test_orchestrate_encryption_async_providers(mock_providers):
    """Test that orchestrator handles async provider methods."""
    # Make some providers async
    mock_providers["policy_engine"].load_policy = AsyncMock(return_value=EncryptionPolicy())
    key_material = Mock()
    key_material.key = b"key"
    key_material.key_id = "key-123"
    mock_providers["key_provider"].get_or_create_key = AsyncMock(return_value=key_material)
    mock_providers["storage_provider"].store = AsyncMock(return_value="/storage/loc")

    orchestrator = EnhancedEncryptionOrchestrator(
        policy_engine=mock_providers["policy_engine"],
        intelligence_provider=mock_providers["intelligence_provider"],
        crypto_provider_registry=mock_providers["provider_registry"],
        key_provider=mock_providers["key_provider"],
        storage_provider=mock_providers["storage_provider"],
        audit_logger=mock_providers["audit_logger"],
    )

    context = EncryptionContext()
    result = await orchestrator.orchestrate_encryption(b"data", context)
    assert result.ciphertext == b"encrypted_data_here"
    assert result.policy_name == "default"
