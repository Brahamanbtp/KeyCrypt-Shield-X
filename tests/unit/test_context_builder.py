"""Comprehensive tests for EncryptionContextBuilder."""

from __future__ import annotations

import pytest

from src.orchestration.context_builder import (
    DataClassification,
    EncryptionContext,
    EncryptionContextBuilder,
    PerformanceTarget,
)


@pytest.fixture
def builder():
    """Create a fresh builder instance."""
    return EncryptionContextBuilder()


class TestDataClassification:
    """Test data classification enum."""

    def test_all_classification_levels_present(self):
        """All required classification levels exist."""
        required = {"PUBLIC", "INTERNAL", "CONFIDENTIAL", "SECRET", "TOP_SECRET"}
        actual = {level.value for level in DataClassification}
        assert required == actual

    def test_classification_values_are_strings(self):
        """Classification values are accessible as strings."""
        assert DataClassification.PUBLIC.value == "PUBLIC"
        assert DataClassification.TOP_SECRET.value == "TOP_SECRET"

    def test_classification_comparison(self):
        """Classifications can be compared."""
        assert DataClassification.PUBLIC != DataClassification.SECRET
        assert DataClassification.SECRET == DataClassification.SECRET


class TestPerformanceTarget:
    """Test performance target enum."""

    def test_all_performance_targets_present(self):
        """All required performance targets exist."""
        required = {"SPEED", "BALANCED", "SECURITY"}
        actual = {target.value for target in PerformanceTarget}
        assert required == actual

    def test_performance_values_are_strings(self):
        """Performance values are accessible as strings."""
        assert PerformanceTarget.SPEED.value == "SPEED"
        assert PerformanceTarget.SECURITY.value == "SECURITY"


class TestEncryptionContextCreation:
    """Test EncryptionContext dataclass creation and validation."""

    def test_create_minimal_context(self):
        """Create context with only required fields."""
        context = EncryptionContext(
            user_id="alice",
            data_classification=DataClassification.INTERNAL,
        )
        assert context.user_id == "alice"
        assert context.data_classification == DataClassification.INTERNAL
        assert context.compliance_requirements == []
        assert context.performance_target == PerformanceTarget.BALANCED
        assert context.metadata == {}

    def test_create_context_with_all_fields(self):
        """Create context with all fields populated."""
        context = EncryptionContext(
            user_id="bob",
            data_classification=DataClassification.CONFIDENTIAL,
            compliance_requirements=["GDPR", "HIPAA"],
            performance_target=PerformanceTarget.SECURITY,
            metadata={"region": "us-east-1", "tier": "premium"},
        )
        assert context.user_id == "bob"
        assert context.data_classification == DataClassification.CONFIDENTIAL
        assert set(context.compliance_requirements) == {"GDPR", "HIPAA"}
        assert context.performance_target == PerformanceTarget.SECURITY
        assert context.metadata == {"region": "us-east-1", "tier": "premium"}

    def test_context_is_frozen(self):
        """EncryptionContext is immutable."""
        context = EncryptionContext(
            user_id="charlie",
            data_classification=DataClassification.PUBLIC,
        )
        with pytest.raises(Exception):  # FrozenInstanceError
            context.user_id = "dave"

    def test_context_allows_any_user_id_value(self):
        """EncryptionContext allows any user_id (validation done in builder)."""
        # Dataclass accepts values; builder validates before construction
        context = EncryptionContext(
            user_id="",
            data_classification=DataClassification.PUBLIC,
        )
        assert context.user_id == ""

    def test_context_allows_any_classification_value(self):
        """EncryptionContext allows any classification (validation done in builder)."""
        # Direct dataclass construction bypasses builder validation
        context = EncryptionContext(
            user_id="eve",
            data_classification=DataClassification.PUBLIC,
        )
        assert context.data_classification == DataClassification.PUBLIC


class TestBuilderBasicMethods:
    """Test core builder methods."""

    def test_with_user_valid(self, builder):
        """with_user() sets user_id."""
        result = builder.with_user("alice@example.com")
        assert result is builder  # Returns self for chaining
        assert builder._user_id == "alice@example.com"

    def test_with_user_strips_whitespace(self, builder):
        """with_user() strips leading/trailing whitespace."""
        builder.with_user("  bob  ")
        assert builder._user_id == "bob"

    def test_with_user_requires_non_empty_string(self, builder):
        """with_user() rejects empty strings."""
        with pytest.raises(ValueError, match="user_id must be"):
            builder.with_user("")

        with pytest.raises(ValueError, match="user_id must be"):
            builder.with_user("   ")

    def test_with_user_requires_string_type(self, builder):
        """with_user() requires string type."""
        with pytest.raises(ValueError):
            builder.with_user(None)  # type: ignore

        with pytest.raises(ValueError):
            builder.with_user(123)  # type: ignore

    def test_with_classification_valid(self, builder):
        """with_classification() sets data classification."""
        result = builder.with_classification(DataClassification.SECRET)
        assert result is builder
        assert builder._data_classification == DataClassification.SECRET

    def test_with_classification_requires_enum(self, builder):
        """with_classification() requires DataClassification enum."""
        with pytest.raises(TypeError, match="DataClassification"):
            builder.with_classification("CONFIDENTIAL")  # type: ignore

    def test_with_compliance_single_standard(self, builder):
        """with_compliance() adds single standard."""
        result = builder.with_compliance("GDPR")
        assert result is builder
        assert "GDPR" in builder._compliance_requirements

    def test_with_compliance_multiple_standards(self, builder):
        """with_compliance() adds multiple standards."""
        builder.with_compliance("GDPR", "HIPAA", "NIST")
        assert "GDPR" in builder._compliance_requirements
        assert "HIPAA" in builder._compliance_requirements
        assert "NIST" in builder._compliance_requirements

    def test_with_compliance_deduplicates(self, builder):
        """with_compliance() avoids duplicates."""
        builder.with_compliance("GDPR", "GDPR", "gdpr")
        # After normalization, all should be "GDPR"
        gdpr_count = sum(1 for req in builder._compliance_requirements if req == "GDPR")
        assert gdpr_count == 1

    def test_with_compliance_normalizes_standards(self, builder):
        """with_compliance() normalizes standard names."""
        builder.with_compliance("hipaa", "NIST 800-53", "fEdRaMP")
        assert "HIPAA" in builder._compliance_requirements
        assert "NIST_800-53" in builder._compliance_requirements  # Spaces become underscores
        assert "FEDRAMP" in builder._compliance_requirements

    def test_with_compliance_requires_non_empty_strings(self, builder):
        """with_compliance() rejects empty strings."""
        with pytest.raises(ValueError, match="compliance standard"):
            builder.with_compliance("")

        with pytest.raises(ValueError):
            builder.with_compliance("   ")


class TestBuilderAdditionalMethods:
    """Test additional builder methods (performance, metadata, clear, reset)."""

    def test_with_performance_valid(self, builder):
        """with_performance() sets performance target."""
        result = builder.with_performance(PerformanceTarget.SECURITY)
        assert result is builder
        assert builder._performance_target == PerformanceTarget.SECURITY

    def test_with_performance_requires_enum(self, builder):
        """with_performance() requires PerformanceTarget enum."""
        with pytest.raises(TypeError, match="PerformanceTarget"):
            builder.with_performance("SECURITY")  # type: ignore

    def test_with_metadata_single_entry(self, builder):
        """with_metadata() adds single metadata entry."""
        result = builder.with_metadata("region", "us-east-1")
        assert result is builder
        assert builder._metadata["region"] == "us-east-1"

    def test_with_metadata_multiple_entries(self, builder):
        """with_metadata() can be chained to add multiple entries."""
        builder.with_metadata("region", "us-east-1").with_metadata("tier", "premium")
        assert builder._metadata["region"] == "us-east-1"
        assert builder._metadata["tier"] == "premium"

    def test_with_metadata_overwrites_existing(self, builder):
        """with_metadata() overwrites existing key."""
        builder.with_metadata("region", "us-east-1")
        builder.with_metadata("region", "eu-west-1")
        assert builder._metadata["region"] == "eu-west-1"

    def test_with_metadata_requires_non_empty_key(self, builder):
        """with_metadata() requires non-empty key."""
        with pytest.raises(ValueError, match="metadata key"):
            builder.with_metadata("", "value")

    def test_with_metadata_accepts_any_value_type(self, builder):
        """with_metadata() accepts any value type."""
        builder.with_metadata("count", 42)
        builder.with_metadata("enabled", True)
        builder.with_metadata("tags", ["tag1", "tag2"])
        builder.with_metadata("config", {"nested": "value"})
        
        assert builder._metadata["count"] == 42
        assert builder._metadata["enabled"] is True
        assert builder._metadata["tags"] == ["tag1", "tag2"]
        assert builder._metadata["config"] == {"nested": "value"}

    def test_with_metadata_dict_merge(self, builder):
        """with_metadata_dict() merges metadata dictionary."""
        builder.with_metadata("first", "value1")
        result = builder.with_metadata_dict({"second": "value2", "third": "value3"})
        
        assert result is builder
        assert builder._metadata["first"] == "value1"
        assert builder._metadata["second"] == "value2"
        assert builder._metadata["third"] == "value3"

    def test_with_metadata_dict_overwrites_existing(self, builder):
        """with_metadata_dict() overwrites existing keys."""
        builder.with_metadata_dict({"region": "us-east-1", "tier": "standard"})
        builder.with_metadata_dict({"region": "eu-west-1"})
        
        assert builder._metadata["region"] == "eu-west-1"
        assert builder._metadata["tier"] == "standard"

    def test_with_metadata_dict_requires_dict_type(self, builder):
        """with_metadata_dict() requires dictionary type."""
        with pytest.raises(TypeError, match="metadata must be"):
            builder.with_metadata_dict({"key": "value"}.items())  # type: ignore

    def test_clear_compliance(self, builder):
        """clear_compliance() removes all compliance requirements."""
        builder.with_compliance("GDPR", "HIPAA", "NIST")
        result = builder.clear_compliance()
        
        assert result is builder
        assert builder._compliance_requirements == []

    def test_clear_metadata(self, builder):
        """clear_metadata() removes all metadata."""
        builder.with_metadata_dict({"key1": "value1", "key2": "value2"})
        result = builder.clear_metadata()
        
        assert result is builder
        assert builder._metadata == {}

    def test_reset(self, builder):
        """reset() clears all builder state."""
        builder.with_user("alice").with_classification(
            DataClassification.CONFIDENTIAL
        ).with_compliance("GDPR").with_performance(
            PerformanceTarget.SECURITY
        ).with_metadata("key", "value")
        
        result = builder.reset()
        
        assert result is builder
        assert builder._user_id is None
        assert builder._data_classification == DataClassification.INTERNAL
        assert builder._compliance_requirements == []
        assert builder._performance_target == PerformanceTarget.BALANCED
        assert builder._metadata == {}


class TestBuilderValidation:
    """Test builder validation and constraint enforcement."""

    def test_build_requires_user_id(self, builder):
        """build() requires user_id to be set."""
        builder.with_classification(DataClassification.PUBLIC)
        with pytest.raises(ValueError, match="user_id is required"):
            builder.build()

    def test_build_requires_classification(self, builder):
        """build() requires classification to be set."""
        builder.with_user("alice")
        # Should use default INTERNAL classification
        context = builder.build()
        assert context.data_classification == DataClassification.INTERNAL

    def test_top_secret_requires_allowed_standards(self, builder):
        """TOP_SECRET requires specific compliance standards."""
        builder.with_user("alice").with_classification(
            DataClassification.TOP_SECRET
        ).with_compliance("GDPR")
        
        with pytest.raises(ValueError, match="TOP_SECRET.*high-assurance"):
            builder.build()

    def test_top_secret_with_allowed_standard_nist(self, builder):
        """TOP_SECRET accepts NIST-800-53-HIGH."""
        builder.with_user("alice").with_classification(
            DataClassification.TOP_SECRET
        ).with_compliance("NIST-800-53-HIGH")
        
        context = builder.build()
        assert context.data_classification == DataClassification.TOP_SECRET
        # Normalization converts to uppercase but keeps hyphens
        assert "NIST-800-53-HIGH" in context.compliance_requirements

    def test_top_secret_with_allowed_standard_cmmc(self, builder):
        """TOP_SECRET accepts CMMC_LEVEL_3."""
        builder.with_user("alice").with_classification(
            DataClassification.TOP_SECRET
        ).with_compliance("CMMC_LEVEL_3")
        
        context = builder.build()
        assert context.data_classification == DataClassification.TOP_SECRET

    def test_top_secret_with_allowed_standard_fips(self, builder):
        """TOP_SECRET accepts FIPS-140-3."""
        builder.with_user("alice").with_classification(
            DataClassification.TOP_SECRET
        ).with_compliance("FIPS-140-3")
        
        context = builder.build()
        assert context.data_classification == DataClassification.TOP_SECRET

    def test_top_secret_with_allowed_standard_itar(self, builder):
        """TOP_SECRET accepts ITAR."""
        builder.with_user("alice").with_classification(
            DataClassification.TOP_SECRET
        ).with_compliance("ITAR")
        
        context = builder.build()
        assert context.data_classification == DataClassification.TOP_SECRET

    def test_top_secret_with_multiple_standards_one_allowed(self, builder):
        """TOP_SECRET accepted if at least one standard is allowed."""
        builder.with_user("alice").with_classification(
            DataClassification.TOP_SECRET
        ).with_compliance("GDPR", "NIST-800-53-HIGH", "HIPAA")
        
        context = builder.build()
        assert context.data_classification == DataClassification.TOP_SECRET


class TestBuilderChaining:
    """Test fluent builder method chaining."""

    def test_method_chaining_full_flow(self, builder):
        """Test complete fluent chaining."""
        context = (
            builder.with_user("alice@example.com")
            .with_classification(DataClassification.CONFIDENTIAL)
            .with_compliance("GDPR", "HIPAA")
            .with_performance(PerformanceTarget.BALANCED)
            .with_metadata("region", "us-east-1")
            .with_metadata("tier", "premium")
            .build()
        )
        
        assert context.user_id == "alice@example.com"
        assert context.data_classification == DataClassification.CONFIDENTIAL
        assert set(context.compliance_requirements) == {"GDPR", "HIPAA"}
        assert context.performance_target == PerformanceTarget.BALANCED
        assert context.metadata["region"] == "us-east-1"
        assert context.metadata["tier"] == "premium"

    def test_method_chaining_with_metadata_dict(self, builder):
        """Test chaining with metadata dict."""
        context = (
            builder.with_user("bob")
            .with_classification(DataClassification.SECRET)
            .with_compliance("NIST-800-53-HIGH")
            .with_metadata_dict({"env": "prod", "sensitive": True})
            .build()
        )
        
        assert context.metadata["env"] == "prod"
        assert context.metadata["sensitive"] is True

    def test_method_chaining_with_clear_and_reset(self, builder):
        """Test chaining with clear and reset operations."""
        builder.with_user("alice").with_compliance("GDPR")
        builder.clear_compliance()
        
        # Compliance should be cleared, user should remain
        assert builder._compliance_requirements == []
        assert builder._user_id == "alice"
        
        builder.reset()
        
        # Everything should be reset
        assert builder._user_id is None
        assert builder._compliance_requirements == []


class TestBuilderEdgeCases:
    """Test builder edge cases and boundary conditions."""

    def test_empty_compliance_list_builds_successfully(self, builder):
        """Context can be built with no compliance requirements."""
        context = (
            builder.with_user("alice")
            .with_classification(DataClassification.PUBLIC)
            .build()
        )
        assert context.compliance_requirements == []

    def test_complex_metadata_values(self, builder):
        """Metadata can contain complex nested structures."""
        context = (
            builder.with_user("alice")
            .with_classification(DataClassification.INTERNAL)
            .with_metadata("config", {"db": {"host": "localhost", "port": 5432}})
            .with_metadata("tags", ["tag1", "tag2", "tag3"])
            .build()
        )
        assert context.metadata["config"]["db"]["host"] == "localhost"
        assert len(context.metadata["tags"]) == 3

    def test_special_characters_in_user_id(self, builder):
        """User ID can contain special characters."""
        user_id = "alice+test@example.com"
        context = (
            builder.with_user(user_id)
            .with_classification(DataClassification.PUBLIC)
            .build()
        )
        assert context.user_id == user_id

    def test_unicode_in_metadata(self, builder):
        """Metadata can contain unicode characters."""
        context = (
            builder.with_user("alice")
            .with_classification(DataClassification.INTERNAL)
            .with_metadata("name", "José García 日本語")
            .build()
        )
        assert context.metadata["name"] == "José García 日本語"

    def test_reuse_builder_after_build(self, builder):
        """Builder can be reused after calling build()."""
        # Build first context
        context1 = (
            builder.with_user("alice")
            .with_classification(DataClassification.PUBLIC)
            .build()
        )
        
        # Reuse builder for second context
        context2 = (
            builder.reset()
            .with_user("bob")
            .with_classification(DataClassification.CONFIDENTIAL)
            .build()
        )
        
        assert context1.user_id == "alice"
        assert context2.user_id == "bob"
        assert context1.data_classification != context2.data_classification


class TestBuilderDefaults:
    """Test builder default values."""

    def test_default_performance_target_is_balanced(self, builder):
        """Default performance target is BALANCED."""
        context = (
            builder.with_user("alice")
            .with_classification(DataClassification.PUBLIC)
            .build()
        )
        assert context.performance_target == PerformanceTarget.BALANCED

    def test_default_classification_is_internal(self, builder):
        """Default classification (not overridden) is INTERNAL."""
        context = (
            builder.with_user("alice")
            .build()
        )
        assert context.data_classification == DataClassification.INTERNAL

    def test_default_empty_compliance_list(self, builder):
        """Default compliance requirements is empty list."""
        context = (
            builder.with_user("alice")
            .with_classification(DataClassification.PUBLIC)
            .build()
        )
        assert context.compliance_requirements == []

    def test_default_empty_metadata(self, builder):
        """Default metadata is empty dictionary."""
        context = (
            builder.with_user("alice")
            .with_classification(DataClassification.PUBLIC)
            .build()
        )
        assert context.metadata == {}
