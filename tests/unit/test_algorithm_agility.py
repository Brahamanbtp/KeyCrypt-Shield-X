import warnings
import pytest
from src.security.algorithm_agility import (
    CryptoAgilityFramework,
    DeprecationLevel,
    MigrationStatus,
)


def dummy_encrypt_aes(data):
    import hashlib
    return hashlib.sha256(data + b"_aes").digest()


def dummy_encrypt_rsa(data):
    import hashlib
    return hashlib.sha256(data + b"_rsa").digest()


def test_register_algorithm_implementation():
    framework = CryptoAgilityFramework()
    framework.register_algorithm_implementation("AES-256-GCM", dummy_encrypt_aes, version="1.0")
    algo_status = framework.get_algorithm_status("AES-256-GCM")
    assert algo_status is not None
    assert algo_status["algorithm_name"] == "AES-256-GCM"
    assert algo_status["version"] == "1.0"
    assert algo_status["deprecation_level"] == "active"


def test_deprecate_algorithm_emits_warning():
    framework = CryptoAgilityFramework()
    framework.register_algorithm_implementation("DES", dummy_encrypt_aes, version="1.0")
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        framework.deprecate_algorithm("DES", replacement="AES-256-GCM")
        assert len(w) >= 1
        assert "deprecated" in str(w[-1].message).lower()


def test_migrate_to_new_algorithm_creates_plan():
    framework = CryptoAgilityFramework()
    framework.register_algorithm_implementation("AES-128", dummy_encrypt_aes, version="1.0")
    framework.register_algorithm_implementation("AES-256", dummy_encrypt_aes, version="2.0")
    # store some records with old algorithm
    framework.store_encrypted_record("r1", "AES-128", b"cipher1", "key1")
    framework.store_encrypted_record("r2", "AES-128", b"cipher2", "key1")
    framework.store_encrypted_record("r3", "AES-256", b"cipher3", "key2")
    # plan migration
    plan = framework.migrate_to_new_algorithm("AES-128", "AES-256")
    assert plan.migration_id is not None
    assert plan.old_algorithm == "AES-128"
    assert plan.new_algorithm == "AES-256"
    assert len(plan.affected_records) == 2  # only r1 and r2


def test_execute_algorithm_migration():
    framework = CryptoAgilityFramework()
    framework.register_algorithm_implementation("OLD", dummy_encrypt_aes, version="1.0")
    framework.register_algorithm_implementation("NEW", dummy_encrypt_rsa, version="2.0")
    # store records
    framework.store_encrypted_record("r1", "OLD", b"data1", "key1")
    framework.store_encrypted_record("r2", "OLD", b"data2", "key1")
    # plan and execute migration
    plan = framework.migrate_to_new_algorithm("OLD", "NEW")
    result = framework.execute_algorithm_migration(plan)
    assert result.status == MigrationStatus.COMPLETED
    assert result.records_migrated == 2
    assert result.records_failed == 0
    # verify records were updated
    r1 = framework._data_store["r1"]
    assert r1.algorithm_used == "NEW"


def test_rollback_algorithm_migration():
    framework = CryptoAgilityFramework()
    framework.register_algorithm_implementation("OLD", dummy_encrypt_aes, version="1.0")
    framework.register_algorithm_implementation("NEW", dummy_encrypt_rsa, version="2.0")
    framework.store_encrypted_record("r1", "OLD", b"original", "key1")
    original_cipher = framework._data_store["r1"].ciphertext
    # plan and execute migration
    plan = framework.migrate_to_new_algorithm("OLD", "NEW")
    result = framework.execute_algorithm_migration(plan)
    assert result.status == MigrationStatus.COMPLETED
    # rollback
    success = framework.rollback_algorithm_migration(plan.migration_id)
    assert success is True
    # verify record is restored
    r1 = framework._data_store["r1"]
    assert r1.algorithm_used == "OLD"
    assert r1.ciphertext == original_cipher


def test_retire_algorithm_warns():
    framework = CryptoAgilityFramework()
    framework.register_algorithm_implementation("ANCIENT", dummy_encrypt_aes, version="1.0")
    framework.register_algorithm_implementation("MODERN", dummy_encrypt_rsa, version="2.0")
    framework.store_encrypted_record("r1", "ANCIENT", b"data", "key")
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        framework.retire_algorithm("ANCIENT")
        plan = framework.migrate_to_new_algorithm("ANCIENT", "MODERN")
        # should warn about retired algorithm
        assert any("retired" in str(warning.message).lower() for warning in w)


def test_get_algorithm_status():
    framework = CryptoAgilityFramework()
    framework.register_algorithm_implementation("TEST-ALGO", dummy_encrypt_aes, version="3.0")
    status = framework.get_algorithm_status("TEST-ALGO")
    assert status is not None
    assert status["algorithm_name"] == "TEST-ALGO"
    assert status["version"] == "3.0"


def test_get_algorithm_status_not_found():
    framework = CryptoAgilityFramework()
    status = framework.get_algorithm_status("NONEXISTENT")
    assert status is None


def test_migrate_nonexistent_algorithm_raises():
    framework = CryptoAgilityFramework()
    framework.register_algorithm_implementation("EXISTING", dummy_encrypt_aes)
    with pytest.raises(ValueError):
        framework.migrate_to_new_algorithm("NONEXISTENT", "EXISTING")


def test_migration_history():
    framework = CryptoAgilityFramework()
    framework.register_algorithm_implementation("A", dummy_encrypt_aes)
    framework.register_algorithm_implementation("B", dummy_encrypt_rsa)
    framework.store_encrypted_record("r1", "A", b"data", "key")
    plan = framework.migrate_to_new_algorithm("A", "B")
    result = framework.execute_algorithm_migration(plan)
    history = framework.get_migration_history()
    assert len(history) == 1
    assert history[0].migration_id == plan.migration_id
    assert history[0].status == MigrationStatus.COMPLETED
