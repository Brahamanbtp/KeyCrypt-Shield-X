from datetime import date, timedelta
import pytest
from src.security.algorithm_lifecycle import (
    AlgorithmLifecycleManager,
    AlgorithmStatus,
    Operation,
)


def test_set_algorithm_status():
    mgr = AlgorithmLifecycleManager()
    mgr.set_algorithm_status("AES-256", AlgorithmStatus.APPROVED)
    info = mgr.get_algorithm_lifecycle_info("AES-256")
    assert info is not None
    assert info["status"] == "approved"
    assert info["approved_date"] is not None


def test_register_algorithm_use_case():
    mgr = AlgorithmLifecycleManager()
    mgr.register_algorithm_use_case("RSA-2048", "signing", AlgorithmStatus.APPROVED)
    mgr.register_algorithm_use_case("RSA-2048", "encryption", AlgorithmStatus.APPROVED)
    info = mgr.get_algorithm_lifecycle_info("RSA-2048")
    assert "signing" in info["use_cases"]
    assert "encryption" in info["use_cases"]


def test_get_approved_algorithms_by_use_case():
    mgr = AlgorithmLifecycleManager()
    mgr.register_algorithm_use_case("AES-256", "encryption", AlgorithmStatus.APPROVED)
    mgr.register_algorithm_use_case("AES-128", "encryption", AlgorithmStatus.EXPERIMENTAL)
    mgr.register_algorithm_use_case("SHA-256", "hashing", AlgorithmStatus.APPROVED)
    approved_encryption = mgr.get_approved_algorithms("encryption")
    assert "AES-256" in approved_encryption
    assert "AES-128" not in approved_encryption
    assert "SHA-256" not in approved_encryption


def test_schedule_algorithm_deprecation():
    mgr = AlgorithmLifecycleManager()
    mgr.register_algorithm_use_case("MD5", "hashing", AlgorithmStatus.APPROVED)
    deprecation_date = date.today() + timedelta(days=90)
    mgr.schedule_algorithm_deprecation("MD5", deprecation_date)
    info = mgr.get_algorithm_lifecycle_info("MD5")
    assert info["deprecation_scheduled_date"] == deprecation_date.isoformat()
    # check that notification was sent
    pending = mgr.get_pending_notifications()
    assert any("Deprecation scheduled" in n.subject for n in pending)


def test_enforce_algorithm_policy_allows_approved():
    mgr = AlgorithmLifecycleManager()
    mgr.register_algorithm_use_case("AES-256", "encryption", AlgorithmStatus.APPROVED)
    op = Operation(operation_id="op1", algorithm="AES-256", use_case="encryption", user_id="user1")
    allowed = mgr.enforce_algorithm_policy(op)
    assert allowed is True
    ops_log = mgr.get_operations_log()
    assert len(ops_log) == 1


def test_enforce_algorithm_policy_blocks_forbidden():
    mgr = AlgorithmLifecycleManager()
    mgr.set_algorithm_status("DES", AlgorithmStatus.FORBIDDEN, reason="Weak key size")
    op = Operation(operation_id="op1", algorithm="DES", use_case="encryption", user_id="user1")
    allowed = mgr.enforce_algorithm_policy(op)
    assert allowed is False
    # check security alert was sent
    pending = mgr.get_pending_notifications()
    assert any("blocked" in n.message.lower() for n in pending)


def test_enforce_algorithm_policy_warns_experimental():
    mgr = AlgorithmLifecycleManager()
    mgr.register_algorithm_use_case("NEWCIPHER", "encryption", AlgorithmStatus.EXPERIMENTAL)
    op = Operation(operation_id="op1", algorithm="NEWCIPHER", use_case="encryption", user_id="user1")
    allowed = mgr.enforce_algorithm_policy(op)
    assert allowed is True
    # check warning was sent
    pending = mgr.get_pending_notifications()
    assert any("experimental" in n.subject.lower() for n in pending)


def test_enforce_algorithm_policy_warns_deprecated():
    mgr = AlgorithmLifecycleManager()
    mgr.register_algorithm_use_case("OLDCIPHER", "encryption", AlgorithmStatus.DEPRECATED)
    op = Operation(operation_id="op1", algorithm="OLDCIPHER", use_case="encryption", user_id="user1")
    allowed = mgr.enforce_algorithm_policy(op)
    assert allowed is True
    # check deprecation warning
    pending = mgr.get_pending_notifications()
    assert any("deprecated" in n.subject.lower() for n in pending)


def test_apply_scheduled_deprecations():
    mgr = AlgorithmLifecycleManager()
    mgr.register_algorithm_use_case("EXPIRING", "encryption", AlgorithmStatus.APPROVED)
    # schedule for yesterday (already due)
    past_date = date.today() - timedelta(days=1)
    mgr.schedule_algorithm_deprecation("EXPIRING", past_date)
    deprecated = mgr.apply_scheduled_deprecations()
    assert "EXPIRING" in deprecated
    info = mgr.get_algorithm_lifecycle_info("EXPIRING")
    assert info["status"] == "deprecated"


def test_get_operations_log_by_algorithm():
    mgr = AlgorithmLifecycleManager()
    mgr.set_algorithm_status("AES", AlgorithmStatus.APPROVED)
    mgr.set_algorithm_status("RSA", AlgorithmStatus.APPROVED)
    mgr.enforce_algorithm_policy(Operation(operation_id="op1", algorithm="AES", use_case="enc", user_id="u1"))
    mgr.enforce_algorithm_policy(Operation(operation_id="op2", algorithm="RSA", use_case="sign", user_id="u1"))
    mgr.enforce_algorithm_policy(Operation(operation_id="op3", algorithm="AES", use_case="enc", user_id="u2"))
    aes_ops = mgr.get_operations_log(algorithm="AES")
    assert len(aes_ops) == 2


def test_get_operations_log_by_user():
    mgr = AlgorithmLifecycleManager()
    mgr.set_algorithm_status("AES", AlgorithmStatus.APPROVED)
    mgr.enforce_algorithm_policy(Operation(operation_id="op1", algorithm="AES", use_case="enc", user_id="alice"))
    mgr.enforce_algorithm_policy(Operation(operation_id="op2", algorithm="AES", use_case="enc", user_id="bob"))
    alice_ops = mgr.get_operations_log(user_id="alice")
    assert len(alice_ops) == 1
    assert alice_ops[0].user_id == "alice"


def test_mark_notification_sent():
    mgr = AlgorithmLifecycleManager()
    mgr.register_algorithm_use_case("TEST", "encryption", AlgorithmStatus.APPROVED)
    # schedule deprecation to trigger notification
    future_date = date.today() + timedelta(days=30)
    mgr.schedule_algorithm_deprecation("TEST", future_date)
    pending = mgr.get_pending_notifications()
    assert len(pending) > 0
    notif_id = pending[0].notification_id
    success = mgr.mark_notification_sent(notif_id)
    assert success is True
    # verify it's no longer pending
    pending_after = mgr.get_pending_notifications()
    assert not any(n.notification_id == notif_id for n in pending_after)


def test_check_algorithm_deprecation_date():
    mgr = AlgorithmLifecycleManager()
    mgr.register_algorithm_use_case("TEMP", "encryption", AlgorithmStatus.APPROVED)
    future_date = date.today() + timedelta(days=30)
    mgr.schedule_algorithm_deprecation("TEMP", future_date)
    scheduled = mgr.check_algorithm_deprecation_date("TEMP")
    assert scheduled == future_date


def test_set_algorithm_status_forbidden_with_reason():
    mgr = AlgorithmLifecycleManager()
    mgr.set_algorithm_status("BROKEN", AlgorithmStatus.FORBIDDEN, reason="Critical vulnerability CVE-2026-12345")
    info = mgr.get_algorithm_lifecycle_info("BROKEN")
    assert info["status"] == "forbidden"
    assert "CVE-2026-12345" in info["forbidden_reason"]
