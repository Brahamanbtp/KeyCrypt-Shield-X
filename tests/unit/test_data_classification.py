from src.governance.data_classification import DataClassifier, ClassificationLevel


class DummyUser:
    def __init__(self, clearance_level: int = 0, roles=None):
        self.clearance_level = clearance_level
        self.roles = roles or []


def test_classify_sensitive_metadata():
    c = DataClassifier()
    data = b"User password and SSN: 123-45-6789"
    metadata = {"sensitive": True}
    level = c.classify_data(data, metadata)
    assert level in (ClassificationLevel.CONFIDENTIAL, ClassificationLevel.SECRET, ClassificationLevel.TOP_SECRET)


def test_apply_classification_policy_mappings():
    c = DataClassifier()
    policy_internal = c.apply_classification_policy(ClassificationLevel.INTERNAL)
    assert policy_internal.algorithm == "AES"
    assert policy_internal.key_size == 128

    policy_public = c.apply_classification_policy(ClassificationLevel.PUBLIC)
    assert policy_public.algorithm == "none"


def test_label_and_validate_authorization():
    c = DataClassifier()
    c.label_data("d1", ClassificationLevel.SECRET)
    high_user = DummyUser(clearance_level=3)
    low_user = DummyUser(clearance_level=1)
    assert c.validate_classification_handling("d1", high_user) is True
    assert c.validate_classification_handling("d1", low_user) is False


def test_role_based_clearance():
    c = DataClassifier()
    c.label_data("d2", ClassificationLevel.CONFIDENTIAL)
    role_user = DummyUser(roles=["clearance:CONFIDENTIAL"])
    assert c.validate_classification_handling("d2", role_user) is True
