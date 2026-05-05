from src.security.device_trust import (
    DeviceInfo,
    Certificate,
    DeviceTrustManager,
)


def test_register_and_attest_device_healthy():
    mgr = DeviceTrustManager()
    di = DeviceInfo(device_id="dev1", os_version="11.2", disk_encrypted=True, antivirus_running=True, tpm_enabled=True, tpm_attestation_token="TPM-VALID", certificate_thumbprint="ABC123")
    mgr.register_device("dev1", di)
    att = mgr.attest_device_health("dev1")
    assert att.is_trusted is True
    assert att.reasons == []


def test_verify_device_certificate_matches():
    mgr = DeviceTrustManager()
    di = DeviceInfo(device_id="dev2", os_version="11", disk_encrypted=True, antivirus_running=True, tpm_enabled=False, certificate_thumbprint="DEF456")
    mgr.register_device("dev2", di)
    cert = Certificate(subject="dev2", thumbprint="DEF456", issuer="CA")
    assert mgr.verify_device_certificate("dev2", cert) is True


def test_quarantine_untrusted_device_blocks_attestation():
    mgr = DeviceTrustManager()
    di = DeviceInfo(device_id="dev3", os_version="9", disk_encrypted=False, antivirus_running=False, tpm_enabled=False)
    mgr.register_device("dev3", di)
    # before quarantine, attestation will include reasons but still return not trusted
    att1 = mgr.attest_device_health("dev3")
    assert att1.is_trusted is False
    mgr.quarantine_untrusted_device("dev3")
    assert mgr.is_quarantined("dev3") is True
    att2 = mgr.attest_device_health("dev3")
    assert att2.is_trusted is False
    assert "quarantined" in att2.reasons
