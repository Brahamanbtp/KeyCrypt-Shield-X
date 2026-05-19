import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.governance.forensics import DigitalForensicsFramework


def test_capture_evidence_and_chain_of_custody_and_analysis():
    framework = DigitalForensicsFramework()
    evidence = framework.capture_evidence(system="srv-1", incident_id="INC-42")

    assert evidence.evidence_hash
    assert evidence.timestamp_token.startswith("rfc3161:")

    custody = framework.preserve_chain_of_custody(evidence)
    assert custody.evidence_id == evidence.evidence_id
    assert len(custody.entries) >= 2

    iocs = framework.extract_iocs(evidence)
    assert any(ioc.ioc_type == "ip" for ioc in iocs)
    assert any(ioc.ioc_type == "domain" for ioc in iocs)
    assert any(ioc.ioc_type == "hash" for ioc in iocs)

    report = framework.analyze_evidence(evidence)
    assert report.evidence_id == evidence.evidence_id
    assert report.timeline


def test_generate_forensic_report_reconstructs_timeline():
    framework = DigitalForensicsFramework()
    evidence = framework.capture_evidence(system="srv-2", incident_id="INC-99")

    report = framework.generate_forensic_report("INC-99")

    assert report.incident_id == "INC-99"
    assert report.evidence_items
    assert report.custody_chains
    assert report.analysis_reports
    assert report.summary["ioc_count"] >= 1
    assert report.timeline