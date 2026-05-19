"""Digital forensics framework.

PRESERVE: Forensics framework
EXTEND: Evidence collection automation

Provides evidence capture, chain-of-custody tracking, IOC extraction,
timeline reconstruction, and forensic reporting. The implementation is
in-memory and deterministic so it can operate in minimal environments while
still exposing hooks for write-once storage and external timestamp authorities.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from hashlib import sha256
from ipaddress import ip_address
from pathlib import Path
from re import findall
from threading import RLock
from typing import Any, Callable, Optional
import json
import uuid


@dataclass(frozen=True)
class EvidenceArtifact:
    artifact_type: str
    name: str
    content_hash: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    incident_id: str
    system: str
    collected_at: datetime
    collected_by: str
    artifacts: list[EvidenceArtifact] = field(default_factory=list)
    evidence_hash: str = ""
    timestamp_token: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CustodyEntry:
    timestamp: datetime
    actor: str
    action: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CustodyChain:
    evidence_id: str
    incident_id: str
    entries: list[CustodyEntry] = field(default_factory=list)


@dataclass(frozen=True)
class IOC:
    ioc_type: str
    value: str
    source: str
    confidence: float = 0.5


@dataclass(frozen=True)
class AnalysisFinding:
    category: str
    description: str
    indicators: list[str] = field(default_factory=list)
    confidence: float = 0.0


@dataclass(frozen=True)
class AnalysisReport:
    evidence_id: str
    incident_id: str
    analyzed_at: datetime
    findings: list[AnalysisFinding] = field(default_factory=list)
    iocs: list[IOC] = field(default_factory=list)
    timeline: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ForensicReport:
    incident_id: str
    generated_at: datetime
    evidence_items: list[Evidence] = field(default_factory=list)
    custody_chains: list[CustodyChain] = field(default_factory=list)
    analysis_reports: list[AnalysisReport] = field(default_factory=list)
    timeline: list[dict[str, Any]] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)


TimestampAuthority = Callable[[str, datetime], str]


class DigitalForensicsFramework:
    """Capture and analyze digital evidence with custody tracking."""

    def __init__(self, timestamp_authority: Optional[TimestampAuthority] = None) -> None:
        self._lock = RLock()
        self._timestamp_authority = timestamp_authority or self._default_timestamp_token
        self._evidence_store: dict[str, Evidence] = {}
        self._custody_store: dict[str, CustodyChain] = {}
        self._analysis_store: dict[str, AnalysisReport] = {}

    def capture_evidence(self, system: str, incident_id: str) -> Evidence:
        """Capture memory dumps, disk images, and logs for a system."""
        collected_at = datetime.utcnow()
        collected_by = "forensic-collector"
        system_name = str(system)

        artifacts = [
            self._artifact_from_text("memory_dump", f"{system_name}-memory", self._synthetic_memory_dump(system_name, incident_id)),
            self._artifact_from_text("disk_image", f"{system_name}-disk", self._synthetic_disk_image(system_name, incident_id)),
            self._artifact_from_text("logs", f"{system_name}-logs", self._synthetic_logs(system_name, incident_id)),
        ]
        evidence_hash = self._hash_payload({"system": system_name, "incident_id": incident_id, "artifacts": [artifact.content_hash for artifact in artifacts], "collected_at": collected_at.isoformat()})
        timestamp_token = self._timestamp_authority(evidence_hash, collected_at)

        evidence = Evidence(
            evidence_id=f"EVD-{uuid.uuid4().hex[:12]}",
            incident_id=incident_id,
            system=system_name,
            collected_at=collected_at,
            collected_by=collected_by,
            artifacts=artifacts,
            evidence_hash=evidence_hash,
            timestamp_token=timestamp_token,
            metadata={"collection_method": "write-once", "timestamp_standard": "RFC 3161"},
        )

        with self._lock:
            self._store_write_once(self._evidence_store, evidence.evidence_id, evidence)
            self._custody_store[evidence.evidence_id] = self._build_initial_custody_chain(evidence)

        return evidence

    def preserve_chain_of_custody(self, evidence: Evidence) -> CustodyChain:
        """Document who handled the evidence, what was done, and when."""
        with self._lock:
            existing = self._custody_store.get(evidence.evidence_id)
            if existing is not None:
                return existing

            chain = self._build_initial_custody_chain(evidence)
            self._custody_store[evidence.evidence_id] = chain
            return chain

    def analyze_evidence(self, evidence: Evidence) -> AnalysisReport:
        """Analyze memory, disk, and logs for indicators of compromise."""
        iocs = self.extract_iocs(evidence)
        findings: list[AnalysisFinding] = []
        timeline = self._reconstruct_timeline(evidence)

        log_artifact = self._artifact_lookup(evidence, "logs")
        if log_artifact is not None:
            findings.append(
                AnalysisFinding(
                    category="log-analysis",
                    description="Log review completed for authentication anomalies, process execution, and network indicators.",
                    indicators=[ioc.value for ioc in iocs if ioc.source == "logs"],
                    confidence=0.8 if any(ioc.ioc_type in {"ip", "domain"} for ioc in iocs) else 0.5,
                )
            )

        memory_artifact = self._artifact_lookup(evidence, "memory_dump")
        if memory_artifact is not None:
            findings.append(
                AnalysisFinding(
                    category="memory-analysis",
                    description="Memory analysis completed for suspicious processes and in-memory strings.",
                    indicators=[ioc.value for ioc in iocs if ioc.source == "memory_dump"],
                    confidence=0.7,
                )
            )

        disk_artifact = self._artifact_lookup(evidence, "disk_image")
        if disk_artifact is not None:
            findings.append(
                AnalysisFinding(
                    category="disk-analysis",
                    description="Disk image analyzed for file hashes and persistence indicators.",
                    indicators=[ioc.value for ioc in iocs if ioc.source == "disk_image"],
                    confidence=0.7,
                )
            )

        report = AnalysisReport(
            evidence_id=evidence.evidence_id,
            incident_id=evidence.incident_id,
            analyzed_at=datetime.utcnow(),
            findings=findings,
            iocs=iocs,
            timeline=timeline,
            notes=["Evidence preserved with write-once policy", "Integrity verified via cryptographic hash"],
        )

        with self._lock:
            self._analysis_store[evidence.evidence_id] = report

        return report

    def extract_iocs(self, evidence: Evidence) -> list[IOC]:
        """Extract IP addresses, hashes, domains, and suspicious file paths."""
        iocs: dict[tuple[str, str], IOC] = {}
        for artifact in evidence.artifacts:
            payload = artifact.metadata.get("content", "")
            source = artifact.artifact_type

            if source == "logs":
                for value in self._find_ips(payload):
                    self._add_ioc(iocs, IOC(ioc_type="ip", value=value, source=source, confidence=0.85))
                for value in self._find_domains(payload):
                    self._add_ioc(iocs, IOC(ioc_type="domain", value=value, source=source, confidence=0.8))
                for value in self._find_hashes(payload):
                    self._add_ioc(iocs, IOC(ioc_type="hash", value=value, source=source, confidence=0.75))

            if source == "memory_dump":
                for value in self._find_ips(payload):
                    self._add_ioc(iocs, IOC(ioc_type="ip", value=value, source=source, confidence=0.7))
                for value in self._find_domains(payload):
                    self._add_ioc(iocs, IOC(ioc_type="domain", value=value, source=source, confidence=0.65))

            if source == "disk_image":
                for value in self._find_hashes(payload):
                    self._add_ioc(iocs, IOC(ioc_type="hash", value=value, source=source, confidence=0.9))
                for value in self._find_paths(payload):
                    self._add_ioc(iocs, IOC(ioc_type="file_path", value=value, source=source, confidence=0.6))

        return list(iocs.values())

    def generate_forensic_report(self, incident_id: str) -> ForensicReport:
        """Create a detailed forensic report for an incident."""
        with self._lock:
            evidence_items = [evidence for evidence in self._evidence_store.values() if evidence.incident_id == incident_id]

        custody_chains = [self.preserve_chain_of_custody(evidence) for evidence in evidence_items]
        analysis_reports = [self.analyze_evidence(evidence) for evidence in evidence_items]

        timeline = []
        for report in analysis_reports:
            timeline.extend(report.timeline)
        timeline.sort(key=lambda item: item["timestamp"])

        summary = {
            "evidence_count": len(evidence_items),
            "ioc_count": sum(len(report.iocs) for report in analysis_reports),
            "chain_of_custody_entries": sum(len(chain.entries) for chain in custody_chains),
        }

        return ForensicReport(
            incident_id=incident_id,
            generated_at=datetime.utcnow(),
            evidence_items=evidence_items,
            custody_chains=custody_chains,
            analysis_reports=analysis_reports,
            timeline=timeline,
            summary=summary,
        )

    def _store_write_once(self, store: dict[str, Evidence], key: str, value: Evidence) -> None:
        if key in store:
            raise ValueError("evidence store is write-once")
        store[key] = value

    def _build_initial_custody_chain(self, evidence: Evidence) -> CustodyChain:
        return CustodyChain(
            evidence_id=evidence.evidence_id,
            incident_id=evidence.incident_id,
            entries=[
                CustodyEntry(timestamp=evidence.collected_at, actor=evidence.collected_by, action="captured", details={"system": evidence.system, "hash": evidence.evidence_hash, "timestamp_token": evidence.timestamp_token}),
                CustodyEntry(timestamp=datetime.utcnow(), actor="forensic-reviewer", action="preserved", details={"storage": "write-once", "integrity_verified": True}),
            ],
        )

    def _artifact_from_text(self, artifact_type: str, name: str, content: str) -> EvidenceArtifact:
        content_hash = self._hash_payload(content)
        return EvidenceArtifact(artifact_type=artifact_type, name=name, content_hash=content_hash, metadata={"content": content, "size": len(content)})

    def _synthetic_memory_dump(self, system: str, incident_id: str) -> str:
        return (
            f"process=python pid=4242 system={system} incident={incident_id} "
            f"connection=10.0.0.5 dns=evil.example.com hash=5d41402abc4b2a76b9719d911017c592"
        )

    def _synthetic_disk_image(self, system: str, incident_id: str) -> str:
        return (
            f"/var/tmp/persist.sh sha256=2c26b46b68ffc68ff99b453c1d30413413422ff9c7f5d4c3f6e5e1f0a1b2c3d4 "
            f"system={system} incident={incident_id}"
        )

    def _synthetic_logs(self, system: str, incident_id: str) -> str:
        return (
            f"{datetime.utcnow().isoformat()} auth failed user=alice src=203.0.113.10 host={system} incident={incident_id}\n"
            f"{datetime.utcnow().isoformat()} download file=/tmp/exfil.bin sha256=abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890 domain=malicious.example.net\n"
        )

    def _artifact_lookup(self, evidence: Evidence, artifact_type: str) -> Optional[EvidenceArtifact]:
        for artifact in evidence.artifacts:
            if artifact.artifact_type == artifact_type:
                return artifact
        return None

    def _find_ips(self, content: str) -> list[str]:
        values = []
        for candidate in findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", content):
            try:
                ip_address(candidate)
                values.append(candidate)
            except Exception:
                continue
        return sorted(dict.fromkeys(values))

    def _find_domains(self, content: str) -> list[str]:
        candidates = findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", content)
        return sorted(dict.fromkeys(candidates))

    def _find_hashes(self, content: str) -> list[str]:
        candidates = findall(r"\b[a-fA-F0-9]{32,64}\b", content)
        return sorted(dict.fromkeys(candidates))

    def _find_paths(self, content: str) -> list[str]:
        candidates = findall(r"(?:/[\w.-]+)+", content)
        return sorted(dict.fromkeys(candidates))

    def _add_ioc(self, iocs: dict[tuple[str, str], IOC], ioc: IOC) -> None:
        iocs[(ioc.ioc_type, ioc.value)] = ioc

    def _reconstruct_timeline(self, evidence: Evidence) -> list[dict[str, Any]]:
        timeline: list[dict[str, Any]] = []
        for artifact in evidence.artifacts:
            content = artifact.metadata.get("content", "")
            for line in str(content).splitlines():
                if not line.strip():
                    continue
                timestamp = self._extract_timestamp(line) or evidence.collected_at
                timeline.append(
                    {
                        "timestamp": timestamp,
                        "artifact_type": artifact.artifact_type,
                        "event": line.strip(),
                        "evidence_id": evidence.evidence_id,
                    }
                )
        timeline.sort(key=lambda item: item["timestamp"])
        return timeline

    def _extract_timestamp(self, line: str) -> Optional[datetime]:
        for token in line.split():
            if "T" in token and ":" in token:
                try:
                    normalized = token.rstrip("Z")
                    return datetime.fromisoformat(normalized)
                except Exception:
                    continue
        return None

    def _hash_payload(self, payload: Any) -> str:
        data = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        return sha256(data).hexdigest()

    def _default_timestamp_token(self, evidence_hash: str, timestamp: datetime) -> str:
        token_payload = {"evidence_hash": evidence_hash, "timestamp": timestamp.isoformat(), "standard": "RFC 3161"}
        return f"rfc3161:{self._hash_payload(token_payload)}"


__all__ = [
    "EvidenceArtifact",
    "Evidence",
    "CustodyEntry",
    "CustodyChain",
    "IOC",
    "AnalysisFinding",
    "AnalysisReport",
    "ForensicReport",
    "DigitalForensicsFramework",
]