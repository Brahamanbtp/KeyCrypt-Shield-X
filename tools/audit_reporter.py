from __future__ import annotations

import csv
import json
import os
import hashlib
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from jinja2 import Template
except Exception:  # pragma: no cover - optional
    Template = None

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
except Exception:  # pragma: no cover - optional
    letter = None

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
except Exception:  # pragma: no cover - optional
    hashes = None


@dataclass
class Report:
    id: str
    generated_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ActivityReport(Report):
    start_date: date | None = None
    end_date: date | None = None
    entries: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class ComplianceReport(Report):
    standard: str = ""
    period: str = ""
    summary: Dict[str, Any] = field(default_factory=dict)
    findings: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class IncidentReport(Report):
    incident_id: str = ""
    detected_at: datetime | None = None
    severity: str = ""
    description: str = ""
    affected_resources: List[str] = field(default_factory=list)
    timeline: List[Dict[str, Any]] = field(default_factory=list)


def _ensure_output_dir() -> Path:
    out = Path("artifacts/reports")
    out.mkdir(parents=True, exist_ok=True)
    return out


def generate_activity_report(start_date: date, end_date: date) -> ActivityReport:
    # Best-effort: try to locate audit logs under ./logs or ./state_store
    report = ActivityReport(id=f"activity-{start_date.isoformat()}-{end_date.isoformat()}", start_date=start_date, end_date=end_date)
    candidates = [Path("logs/audit.jsonl"), Path("logs/audit.log"), Path("state_store/audit.jsonl")]
    for p in candidates:
        if p.exists():
            try:
                with p.open("r", encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            obj = json.loads(line)
                        except Exception:
                            try:
                                obj = json.loads(line)
                            except Exception:
                                continue
                        # Expect fields like timestamp, operation, key_id, user, bytes
                        ts = obj.get("timestamp")
                        try:
                            tsd = datetime.fromisoformat(ts) if ts else None
                        except Exception:
                            tsd = None
                        if tsd:
                            d = tsd.date()
                            if not (start_date <= d <= end_date):
                                continue
                        report.entries.append(obj)
            except Exception:
                continue
    return report


def generate_compliance_report(standard: str, period: str) -> ComplianceReport:
    # Placeholder automation: basic checks and summary
    report = ComplianceReport(id=f"compliance-{standard}-{period}", standard=standard, period=period)
    report.summary = {"status": "partial", "checked": []}
    # Simple rulesets
    if standard.lower() in {"hipaa", "gdpr", "soc2"}:
        report.summary["status"] = "incomplete"
        report.findings.append({"id": "P1", "title": "Encryption at rest", "status": "checked"})
        report.summary["checked"].append("encryption_at_rest")
    else:
        report.summary["status"] = "unknown_standard"
    return report


def generate_security_incident_report(incident_id: str) -> IncidentReport:
    # Best-effort: try to pull incident data from artifacts or logs
    report = IncidentReport(id=f"incident-{incident_id}", incident_id=incident_id, detected_at=datetime.utcnow(), severity="medium", description="Auto-generated incident report")
    # Attempt to read a matching file
    candidate = Path(f"artifacts/incidents/{incident_id}.json")
    if candidate.exists():
        try:
            data = json.loads(candidate.read_text(encoding="utf-8"))
            report.description = data.get("description", report.description)
            report.affected_resources = data.get("affected_resources", [])
            report.timeline = data.get("timeline", [])
        except Exception:
            pass
    return report


def _render_html(report: Report) -> str:
    if Template is None:
        # Simple fallback
        return f"<html><body><h1>Report {report.id}</h1><pre>{json.dumps(report.__dict__, default=str, indent=2)}</pre></body></html>"
    tpl = Template("""
    <html><body>
    <h1>Report {{ report.id }}</h1>
    <p>Generated: {{ report.generated_at }}</p>
    <pre>{{ report_dict }}</pre>
    </body></html>
    """)
    return tpl.render(report=report, report_dict=json.dumps(report.__dict__, default=str, indent=2))


def _render_csv(report: Report, path: Path) -> None:
    # For ActivityReport, write entries rows
    if isinstance(report, ActivityReport):
        with path.open("w", newline="", encoding="utf-8") as fh:
            if not report.entries:
                fh.write("")
                return
            # Normalize keys
            keys = set()
            for e in report.entries:
                keys.update(e.keys())
            keys = list(sorted(keys))
            writer = csv.DictWriter(fh, fieldnames=keys)
            writer.writeheader()
            for e in report.entries:
                writer.writerow({k: e.get(k, "") for k in keys})
    else:
        # Generic: dump metadata and fields
        with path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["field", "value"])
            for k, v in report.__dict__.items():
                writer.writerow([k, json.dumps(v, default=str)])


def _render_pdf(report: Report, path: Path) -> None:
    if letter is None:
        raise RuntimeError("reportlab is required to generate PDF reports")
    c = canvas.Canvas(str(path), pagesize=letter)
    width, height = letter
    c.setFont("Helvetica", 12)
    y = height - 40
    c.drawString(40, y, f"Report: {report.id}")
    y -= 20
    c.drawString(40, y, f"Generated: {report.generated_at}")
    y -= 30
    text = json.dumps(report.__dict__, default=str, indent=2)
    for line in text.splitlines():
        if y < 40:
            c.showPage()
            y = height - 40
            c.setFont("Helvetica", 12)
        c.drawString(40, y, line[:100])
        y -= 14
    c.save()


def sign_report_bytes(data: bytes, private_key_pem: Optional[bytes] = None) -> bytes:
    # If cryptography is available and a PEM key is provided, sign with RSA-PSS/SHA256
    if hashes is not None and private_key_pem:
        try:
            key = load_pem_private_key(private_key_pem, password=None)
            sig = key.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            return sig
        except Exception:
            pass
    # Fallback: return SHA256 digest bytes
    return hashlib.sha256(data).digest()


def export_report(report: Report, format: str = "json", sign: bool = False, private_key_pem: Optional[bytes] = None) -> Path:
    out = _ensure_output_dir()
    fmt = format.lower()
    base = out / f"{report.id}.{fmt}"
    if fmt == "json":
        base.write_text(json.dumps(report.__dict__, default=str, indent=2), encoding="utf-8")
    elif fmt == "csv":
        _render_csv(report, base)
    elif fmt == "html":
        html = _render_html(report)
        base.write_text(html, encoding="utf-8")
    elif fmt == "pdf":
        _render_pdf(report, base)
    else:
        raise ValueError(f"Unsupported export format: {format}")

    if sign:
        data = base.read_bytes()
        signature = sign_report_bytes(data, private_key_pem=private_key_pem)
        sig_path = base.with_suffix(base.suffix + ".sig")
        sig_path.write_bytes(signature)
    return base


if __name__ == "__main__":
    from datetime import date
    r = generate_activity_report(date.today(), date.today())
    p = export_report(r, format="json")
    print("Exported:", p)
