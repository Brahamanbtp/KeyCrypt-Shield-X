from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import pandas as pd
except Exception:  # pragma: no cover - optional dependency
    pd = None

try:
    import plotly.express as px
    import plotly.graph_objects as go
except Exception:  # pragma: no cover - optional dependency
    px = None
    go = None


@dataclass
class LogEntry:
    timestamp: datetime
    level: str
    message: str
    correlation_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FilterCriteria:
    levels: Optional[List[str]] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    correlation_id: Optional[str] = None


@dataclass
class ErrorPattern:
    pattern: str
    count: int
    samples: List[str] = field(default_factory=list)


@dataclass
class Timeline:
    entries: List[LogEntry]

    def to_dataframe(self) -> "pd.DataFrame":
        if pd is None:
            raise RuntimeError("pandas is required to convert timeline to DataFrame")
        df = pd.DataFrame([
            {
                "timestamp": e.timestamp,
                "level": e.level,
                "message": e.message,
                "correlation_id": e.correlation_id,
                **{f"meta_{k}": v for k, v in e.metadata.items()},
            }
            for e in self.entries
        ])
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        return df

    def plot(self, title: str = "Log Timeline"):
        if px is None or pd is None:
            raise RuntimeError("plotly and pandas are required for plotting the timeline")
        df = self.to_dataframe()
        # Assign numeric severity for plotting order
        severity_map = {"CRITICAL": 50, "ERROR": 40, "WARNING": 30, "INFO": 20, "DEBUG": 10}
        df["severity"] = df["level"].map(lambda x: severity_map.get(str(x).upper(), 0))
        fig = px.scatter(df, x="timestamp", y="severity", color="level", hover_data=["message", "correlation_id"], title=title)
        fig.update_yaxes(title_text="Severity (higher = more severe)")
        return fig


@dataclass
class EventGroup:
    correlation_id: Optional[str]
    events: List[LogEntry]


def _load_json_lines(path: Path) -> List[Dict[str, Any]]:
    docs: List[Dict[str, Any]] = []
    text = path.read_text(encoding="utf-8")
    text = text.strip()
    if not text:
        return []
    # Try JSON lines (one JSON object per line)
    if text.count("\n") > 0 and text.lstrip().startswith("{"):
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                docs.append(json.loads(line))
            except json.JSONDecodeError:
                # fallthrough to try to parse entire file as JSON array/object
                docs = []
                break
        if docs:
            return docs

    # Try parse the full file as JSON array or object
    obj = json.loads(text)
    if isinstance(obj, list):
        return obj
    if isinstance(obj, dict):
        # Some log files put events under a key
        # Try to find a list-valued key
        for v in obj.values():
            if isinstance(v, list):
                return v
        # Otherwise treat the dict itself as a single event
        return [obj]
    return []


def parse_log_file(log_path: Path) -> List[LogEntry]:
    """Parse a JSON structured log file into a list of LogEntry.

    Supports JSON Lines (one JSON object per line) or a JSON array/object.
    Expected fields: timestamp, level, message, correlation_id, metadata
    """
    docs = _load_json_lines(log_path)
    entries: List[LogEntry] = []
    for d in docs:
        ts = None
        if "timestamp" in d:
            try:
                ts = pd.to_datetime(d["timestamp"]) if pd is not None else datetime.fromisoformat(str(d["timestamp"]))
                if hasattr(ts, "to_pydatetime"):
                    ts = ts.to_pydatetime()
            except Exception:
                try:
                    ts = datetime.fromisoformat(str(d["timestamp"]))
                except Exception:
                    ts = datetime.utcnow()
        else:
            ts = datetime.utcnow()
        level = d.get("level") or d.get("severity") or "INFO"
        message = d.get("message") or d.get("msg") or json.dumps(d)
        correlation_id = d.get("correlation_id") or d.get("trace_id") or d.get("request_id")
        metadata = d.get("metadata") or {k: v for k, v in d.items() if k not in {"timestamp", "level", "severity", "message", "msg", "correlation_id", "trace_id", "request_id"}}
        entries.append(LogEntry(timestamp=ts, level=str(level), message=str(message), correlation_id=correlation_id, metadata=metadata))
    # Sort chronologically
    entries.sort(key=lambda e: e.timestamp)
    return entries


def filter_logs(logs: List[LogEntry], criteria: FilterCriteria) -> List[LogEntry]:
    """Filter logs by level, time range, and correlation id."""
    filtered = logs
    if criteria.levels:
        levels_lower = {l.lower() for l in criteria.levels}
        filtered = [e for e in filtered if str(e.level).lower() in levels_lower]
    if criteria.start_time:
        filtered = [e for e in filtered if e.timestamp >= criteria.start_time]
    if criteria.end_time:
        filtered = [e for e in filtered if e.timestamp <= criteria.end_time]
    if criteria.correlation_id:
        filtered = [e for e in filtered if e.correlation_id == criteria.correlation_id]
    return filtered


_UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
_HEX_RE = re.compile(r"\b0x[0-9a-fA-F]+\b")
_NUM_RE = re.compile(r"\b\d+\b")
_PATH_RE = re.compile(r"(/[\w\-\.]+)+")


def _generalize_message(msg: str) -> str:
    s = _UUID_RE.sub("<UUID>", msg)
    s = _HEX_RE.sub("<HEX>", s)
    s = _NUM_RE.sub("<NUM>", s)
    s = _PATH_RE.sub("<PATH>", s)
    return s


def find_error_patterns(logs: List[LogEntry], top_n: int = 10) -> List[ErrorPattern]:
    """Identify common error patterns in the provided logs.

    Returns a list of ErrorPattern ordered by frequency. Message generalization is used
    to collapse variable parts like IDs and numbers.
    """
    error_msgs: List[str] = [e.message for e in logs if str(e.level).upper() in {"ERROR", "CRITICAL", "WARNING"}]
    generalized = [_generalize_message(m) for m in error_msgs]
    counts: Dict[str, List[str]] = {}
    for orig, gen in zip(error_msgs, generalized):
        counts.setdefault(gen, []).append(orig)
    patterns: List[ErrorPattern] = []
    for gen, samples in sorted(counts.items(), key=lambda kv: -len(kv[1]))[:top_n]:
        patterns.append(ErrorPattern(pattern=gen, count=len(samples), samples=samples[:3]))
    return patterns


def generate_timeline(logs: List[LogEntry]) -> Timeline:
    """Create a chronological timeline from logs."""
    entries = sorted(logs, key=lambda e: e.timestamp)
    return Timeline(entries=entries)


def correlate_events(logs: List[LogEntry]) -> List[EventGroup]:
    """Group related events by `correlation_id`. Entries without a correlation id are
    placed in a separate group with `None` as the correlation_id.
    """
    groups: Dict[Optional[str], List[LogEntry]] = {}
    for e in logs:
        groups.setdefault(e.correlation_id, []).append(e)
    # Sort each group's events chronologically
    result = [EventGroup(correlation_id=k, events=sorted(v, key=lambda e: e.timestamp)) for k, v in groups.items()]
    # Sort groups with correlation_id first (non-None), then None last
    result.sort(key=lambda g: (g.correlation_id is None, g.correlation_id or ""))
    return result


if __name__ == "__main__":
    import argparse
    from pprint import pprint

    p = argparse.ArgumentParser(description="Analyze structured JSON logs")
    p.add_argument("logfile", type=Path)
    p.add_argument("--plot", action="store_true")
    args = p.parse_args()
    logs = parse_log_file(args.logfile)
    print(f"Parsed {len(logs)} entries")
    patterns = find_error_patterns(logs, top_n=5)
    print("Top error patterns:")
    for pat in patterns:
        print(f"- {pat.count}x {pat.pattern}")
    timeline = generate_timeline(logs)
    groups = correlate_events(logs)
    print(f"Found {len(groups)} event groups (by correlation id)")
    if args.plot:
        try:
            fig = timeline.plot()
            fig.show()
        except Exception as exc:
            print("Plotting failed:", exc)
