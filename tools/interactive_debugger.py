#!/usr/bin/env python3
"""Interactive debugging helpers for encryption operations.

This module provides a lightweight debugger that can step through
instrumented encryption operations, inspect intermediate state, visualize
data flow, and replay operations with parameter modifications.

Note: For automated tests the interactive pdb breakpoints are disabled by
default. For manual debugging set ``interactive=True`` on session start.
"""

from __future__ import annotations

import pdb
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional


@dataclass(frozen=True)
class StateSnapshot:
    step: int
    name: str
    data: Mapping[str, Any]


@dataclass(frozen=True)
class DataFlowDiagram:
    mermaid: str


@dataclass(frozen=True)
class Result:
    success: bool
    output: Any
    history: tuple[StateSnapshot, ...]


@dataclass
class DebugSession:
    id: str
    operation: str
    history: List[StateSnapshot]
    interactive: bool = False
    initial_inputs: Dict[str, Any] = None


# Registry of instrumented operations for quick lookup in tests and manual use.
_OP_REGISTRY: Dict[str, Callable[..., Any]] = {}


def register_operation(name: str, func: Callable[..., Any]) -> None:
    _OP_REGISTRY[name] = func


def _default_instrumented_encrypt(data: bytes, key: bytes) -> Dict[str, Any]:
    """A simple, deterministic 'encryption' operation that yields intermediate state.

    This is not cryptographically secure; it's for debugging examples and tests.
    The function returns a mapping with intermediate pieces so the debugger can
    record them.
    """
    # step 1: key derivation
    derived_key = key[:16]
    # step 2: padding
    padded = data + b"\x00" * ((16 - (len(data) % 16)) % 16)
    # step 3: block transform (toy XOR)
    blocks = [padded[i : i + 16] for i in range(0, len(padded), 16)]
    transformed = b"".join(bytes(a ^ b for a, b in zip(block, derived_key)) for block in blocks)
    # step 4: tag (toy)
    tag = bytes([sum(transformed) % 256])

    return {
        "derived_key": derived_key,
        "padded": padded,
        "transformed": transformed,
        "tag": tag,
        "ciphertext": transformed + tag,
    }


# Register the default example operation
register_operation("sample_encrypt", _default_instrumented_encrypt)


def start_debug_session(operation: str, *, interactive: bool = False, **kwargs) -> DebugSession:
    """Start a debug session for a named operation.

    The function looks up a registered instrumented operation by name and runs it
    while recording intermediate snapshots. If ``interactive`` is True, a pdb
    prompt is invoked at each recorded step.
    """
    op = _OP_REGISTRY.get(operation)
    if op is None:
        raise ValueError(f"unknown operation: {operation}")

    session_id = str(uuid.uuid4())
    session = DebugSession(id=session_id, operation=operation, history=[], interactive=interactive, initial_inputs=dict(kwargs))

    # Run operation and capture its stages if it returns mapping of named parts.
    result = op(**kwargs)

    if isinstance(result, dict):
        # recorded order: sorted keys to make snapshots deterministic
        for idx, (name, value) in enumerate(sorted(result.items()), start=1):
            snapshot = StateSnapshot(step=idx, name=str(name), data={"value": value})
            session.history.append(snapshot)
            if interactive:
                # expose session and snapshot for the pdb user
                globals().update({"session": session, "snapshot": snapshot})
                pdb.set_trace()

    return session


def inspect_encryption_state(session: DebugSession, step: int) -> StateSnapshot:
    """Return the StateSnapshot at the requested 1-based step index."""
    if not isinstance(session, DebugSession):
        raise TypeError("session must be a DebugSession")
    if step < 1 or step > len(session.history):
        raise IndexError("step out of range")
    return session.history[step - 1]


def visualize_data_flow(operation: str) -> DataFlowDiagram:
    """Generate a simple mermaid flow diagram for a known operation.

    This produces a human-readable overview suitable for quick inspection.
    """
    if operation == "sample_encrypt":
        mermaid = """
graph TD
  A[Input] --> B[Key derivation]
  B --> C[Padding]
  C --> D[Block transform]
  D --> E[Tag]
  E --> F[Ciphertext]
"""
        return DataFlowDiagram(mermaid=mermaid.strip())

    # generic fallback tries to infer steps from registry by name
    if operation in _OP_REGISTRY:
        keys = list(sorted(_OP_REGISTRY[operation]().__class__.__name__))
        mermaid = "graph TD\n  A[Input] --> Z[Output]"
        return DataFlowDiagram(mermaid=mermaid)

    raise ValueError(f"unknown operation: {operation}")


def replay_operation(session: DebugSession, modifications: Mapping[str, Any] | None = None, *, interactive: bool = False) -> Result:
    """Re-run the operation from a debug session with optional modifications.

    ``modifications`` can replace named inputs such as ``data`` or ``key`` for the
    re-run. The returned Result contains the new output and the recorded history.
    """
    if not isinstance(session, DebugSession):
        raise TypeError("session must be a DebugSession")

    op = _OP_REGISTRY.get(session.operation)
    if op is None:
        raise ValueError(f"unknown operation: {session.operation}")

    base_inputs: Dict[str, Any] = dict(session.initial_inputs or {})
    merged = dict(base_inputs)
    if modifications:
        merged.update(modifications)

    # Avoid invoking pdb in test runs unless requested
    new_session = start_debug_session(session.operation, interactive=interactive, **merged)

    # produce a Result object with output from the last snapshot if available
    output = None
    if new_session.history:
        output = new_session.history[-1].data.get("value")

    return Result(success=True, output=output, history=tuple(new_session.history))


__all__ = [
    "DebugSession",
    "StateSnapshot",
    "DataFlowDiagram",
    "Result",
    "start_debug_session",
    "inspect_encryption_state",
    "visualize_data_flow",
    "replay_operation",
    "register_operation",
]
