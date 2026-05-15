"""Unit tests for tools/interactive_debugger.py."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def _load_debugger_module():
    module_path = Path(__file__).resolve().parents[2] / "tools/interactive_debugger.py"
    spec = importlib.util.spec_from_file_location("interactive_debugger_tool", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load interactive_debugger module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_start_and_inspect_session():
    module = _load_debugger_module()

    # run sample_encrypt with explicit data and key
    session = module.start_debug_session("sample_encrypt", data=b"hello", key=b"0123456789abcdef")

    assert session.operation == "sample_encrypt"
    assert session.history
    # inspect first step
    first = module.inspect_encryption_state(session, 1)
    assert first.step == 1
    assert "value" in first.data


def test_visualize_data_flow_returns_mermaid():
    module = _load_debugger_module()

    diag = module.visualize_data_flow("sample_encrypt")
    assert isinstance(diag.mermaid, str)
    assert "Key derivation" in diag.mermaid


def test_replay_operation_applies_modifications():
    module = _load_debugger_module()

    session = module.start_debug_session("sample_encrypt", data=b"abc", key=b"0123456789abcdef")
    result = module.replay_operation(session, modifications={"data": b"xyz"})

    assert result.success is True
    assert result.history
    # final output should differ when data changed
    original_final = session.history[-1].data["value"]
    replay_final = result.history[-1].data["value"]
    assert original_final != replay_final
