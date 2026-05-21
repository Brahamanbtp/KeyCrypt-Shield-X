import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.integrations.quantum.qrng_service import (
    generate_qrng,
    validate_randomness,
    mix_entropy_sources,
)


def test_generate_qrng_length_and_entropy():
    b = generate_qrng(32, source="atmospheric")
    assert isinstance(b, (bytes, bytearray))
    assert len(b) == 32
    t = validate_randomness(b)
    assert isinstance(t.shannon_entropy, float)


def test_mix_entropy_sources_changes_output():
    def s1(n: int) -> bytes:
        return b"\x00" * n

    def s2(n: int) -> bytes:
        return b"\xff" * n

    out = mix_entropy_sources([("z", s1), ("o", s2)], 16)
    assert out != b"\x00" * 16
    assert out != b"\xff" * 16
