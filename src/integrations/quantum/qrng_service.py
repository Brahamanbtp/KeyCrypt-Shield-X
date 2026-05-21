from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple
import os
import base64
import threading
import time
import math

try:
    from src.integrations.quantum.quantum_hardware_interface import (
        connect_to_quantum_computer,
        generate_quantum_random_numbers,
    )
except Exception:
    # graceful fallback if module not present
    connect_to_quantum_computer = None  # type: ignore
    generate_quantum_random_numbers = None  # type: ignore

try:
    from flask import Flask, Response, request  # type: ignore
except Exception:
    Flask = None  # type: ignore


@dataclass
class RandomnessTest:
    passed: bool
    monobit_p_value: float
    runs_p_value: float
    shannon_entropy: float
    details: Dict[str, Any] = None


EntropySource = Tuple[str, Callable[[int], bytes]]


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freqs = {}
    for b in data:
        freqs[b] = freqs.get(b, 0) + 1
    entropy = 0.0
    ln2 = math.log(2)
    for v in freqs.values():
        p = v / len(data)
        entropy -= p * (math.log(p) / ln2)
    return entropy


def generate_qrng(num_bytes: int, source: str = "hardware", conn: Optional[Any] = None) -> bytes:
    """Generate quantum random bytes from a given source.

    Sources:
    - 'hardware': use quantum hardware interface when available
    - 'quantum_noise': attempt hardware then fallback
    - 'atmospheric': mix OS randomness with timing noise
    - 'hybrid': combine multiple sources
    """
    src = (source or "hardware").lower()
    if src in ("hardware", "quantum_noise") and generate_quantum_random_numbers is not None:
        try:
            return generate_quantum_random_numbers(num_bytes, conn)
        except Exception:
            pass

    if src == "atmospheric":
        # mix os.urandom with timing jitter
        out = bytearray(os.urandom(num_bytes))
        for i in range(num_bytes):
            t = int((time.time() * 1000000) % 256)
            out[i] ^= t
            time.sleep(0.00001)
        return bytes(out)

    if src == "hybrid":
        # simple hybrid: XOR of hardware (if available) and os.urandom
        a = generate_qrng(num_bytes, "hardware", conn) if generate_quantum_random_numbers is not None else os.urandom(num_bytes)
        b = os.urandom(num_bytes)
        return bytes(x ^ y for x, y in zip(a, b))

    # default fallback
    return os.urandom(num_bytes)


def validate_randomness(random_bytes: bytes) -> RandomnessTest:
    """Run lightweight randomness checks: monobit (frequency), runs test, and Shannon entropy.

    Returns simplified p-values and an overall pass boolean using heuristic thresholds.
    """
    n = len(random_bytes) * 8
    bits = []
    for b in random_bytes:
        for i in range(8):
            bits.append((b >> i) & 1)

    ones = sum(bits)
    zeros = n - ones
    # monobit test statistic (approx)
    s = abs(ones - zeros) / math.sqrt(n)
    # convert to a pseudo p-value using complementary error function approximation
    try:
        import math as _m
        p_monobit = _m.erfc(s / _m.sqrt(2))
    except Exception:
        p_monobit = 0.0

    # runs test (approx): count runs
    runs = 1
    for i in range(1, len(bits)):
        if bits[i] != bits[i - 1]:
            runs += 1
    # expected runs under randomness
    pi = ones / n if n else 0.5
    expected_runs = 1 + 2 * n * pi * (1 - pi)
    sigma_runs = math.sqrt(2 * n) * pi * (1 - pi)
    z = abs(runs - expected_runs) / (sigma_runs or 1)
    try:
        p_runs = math.erfc(z / math.sqrt(2))
    except Exception:
        p_runs = 0.0

    shannon = _shannon_entropy(random_bytes)

    # heuristic thresholds: p-values > 0.01 and entropy > 7.5 bits per byte
    passed = (p_monobit > 0.01) and (p_runs > 0.01) and (shannon > 7.5)
    return RandomnessTest(passed=passed, monobit_p_value=p_monobit, runs_p_value=p_runs, shannon_entropy=shannon, details={"ones": ones, "runs": runs})


def mix_entropy_sources(sources: List[EntropySource], num_bytes: int) -> bytes:
    """Mix multiple entropy sources deterministically using a hash-XOR combiner.

    Each source is a tuple (name, callable(num_bytes)->bytes).
    """
    parts = []
    for name, fn in sources:
        try:
            parts.append(fn(num_bytes))
        except Exception:
            parts.append(os.urandom(num_bytes))

    if not parts:
        return os.urandom(num_bytes)

    # XOR combine all parts
    combined = bytearray(parts[0])
    for p in parts[1:]:
        for i in range(num_bytes):
            combined[i] ^= p[i]

    # finalize with SHA-256-derived keystream to avoid bias
    import hashlib

    digest = hashlib.sha256(bytes(combined)).digest()
    out = bytearray()
    # expand digest as needed
    while len(out) < num_bytes:
        digest = hashlib.sha256(digest).digest()
        out.extend(digest)
    return bytes(a ^ b for a, b in zip(bytes(combined), out[:num_bytes]))


def provide_qrng_as_service(api_endpoint: str = "0.0.0.0:8000", conn: Optional[Any] = None) -> None:
    """Expose a minimal QRNG HTTP endpoint. Requires Flask for full features; falls back to a simple http.server.

    Endpoint: GET /qrng?bytes=16&source=hardware
    Returns: raw bytes as base64
    """
    host, port_str = api_endpoint.split(":") if ":" in api_endpoint else (api_endpoint, "8000")
    port = int(port_str)

    if Flask is not None:
        app = Flask(__name__)

        @app.route("/qrng")
        def qrng():
            b = int(request.args.get("bytes", "16"))
            source = request.args.get("source", "hardware")
            data = generate_qrng(b, source, conn)
            return Response(base64.b64encode(data), mimetype="text/plain")

        threading.Thread(target=app.run, kwargs={"host": host, "port": port}, daemon=True).start()
        return

    # fallback: minimal HTTP server that responds once and exits
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.startswith("/qrng"):
                import urllib.parse as _p

                q = _p.urlparse(self.path).query
                params = dict(_p.parse_qsl(q))
                b = int(params.get("bytes", "16"))
                data = generate_qrng(b, "hardware", conn)
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(base64.b64encode(data))
            else:
                self.send_response(404)
                self.end_headers()

    server = HTTPServer((host, port), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
