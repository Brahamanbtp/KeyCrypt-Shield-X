from __future__ import annotations

import io
import math
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

try:
    import matplotlib.pyplot as plt
    from matplotlib.patches import Rectangle, FancyArrow
except Exception:  # pragma: no cover - optional
    plt = None

try:
    from PIL import Image, ImageDraw, ImageFont
except Exception:  # pragma: no cover - optional
    Image = None


@dataclass
class Visualization:
    image: Image.Image | bytes
    description: str = ""


def _ensure_matplotlib():
    if plt is None:
        raise RuntimeError("matplotlib is required for visualizations")


def _ensure_pillow():
    if Image is None:
        raise RuntimeError("Pillow is required for animations")


def _draw_block_diagram(steps: List[str], title: Optional[str] = None, figsize=(8, 2)) -> bytes:
    _ensure_matplotlib()
    fig, ax = plt.subplots(figsize=figsize)
    ax.axis("off")
    num = len(steps)
    width = 0.8 / num
    x = 0.05
    y = 0.4
    boxes = []
    for i, s in enumerate(steps):
        rect = Rectangle((x + i * (width + 0.05), y), width, 0.2, facecolor="#cfe2f3", edgecolor="#2b6cb0")
        ax.add_patch(rect)
        ax.text(x + i * (width + 0.05) + width / 2, y + 0.1, s, ha="center", va="center", wrap=True)
        boxes.append((x + i * (width + 0.05), y))
        if i < num - 1:
            ax.add_patch(FancyArrow(x + i * (width + 0.05) + width, y + 0.1, 0.03, 0, width=0.01, length_includes_head=True, head_width=0.03))
    if title:
        ax.set_title(title)
    buf = io.BytesIO()
    fig.tight_layout()
    fig.savefig(buf, format="png")
    plt.close(fig)
    buf.seek(0)
    return buf.read()


def visualize_encryption_process(algorithm: str, data: bytes, educational: bool = False) -> Visualization:
    """Create a block diagram showing the encryption process for `algorithm`.

    For block ciphers we show: Plaintext -> IV/Nonce -> Encrypt -> Ciphertext
    For hybrid we show: Generate key -> Encrypt data with symmetric -> Encrypt key with asymmetric -> Package
    """
    alg = algorithm.lower()
    desc_lines = []
    if "aes" in alg or "gcm" in alg or "cbc" in alg:
        steps = ["Plaintext", "IV/Nonce", "Encrypt (symmetric)", "Ciphertext"]
        desc_lines.append(f"Algorithm: {algorithm}. Symmetric encryption with IV/Nonce.")
        if educational:
            desc_lines.append("Symmetric encryption encrypts blocks/stream using a shared key. IV prevents repeats.")
    elif "rsa" in alg or "ecdsa" in alg or "hybrid" in alg:
        steps = ["Plaintext", "Symmetric Key", "Encrypt with Symmetric", "Encrypt Key (asymmetric)", "Package"]
        desc_lines.append(f"Algorithm: {algorithm}. Hybrid asymmetric+symmetric flow.")
        if educational:
            desc_lines.append("Hybrid mode encrypts large data with symmetric key and protects the key with asymmetric encryption.")
    else:
        steps = ["Plaintext", "Encrypt", "Ciphertext"]
        desc_lines.append(f"Algorithm: {algorithm}. Generic encryption flow.")
    img_bytes = _draw_block_diagram(steps, title=f"Encryption: {algorithm}")
    return Visualization(image=img_bytes, description="\n".join(desc_lines))


def visualize_key_derivation(password: str, salt: bytes, iterations: int = 1000, educational: bool = False) -> Visualization:
    """Illustrate PBKDF2 iterations by showing derivation steps (conceptual)."""
    # Create textual steps: password + salt -> H1 -> H2 -> ... -> derived key
    steps = ["Password+Salt"]
    steps += [f"H{i+1}" for i in range(min(6, max(1, int(math.log(iterations + 1, 2)))))]
    steps.append("Derived Key")
    desc = f"PBKDF2 iterations: {iterations}. Salt len={len(salt)} bytes."
    if educational:
        desc += "\nPBKDF2 applies HMAC repeatedly to slow brute-force attacks; more iterations increases cost."
    img = _draw_block_diagram(steps, title="Key Derivation (PBKDF2)")
    return Visualization(image=img, description=desc)


def visualize_hybrid_pqc(plaintext: bytes, educational: bool = False) -> Visualization:
    """Show parallel classical + PQC encryption in a hybrid scheme."""
    steps = ["Plaintext", "Generate Symmetric Key", "Encrypt (AES)", "Encrypt Key (Classical RSA)", "Encrypt Key (PQC)", "Package"]
    desc = "Hybrid classical + PQC: symmetric encryption protected by both classical and PQC key encapsulation methods." 
    if educational:
        desc += "\nThis approach provides post-quantum resilience while maintaining performance."
    img = _draw_block_diagram(steps, title="Hybrid Classical + PQC Encryption")
    return Visualization(image=img, description=desc)


def _pil_image_from_bytes(png_bytes: bytes) -> "Image.Image":
    _ensure_pillow()
    return Image.open(io.BytesIO(png_bytes)).convert("RGBA")


def animate_encryption(algorithm: str, data: bytes, educational: bool = False, out_path: Optional[Path] = None, frame_count: int = 8, duration: int = 200) -> Path:
    """Create an animated GIF illustrating the encryption steps.

    Returns the `Path` to the generated GIF in `artifacts/visualizations`.
    """
    _ensure_pillow()
    vis = visualize_encryption_process(algorithm, data, educational=educational)
    base_img = _pil_image_from_bytes(vis.image if isinstance(vis.image, (bytes, bytearray)) else vis.image.tobytes()) if isinstance(vis.image, bytes) else _pil_image_from_bytes(vis.image)
    # If conversion failed, fallback to creating simple frames with text
    frames: List[Image.Image] = []
    try:
        # Create frames by adding progressive highlights to steps
        # Reuse _draw_block_diagram to create images per step with title
        steps = []
        alg = algorithm.lower()
        if "aes" in alg or "gcm" in alg or "cbc" in alg:
            steps = ["Plaintext", "IV/Nonce", "Encrypt (symmetric)", "Ciphertext"]
        elif "rsa" in alg or "ecdsa" in alg or "hybrid" in alg:
            steps = ["Plaintext", "Symmetric Key", "Encrypt with Symmetric", "Encrypt Key (asymmetric)", "Package"]
        else:
            steps = ["Plaintext", "Encrypt", "Ciphertext"]

        for i in range(len(steps)):
            png = _draw_block_diagram(steps[: i + 1] + ["..."] if i < len(steps) - 1 else steps, title=f"{algorithm} (step {i+1}/{len(steps)})")
            frame = _pil_image_from_bytes(png)
            # add caption
            draw = ImageDraw.Draw(frame)
            try:
                font = ImageFont.load_default()
            except Exception:
                font = None
            caption = f"Step {i+1}/{len(steps)}: {steps[i]}"
            draw.rectangle([0, frame.height - 30, frame.width, frame.height], fill=(255, 255, 255, 200))
            draw.text((10, frame.height - 24), caption, fill=(0, 0, 0), font=font)
            frames.append(frame.convert("P", palette=Image.ADAPTIVE))
    except Exception:
        # Fallback: create simple text frames
        for i in range(frame_count):
            img = Image.new("RGBA", (800, 200), (255, 255, 255, 255))
            d = ImageDraw.Draw(img)
            txt = f"{algorithm} encryption animation frame {i+1}/{frame_count}"
            try:
                font = ImageFont.load_default()
                d.text((20, 80), txt, fill=(0, 0, 0), font=font)
            except Exception:
                d.text((20, 80), txt, fill=(0, 0, 0))
            frames.append(img.convert("P", palette=Image.ADAPTIVE))

    out_dir = Path("artifacts/visualizations")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_path or out_dir / f"encryption_{algorithm.replace(' ', '_')}.gif"
    frames[0].save(str(out_file), save_all=True, append_images=frames[1:], duration=duration, loop=0)
    return out_file


if __name__ == "__main__":
    # Simple self-test: create static visualization
    v = visualize_encryption_process("AES-GCM", b"hello", educational=True)
    if isinstance(v.image, (bytes, bytearray)):
        with open("artifacts/visualizations/aes_example.png", "wb") as fh:
            fh.write(v.image)
    print("Visualizations ready")
