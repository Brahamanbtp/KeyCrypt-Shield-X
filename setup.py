from pathlib import Path

from setuptools import find_packages, setup


BASE_DIR = Path(__file__).parent
README_PATH = BASE_DIR / "README.md"
LONG_DESCRIPTION = README_PATH.read_text(encoding="utf-8") if README_PATH.exists() else ""


setup(
    name="keycrypt-shield-x",
    version="0.1.0",
    description="Quantum-resistant cryptographic storage system",
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    author="Pranay Sharma",
    author_email="brahamanbtp@gmail.com",
    url="https://github.com/example/KeyCrypt-Shield-X",
    license="MIT",
    packages=find_packages(exclude=("tests", "tests.*", "docs", "docs.*")),
    include_package_data=True,
    install_requires=[
        "cryptography",
        "numpy",
        "scipy",
        "torch",
        "qiskit",
    ],
    python_requires=">=3.10",
    entry_points={
        "console_scripts": [
            "keycrypt-shield-x=keycrypt_shield_x.cli:main",
        ]
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Topic :: Security :: Cryptography",
    ],
    keywords="cryptography, post-quantum, storage, security, qiskit",
)
