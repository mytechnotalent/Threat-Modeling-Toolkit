"""Setup configuration for the TMT threat modeling toolkit."""

from setuptools import setup, find_packages

setup(
    name="tmt",
    version="1.0.0",
    description="Lightweight Threat Modeling Toolkit for Release Cycles",
    author="Kevin Thomas",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "pyyaml>=6.0",
        "openai>=1.0.0",
        "anthropic>=0.18.0",
        "huggingface-hub>=0.20.0",
        "jinja2>=3.1.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "tmt=run_threat_model:main",
        ],
    },
)
