"""Configuration management for the TMT threat modeling toolkit.

Loads and validates YAML-based configuration files with environment
variable fallbacks for sensitive values like API keys.
"""

import os
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)


@dataclass
class ScannerConfig:
    """Configuration for pattern-based security scanners.

    Attributes:
        enabled: Whether pattern-based scanning is active.
        severity_threshold: Minimum severity level to report.
        custom_patterns: Additional user-defined vulnerability patterns.
    """

    enabled: bool = True
    severity_threshold: str = "low"
    custom_patterns: Dict[str, List[str]] = field(default_factory=dict)


@dataclass
class LLMConfig:
    """Configuration for LLM-powered security review.

    Attributes:
        enabled: Whether LLM review is active.
        provider: LLM provider name (huggingface, openai, or anthropic).
        model: Model identifier to use for reviews.
        api_key: API key for the LLM provider.
        base_url: Optional custom base URL for OpenAI-compatible APIs.
        temperature: Sampling temperature for LLM responses.
        max_tokens: Maximum tokens for LLM response generation.
        timeout_seconds: Request timeout in seconds.
    """

    enabled: bool = False
    provider: str = "huggingface"
    model: str = "Qwen/Qwen2.5-72B-Instruct"
    api_key: str = ""
    base_url: Optional[str] = None
    temperature: float = 0.1
    max_tokens: int = 4096
    timeout_seconds: int = 120


@dataclass
class ReportConfig:
    """Configuration for report generation output.

    Attributes:
        output_dir: Directory path for generated reports.
        formats: List of output formats to generate.
        include_code_snippets: Whether to embed code in reports.
        max_snippet_lines: Maximum lines per code snippet.
    """

    output_dir: str = "reports"
    formats: List[str] = field(default_factory=lambda: ["markdown", "json"])
    include_code_snippets: bool = True
    max_snippet_lines: int = 10


@dataclass
class TMTConfig:
    """Top-level configuration for the threat modeling toolkit.

    Attributes:
        project_name: Human-readable project identifier.
        target_dirs: Directories to scan for source files.
        file_extensions: File extensions to include in scanning.
        exclude_dirs: Directory names to skip during scanning.
        scanner: Pattern-based scanner configuration.
        llm: LLM-powered review configuration.
        report: Report generation configuration.
    """

    project_name: str = "unnamed-project"
    target_dirs: List[str] = field(default_factory=lambda: ["src", "app", "api"])
    file_extensions: List[str] = field(default_factory=lambda: [".py", ".js", ".ts"])
    exclude_dirs: List[str] = field(
        default_factory=lambda: ["node_modules", ".venv", "__pycache__", ".git"]
    )
    scanner: ScannerConfig = field(default_factory=ScannerConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    report: ReportConfig = field(default_factory=ReportConfig)


def _read_yaml_file(config_path: str) -> dict:
    """Read and parse a YAML configuration file from disk.

    Args:
        config_path: Absolute or relative path to the YAML file.

    Returns:
        Parsed dictionary from the YAML file contents.
    """
    with open(config_path, "r") as f:
        data = yaml.safe_load(f) or {}
    logger.info("Loaded configuration from %s", config_path)
    return data


def _build_scanner_config(raw: dict) -> ScannerConfig:
    """Build a ScannerConfig from a raw dictionary section.

    Args:
        raw: Dictionary containing scanner configuration keys.

    Returns:
        Populated ScannerConfig dataclass instance.
    """
    return ScannerConfig(
        enabled=raw.get("enabled", True),
        severity_threshold=raw.get("severity_threshold", "low"),
        custom_patterns=raw.get("custom_patterns", {}),
    )


def _build_llm_basics(raw: dict) -> dict:
    """Extract basic LLM fields from raw configuration.

    Args:
        raw: Dictionary containing LLM configuration keys.

    Returns:
        Dictionary with provider, model, and auth fields.
    """
    api_key = raw.get("api_key", os.environ.get("TMT_LLM_API_KEY", ""))
    return {
        "enabled": raw.get("enabled", False),
        "provider": raw.get("provider", "huggingface"),
        "model": raw.get("model", "Qwen/Qwen2.5-72B-Instruct"),
        "api_key": api_key,
        "base_url": raw.get("base_url"),
    }


def _build_llm_tuning(raw: dict) -> dict:
    """Extract tuning parameter fields from raw LLM configuration.

    Args:
        raw: Dictionary containing LLM tuning keys.

    Returns:
        Dictionary with temperature, max_tokens, and timeout fields.
    """
    return {
        "temperature": raw.get("temperature", 0.1),
        "max_tokens": raw.get("max_tokens", 4096),
        "timeout_seconds": raw.get("timeout_seconds", 120),
    }


def _build_llm_config(raw: dict) -> LLMConfig:
    """Build an LLMConfig from a raw dictionary with env var fallbacks.

    Args:
        raw: Dictionary containing LLM configuration keys.

    Returns:
        Populated LLMConfig dataclass instance.
    """
    basics = _build_llm_basics(raw)
    tuning = _build_llm_tuning(raw)
    return LLMConfig(**basics, **tuning)


def _build_report_config(raw: dict) -> ReportConfig:
    """Build a ReportConfig from a raw dictionary section.

    Args:
        raw: Dictionary containing report configuration keys.

    Returns:
        Populated ReportConfig dataclass instance.
    """
    return ReportConfig(
        output_dir=raw.get("output_dir", "reports"),
        formats=raw.get("formats", ["markdown", "json"]),
        include_code_snippets=raw.get("include_code_snippets", True),
        max_snippet_lines=raw.get("max_snippet_lines", 10),
    )


def _build_tmt_config(data: dict) -> TMTConfig:
    """Build a complete TMTConfig from parsed YAML data.

    Args:
        data: Root dictionary from the parsed YAML config file.

    Returns:
        Fully populated TMTConfig dataclass instance.
    """
    scanner = _build_scanner_config(data.get("scanner", {}))
    llm = _build_llm_config(data.get("llm", {}))
    report = _build_report_config(data.get("report", {}))
    return TMTConfig(
        project_name=data.get("project_name", "unnamed-project"),
        target_dirs=data.get("target_dirs", ["src", "app", "api"]),
        file_extensions=data.get("file_extensions", [".py", ".js", ".ts"]),
        exclude_dirs=data.get(
            "exclude_dirs", ["node_modules", ".venv", "__pycache__", ".git"]
        ),
        scanner=scanner,
        llm=llm,
        report=report,
    )


def load_config(config_path: str) -> TMTConfig:
    """Load and parse a TMT configuration file into a typed config object.

    Args:
        config_path: Path to the YAML configuration file.

    Returns:
        Fully populated TMTConfig instance ready for use.
    """
    data = _read_yaml_file(config_path)
    config = _build_tmt_config(data)
    logger.info("Configuration built for project: %s", config.project_name)
    return config


def default_config() -> TMTConfig:
    """Create a TMTConfig with all default values for quick startup.

    Returns:
        TMTConfig instance with sensible default values.
    """
    return TMTConfig()
