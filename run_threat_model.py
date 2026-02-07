#!/usr/bin/env python3
"""CLI entry point for the TMT threat modeling toolkit.

Run as a script or via the installed 'tmt' console command to execute
the full threat modeling loop: pattern scanning, optional LLM review,
and report generation.

Usage:
    python run_threat_model.py --target ./src --config config.yaml
    python run_threat_model.py --target ./src --llm --llm-provider openai --llm-model gpt-4
    python run_threat_model.py --target ./src --output-dir ./security-reports
"""

import argparse
import logging
import sys

from tmt.config import (
    TMTConfig,
    load_config,
    default_config,
    LLMConfig,
    ReportConfig,
    ScannerConfig,
)
from tmt.models import Severity, compute_report_statistics
from tmt.runner import ThreatModelRunner

# ──────────────────────────────────────────────────────────────────────────────
# Configure module-level logging
# ──────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("tmt")


def _build_argument_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser with all supported options.

    Returns:
        Configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        prog="tmt",
        description="TMT - Lightweight Threat Modeling Toolkit for Release Cycles",
    )
    parser.add_argument(
        "--target",
        "-t",
        default=".",
        help="Target directory to scan (default: current directory)",
    )
    parser.add_argument("--config", "-c", default=None, help="Path to YAML config file")
    parser.add_argument(
        "--project-name", "-p", default=None, help="Project name for the report"
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        default="reports",
        help="Report output directory (default: reports)",
    )
    parser.add_argument(
        "--formats",
        nargs="+",
        default=["markdown", "json"],
        help="Report formats: markdown json",
    )
    parser.add_argument("--llm", action="store_true", help="Enable LLM-powered review")
    parser.add_argument(
        "--llm-provider",
        default="huggingface",
        choices=["huggingface", "openai", "anthropic"],
        help="LLM provider (default: huggingface)",
    )
    parser.add_argument(
        "--llm-model",
        default="Qwen/Qwen2.5-72B-Instruct",
        help="LLM model name (default: Qwen/Qwen2.5-72B-Instruct)",
    )
    return parser


def _load_or_build_config(args: argparse.Namespace) -> TMTConfig:
    """Load config from file or build from CLI arguments.

    Args:
        args: Parsed CLI argument namespace.

    Returns:
        TMTConfig populated from file or CLI arguments.
    """
    if args.config:
        return load_config(args.config)
    return default_config()


def _apply_cli_overrides(config: TMTConfig, args: argparse.Namespace) -> TMTConfig:
    """Apply CLI argument overrides to the loaded configuration.

    Args:
        config: Base TMTConfig to modify.
        args: Parsed CLI argument namespace with overrides.

    Returns:
        Modified TMTConfig with CLI overrides applied.
    """
    if args.project_name:
        config.project_name = args.project_name
    config.report.output_dir = args.output_dir
    config.report.formats = args.formats
    config.llm.enabled = args.llm
    config.llm.provider = args.llm_provider
    config.llm.model = args.llm_model
    return config


def _print_summary(report) -> None:
    """Print a concise findings summary to stdout.

    Args:
        report: ThreatModelReport with computed statistics.
    """
    report = compute_report_statistics(report)
    print(f"\n{'='*60}")
    print(f"  TMT Threat Model Report: {report.project_name}")
    print(f"{'='*60}")
    print(f"  🔴 Critical: {report.critical_count}")
    print(f"  🟠 High:     {report.high_count}")
    print(f"  🟡 Medium:   {report.medium_count}")
    print(f"  🔵 Low:      {report.low_count}")
    print(f"  ⚪ Info:     {report.info_count}")
    print(f"  ─────────────────────────")
    print(f"  Total:       {report.total_findings}")
    print(f"{'='*60}\n")


def _determine_exit_code(report) -> int:
    """Determine process exit code based on finding severity.

    Args:
        report: ThreatModelReport with computed statistics.

    Returns:
        Exit code: 2 for critical, 1 for high, 0 otherwise.
    """
    report = compute_report_statistics(report)
    if report.critical_count > 0:
        return 2
    if report.high_count > 0:
        return 1
    return 0


def main():
    """Execute the TMT threat modeling CLI workflow.

    Parses CLI arguments, loads configuration, runs the threat model
    loop, prints a summary, and exits with an appropriate code.
    """
    parser = _build_argument_parser()
    args = parser.parse_args()
    config = _load_or_build_config(args)
    config = _apply_cli_overrides(config, args)
    runner = ThreatModelRunner(config)
    report = runner.run(target_path=args.target)
    _print_summary(report)
    sys.exit(_determine_exit_code(report))


# ──────────────────────────────────────────────────────────────────────────────
# Script-level entry: invoke main when executed directly
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    main()
