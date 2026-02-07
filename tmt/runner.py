"""Threat model runner orchestrating the full scan-review-report loop.

Coordinates pattern-based scanners, optional LLM-powered reviews,
and report generation into a single repeatable workflow that teams
can execute each release cycle.
"""

import logging
import os
import time
from typing import List, Optional

from tmt.config import TMTConfig
from tmt.llm.reviewer import LLMReviewer
from tmt.models import LLMReview, ScanResult, ThreatModelReport
from tmt.reports.generator import ReportGenerator
from tmt.scanners.api_route_scanner import APIRouteScanner
from tmt.scanners.auth_session_scanner import AuthSessionScanner
from tmt.scanners.base_scanner import BaseScanner
from tmt.scanners.race_condition_scanner import RaceConditionScanner
from tmt.scanners.replay_scanner import ReplayScanner
from tmt.scanners.token_abuse_scanner import TokenAbuseScanner

logger = logging.getLogger(__name__)


def _create_scanner(scanner_cls, config: TMTConfig) -> BaseScanner:
    """Instantiate a scanner with shared configuration parameters.

    Args:
        scanner_cls: Scanner class to instantiate.
        config: Top-level TMT configuration.

    Returns:
        Initialized scanner instance.
    """
    return scanner_cls(
        config=config.scanner,
        file_extensions=config.file_extensions,
        exclude_dirs=config.exclude_dirs,
    )


def _build_all_scanners(config: TMTConfig) -> List[BaseScanner]:
    """Build the complete set of pattern-based scanners.

    Args:
        config: Top-level TMT configuration.

    Returns:
        List of initialized scanner instances ordered by category.
    """
    scanner_classes = [
        ReplayScanner,
        RaceConditionScanner,
        TokenAbuseScanner,
        AuthSessionScanner,
        APIRouteScanner,
    ]
    return [_create_scanner(cls, config) for cls in scanner_classes]


def _run_all_scanners(
    scanners: List[BaseScanner], target_path: str
) -> List[ScanResult]:
    """Execute all scanners against a target directory.

    Args:
        scanners: List of initialized scanner instances.
        target_path: Root directory path to scan.

    Returns:
        List of ScanResult objects from all scanners.
    """
    results = []
    for scanner in scanners:
        logger.info("Running %s...", scanner.scanner_name)
        result = scanner.scan(target_path)
        results.append(result)
    return results


def _collect_llm_target_files(config: TMTConfig, target_path: str) -> List[str]:
    """Collect files for LLM review using the first scanner's file collection.

    Args:
        config: Top-level TMT configuration.
        target_path: Root directory path to collect files from.

    Returns:
        List of file paths suitable for LLM review.
    """
    collector = _create_scanner(ReplayScanner, config)
    return collector._collect_files(target_path)


def _run_llm_reviews(config: TMTConfig, target_path: str) -> List[LLMReview]:
    """Execute LLM-powered reviews against target files.

    Args:
        config: Top-level TMT configuration with LLM settings.
        target_path: Root directory path containing files to review.

    Returns:
        List of LLMReview objects from completed reviews.
    """
    reviewer = LLMReviewer(config.llm)
    file_paths = _collect_llm_target_files(config, target_path)
    logger.info("Submitting %d files for LLM review", len(file_paths))
    return reviewer.review_files(file_paths)


def _build_report(
    config: TMTConfig, scan_results: List[ScanResult], llm_reviews: List[LLMReview]
) -> ThreatModelReport:
    """Assemble a ThreatModelReport from scan results and LLM reviews.

    Args:
        config: Top-level TMT configuration.
        scan_results: Results from pattern-based scanners.
        llm_reviews: Results from LLM-powered reviews.

    Returns:
        Assembled ThreatModelReport ready for rendering.
    """
    return ThreatModelReport(
        project_name=config.project_name,
        scan_results=scan_results,
        llm_reviews=llm_reviews,
    )


class ThreatModelRunner:
    """Orchestrates the complete threat modeling loop for a release cycle.

    Manages the lifecycle of initializing scanners, executing pattern-based
    scans, optionally running LLM-powered reviews, and generating reports.
    """

    def __init__(self, config: TMTConfig):
        """Initialize the runner with project configuration.

        Args:
            config: Top-level TMT configuration for all components.
        """
        self.config = config
        self.scanners = _build_all_scanners(config)
        self.report_generator = ReportGenerator(config.report)

    def _resolve_target_path(self, target_path: Optional[str]) -> str:
        """Resolve the target scan directory from explicit path or config.

        Args:
            target_path: Optional explicit target directory override.

        Returns:
            Absolute path to the target directory for scanning.
        """
        if target_path:
            return os.path.abspath(target_path)
        return os.path.abspath(".")

    def _execute_scans(self, target_path: str) -> List[ScanResult]:
        """Run all pattern-based scanners if scanning is enabled.

        Args:
            target_path: Resolved absolute path to scan.

        Returns:
            List of ScanResult objects, empty if scanning disabled.
        """
        if not self.config.scanner.enabled:
            logger.info("Pattern scanning disabled, skipping")
            return []
        return _run_all_scanners(self.scanners, target_path)

    def _execute_llm_reviews(self, target_path: str) -> List[LLMReview]:
        """Run LLM-powered reviews if LLM integration is enabled.

        Args:
            target_path: Resolved absolute path to review.

        Returns:
            List of LLMReview objects, empty if LLM disabled.
        """
        if not self.config.llm.enabled:
            logger.info("LLM review disabled, skipping")
            return []
        return _run_llm_reviews(self.config, target_path)

    def _log_completion_summary(
        self, report: ThreatModelReport, elapsed: float
    ) -> None:
        """Log a summary of the completed threat model run.

        Args:
            report: Completed report with computed statistics.
            elapsed: Total wall-clock time in seconds.
        """
        logger.info(
            "Threat model complete in %.1fs: %d findings "
            "(%d critical, %d high, %d medium, %d low, %d info)",
            elapsed,
            report.total_findings,
            report.critical_count,
            report.high_count,
            report.medium_count,
            report.low_count,
            report.info_count,
        )

    def run(self, target_path: Optional[str] = None) -> ThreatModelReport:
        """Execute the complete threat modeling loop and generate reports.

        Args:
            target_path: Optional directory to scan. Defaults to current directory.

        Returns:
            Completed ThreatModelReport with all findings and statistics.
        """
        start_time = time.time()
        resolved_path = self._resolve_target_path(target_path)
        logger.info(
            "Starting threat model for '%s' at %s",
            self.config.project_name,
            resolved_path,
        )
        scan_results = self._execute_scans(resolved_path)
        llm_reviews = self._execute_llm_reviews(resolved_path)
        report = _build_report(self.config, scan_results, llm_reviews)
        output_paths = self.report_generator.generate(report)
        self._log_completion_summary(report, time.time() - start_time)
        return report
