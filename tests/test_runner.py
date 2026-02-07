"""Test suite for the threat model runner and report generation.

Validates the end-to-end workflow: scanner orchestration, report
assembly, statistics computation, and file output generation.
"""

import json
import os
import tempfile
import pytest

from tmt.config import TMTConfig, ScannerConfig, LLMConfig, ReportConfig
from tmt.models import (
    Finding,
    FindingCategory,
    ScanResult,
    Severity,
    ThreatModelReport,
    compute_report_statistics,
)
from tmt.reports.generator import ReportGenerator
from tmt.runner import ThreatModelRunner

# ──────────────────────────────────────────────────────────────────────────────
# Path constants for test fixtures
# ──────────────────────────────────────────────────────────────────────────────

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def _make_test_config(output_dir: str) -> TMTConfig:
    """Create a TMTConfig tailored for testing with output to a temp dir.

    Args:
        output_dir: Temporary directory for report output.

    Returns:
        TMTConfig with scanning enabled and LLM disabled.
    """
    return TMTConfig(
        project_name="test-project",
        target_dirs=[FIXTURES_DIR],
        file_extensions=[".py"],
        exclude_dirs=["__pycache__", ".git"],
        scanner=ScannerConfig(enabled=True),
        llm=LLMConfig(enabled=False),
        report=ReportConfig(output_dir=output_dir, formats=["markdown", "json"]),
    )


def _make_sample_finding(severity: Severity = Severity.HIGH) -> Finding:
    """Create a sample Finding for report generation tests.

    Args:
        severity: Severity level for the sample finding.

    Returns:
        Finding with test data populated.
    """
    return Finding(
        title="Test Finding",
        description="A test vulnerability description",
        severity=severity,
        category=FindingCategory.AUTH_SESSION,
        file_path="test.py",
        line_number=10,
        code_snippet="vulnerable_code()",
        recommendation="Fix the vulnerability",
        confidence=0.9,
        cwe_id="CWE-000",
    )


# ──────────────────────────────────────────────────────────────────────────────
# Report statistics tests
# ──────────────────────────────────────────────────────────────────────────────


class TestReportStatistics:
    """Test suite for report statistics computation."""

    def test_compute_empty_report(self):
        """Verify empty report has zero counts."""
        report = ThreatModelReport(project_name="test")
        report = compute_report_statistics(report)
        assert report.total_findings == 0
        assert report.critical_count == 0

    def test_compute_with_findings(self):
        """Verify statistics correctly count findings by severity."""
        scan_result = ScanResult(
            scanner_name="TestScanner",
            findings=[
                _make_sample_finding(Severity.CRITICAL),
                _make_sample_finding(Severity.CRITICAL),
                _make_sample_finding(Severity.HIGH),
                _make_sample_finding(Severity.MEDIUM),
                _make_sample_finding(Severity.LOW),
            ],
        )
        report = ThreatModelReport(project_name="test", scan_results=[scan_result])
        report = compute_report_statistics(report)
        assert report.total_findings == 5
        assert report.critical_count == 2
        assert report.high_count == 1
        assert report.medium_count == 1
        assert report.low_count == 1


# ──────────────────────────────────────────────────────────────────────────────
# Report generation tests
# ──────────────────────────────────────────────────────────────────────────────


class TestReportGenerator:
    """Test suite for Markdown and JSON report file generation."""

    def test_generates_markdown_file(self):
        """Verify Markdown report file is created with correct content."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = ReportConfig(output_dir=tmpdir, formats=["markdown"])
            generator = ReportGenerator(config)
            report = ThreatModelReport(project_name="md-test")
            paths = generator.generate(report)
            assert len(paths) == 1
            assert paths[0].endswith(".md")
            assert os.path.exists(paths[0])

    def test_generates_json_file(self):
        """Verify JSON report file is created with valid JSON content."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = ReportConfig(output_dir=tmpdir, formats=["json"])
            generator = ReportGenerator(config)
            report = ThreatModelReport(project_name="json-test")
            paths = generator.generate(report)
            assert len(paths) == 1
            with open(paths[0]) as f:
                data = json.load(f)
            assert data["project_name"] == "json-test"

    def test_generates_both_formats(self):
        """Verify both Markdown and JSON files are generated together."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = ReportConfig(output_dir=tmpdir, formats=["markdown", "json"])
            generator = ReportGenerator(config)
            report = ThreatModelReport(project_name="dual-test")
            paths = generator.generate(report)
            assert len(paths) == 2

    def test_markdown_includes_findings(self):
        """Verify Markdown report includes finding details."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = ReportConfig(output_dir=tmpdir, formats=["markdown"])
            generator = ReportGenerator(config)
            finding = _make_sample_finding()
            scan_result = ScanResult(scanner_name="TestScanner", findings=[finding])
            report = ThreatModelReport(
                project_name="detail-test", scan_results=[scan_result]
            )
            paths = generator.generate(report)
            content = open(paths[0]).read()
            assert "Test Finding" in content
            assert "CWE-000" in content


# ──────────────────────────────────────────────────────────────────────────────
# End-to-end runner tests
# ──────────────────────────────────────────────────────────────────────────────


class TestThreatModelRunner:
    """Test suite for the end-to-end threat modeling workflow."""

    def test_runner_produces_report(self):
        """Verify runner completes and returns a populated report."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = _make_test_config(tmpdir)
            runner = ThreatModelRunner(config)
            report = runner.run(target_path=FIXTURES_DIR)
            assert isinstance(report, ThreatModelReport)
            assert len(report.scan_results) == 5

    def test_runner_generates_report_files(self):
        """Verify runner writes report files to the output directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = _make_test_config(tmpdir)
            runner = ThreatModelRunner(config)
            runner.run(target_path=FIXTURES_DIR)
            md_path = os.path.join(tmpdir, "threat_model_report.md")
            json_path = os.path.join(tmpdir, "threat_model_report.json")
            assert os.path.exists(md_path), "Markdown report should exist"
            assert os.path.exists(json_path), "JSON report should exist"

    def test_runner_detects_vulnerabilities(self):
        """Verify runner finds vulnerabilities in the vulnerable fixture."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = _make_test_config(tmpdir)
            runner = ThreatModelRunner(config)
            report = runner.run(target_path=FIXTURES_DIR)
            report = compute_report_statistics(report)
            assert (
                report.total_findings > 0
            ), "Should find vulnerabilities in test fixtures"

    def test_runner_with_llm_disabled(self):
        """Verify runner works correctly when LLM review is disabled."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = _make_test_config(tmpdir)
            config.llm.enabled = False
            runner = ThreatModelRunner(config)
            report = runner.run(target_path=FIXTURES_DIR)
            assert len(report.llm_reviews) == 0

    def test_json_report_is_valid(self):
        """Verify generated JSON report parses correctly and has structure."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = _make_test_config(tmpdir)
            runner = ThreatModelRunner(config)
            runner.run(target_path=FIXTURES_DIR)
            json_path = os.path.join(tmpdir, "threat_model_report.json")
            with open(json_path) as f:
                data = json.load(f)
            assert "project_name" in data
            assert "summary" in data
            assert "scan_results" in data
