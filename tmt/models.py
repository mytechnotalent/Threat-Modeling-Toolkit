"""Data models for threat modeling findings, scan results, and reports.

Provides dataclass-based models for representing security findings,
scan results from pattern-based scanners, LLM review outputs, and
aggregated threat model reports.
"""

import datetime
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Severity(Enum):
    """Enumeration of finding severity levels aligned with CVSS qualitative ratings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCategory(Enum):
    """Enumeration of threat finding categories tracked by the toolkit."""

    REPLAY_ATTACK = "replay_attack"
    RACE_CONDITION = "race_condition"
    TOKEN_ABUSE = "token_abuse"
    AUTH_SESSION = "auth_session"
    API_ROUTE = "api_route"
    LLM_REVIEW = "llm_review"


SEVERITY_RANK = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}
"""Numeric ranking for severity comparison and sorting."""


@dataclass
class Finding:
    """Represents a single security finding from a scan or LLM review.

    Attributes:
        title: Short descriptive title of the finding.
        description: Detailed explanation of the vulnerability.
        severity: Severity level of the finding.
        category: Category classification of the finding.
        file_path: Path to the affected source file.
        line_number: Line number where the issue was detected.
        code_snippet: Relevant code excerpt surrounding the finding.
        recommendation: Actionable remediation guidance.
        confidence: Confidence score between 0.0 and 1.0.
        cwe_id: Optional CWE identifier for the vulnerability class.
    """

    title: str
    description: str
    severity: Severity
    category: FindingCategory
    file_path: str
    line_number: int
    code_snippet: str
    recommendation: str
    confidence: float = 0.8
    cwe_id: Optional[str] = None


def _utc_now_iso() -> str:
    """Return the current UTC time as an ISO 8601 formatted string.

    Returns:
        ISO 8601 timestamp string with UTC timezone.
    """
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


@dataclass
class ScanResult:
    """Container for results produced by a single scanner execution.

    Attributes:
        scanner_name: Identifier of the scanner that produced results.
        findings: List of security findings detected.
        files_scanned: Number of files analyzed during the scan.
        scan_duration_seconds: Wall-clock time taken for the scan.
        timestamp: ISO 8601 timestamp of when the scan completed.
    """

    scanner_name: str
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    scan_duration_seconds: float = 0.0
    timestamp: str = field(default_factory=_utc_now_iso)


@dataclass
class LLMReview:
    """Container for results from an LLM-powered security review.

    Attributes:
        reviewer_name: Identifier of the review workflow used.
        model_used: LLM model identifier used for the review.
        prompt_tokens: Number of input tokens consumed.
        completion_tokens: Number of output tokens generated.
        findings: List of security findings from the review.
        raw_response: Unprocessed LLM response text.
        timestamp: ISO 8601 timestamp of when the review completed.
    """

    reviewer_name: str
    model_used: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    findings: List[Finding] = field(default_factory=list)
    raw_response: str = ""
    timestamp: str = field(default_factory=_utc_now_iso)


@dataclass
class ThreatModelReport:
    """Complete threat model report aggregating all scan and review results.

    Attributes:
        project_name: Name of the project being assessed.
        scan_results: Results from all pattern-based scanners.
        llm_reviews: Results from all LLM-powered reviews.
        total_findings: Total count of all findings across sources.
        critical_count: Number of critical severity findings.
        high_count: Number of high severity findings.
        medium_count: Number of medium severity findings.
        low_count: Number of low severity findings.
        info_count: Number of informational findings.
        timestamp: ISO 8601 timestamp of report generation.
    """

    project_name: str = ""
    scan_results: List[ScanResult] = field(default_factory=list)
    llm_reviews: List[LLMReview] = field(default_factory=list)
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    timestamp: str = field(default_factory=_utc_now_iso)


def _count_by_severity(findings: List[Finding], severity: Severity) -> int:
    """Count findings matching a specific severity level.

    Args:
        findings: List of Finding objects to count.
        severity: Target severity level to match.

    Returns:
        Integer count of findings with the specified severity.
    """
    return sum(1 for f in findings if f.severity == severity)


def _gather_all_findings(report: ThreatModelReport) -> List[Finding]:
    """Collect all findings from scan results and LLM reviews into one list.

    Args:
        report: ThreatModelReport containing scan results and LLM reviews.

    Returns:
        Flat list of all Finding objects from every source.
    """
    scan_findings = [f for sr in report.scan_results for f in sr.findings]
    llm_findings = [f for lr in report.llm_reviews for f in lr.findings]
    return scan_findings + llm_findings


def compute_report_statistics(report: ThreatModelReport) -> ThreatModelReport:
    """Compute and populate severity counts on a ThreatModelReport.

    Args:
        report: ThreatModelReport to update with computed statistics.

    Returns:
        The same ThreatModelReport with updated count fields.
    """
    all_findings = _gather_all_findings(report)
    report.total_findings = len(all_findings)
    report.critical_count = _count_by_severity(all_findings, Severity.CRITICAL)
    report.high_count = _count_by_severity(all_findings, Severity.HIGH)
    report.medium_count = _count_by_severity(all_findings, Severity.MEDIUM)
    report.low_count = _count_by_severity(all_findings, Severity.LOW)
    report.info_count = _count_by_severity(all_findings, Severity.INFO)
    return report
