"""Base scanner providing shared file collection and pattern matching logic.

All concrete scanners inherit from BaseScanner, which handles directory
traversal, file reading, regex-based vulnerability detection, and
finding creation in a framework-agnostic manner.
"""

import logging
import os
import re
import time
from dataclasses import dataclass
from typing import List, Optional

from tmt.config import ScannerConfig
from tmt.models import Finding, FindingCategory, ScanResult, Severity

logger = logging.getLogger(__name__)


@dataclass
class VulnerabilityPattern:
    """Defines a single vulnerability detection rule.

    Attributes:
        name: Human-readable name of the vulnerability.
        trigger_pattern: Regex that identifies potentially vulnerable code.
        defense_pattern: Regex for defensive code that mitigates the issue.
        context_window: Number of lines around a match to check for defenses.
        description: Detailed description of the vulnerability.
        severity: Severity level assigned to findings from this pattern.
        category: Finding category classification.
        recommendation: Remediation guidance for developers.
        cwe_id: CWE identifier for the vulnerability class.
        confidence: Default confidence score for matches.
    """

    name: str
    trigger_pattern: str
    defense_pattern: Optional[str]
    context_window: int
    description: str
    severity: Severity
    category: FindingCategory
    recommendation: str
    cwe_id: Optional[str] = None
    confidence: float = 0.8


class BaseScanner:
    """Abstract base scanner providing pattern-based vulnerability detection.

    Subclasses must define their own PATTERNS list of VulnerabilityPattern
    objects. The base class handles file traversal, content reading,
    pattern matching, and finding assembly.
    """

    PATTERNS: List[VulnerabilityPattern] = []

    def __init__(
        self, config: ScannerConfig, file_extensions: List[str], exclude_dirs: List[str]
    ):
        """Initialize the base scanner with configuration parameters.

        Args:
            config: Scanner configuration controlling behavior.
            file_extensions: File extensions to include in scanning.
            exclude_dirs: Directory names to skip during traversal.
        """
        self.config = config
        self.file_extensions = file_extensions
        self.exclude_dirs = set(exclude_dirs)
        self.scanner_name = self.__class__.__name__

    def _is_excluded_dir(self, dir_name: str) -> bool:
        """Check whether a directory name should be excluded from scanning.

        Args:
            dir_name: Name of the directory to check.

        Returns:
            True if the directory should be skipped.
        """
        return dir_name in self.exclude_dirs or dir_name.startswith(".")

    def _has_valid_extension(self, file_name: str) -> bool:
        """Check whether a file has an extension included in the scan scope.

        Args:
            file_name: Name of the file to check.

        Returns:
            True if the file extension matches a configured extension.
        """
        return any(file_name.endswith(ext) for ext in self.file_extensions)

    def _collect_files(self, target_path: str) -> List[str]:
        """Walk a directory tree and collect all files matching scan criteria.

        Args:
            target_path: Root directory path to begin traversal.

        Returns:
            List of absolute file paths matching extension and exclusion rules.
        """
        collected = []
        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if not self._is_excluded_dir(d)]
            for fname in files:
                if self._has_valid_extension(fname):
                    collected.append(os.path.join(root, fname))
        return collected

    def _read_file_safe(self, file_path: str) -> Optional[str]:
        """Read a file's contents with graceful error handling.

        Args:
            file_path: Absolute path to the file to read.

        Returns:
            File contents as a string, or None if reading failed.
        """
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()
        except OSError as exc:
            logger.warning("Could not read %s: %s", file_path, exc)
            return None

    def _extract_context(self, lines: List[str], line_num: int, window: int) -> str:
        """Extract a context window of code lines around a specific line.

        Args:
            lines: All lines of the source file.
            line_num: Zero-based line index of the match.
            window: Number of lines above and below to include.

        Returns:
            Concatenated string of context lines.
        """
        start = max(0, line_num - window)
        end = min(len(lines), line_num + window + 1)
        return "\n".join(lines[start:end])

    def _has_defense(self, context: str, defense_pattern: Optional[str]) -> bool:
        """Check whether defensive code exists within a context block.

        Args:
            context: Code context string to search.
            defense_pattern: Regex pattern indicating proper defense.

        Returns:
            True if defense pattern found or no defense pattern required.
        """
        if not defense_pattern:
            return False
        return bool(re.search(defense_pattern, context, re.IGNORECASE))

    def _find_trigger_lines(self, content: str, trigger_pattern: str) -> List[int]:
        """Find all line numbers where a trigger pattern matches.

        Args:
            content: Full file content to search.
            trigger_pattern: Regex pattern identifying potentially vulnerable code.

        Returns:
            List of zero-based line numbers with matches.
        """
        lines = content.split("\n")
        matched = []
        for i, line in enumerate(lines):
            if re.search(trigger_pattern, line, re.IGNORECASE):
                matched.append(i)
        return matched

    def _create_finding(
        self, pattern: VulnerabilityPattern, file_path: str, line_num: int, snippet: str
    ) -> Finding:
        """Create a Finding object from a matched vulnerability pattern.

        Args:
            pattern: The VulnerabilityPattern that was matched.
            file_path: Path to the file containing the finding.
            line_num: One-based line number of the finding.
            snippet: Code snippet from the surrounding context.

        Returns:
            Populated Finding dataclass instance.
        """
        return Finding(
            title=pattern.name,
            description=pattern.description,
            severity=pattern.severity,
            category=pattern.category,
            file_path=file_path,
            line_number=line_num,
            code_snippet=snippet,
            recommendation=pattern.recommendation,
            confidence=pattern.confidence,
            cwe_id=pattern.cwe_id,
        )

    def _scan_file_for_pattern(
        self, content: str, file_path: str, pattern: VulnerabilityPattern
    ) -> List[Finding]:
        """Scan a single file's content against one vulnerability pattern.

        Args:
            content: Full text content of the source file.
            file_path: Path to the source file being scanned.
            pattern: VulnerabilityPattern to match against.

        Returns:
            List of Finding objects for undefended trigger matches.
        """
        findings = []
        lines = content.split("\n")
        trigger_lines = self._find_trigger_lines(content, pattern.trigger_pattern)
        for line_num in trigger_lines:
            context = self._extract_context(lines, line_num, pattern.context_window)
            if not self._has_defense(context, pattern.defense_pattern):
                finding = self._create_finding(
                    pattern, file_path, line_num + 1, context
                )
                findings.append(finding)
        return findings

    def _scan_single_file(self, file_path: str, content: str) -> List[Finding]:
        """Apply all vulnerability patterns against a single file.

        Args:
            file_path: Path to the file being scanned.
            content: Full text content of the file.

        Returns:
            Aggregated list of findings from all pattern checks.
        """
        findings = []
        for pattern in self.PATTERNS:
            pattern_findings = self._scan_file_for_pattern(content, file_path, pattern)
            findings.extend(pattern_findings)
        return findings

    def _process_files(self, file_paths: List[str]) -> List[Finding]:
        """Read and scan each file, collecting all findings.

        Args:
            file_paths: List of absolute file paths to scan.

        Returns:
            Combined list of findings from all files.
        """
        findings = []
        for file_path in file_paths:
            content = self._read_file_safe(file_path)
            if content:
                findings.extend(self._scan_single_file(file_path, content))
        return findings

    def scan(self, target_path: str) -> ScanResult:
        """Execute the full scan workflow against a target directory.

        Args:
            target_path: Root directory path to scan for vulnerabilities.

        Returns:
            ScanResult containing all findings and scan metadata.
        """
        start_time = time.time()
        file_paths = self._collect_files(target_path)
        findings = self._process_files(file_paths)
        elapsed = time.time() - start_time
        logger.info(
            "%s scanned %d files in %.2fs, found %d issues",
            self.scanner_name,
            len(file_paths),
            elapsed,
            len(findings),
        )
        return ScanResult(
            scanner_name=self.scanner_name,
            findings=findings,
            files_scanned=len(file_paths),
            scan_duration_seconds=round(elapsed, 3),
        )
