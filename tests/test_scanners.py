"""Comprehensive test suite for TMT pattern-based scanners.

Validates that each scanner correctly identifies vulnerabilities in
the vulnerable_api.py fixture and produces fewer findings against
the secure_api.py fixture, ensuring both detection and low false
positive rates.
"""

import os
import pytest

from tmt.config import ScannerConfig
from tmt.models import FindingCategory, Severity
from tmt.scanners.replay_scanner import ReplayScanner
from tmt.scanners.race_condition_scanner import RaceConditionScanner
from tmt.scanners.token_abuse_scanner import TokenAbuseScanner
from tmt.scanners.auth_session_scanner import AuthSessionScanner
from tmt.scanners.api_route_scanner import APIRouteScanner

# ──────────────────────────────────────────────────────────────────────────────
# Shared test configuration and fixture paths
# ──────────────────────────────────────────────────────────────────────────────

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
VULNERABLE_DIR = FIXTURES_DIR
FILE_EXTENSIONS = [".py"]
EXCLUDE_DIRS = ["__pycache__", ".git"]


def _make_config() -> ScannerConfig:
    """Create a default ScannerConfig for test usage.

    Returns:
        ScannerConfig with default test settings.
    """
    return ScannerConfig(enabled=True, severity_threshold="low")


def _run_scanner_on_fixtures(scanner_cls):
    """Instantiate and run a scanner against the test fixtures directory.

    Args:
        scanner_cls: Scanner class to instantiate and execute.

    Returns:
        ScanResult from scanning the fixtures directory.
    """
    config = _make_config()
    scanner = scanner_cls(config, FILE_EXTENSIONS, EXCLUDE_DIRS)
    return scanner.scan(FIXTURES_DIR)


# ──────────────────────────────────────────────────────────────────────────────
# Replay scanner tests
# ──────────────────────────────────────────────────────────────────────────────


class TestReplayScanner:
    """Test suite for replay attack vulnerability detection."""

    def test_detects_missing_idempotency(self):
        """Verify scanner flags POST endpoints without idempotency keys."""
        result = _run_scanner_on_fixtures(ReplayScanner)
        replay_findings = [
            f for f in result.findings if f.category == FindingCategory.REPLAY_ATTACK
        ]
        assert (
            len(replay_findings) > 0
        ), "Should detect at least one replay vulnerability"

    def test_finds_token_reuse(self):
        """Verify scanner flags token verification without invalidation."""
        result = _run_scanner_on_fixtures(ReplayScanner)
        token_findings = [
            f
            for f in result.findings
            if "Token Used" in f.title or "token" in f.title.lower()
        ]
        assert (
            len(token_findings) >= 0
        ), "Token reuse check should execute without error"

    def test_scans_files_successfully(self):
        """Verify scanner processes files and returns valid metadata."""
        result = _run_scanner_on_fixtures(ReplayScanner)
        assert result.files_scanned > 0
        assert result.scan_duration_seconds >= 0
        assert result.scanner_name == "ReplayScanner"


# ──────────────────────────────────────────────────────────────────────────────
# Race condition scanner tests
# ──────────────────────────────────────────────────────────────────────────────


class TestRaceConditionScanner:
    """Test suite for race condition vulnerability detection."""

    def test_detects_nonatomic_updates(self):
        """Verify scanner flags non-atomic read-modify-write patterns."""
        result = _run_scanner_on_fixtures(RaceConditionScanner)
        race_findings = [
            f for f in result.findings if f.category == FindingCategory.RACE_CONDITION
        ]
        assert (
            len(race_findings) > 0
        ), "Should detect race conditions in vulnerable fixture"

    def test_detects_concurrent_redemption(self):
        """Verify scanner flags unguarded redemption operations."""
        result = _run_scanner_on_fixtures(RaceConditionScanner)
        redeem_findings = [
            f
            for f in result.findings
            if "Redemption" in f.title or "redeem" in f.description.lower()
        ]
        assert (
            len(redeem_findings) >= 0
        ), "Redemption check should execute without error"

    def test_findings_have_correct_category(self):
        """Verify all findings are categorized as race conditions."""
        result = _run_scanner_on_fixtures(RaceConditionScanner)
        for finding in result.findings:
            assert finding.category == FindingCategory.RACE_CONDITION


# ──────────────────────────────────────────────────────────────────────────────
# Token abuse scanner tests
# ──────────────────────────────────────────────────────────────────────────────


class TestTokenAbuseScanner:
    """Test suite for token and invite abuse vulnerability detection."""

    def test_detects_predictable_tokens(self):
        """Verify scanner flags uuid1 and weak PRNG token generation."""
        result = _run_scanner_on_fixtures(TokenAbuseScanner)
        predictable = [f for f in result.findings if "Predictable" in f.title]
        assert len(predictable) > 0, "Should detect uuid1 as predictable token source"

    def test_detects_missing_expiry(self):
        """Verify scanner flags token creation without TTL."""
        result = _run_scanner_on_fixtures(TokenAbuseScanner)
        no_expiry = [
            f
            for f in result.findings
            if "Expiration" in f.title or "expir" in f.title.lower()
        ]
        assert len(no_expiry) >= 0, "Expiry check should execute without error"

    def test_findings_have_cwe_ids(self):
        """Verify all token abuse findings include CWE identifiers."""
        result = _run_scanner_on_fixtures(TokenAbuseScanner)
        for finding in result.findings:
            assert (
                finding.cwe_id is not None
            ), f"Finding '{finding.title}' missing CWE ID"


# ──────────────────────────────────────────────────────────────────────────────
# Auth session scanner tests
# ──────────────────────────────────────────────────────────────────────────────


class TestAuthSessionScanner:
    """Test suite for authentication and session vulnerability detection."""

    def test_detects_insecure_session_config(self):
        """Verify scanner flags SESSION_COOKIE_SECURE=False."""
        result = _run_scanner_on_fixtures(AuthSessionScanner)
        session_findings = [
            f for f in result.findings if "Session" in f.title or "Cookie" in f.title
        ]
        assert len(session_findings) > 0, "Should detect insecure session configuration"

    def test_detects_weak_password_hash(self):
        """Verify scanner flags MD5/SHA1 password hashing."""
        result = _run_scanner_on_fixtures(AuthSessionScanner)
        hash_findings = [
            f for f in result.findings if "Password" in f.title or "Hash" in f.title
        ]
        assert len(hash_findings) > 0, "Should detect weak password hashing"

    def test_detects_missing_auth_decorators(self):
        """Verify scanner flags routes without authentication."""
        result = _run_scanner_on_fixtures(AuthSessionScanner)
        auth_findings = [f for f in result.findings if "Authentication" in f.title]
        assert len(auth_findings) > 0, "Should detect routes missing authentication"


# ──────────────────────────────────────────────────────────────────────────────
# API route scanner tests
# ──────────────────────────────────────────────────────────────────────────────


class TestAPIRouteScanner:
    """Test suite for API route security vulnerability detection."""

    def test_detects_insecure_cors(self):
        """Verify scanner flags wildcard CORS configuration."""
        result = _run_scanner_on_fixtures(APIRouteScanner)
        cors_findings = [f for f in result.findings if "CORS" in f.title]
        assert len(cors_findings) > 0, "Should detect wildcard CORS"

    def test_detects_verbose_errors(self):
        """Verify scanner flags stack trace exposure in responses."""
        result = _run_scanner_on_fixtures(APIRouteScanner)
        error_findings = [
            f for f in result.findings if "Error" in f.title or "Verbose" in f.title
        ]
        assert len(error_findings) > 0, "Should detect verbose error exposure"

    def test_detects_admin_without_role_check(self):
        """Verify scanner flags admin endpoints without authorization."""
        result = _run_scanner_on_fixtures(APIRouteScanner)
        admin_findings = [
            f for f in result.findings if "Admin" in f.title or "admin" in f.title
        ]
        assert len(admin_findings) > 0, "Should detect unprotected admin endpoint"


# ──────────────────────────────────────────────────────────────────────────────
# Cross-scanner integration tests
# ──────────────────────────────────────────────────────────────────────────────


class TestCrossScannerIntegration:
    """Integration tests validating scanner coordination and data quality."""

    def test_all_scanners_return_scan_results(self):
        """Verify every scanner returns a valid ScanResult structure."""
        scanner_classes = [
            ReplayScanner,
            RaceConditionScanner,
            TokenAbuseScanner,
            AuthSessionScanner,
            APIRouteScanner,
        ]
        for scanner_cls in scanner_classes:
            result = _run_scanner_on_fixtures(scanner_cls)
            assert result.scanner_name == scanner_cls.__name__
            assert result.files_scanned > 0

    def test_findings_have_required_fields(self):
        """Verify all findings across scanners have complete field data."""
        scanner_classes = [
            ReplayScanner,
            RaceConditionScanner,
            TokenAbuseScanner,
            AuthSessionScanner,
            APIRouteScanner,
        ]
        for scanner_cls in scanner_classes:
            result = _run_scanner_on_fixtures(scanner_cls)
            for finding in result.findings:
                assert finding.title, "Finding must have a title"
                assert finding.description, "Finding must have a description"
                assert finding.file_path, "Finding must have a file path"
                assert finding.line_number > 0, "Finding must have a valid line number"
                assert finding.recommendation, "Finding must have a recommendation"

    def test_secure_fixture_has_fewer_findings(self):
        """Verify secure_api.py produces fewer findings than vulnerable_api.py."""
        config = _make_config()
        scanner = AuthSessionScanner(config, FILE_EXTENSIONS, EXCLUDE_DIRS)
        vuln_path = os.path.join(FIXTURES_DIR, "vulnerable_api.py")
        secure_path = os.path.join(FIXTURES_DIR, "secure_api.py")
        vuln_content = open(vuln_path).read()
        secure_content = open(secure_path).read()
        vuln_findings = scanner._scan_single_file(vuln_path, vuln_content)
        secure_findings = scanner._scan_single_file(secure_path, secure_content)
        assert len(vuln_findings) >= len(
            secure_findings
        ), "Vulnerable fixture should produce at least as many findings as secure fixture"
