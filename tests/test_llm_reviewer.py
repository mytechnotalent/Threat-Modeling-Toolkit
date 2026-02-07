"""Test suite for the LLM reviewer response parsing and prompt assembly.

Tests focus on deterministic components: prompt building, JSON parsing,
and finding assembly. Live LLM API calls are not invoked in tests.
"""

import json
import pytest

from tmt.config import LLMConfig
from tmt.llm.prompts import PromptLibrary
from tmt.llm.reviewer import (
    _parse_findings_json,
    _strip_markdown_fences,
    _parse_severity,
    _parse_category,
)
from tmt.models import FindingCategory, Severity

# ──────────────────────────────────────────────────────────────────────────────
# Prompt library tests
# ──────────────────────────────────────────────────────────────────────────────


class TestPromptLibrary:
    """Test suite for prompt template assembly and formatting."""

    def test_get_template_names(self):
        """Verify all expected template names are available."""
        lib = PromptLibrary()
        names = lib.get_template_names()
        assert "api_route" in names
        assert "auth_session" in names
        assert "logic_bug" in names
        assert "comprehensive" in names

    def test_build_prompt_contains_code(self):
        """Verify built prompt includes the provided source code."""
        lib = PromptLibrary()
        code = "def hello(): pass"
        result = lib.build_prompt("api_route", code)
        assert "system" in result
        assert "user" in result
        assert code in result["user"]

    def test_build_prompt_includes_schema(self):
        """Verify built prompt includes the JSON output schema instructions."""
        lib = PromptLibrary()
        result = lib.build_prompt("comprehensive", "x = 1")
        assert "JSON" in result["user"]
        assert "severity" in result["user"]

    def test_build_all_prompts(self):
        """Verify build_all_prompts returns prompts for every template."""
        lib = PromptLibrary()
        all_prompts = lib.build_all_prompts("def foo(): pass")
        assert len(all_prompts) == 4
        for name, prompt_pair in all_prompts.items():
            assert "system" in prompt_pair
            assert "user" in prompt_pair

    def test_invalid_template_raises_key_error(self):
        """Verify requesting a non-existent template raises KeyError."""
        lib = PromptLibrary()
        with pytest.raises(KeyError):
            lib.build_prompt("nonexistent", "code")


# ──────────────────────────────────────────────────────────────────────────────
# Response parsing tests
# ──────────────────────────────────────────────────────────────────────────────


class TestResponseParsing:
    """Test suite for LLM response parsing and finding extraction."""

    def test_strip_markdown_fences_json(self):
        """Verify markdown code fences are stripped from JSON responses."""
        raw = '```json\n[{"title": "test"}]\n```'
        cleaned = _strip_markdown_fences(raw)
        assert cleaned == '[{"title": "test"}]'

    def test_strip_markdown_fences_plain(self):
        """Verify plain text without fences is returned unchanged."""
        raw = '[{"title": "test"}]'
        cleaned = _strip_markdown_fences(raw)
        assert cleaned == raw

    def test_parse_valid_findings_json(self):
        """Verify valid JSON array is parsed into Finding objects."""
        raw = json.dumps(
            [
                {
                    "title": "Test Finding",
                    "description": "A test vulnerability",
                    "severity": "high",
                    "category": "replay_attack",
                    "line_number": 42,
                    "recommendation": "Fix it",
                    "confidence": 0.9,
                    "cwe_id": "CWE-294",
                }
            ]
        )
        findings = _parse_findings_json(raw, "test.py")
        assert len(findings) == 1
        assert findings[0].title == "Test Finding"
        assert findings[0].severity == Severity.HIGH
        assert findings[0].category == FindingCategory.REPLAY_ATTACK

    def test_parse_empty_array(self):
        """Verify empty JSON array returns empty findings list."""
        findings = _parse_findings_json("[]", "test.py")
        assert findings == []

    def test_parse_invalid_json_returns_empty(self):
        """Verify malformed JSON returns empty list without raising."""
        findings = _parse_findings_json("not valid json {{{", "test.py")
        assert findings == []

    def test_parse_severity_mapping(self):
        """Verify all severity strings map correctly to enum values."""
        assert _parse_severity("critical") == Severity.CRITICAL
        assert _parse_severity("high") == Severity.HIGH
        assert _parse_severity("medium") == Severity.MEDIUM
        assert _parse_severity("low") == Severity.LOW
        assert _parse_severity("info") == Severity.INFO
        assert _parse_severity("unknown") == Severity.MEDIUM

    def test_parse_category_mapping(self):
        """Verify all category strings map correctly to enum values."""
        assert _parse_category("replay_attack") == FindingCategory.REPLAY_ATTACK
        assert _parse_category("race_condition") == FindingCategory.RACE_CONDITION
        assert _parse_category("token_abuse") == FindingCategory.TOKEN_ABUSE
        assert _parse_category("auth_session") == FindingCategory.AUTH_SESSION
        assert _parse_category("api_route") == FindingCategory.API_ROUTE
        assert _parse_category("unknown") == FindingCategory.LLM_REVIEW

    def test_parse_single_object_wrapped_in_list(self):
        """Verify a single JSON object (not array) is wrapped and parsed."""
        raw = json.dumps(
            {
                "title": "Single",
                "description": "desc",
                "severity": "low",
                "category": "api_route",
                "line_number": 1,
                "recommendation": "fix",
                "confidence": 0.5,
            }
        )
        findings = _parse_findings_json(raw, "test.py")
        assert len(findings) == 1
        assert findings[0].title == "Single"
