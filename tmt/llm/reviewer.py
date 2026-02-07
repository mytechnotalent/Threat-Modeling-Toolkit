"""LLM-powered security reviewer with multi-provider support.

Integrates with Hugging Face, OpenAI, and Anthropic APIs to perform
deep security reviews of source code using structured prompts. Parses
JSON responses into Finding objects and aggregates results into
LLMReview containers.
"""

import json
import logging
import os
import time
from typing import Dict, List, Optional

from tmt.config import LLMConfig
from tmt.llm.prompts import PromptLibrary
from tmt.models import (
    Finding,
    FindingCategory,
    LLMReview,
    Severity,
)

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Severity and category mapping from LLM string output to enums
# ──────────────────────────────────────────────────────────────────────────────

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

CATEGORY_MAP = {
    "replay_attack": FindingCategory.REPLAY_ATTACK,
    "race_condition": FindingCategory.RACE_CONDITION,
    "token_abuse": FindingCategory.TOKEN_ABUSE,
    "auth_session": FindingCategory.AUTH_SESSION,
    "api_route": FindingCategory.API_ROUTE,
    "llm_review": FindingCategory.LLM_REVIEW,
}


def _call_openai(config: LLMConfig, system: str, user: str) -> Dict:
    """Send a review prompt to the OpenAI API and return the response.

    Args:
        config: LLM configuration with API key and model settings.
        system: System persona message content.
        user: User prompt message content.

    Returns:
        Dictionary with 'content', 'prompt_tokens', and 'completion_tokens'.
    """
    from openai import OpenAI

    client_kwargs = {"api_key": config.api_key, "timeout": config.timeout_seconds}
    if config.base_url:
        client_kwargs["base_url"] = config.base_url
    client = OpenAI(**client_kwargs)
    response = client.chat.completions.create(
        model=config.model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        temperature=config.temperature,
        max_tokens=config.max_tokens,
    )
    return {
        "content": response.choices[0].message.content,
        "prompt_tokens": response.usage.prompt_tokens if response.usage else 0,
        "completion_tokens": response.usage.completion_tokens if response.usage else 0,
    }


def _resolve_hf_api_key(config: LLMConfig) -> str:
    """Resolve the Hugging Face API key from config or environment.

    Args:
        config: LLM configuration that may contain an explicit api_key.

    Returns:
        API key string from config, HF_TOKEN env var, or TMT_LLM_API_KEY.
    """
    if config.api_key:
        return config.api_key
    return os.environ.get("HF_TOKEN", os.environ.get("TMT_LLM_API_KEY", ""))


def _call_huggingface(config: LLMConfig, system: str, user: str) -> Dict:
    """Send a review prompt to the Hugging Face Inference API.

    Uses the OpenAI-compatible chat completions endpoint provided by
    Hugging Face's free serverless Inference API. Supports all models
    available on the HF Hub with the Inference API enabled.

    Args:
        config: LLM configuration with model and optional api_key.
        system: System persona message content.
        user: User prompt message content.

    Returns:
        Dictionary with 'content', 'prompt_tokens', and 'completion_tokens'.
    """
    from huggingface_hub import InferenceClient

    api_key = _resolve_hf_api_key(config)
    client = InferenceClient(api_key=api_key or None, timeout=config.timeout_seconds)
    response = client.chat.completions.create(
        model=config.model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        temperature=config.temperature,
        max_tokens=config.max_tokens,
    )
    return {
        "content": response.choices[0].message.content,
        "prompt_tokens": response.usage.prompt_tokens if response.usage else 0,
        "completion_tokens": response.usage.completion_tokens if response.usage else 0,
    }


def _call_anthropic(config: LLMConfig, system: str, user: str) -> Dict:
    """Send a review prompt to the Anthropic API and return the response.

    Args:
        config: LLM configuration with API key and model settings.
        system: System persona message content.
        user: User prompt message content.

    Returns:
        Dictionary with 'content', 'prompt_tokens', and 'completion_tokens'.
    """
    from anthropic import Anthropic

    client = Anthropic(api_key=config.api_key, timeout=config.timeout_seconds)
    response = client.messages.create(
        model=config.model,
        max_tokens=config.max_tokens,
        system=system,
        messages=[{"role": "user", "content": user}],
        temperature=config.temperature,
    )
    return {
        "content": response.content[0].text,
        "prompt_tokens": response.usage.input_tokens,
        "completion_tokens": response.usage.output_tokens,
    }


def _select_provider_call(provider: str):
    """Select the appropriate API call function for the configured provider.

    Args:
        provider: LLM provider name ('huggingface', 'openai', or 'anthropic').

    Returns:
        Callable that sends prompts to the selected provider API.

    Raises:
        ValueError: If the provider is not supported.
    """
    providers = {
        "huggingface": _call_huggingface,
        "openai": _call_openai,
        "anthropic": _call_anthropic,
    }
    if provider not in providers:
        raise ValueError(f"Unsupported LLM provider: {provider}")
    return providers[provider]


def _strip_markdown_fences(text: str) -> str:
    """Remove markdown code fences from LLM response text.

    Args:
        text: Raw LLM response that may contain code fence markers.

    Returns:
        Cleaned text with markdown fences stripped.
    """
    text = text.strip()
    if text.startswith("```json"):
        text = text[7:]
    if text.startswith("```"):
        text = text[3:]
    if text.endswith("```"):
        text = text[:-3]
    return text.strip()


def _parse_severity(raw_severity: str) -> Severity:
    """Convert a raw severity string to a Severity enum value.

    Args:
        raw_severity: Severity string from LLM JSON output.

    Returns:
        Corresponding Severity enum value, defaulting to MEDIUM.
    """
    return SEVERITY_MAP.get(raw_severity.lower(), Severity.MEDIUM)


def _parse_category(raw_category: str) -> FindingCategory:
    """Convert a raw category string to a FindingCategory enum value.

    Args:
        raw_category: Category string from LLM JSON output.

    Returns:
        Corresponding FindingCategory enum value, defaulting to LLM_REVIEW.
    """
    return CATEGORY_MAP.get(raw_category.lower(), FindingCategory.LLM_REVIEW)


def _parse_single_finding(item: dict, file_path: str) -> Finding:
    """Parse a single finding dictionary from LLM output into a Finding object.

    Args:
        item: Dictionary containing finding fields from LLM JSON response.
        file_path: Source file path the finding relates to.

    Returns:
        Populated Finding dataclass instance.
    """
    return Finding(
        title=item.get("title", "LLM Finding"),
        description=item.get("description", ""),
        severity=_parse_severity(item.get("severity", "medium")),
        category=_parse_category(item.get("category", "llm_review")),
        file_path=file_path,
        line_number=item.get("line_number", 0),
        code_snippet="",
        recommendation=item.get("recommendation", ""),
        confidence=float(item.get("confidence", 0.7)),
        cwe_id=item.get("cwe_id"),
    )


def _parse_findings_json(raw_text: str, file_path: str) -> List[Finding]:
    """Parse LLM JSON response text into a list of Finding objects.

    Args:
        raw_text: Raw JSON text from the LLM response.
        file_path: Source file path the findings relate to.

    Returns:
        List of parsed Finding objects, empty list on parse failure.
    """
    try:
        cleaned = _strip_markdown_fences(raw_text)
        items = json.loads(cleaned)
        if not isinstance(items, list):
            items = [items]
        return [_parse_single_finding(item, file_path) for item in items]
    except (json.JSONDecodeError, TypeError, KeyError) as exc:
        logger.warning("Failed to parse LLM response as JSON: %s", exc)
        return []


class LLMReviewer:
    """Orchestrates LLM-powered security reviews of source code files.

    Manages prompt construction, API communication, response parsing,
    and finding assembly for OpenAI and Anthropic providers.
    """

    def __init__(self, config: LLMConfig):
        """Initialize the LLM reviewer with provider configuration.

        Args:
            config: LLM configuration controlling provider, model, and limits.
        """
        self.config = config
        self.prompt_library = PromptLibrary()
        self._call_fn = _select_provider_call(config.provider)

    def _send_review_request(self, system: str, user: str) -> Dict:
        """Send a prompt pair to the configured LLM provider.

        Args:
            system: System persona prompt text.
            user: User review prompt text with code.

        Returns:
            Provider response dictionary with content and token counts.
        """
        logger.info(
            "Sending review request to %s/%s", self.config.provider, self.config.model
        )
        return self._call_fn(self.config, system, user)

    def _build_review_result(
        self, response: Dict, file_path: str, template_name: str
    ) -> LLMReview:
        """Assemble an LLMReview from a provider response and parsed findings.

        Args:
            response: Provider response with content and token usage.
            file_path: Source file that was reviewed.
            template_name: Name of the prompt template used.

        Returns:
            Populated LLMReview with parsed findings.
        """
        findings = _parse_findings_json(response["content"], file_path)
        return LLMReview(
            reviewer_name=f"llm_{template_name}",
            model_used=self.config.model,
            prompt_tokens=response.get("prompt_tokens", 0),
            completion_tokens=response.get("completion_tokens", 0),
            findings=findings,
            raw_response=response["content"],
        )

    def review_file(
        self, file_path: str, code: str, template_name: str = "comprehensive"
    ) -> LLMReview:
        """Review a single source file using a specified prompt template.

        Args:
            file_path: Path to the source file being reviewed.
            code: Full source code content of the file.
            template_name: Prompt template to use for the review.

        Returns:
            LLMReview containing all findings from the review.
        """
        prompts = self.prompt_library.build_prompt(template_name, code)
        response = self._send_review_request(prompts["system"], prompts["user"])
        review = self._build_review_result(response, file_path, template_name)
        logger.info("Review of %s found %d findings", file_path, len(review.findings))
        return review

    def _read_file_safe(self, file_path: str) -> Optional[str]:
        """Read a file with graceful error handling for LLM review.

        Args:
            file_path: Absolute path to the file to read.

        Returns:
            File contents as string, or None on read failure.
        """
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()
        except OSError as exc:
            logger.warning("Could not read %s for LLM review: %s", file_path, exc)
            return None

    def _review_single_file(
        self, file_path: str, template_name: str
    ) -> Optional[LLMReview]:
        """Read and review a single file, handling errors gracefully.

        Args:
            file_path: Path to the source file to review.
            template_name: Prompt template name to use.

        Returns:
            LLMReview if successful, None if file could not be read.
        """
        code = self._read_file_safe(file_path)
        if not code:
            return None
        return self.review_file(file_path, code, template_name)

    def review_files(
        self, file_paths: List[str], template_name: str = "comprehensive"
    ) -> List[LLMReview]:
        """Review multiple files sequentially with the specified template.

        Args:
            file_paths: List of source file paths to review.
            template_name: Prompt template to use for all reviews.

        Returns:
            List of LLMReview objects, one per successfully reviewed file.
        """
        reviews = []
        for file_path in file_paths:
            review = self._review_single_file(file_path, template_name)
            if review:
                reviews.append(review)
        logger.info(
            "Completed LLM review of %d/%d files", len(reviews), len(file_paths)
        )
        return reviews
