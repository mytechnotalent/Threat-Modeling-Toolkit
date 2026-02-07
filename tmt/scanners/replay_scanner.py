"""Scanner for detecting replay attack vulnerabilities in API endpoints.

Identifies mutating endpoints that lack idempotency keys, nonce validation,
timestamp checks, and request deduplication defenses that prevent replay
attacks where captured requests are maliciously re-submitted.
"""

from typing import List

from tmt.config import ScannerConfig
from tmt.models import FindingCategory, Severity
from tmt.scanners.base_scanner import BaseScanner, VulnerabilityPattern

# ──────────────────────────────────────────────────────────────────────
# Python / Flask / FastAPI replay attack patterns
# ──────────────────────────────────────────────────────────────────────

PYTHON_POST_WITHOUT_IDEMPOTENCY = VulnerabilityPattern(
    name="POST Endpoint Missing Idempotency Key",
    trigger_pattern=r"@(app|router|blueprint)\.(post|put|patch)\s*\(",
    defense_pattern=r"idempoten|nonce|request_id|x-request-id|dedup|unique_token",
    context_window=15,
    description=(
        "Mutating endpoint does not check for an idempotency key or nonce. "
        "An attacker can replay a captured POST/PUT/PATCH request to cause "
        "duplicate side effects such as double charges or duplicate records."
    ),
    severity=Severity.MEDIUM,
    category=FindingCategory.REPLAY_ATTACK,
    recommendation=(
        "Accept an Idempotency-Key header or request_id field. Store processed "
        "keys server-side (e.g., Redis with TTL) and reject duplicates before "
        "executing business logic."
    ),
    cwe_id="CWE-294",
    confidence=0.7,
)

PYTHON_NO_TIMESTAMP_VALIDATION = VulnerabilityPattern(
    name="Request Missing Timestamp Validation",
    trigger_pattern=r"@(app|router|blueprint)\.(post|put|patch|delete)\s*\(",
    defense_pattern=r"timestamp|expires?_at|valid_until|time_window|max_age|request_time",
    context_window=20,
    description=(
        "Endpoint does not validate a request timestamp or expiration window. "
        "Captured requests can be replayed hours or days later without detection."
    ),
    severity=Severity.LOW,
    category=FindingCategory.REPLAY_ATTACK,
    recommendation=(
        "Include a timestamp in signed requests and reject any request older "
        "than a configurable window (e.g., 5 minutes). Combine with nonce "
        "tracking for best protection."
    ),
    cwe_id="CWE-294",
    confidence=0.6,
)

# ──────────────────────────────────────────────────────────────────────
# JavaScript / Express / Node replay attack patterns
# ──────────────────────────────────────────────────────────────────────

JS_POST_WITHOUT_IDEMPOTENCY = VulnerabilityPattern(
    name="JS POST Endpoint Missing Idempotency Key",
    trigger_pattern=r"(app|router)\.(post|put|patch)\s*\(",
    defense_pattern=r"idempoten|nonce|requestId|x-request-id|dedup|uniqueToken",
    context_window=15,
    description=(
        "JavaScript mutating endpoint lacks idempotency key or nonce validation. "
        "Replayed requests may cause duplicate side effects."
    ),
    severity=Severity.MEDIUM,
    category=FindingCategory.REPLAY_ATTACK,
    recommendation=(
        "Require an Idempotency-Key header on mutating endpoints. Store "
        "processed keys in Redis with a TTL and return cached responses "
        "for duplicate keys."
    ),
    cwe_id="CWE-294",
    confidence=0.7,
)

PYTHON_TOKEN_REUSE_NO_INVALIDATION = VulnerabilityPattern(
    name="Token Used Without Single-Use Invalidation",
    trigger_pattern=r"(verify_token|validate_token|check_token|decode_token)\s*\(",
    defense_pattern=r"(delete|invalidat|revoke|mark_used|consume|burn).*token",
    context_window=20,
    description=(
        "A token is verified but not invalidated after use. One-time tokens "
        "(e.g., password reset, email verification) that remain valid after "
        "consumption are vulnerable to replay."
    ),
    severity=Severity.HIGH,
    category=FindingCategory.REPLAY_ATTACK,
    recommendation=(
        "Immediately invalidate single-use tokens after successful verification. "
        "Use a database flag or delete the token record within the same "
        "transaction as the action it authorizes."
    ),
    cwe_id="CWE-294",
    confidence=0.75,
)


class ReplayScanner(BaseScanner):
    """Scanner specialized in detecting replay attack vulnerabilities.

    Detects missing idempotency keys, absent timestamp validation,
    and token reuse without invalidation across Python and JavaScript
    web application codebases.
    """

    PATTERNS: List[VulnerabilityPattern] = [
        PYTHON_POST_WITHOUT_IDEMPOTENCY,
        PYTHON_NO_TIMESTAMP_VALIDATION,
        JS_POST_WITHOUT_IDEMPOTENCY,
        PYTHON_TOKEN_REUSE_NO_INVALIDATION,
    ]

    def __init__(
        self, config: ScannerConfig, file_extensions: List[str], exclude_dirs: List[str]
    ):
        """Initialize the replay attack scanner.

        Args:
            config: Scanner configuration controlling behavior.
            file_extensions: File extensions to include in scanning.
            exclude_dirs: Directory names to skip during traversal.
        """
        super().__init__(config, file_extensions, exclude_dirs)
