"""Scanner for detecting token and invite abuse vulnerabilities.

Identifies unbounded token generation, predictable token creation,
missing expiration on tokens, multi-use invite tokens, and absent
rate limiting on token issuance endpoints.
"""

from typing import List

from tmt.config import ScannerConfig
from tmt.models import FindingCategory, Severity
from tmt.scanners.base_scanner import BaseScanner, VulnerabilityPattern

# ──────────────────────────────────────────────────────────────────────
# Token generation without rate limiting
# ──────────────────────────────────────────────────────────────────────

UNBOUNDED_TOKEN_GENERATION = VulnerabilityPattern(
    name="Token Generation Without Rate Limiting",
    trigger_pattern=r"(generate_token|create_token|issue_token|create_invite|generate_invite|send_invite)\s*\(",
    defense_pattern=r"(rate_limit|throttle|cooldown|max_attempts|limit_per|RateLimit|slowapi|ratelimit)",
    context_window=20,
    description=(
        "Token or invite generation endpoint lacks rate limiting. An attacker "
        "can flood the endpoint to generate excessive tokens, exhausting "
        "resources or creating mass invite abuse."
    ),
    severity=Severity.HIGH,
    category=FindingCategory.TOKEN_ABUSE,
    recommendation=(
        "Apply rate limiting per user/IP on token generation endpoints. "
        "Use a sliding window counter (e.g., Redis-based) with reasonable "
        "limits such as 5 invites per hour per user."
    ),
    cwe_id="CWE-799",
    confidence=0.75,
)

# ──────────────────────────────────────────────────────────────────────
# Predictable token generation
# ──────────────────────────────────────────────────────────────────────

PREDICTABLE_TOKEN = VulnerabilityPattern(
    name="Predictable Token Generation",
    trigger_pattern=r"(uuid\.uuid1|random\.random|random\.randint|Math\.random|hashlib\.(md5|sha1)\(.*time|str\(.*id\))",
    defense_pattern=r"(secrets\.|crypto\.random|uuid\.uuid4|os\.urandom|token_hex|token_urlsafe|randomBytes)",
    context_window=8,
    description=(
        "Token generation uses predictable sources like UUID1 (MAC-based), "
        "Python's random module (not CSPRNG), or timestamp-based hashing. "
        "Predictable tokens can be guessed or brute-forced by attackers."
    ),
    severity=Severity.CRITICAL,
    category=FindingCategory.TOKEN_ABUSE,
    recommendation=(
        "Use cryptographically secure random generators: secrets.token_urlsafe() "
        "in Python, crypto.randomBytes() in Node.js, or uuid4 for identifiers. "
        "Never derive tokens from timestamps, sequential IDs, or weak PRNGs."
    ),
    cwe_id="CWE-330",
    confidence=0.85,
)

# ──────────────────────────────────────────────────────────────────────
# Tokens without expiration
# ──────────────────────────────────────────────────────────────────────

TOKEN_NO_EXPIRY = VulnerabilityPattern(
    name="Token Created Without Expiration",
    trigger_pattern=r"(Token\.create|Token\.objects\.create|create_token|generate_token|new\s+Token|InviteToken)\s*\(",
    defense_pattern=r"(expir|ttl|valid_until|max_age|lifetime|duration|exp\s*=|expiresAt|expires_at)",
    context_window=10,
    description=(
        "Tokens are created without an expiration time. Long-lived tokens "
        "increase the window for token theft and abuse, and make revocation "
        "more critical and harder to enforce."
    ),
    severity=Severity.HIGH,
    category=FindingCategory.TOKEN_ABUSE,
    recommendation=(
        "Set a reasonable TTL on all tokens: 15 minutes for password reset, "
        "24-72 hours for invites, 1 hour for session tokens. Store the "
        "expiration and check it on every validation."
    ),
    cwe_id="CWE-613",
    confidence=0.75,
)

# ──────────────────────────────────────────────────────────────────────
# Multi-use invite tokens
# ──────────────────────────────────────────────────────────────────────

MULTI_USE_INVITE = VulnerabilityPattern(
    name="Invite Token Allows Multiple Redemptions",
    trigger_pattern=r"(accept_invite|redeem_invite|use_invite|claim_invite|join_.*invite)\s*\(",
    defense_pattern=r"(is_used|used_at|redeemed|consumed|single_use|max_uses|use_count|delete.*invite|mark.*used)",
    context_window=15,
    description=(
        "Invite acceptance logic does not check or enforce single-use. "
        "An invite link can be shared and used by multiple unauthorized "
        "users to gain access to the system."
    ),
    severity=Severity.HIGH,
    category=FindingCategory.TOKEN_ABUSE,
    recommendation=(
        "Track invite usage with a used_at timestamp or use_count field. "
        "Atomically mark invites as consumed during acceptance. Consider "
        "binding invites to specific email addresses."
    ),
    cwe_id="CWE-841",
    confidence=0.8,
)

# ──────────────────────────────────────────────────────────────────────
# Missing token revocation
# ──────────────────────────────────────────────────────────────────────

NO_TOKEN_REVOCATION = VulnerabilityPattern(
    name="No Token Revocation Mechanism",
    trigger_pattern=r"(def\s+logout|def\s+revoke|def\s+invalidate|signOut|logOut)\s*\(",
    defense_pattern=r"(delete.*token|revoke.*token|blacklist|blocklist|token.*delete|destroy.*session|clear.*token)",
    context_window=15,
    description=(
        "Logout or revocation endpoint does not actually invalidate the "
        "token server-side. The token remains valid and usable even after "
        "the user believes they have logged out."
    ),
    severity=Severity.HIGH,
    category=FindingCategory.TOKEN_ABUSE,
    recommendation=(
        "Maintain a server-side token blocklist or delete the token record "
        "on logout. For JWTs, use short expiration combined with a refresh "
        "token that can be revoked from the database."
    ),
    cwe_id="CWE-613",
    confidence=0.7,
)


class TokenAbuseScanner(BaseScanner):
    """Scanner specialized in detecting token and invite abuse vulnerabilities.

    Detects unbounded generation, predictable tokens, missing expiration,
    multi-use invites, and absent revocation mechanisms across Python
    and JavaScript codebases.
    """

    PATTERNS: List[VulnerabilityPattern] = [
        UNBOUNDED_TOKEN_GENERATION,
        PREDICTABLE_TOKEN,
        TOKEN_NO_EXPIRY,
        MULTI_USE_INVITE,
        NO_TOKEN_REVOCATION,
    ]

    def __init__(
        self, config: ScannerConfig, file_extensions: List[str], exclude_dirs: List[str]
    ):
        """Initialize the token abuse scanner.

        Args:
            config: Scanner configuration controlling behavior.
            file_extensions: File extensions to include in scanning.
            exclude_dirs: Directory names to skip during traversal.
        """
        super().__init__(config, file_extensions, exclude_dirs)
