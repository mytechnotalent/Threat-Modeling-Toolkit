"""Scanner for detecting API route security vulnerabilities.

Identifies missing input validation, absent rate limiting, verbose
error exposure, insecure CORS configuration, unprotected admin
endpoints, and mass assignment risks in API route handlers.
"""

from typing import List

from tmt.config import ScannerConfig
from tmt.models import FindingCategory, Severity
from tmt.scanners.base_scanner import BaseScanner, VulnerabilityPattern

# ──────────────────────────────────────────────────────────────────────
# Missing input validation
# ──────────────────────────────────────────────────────────────────────

MISSING_INPUT_VALIDATION = VulnerabilityPattern(
    name="Endpoint Missing Input Validation",
    trigger_pattern=r"(request\.(json|form|data|body|args|params|query)\s*(\[|\.get))",
    defense_pattern=r"(validate|schema|serializer|pydantic|marshmallow|cerberus|joi\.|yup\.|zod\.|express-validator|class-validator)",
    context_window=15,
    description=(
        "Request data is accessed directly without visible schema validation. "
        "Missing input validation can lead to injection attacks, type confusion, "
        "and unexpected application behavior from malformed data."
    ),
    severity=Severity.MEDIUM,
    category=FindingCategory.API_ROUTE,
    recommendation=(
        "Validate all input using a schema library: Pydantic or Marshmallow "
        "for Python, Joi or Zod for JavaScript. Define strict schemas with "
        "type constraints, length limits, and allowed value ranges."
    ),
    cwe_id="CWE-20",
    confidence=0.6,
)

# ──────────────────────────────────────────────────────────────────────
# Missing rate limiting
# ──────────────────────────────────────────────────────────────────────

MISSING_RATE_LIMIT = VulnerabilityPattern(
    name="Endpoint Missing Rate Limiting",
    trigger_pattern=r"@(app|router|blueprint)\.(post|put|patch|delete)\s*\(",
    defense_pattern=r"(rate_limit|throttle|RateLimit|slowapi|ratelimit|limiter|express-rate-limit|bottleneck)",
    context_window=10,
    description=(
        "Mutating endpoint has no rate limiting. Without rate limiting, "
        "attackers can brute-force credentials, exhaust resources, or "
        "abuse business logic at scale."
    ),
    severity=Severity.MEDIUM,
    category=FindingCategory.API_ROUTE,
    recommendation=(
        "Apply rate limiting to all endpoints, with stricter limits on "
        "authentication and resource-creation routes. Use per-user and "
        "per-IP limits with a sliding window algorithm."
    ),
    cwe_id="CWE-770",
    confidence=0.5,
)

# ──────────────────────────────────────────────────────────────────────
# Verbose error exposure
# ──────────────────────────────────────────────────────────────────────

VERBOSE_ERROR_EXPOSURE = VulnerabilityPattern(
    name="Verbose Error Details Exposed in Response",
    trigger_pattern=r"(traceback\.|str\(e\)|str\(err\)|exc_info|stack.*trace|error.*message.*str\(|\.message\s*\})",
    defense_pattern=r"(if\s+.*DEBUG|production|sanitize.*error|generic.*error|log.*error.*return|sentry|logging\.exception)",
    context_window=8,
    description=(
        "Exception details or stack traces may be returned to API clients. "
        "Verbose errors leak implementation details, library versions, file "
        "paths, and database structure to attackers."
    ),
    severity=Severity.MEDIUM,
    category=FindingCategory.API_ROUTE,
    recommendation=(
        "Return generic error messages to clients and log full details "
        "server-side. Use a global error handler that returns sanitized "
        "responses with error codes rather than internal messages."
    ),
    cwe_id="CWE-209",
    confidence=0.7,
)

# ──────────────────────────────────────────────────────────────────────
# Insecure CORS configuration
# ──────────────────────────────────────────────────────────────────────

INSECURE_CORS = VulnerabilityPattern(
    name="Overly Permissive CORS Configuration",
    trigger_pattern=r"""(origins?\s*=\s*['"]\*['"]|Access-Control-Allow-Origin.*\*|allow_origins\s*=\s*\[['"]?\*['"]?\])""",
    defense_pattern=None,
    context_window=5,
    description=(
        "CORS is configured to allow all origins with a wildcard. This "
        "permits any website to make authenticated cross-origin requests "
        "to the API when credentials are included."
    ),
    severity=Severity.HIGH,
    category=FindingCategory.API_ROUTE,
    recommendation=(
        "Specify an explicit allowlist of trusted origins. Never combine "
        "wildcard origins with allow_credentials=True. Use environment-based "
        "configuration to set different origins per deployment."
    ),
    cwe_id="CWE-942",
    confidence=0.9,
)

# ──────────────────────────────────────────────────────────────────────
# Unprotected admin endpoints
# ──────────────────────────────────────────────────────────────────────

UNPROTECTED_ADMIN = VulnerabilityPattern(
    name="Admin Endpoint Without Role Check",
    trigger_pattern=r"""(admin|superuser|staff|management|internal)[/'"]""",
    defense_pattern=r"(is_admin|is_superuser|is_staff|role.*admin|admin_required|@admin|permission_classes|has_role|authorize.*admin)",
    context_window=10,
    description=(
        "An endpoint with an admin-related path does not have visible "
        "role-based authorization checks. Access to admin functionality "
        "without proper role verification is a privilege escalation risk."
    ),
    severity=Severity.CRITICAL,
    category=FindingCategory.API_ROUTE,
    recommendation=(
        "Enforce role-based access control on all admin endpoints. Use "
        "decorators or middleware that verify the user has an admin role "
        "before executing handler logic. Apply defense in depth."
    ),
    cwe_id="CWE-269",
    confidence=0.7,
)

# ──────────────────────────────────────────────────────────────────────
# Mass assignment
# ──────────────────────────────────────────────────────────────────────

MASS_ASSIGNMENT = VulnerabilityPattern(
    name="Potential Mass Assignment Vulnerability",
    trigger_pattern=r"(\*\*request\.(json|data|form|body)|\*\*req\.body|\.update\s*\(\s*request\.(json|data)|\.create\s*\(\s*\*\*)",
    defense_pattern=r"(schema|serializer|allow(ed)?_fields|pick\s*\(|whitelist|only\s*=|exclude\s*=|fields\s*=)",
    context_window=10,
    description=(
        "User input is spread directly into a model create or update call. "
        "An attacker can inject unexpected fields like is_admin=True or "
        "role=superuser to escalate their privileges."
    ),
    severity=Severity.CRITICAL,
    category=FindingCategory.API_ROUTE,
    recommendation=(
        "Never spread raw request data into models. Use a schema or "
        "serializer to explicitly define which fields are accepted. "
        "Reject unknown fields and validate types strictly."
    ),
    cwe_id="CWE-915",
    confidence=0.8,
)


class APIRouteScanner(BaseScanner):
    """Scanner specialized in detecting API route security vulnerabilities.

    Detects missing input validation, absent rate limiting, verbose errors,
    insecure CORS, unprotected admin endpoints, and mass assignment risks
    across Python and JavaScript codebases.
    """

    PATTERNS: List[VulnerabilityPattern] = [
        MISSING_INPUT_VALIDATION,
        MISSING_RATE_LIMIT,
        VERBOSE_ERROR_EXPOSURE,
        INSECURE_CORS,
        UNPROTECTED_ADMIN,
        MASS_ASSIGNMENT,
    ]

    def __init__(
        self, config: ScannerConfig, file_extensions: List[str], exclude_dirs: List[str]
    ):
        """Initialize the API route scanner.

        Args:
            config: Scanner configuration controlling behavior.
            file_extensions: File extensions to include in scanning.
            exclude_dirs: Directory names to skip during traversal.
        """
        super().__init__(config, file_extensions, exclude_dirs)
