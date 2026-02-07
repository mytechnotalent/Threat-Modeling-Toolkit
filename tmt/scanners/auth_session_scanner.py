"""Scanner for detecting authentication and session management vulnerabilities.

Identifies missing authentication decorators, insecure session configuration,
absent CSRF protection, weak password handling, session fixation risks,
and missing authorization checks on protected endpoints.
"""

from typing import List

from tmt.config import ScannerConfig
from tmt.models import FindingCategory, Severity
from tmt.scanners.base_scanner import BaseScanner, VulnerabilityPattern

# ──────────────────────────────────────────────────────────────────────
# Missing authentication on route handlers
# ──────────────────────────────────────────────────────────────────────

MISSING_AUTH_DECORATOR = VulnerabilityPattern(
    name="Route Handler Missing Authentication",
    trigger_pattern=r"@(app|router|blueprint)\.(get|post|put|patch|delete)\s*\(",
    defense_pattern=r"(login_required|auth_required|authenticated|Depends.*auth|jwt_required|token_required|IsAuthenticated|@require|@protect|@secured)",
    context_window=8,
    description=(
        "An API route handler does not have a visible authentication "
        "decorator or dependency. Unauthenticated access to endpoints "
        "can expose sensitive data or allow unauthorized operations."
    ),
    severity=Severity.HIGH,
    category=FindingCategory.AUTH_SESSION,
    recommendation=(
        "Apply an authentication decorator or dependency to every non-public "
        "endpoint. Use a whitelist approach where routes are authenticated "
        "by default and explicitly marked as public."
    ),
    cwe_id="CWE-306",
    confidence=0.6,
)

# ──────────────────────────────────────────────────────────────────────
# Insecure session configuration
# ──────────────────────────────────────────────────────────────────────

INSECURE_SESSION_CONFIG = VulnerabilityPattern(
    name="Insecure Session Cookie Configuration",
    trigger_pattern=r"(SESSION_COOKIE_SECURE|session.*secure|cookie.*secure)\s*=\s*(False|false|0)",
    defense_pattern=None,
    context_window=5,
    description=(
        "Session cookie is configured without the Secure flag. Cookies "
        "will be transmitted over unencrypted HTTP connections, allowing "
        "session hijacking via network sniffing."
    ),
    severity=Severity.HIGH,
    category=FindingCategory.AUTH_SESSION,
    recommendation=(
        "Set SESSION_COOKIE_SECURE=True and SESSION_COOKIE_HTTPONLY=True. "
        "Also set SESSION_COOKIE_SAMESITE='Lax' or 'Strict' to prevent "
        "CSRF attacks via cookie inclusion."
    ),
    cwe_id="CWE-614",
    confidence=0.95,
)

# ──────────────────────────────────────────────────────────────────────
# Missing CSRF protection
# ──────────────────────────────────────────────────────────────────────

MISSING_CSRF = VulnerabilityPattern(
    name="Missing CSRF Protection on State-Changing Endpoint",
    trigger_pattern=r"@(app|router|blueprint)\.(post|put|patch|delete)\s*\(",
    defense_pattern=r"(csrf|CSRFProtect|CsrfViewMiddleware|csurf|_token|xsrf|anti_forgery|SameSite|Bearer)",
    context_window=20,
    description=(
        "State-changing endpoint lacks visible CSRF protection. Without CSRF "
        "tokens or SameSite cookie policy, an attacker can craft malicious "
        "pages that trigger authenticated actions on behalf of users."
    ),
    severity=Severity.MEDIUM,
    category=FindingCategory.AUTH_SESSION,
    recommendation=(
        "For cookie-based auth: implement CSRF tokens on all state-changing "
        "endpoints. For token-based auth (Bearer tokens): ensure tokens are "
        "not stored in cookies. Set SameSite=Lax on session cookies."
    ),
    cwe_id="CWE-352",
    confidence=0.5,
)

# ──────────────────────────────────────────────────────────────────────
# Weak password hashing
# ──────────────────────────────────────────────────────────────────────

WEAK_PASSWORD_HASH = VulnerabilityPattern(
    name="Weak Password Hashing Algorithm",
    trigger_pattern=r"(hashlib\.(md5|sha1|sha256)\s*\(|MD5|SHA1|createHash\s*\(\s*['\"](?:md5|sha1)['\"])",
    defense_pattern=r"(bcrypt|argon2|scrypt|pbkdf2|passlib|password_hash|hash_password)",
    context_window=10,
    description=(
        "Password hashing uses a fast, non-salted algorithm like MD5 or SHA1. "
        "These can be reversed with rainbow tables or brute-forced at billions "
        "of attempts per second on modern GPUs."
    ),
    severity=Severity.CRITICAL,
    category=FindingCategory.AUTH_SESSION,
    recommendation=(
        "Use bcrypt, argon2id, or scrypt for password hashing. These algorithms "
        "include salting and configurable work factors that resist brute-force. "
        "Migrate existing hashes on next user login."
    ),
    cwe_id="CWE-916",
    confidence=0.85,
)

# ──────────────────────────────────────────────────────────────────────
# Session fixation risk
# ──────────────────────────────────────────────────────────────────────

SESSION_FIXATION = VulnerabilityPattern(
    name="Session Not Regenerated After Authentication",
    trigger_pattern=r"(def\s+login|def\s+authenticate|def\s+sign_in|async\s+def\s+login)\s*\(",
    defense_pattern=r"(session\.regenerate|cycle_key|rotate.*session|new_session|session\.clear|flush.*session|create_session)",
    context_window=15,
    description=(
        "Login handler does not regenerate the session ID after successful "
        "authentication. An attacker who sets a session cookie before login "
        "retains access to the authenticated session."
    ),
    severity=Severity.HIGH,
    category=FindingCategory.AUTH_SESSION,
    recommendation=(
        "Regenerate the session ID immediately after successful authentication. "
        "In Django use request.session.cycle_key(), in Flask use "
        "session.regenerate(), in Express use req.session.regenerate()."
    ),
    cwe_id="CWE-384",
    confidence=0.7,
)

# ──────────────────────────────────────────────────────────────────────
# Missing authorization (IDOR risk)
# ──────────────────────────────────────────────────────────────────────

MISSING_AUTHORIZATION_CHECK = VulnerabilityPattern(
    name="Object Access Without Authorization Check",
    trigger_pattern=r"\.(get|filter|find_one|findById|findOne)\s*\(\s*(request\.(args|params|query|json|form|data)|req\.(params|query|body))",
    defense_pattern=r"(owner|user_id.*current|current_user|request\.user|belongs_to|authorize|permission|can\s*\(|has_perm)",
    context_window=10,
    description=(
        "Database query uses user-supplied ID without checking ownership or "
        "permissions. An attacker can modify the ID parameter to access "
        "other users' data (Insecure Direct Object Reference)."
    ),
    severity=Severity.CRITICAL,
    category=FindingCategory.AUTH_SESSION,
    recommendation=(
        "Always filter queries by the authenticated user's ID or check "
        "object ownership before returning data. Use a policy layer or "
        "scope queries: Model.objects.filter(user=request.user, id=obj_id)."
    ),
    cwe_id="CWE-639",
    confidence=0.75,
)


class AuthSessionScanner(BaseScanner):
    """Scanner specialized in detecting authentication and session vulnerabilities.

    Detects missing authentication, insecure session configuration,
    CSRF gaps, weak password hashing, session fixation, and IDOR
    risks across Python and JavaScript codebases.
    """

    PATTERNS: List[VulnerabilityPattern] = [
        MISSING_AUTH_DECORATOR,
        INSECURE_SESSION_CONFIG,
        MISSING_CSRF,
        WEAK_PASSWORD_HASH,
        SESSION_FIXATION,
        MISSING_AUTHORIZATION_CHECK,
    ]

    def __init__(
        self, config: ScannerConfig, file_extensions: List[str], exclude_dirs: List[str]
    ):
        """Initialize the authentication and session scanner.

        Args:
            config: Scanner configuration controlling behavior.
            file_extensions: File extensions to include in scanning.
            exclude_dirs: Directory names to skip during traversal.
        """
        super().__init__(config, file_extensions, exclude_dirs)
