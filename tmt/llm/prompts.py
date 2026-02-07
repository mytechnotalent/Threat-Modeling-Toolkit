"""Structured prompt templates for LLM-powered security reviews.

Provides battle-tested prompt templates for reviewing API routes,
authentication/session logic, and business logic for replay attacks,
race conditions, and token abuse. Each prompt enforces structured
JSON output to minimize noise and maximize actionable findings.
"""

from typing import Dict

# ──────────────────────────────────────────────────────────────────────────────
# System persona prompt shared across all review types
# ──────────────────────────────────────────────────────────────────────────────

SYSTEM_PERSONA = (
    "You are a senior application security engineer performing a focused "
    "code review. You specialize in finding logic bugs, authentication "
    "bypasses, race conditions, and business logic flaws. You only report "
    "findings you are confident about (>70 percent confidence) with concrete "
    "evidence from the code provided. You never report theoretical "
    "vulnerabilities without specific code references."
)

# ──────────────────────────────────────────────────────────────────────────────
# JSON output schema enforced in all prompts
# ──────────────────────────────────────────────────────────────────────────────

OUTPUT_SCHEMA = """
Respond ONLY with a JSON array of findings. Each finding must follow this exact schema:
{
  "title": "Short descriptive title",
  "description": "Detailed explanation with specific code references",
  "severity": "critical|high|medium|low|info",
  "category": "replay_attack|race_condition|token_abuse|auth_session|api_route",
  "line_number": <approximate line number in the provided code>,
  "recommendation": "Specific actionable fix with code example if possible",
  "confidence": <float between 0.0 and 1.0>,
  "cwe_id": "CWE-XXX"
}

If you find NO issues, return an empty array: []
Do NOT wrap the JSON in markdown code blocks. Return raw JSON only.
"""

# ──────────────────────────────────────────────────────────────────────────────
# API route review prompt
# ──────────────────────────────────────────────────────────────────────────────

API_ROUTE_REVIEW_PROMPT = """Review the following API route code for security vulnerabilities.

FOCUS AREAS (check each one systematically):
1. **Authentication**: Is every non-public endpoint protected with auth middleware/decorators?
2. **Authorization**: Are object-level permissions checked before returning data (IDOR)?
3. **Input Validation**: Is all user input validated with schemas/types before use?
4. **Rate Limiting**: Are sensitive endpoints (login, signup, token generation) rate-limited?
5. **Mass Assignment**: Is raw request data spread into database models without field filtering?
6. **Error Handling**: Are internal details (stack traces, DB errors) leaked in responses?
7. **CORS**: Is Access-Control-Allow-Origin overly permissive (wildcard with credentials)?
8. **SQL/NoSQL Injection**: Are queries parameterized or using ORM safely?

CODE TO REVIEW:
```
{code}
```

{output_schema}
"""

# ──────────────────────────────────────────────────────────────────────────────
# Auth and session logic review prompt
# ──────────────────────────────────────────────────────────────────────────────

AUTH_SESSION_REVIEW_PROMPT = """Review the following authentication and session management code for security vulnerabilities.

FOCUS AREAS (check each one systematically):
1. **Password Storage**: Are passwords hashed with bcrypt/argon2/scrypt (not MD5/SHA1/SHA256)?
2. **Session Fixation**: Is the session ID regenerated after successful login?
3. **Token Handling**: Are JWTs validated properly (signature, expiration, issuer, audience)?
4. **Cookie Security**: Are session cookies set with Secure, HttpOnly, SameSite flags?
5. **Brute Force**: Is there account lockout or progressive delays after failed login attempts?
6. **Privilege Escalation**: Can users modify their own role/permission fields?
7. **Logout**: Does logout actually invalidate the session/token server-side?
8. **MFA Bypass**: Can MFA verification be skipped by manipulating request flow?
9. **Password Reset**: Are reset tokens single-use, time-limited, and securely generated?
10. **OAuth/SSO**: Are redirect URIs validated strictly (no open redirects)?

CODE TO REVIEW:
```
{code}
```

{output_schema}
"""

# ──────────────────────────────────────────────────────────────────────────────
# Logic bug review prompt (replay, race, token abuse)
# ──────────────────────────────────────────────────────────────────────────────

LOGIC_BUG_REVIEW_PROMPT = """Review the following code for logic bugs related to replay attacks, race conditions, and token/invite abuse.

FOCUS AREAS (check each one systematically):
1. **Replay Attack**: Can captured requests be re-submitted? Are there idempotency keys or nonces?
2. **Race Condition - Read/Modify/Write**: Are balance changes, counter increments, or stock decrements atomic?
3. **Race Condition - TOCTOU**: Is there a gap between checking permissions/existence and acting on it?
4. **Race Condition - Double Spend**: Can a token/coupon/credit be redeemed concurrently before being marked as used?
5. **Token Reuse**: Are one-time tokens (reset, verify, invite) invalidated after successful use?
6. **Invite Abuse**: Can invite links be shared and reused by multiple users?
7. **State Machine Violations**: Can operations be performed out of expected order?
8. **Enumeration**: Can sequential/predictable IDs be enumerated to discover resources?

THINK STEP BY STEP about request concurrency and timing. Consider what happens when:
- The same request arrives twice within 1ms
- Two users click the same invite link simultaneously
- A token is used in two concurrent requests before the DB marks it as consumed

CODE TO REVIEW:
```
{code}
```

{output_schema}
"""

# ──────────────────────────────────────────────────────────────────────────────
# Comprehensive single-pass review prompt
# ──────────────────────────────────────────────────────────────────────────────

COMPREHENSIVE_REVIEW_PROMPT = """Perform a comprehensive security review of the following code, covering all threat categories.

THREAT CATEGORIES TO CHECK:

**A. Replay Attacks**
- Missing idempotency keys on mutating endpoints
- Tokens verifiable but not invalidated after use
- No request timestamp/nonce validation

**B. Race Conditions**
- Non-atomic read-modify-write (balance, inventory, counters)
- TOCTOU gaps between check and action
- Concurrent token/coupon/invite redemption without locks
- Shared mutable state without synchronization

**C. Token & Invite Abuse**
- Token generation without rate limiting
- Predictable token generation (weak PRNG, UUID1, timestamp-based)
- Tokens without expiration
- Invite tokens usable multiple times
- Missing token revocation on logout

**D. Auth & Session**
- Missing authentication on endpoints
- Missing authorization/ownership checks (IDOR)
- Weak password hashing
- Session fixation (no regeneration after login)
- Insecure cookie settings

**E. API Security**
- Missing input validation/sanitization
- Verbose error messages leaking internals
- Overly permissive CORS
- Mass assignment via raw request data spreading

CODE TO REVIEW:
```
{code}
```

{output_schema}
"""


class PromptLibrary:
    """Registry of security review prompt templates for LLM-powered analysis.

    Provides access to specialized and comprehensive prompt templates
    with consistent formatting, output schema enforcement, and
    systematic checklist-based review instructions.
    """

    def __init__(self):
        """Initialize the prompt library with all available templates."""
        self.system_persona = SYSTEM_PERSONA
        self.output_schema = OUTPUT_SCHEMA
        self._templates = {
            "api_route": API_ROUTE_REVIEW_PROMPT,
            "auth_session": AUTH_SESSION_REVIEW_PROMPT,
            "logic_bug": LOGIC_BUG_REVIEW_PROMPT,
            "comprehensive": COMPREHENSIVE_REVIEW_PROMPT,
        }

    def get_template_names(self) -> list:
        """Return a list of all available prompt template names.

        Returns:
            List of string template identifiers.
        """
        return list(self._templates.keys())

    def _format_template(self, template: str, code: str) -> str:
        """Inject code and output schema into a prompt template.

        Args:
            template: Raw prompt template string with placeholders.
            code: Source code to embed in the prompt.

        Returns:
            Fully formatted prompt string ready to send to an LLM.
        """
        return template.format(code=code, output_schema=self.output_schema)

    def build_prompt(self, template_name: str, code: str) -> Dict[str, str]:
        """Build a complete system + user prompt pair for LLM submission.

        Args:
            template_name: Name of the template to use from the registry.
            code: Source code to include in the review prompt.

        Returns:
            Dictionary with 'system' and 'user' keys containing prompt text.

        Raises:
            KeyError: If template_name is not found in the registry.
        """
        template = self._templates[template_name]
        user_prompt = self._format_template(template, code)
        return {"system": self.system_persona, "user": user_prompt}

    def build_all_prompts(self, code: str) -> Dict[str, Dict[str, str]]:
        """Build prompt pairs for every template in the library.

        Args:
            code: Source code to include in all review prompts.

        Returns:
            Dictionary mapping template names to system/user prompt pairs.
        """
        return {name: self.build_prompt(name, code) for name in self._templates}
