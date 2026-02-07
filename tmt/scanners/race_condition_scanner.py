"""Scanner for detecting race condition vulnerabilities in application code.

Identifies non-atomic read-modify-write sequences, time-of-check to
time-of-use (TOCTOU) patterns, concurrent resource access without locking,
and unprotected shared state modifications that enable race conditions.
"""

from typing import List

from tmt.config import ScannerConfig
from tmt.models import FindingCategory, Severity
from tmt.scanners.base_scanner import BaseScanner, VulnerabilityPattern

# ──────────────────────────────────────────────────────────────────────
# Read-modify-write without atomicity
# ──────────────────────────────────────────────────────────────────────

NON_ATOMIC_READ_MODIFY_WRITE = VulnerabilityPattern(
    name="Non-Atomic Read-Modify-Write Sequence",
    trigger_pattern=r"(\.\s*save\s*\(|\.\s*update\s*\(|UPDATE\s+.*SET)",
    defense_pattern=r"(select_for_update|FOR UPDATE|atomic|transaction|lock|mutex|semaphore|compare_and_swap|F\s*\()",
    context_window=10,
    description=(
        "A database record is read and then updated without atomic protection. "
        "Concurrent requests can read stale state and apply conflicting writes, "
        "leading to lost updates (e.g., balance overdraws, inventory oversells)."
    ),
    severity=Severity.HIGH,
    category=FindingCategory.RACE_CONDITION,
    recommendation=(
        "Use SELECT FOR UPDATE, database-level atomic operations (e.g., "
        "Django F() expressions), or application-level distributed locks. "
        "Wrap read-modify-write in a serializable transaction."
    ),
    cwe_id="CWE-362",
    confidence=0.7,
)

# ──────────────────────────────────────────────────────────────────────
# TOCTOU (Time-of-Check to Time-of-Use)
# ──────────────────────────────────────────────────────────────────────

TOCTOU_CHECK_THEN_ACT = VulnerabilityPattern(
    name="TOCTOU Check-Then-Act Pattern",
    trigger_pattern=r"(if\s+.*\.(exists|count|filter|find|get)\s*\(.*\).*:[\s\S]*?\.(create|save|insert|delete|remove)\s*\()",
    defense_pattern=r"(atomic|transaction|lock|unique_together|unique=True|get_or_create|upsert|ON CONFLICT)",
    context_window=12,
    description=(
        "Code checks for existence then acts on the result without atomicity. "
        "Between the check and the action, another request can change the state, "
        "causing phantom reads or duplicate inserts."
    ),
    severity=Severity.HIGH,
    category=FindingCategory.RACE_CONDITION,
    recommendation=(
        "Replace check-then-act with atomic operations like get_or_create, "
        "upsert, or INSERT ON CONFLICT. If not possible, wrap both the check "
        "and action in a serializable transaction with proper locking."
    ),
    cwe_id="CWE-367",
    confidence=0.7,
)

# ──────────────────────────────────────────────────────────────────────
# Concurrent token/coupon redemption
# ──────────────────────────────────────────────────────────────────────

CONCURRENT_REDEMPTION = VulnerabilityPattern(
    name="Unguarded Concurrent Redemption",
    trigger_pattern=r"(redeem|claim|activate|consume|use_coupon|apply_code|accept_invite)\s*\(",
    defense_pattern=r"(atomic|transaction|lock|select_for_update|FOR UPDATE|mutex|semaphore|compare_and_swap)",
    context_window=15,
    description=(
        "A redemption or claim operation is not protected against concurrent "
        "execution. Multiple simultaneous requests can redeem the same token, "
        "coupon, or invite before any single request marks it as consumed."
    ),
    severity=Severity.CRITICAL,
    category=FindingCategory.RACE_CONDITION,
    recommendation=(
        "Use SELECT FOR UPDATE or a distributed lock around the redemption "
        "check and mark-as-used operation. Ensure both steps execute within "
        "a single atomic transaction."
    ),
    cwe_id="CWE-362",
    confidence=0.8,
)

# ──────────────────────────────────────────────────────────────────────
# Shared mutable state without synchronization
# ──────────────────────────────────────────────────────────────────────

UNPROTECTED_SHARED_STATE = VulnerabilityPattern(
    name="Shared Mutable State Without Synchronization",
    trigger_pattern=r"(global\s+\w|threading\.Thread|asyncio\.\w+|celery.*\.delay|\.apply_async)",
    defense_pattern=r"(Lock|RLock|Semaphore|Event|Condition|Queue|atomic|mutex|synchronized)",
    context_window=10,
    description=(
        "Code uses global mutable state or spawns concurrent execution without "
        "visible synchronization primitives. Unsynchronized shared state leads "
        "to data corruption and non-deterministic behavior."
    ),
    severity=Severity.MEDIUM,
    category=FindingCategory.RACE_CONDITION,
    recommendation=(
        "Use threading.Lock, asyncio.Lock, or move shared state to a "
        "thread-safe data structure like queue.Queue. Prefer stateless "
        "request handlers with database-backed state."
    ),
    cwe_id="CWE-362",
    confidence=0.6,
)

# ──────────────────────────────────────────────────────────────────────
# JavaScript concurrent state patterns
# ──────────────────────────────────────────────────────────────────────

JS_ASYNC_RACE = VulnerabilityPattern(
    name="JS Async Race Condition",
    trigger_pattern=r"(await\s+.*find|await\s+.*get)[\s\S]*?(await\s+.*save|await\s+.*update)",
    defense_pattern=r"(transaction|findOneAndUpdate|atomicUpdate|\$inc|\$set.*upsert|lock|mutex|semaphore)",
    context_window=12,
    description=(
        "An async find-then-update pattern without atomicity. In Node.js with "
        "concurrent request handling, this window allows race conditions."
    ),
    severity=Severity.HIGH,
    category=FindingCategory.RACE_CONDITION,
    recommendation=(
        "Use MongoDB findOneAndUpdate, Sequelize transactions, or Prisma "
        "interactive transactions. Avoid separate find-then-save in "
        "concurrent contexts."
    ),
    cwe_id="CWE-362",
    confidence=0.7,
)


class RaceConditionScanner(BaseScanner):
    """Scanner specialized in detecting race condition vulnerabilities.

    Detects non-atomic operations, TOCTOU patterns, unguarded concurrent
    redemptions, unsynchronized shared state, and async race conditions
    across Python and JavaScript codebases.
    """

    PATTERNS: List[VulnerabilityPattern] = [
        NON_ATOMIC_READ_MODIFY_WRITE,
        TOCTOU_CHECK_THEN_ACT,
        CONCURRENT_REDEMPTION,
        UNPROTECTED_SHARED_STATE,
        JS_ASYNC_RACE,
    ]

    def __init__(
        self, config: ScannerConfig, file_extensions: List[str], exclude_dirs: List[str]
    ):
        """Initialize the race condition scanner.

        Args:
            config: Scanner configuration controlling behavior.
            file_extensions: File extensions to include in scanning.
            exclude_dirs: Directory names to skip during traversal.
        """
        super().__init__(config, file_extensions, exclude_dirs)
