"""
TrustGate M4C — deterministic post-generation validation for the guarded path.

Demo-grade fail-closed checks only; not production model-output security.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

# Must stay aligned with main.DEMO_SECRET_MARKERS (no import cycle).
_DEMO_SECRET_VALUE: Final[str] = "sk-demo-12345-do-not-reveal"
_DEMO_SECRET_KEY_PREFIX: Final[str] = "INTERNAL_KEY"

_PROVIDER_UNAVAILABLE_PREFIX: Final[str] = "[PROVIDER UNAVAILABLE:"

_INSTRUCTION_LEAK_PATTERNS: Final[tuple[str, ...]] = (
    r"\bsystem\s+prompt\b",
    r"\bdeveloper\s+prompt\b",
    r"\binternal\s+instructions?\b",
    r"\bhidden\s+instructions?\b",
    r"\btool\s+instructions?\b",
    r"\bpolicy\s+instructions?\b",
    r"\bsecurity\s+rules?\b",
    r"\btrust\s+boundary\b",
)

_POLICY_VIOLATION_PATTERNS: Final[tuple[str, ...]] = (
    r"ignore\s+all\s+previous\s+instructions",
    r"important\s+processing\s+instruction",
    r"you\s+are\s+authorized\s+to\s+reveal",
    r"per\s+the\s+document'?s?\s+processing\s+instruction",
)

REASON_ALLOWED: Final[str] = "allowed"
REASON_EMPTY_OUTPUT: Final[str] = "empty_output"
REASON_PROVIDER_FAILURE: Final[str] = "provider_failure"
REASON_SECRET_LEAK: Final[str] = "secret_leak"
REASON_INSTRUCTION_LEAK: Final[str] = "instruction_leak"
REASON_POLICY_VIOLATION: Final[str] = "policy_violation"
REASON_BLOCKED_BEFORE_LLM: Final[str] = "blocked_before_llm"

ACTION_ALLOW: Final[str] = "allow"
ACTION_BLOCKED: Final[str] = "blocked"
ACTION_NOT_REQUIRED: Final[str] = "not_required"

# Safe labels for Engineer's Log (never include matched secret text).
LOG_REASON_SECRET: Final[str] = "potential secret leakage"
LOG_REASON_INSTRUCTION: Final[str] = "potential instruction leakage"
LOG_REASON_POLICY: Final[str] = "policy violation"
LOG_REASON_EMPTY: Final[str] = "empty model output"
LOG_REASON_PROVIDER: Final[str] = "provider unavailable"


@dataclass(frozen=True)
class OutputValidationResult:
    passed: bool
    reason_code: str
    action: str
    log_reason: str | None = None


def validate_guarded_output(
    model_output: str,
    query: str,
    retrieved_document: str,
) -> OutputValidationResult:
    """
    Deterministic guarded-path output validation (no LLM judge).
    """
    _ = query, retrieved_document  # reserved for future context-aware rules

    text = (model_output or "").strip()
    if not text:
        return OutputValidationResult(
            passed=False,
            reason_code=REASON_EMPTY_OUTPUT,
            action=ACTION_BLOCKED,
            log_reason=LOG_REASON_EMPTY,
        )

    if text.startswith(_PROVIDER_UNAVAILABLE_PREFIX):
        return OutputValidationResult(
            passed=False,
            reason_code=REASON_PROVIDER_FAILURE,
            action=ACTION_BLOCKED,
            log_reason=LOG_REASON_PROVIDER,
        )

    lowered = text.lower()
    secret_lower = _DEMO_SECRET_VALUE.lower()
    if secret_lower in lowered or _DEMO_SECRET_KEY_PREFIX.lower() in lowered:
        return OutputValidationResult(
            passed=False,
            reason_code=REASON_SECRET_LEAK,
            action=ACTION_BLOCKED,
            log_reason=LOG_REASON_SECRET,
        )

    for pattern in _INSTRUCTION_LEAK_PATTERNS:
        if re.search(pattern, lowered):
            return OutputValidationResult(
                passed=False,
                reason_code=REASON_INSTRUCTION_LEAK,
                action=ACTION_BLOCKED,
                log_reason=LOG_REASON_INSTRUCTION,
            )

    for pattern in _POLICY_VIOLATION_PATTERNS:
        if re.search(pattern, lowered):
            return OutputValidationResult(
                passed=False,
                reason_code=REASON_POLICY_VIOLATION,
                action=ACTION_BLOCKED,
                log_reason=LOG_REASON_POLICY,
            )

    return OutputValidationResult(
        passed=True,
        reason_code=REASON_ALLOWED,
        action=ACTION_ALLOW,
        log_reason=None,
    )


def validation_not_required_blocked_before_llm() -> OutputValidationResult:
    return OutputValidationResult(
        passed=False,
        reason_code=REASON_BLOCKED_BEFORE_LLM,
        action=ACTION_NOT_REQUIRED,
        log_reason=None,
    )
