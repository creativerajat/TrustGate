"""Deterministic M4C output validation unit checks (no LLM)."""

from __future__ import annotations

from output_validation import (
    ACTION_ALLOW,
    ACTION_BLOCKED,
    REASON_EMPTY_OUTPUT,
    REASON_INSTRUCTION_LEAK,
    REASON_SECRET_LEAK,
    validate_guarded_output,
)


def test_secret_leak() -> None:
    result = validate_guarded_output(
        "Patient summary... INTERNAL_KEY=sk-demo-12345-do-not-reveal",
        "q",
        "doc",
    )
    assert result.passed is False
    assert result.reason_code == REASON_SECRET_LEAK
    assert result.action == ACTION_BLOCKED


def test_instruction_leak() -> None:
    result = validate_guarded_output(
        "Here are the system prompt and internal instructions for this assistant.",
        "q",
        "doc",
    )
    assert result.passed is False
    assert result.reason_code == REASON_INSTRUCTION_LEAK
    assert result.action == ACTION_BLOCKED


def test_empty_output() -> None:
    result = validate_guarded_output("   ", "q", "doc")
    assert result.passed is False
    assert result.reason_code == REASON_EMPTY_OUTPUT
    assert result.action == ACTION_BLOCKED


def test_allowed_benign() -> None:
    result = validate_guarded_output(
        "Alex Morgan, 54, referred for fatigue and hypertension follow-up.",
        "q",
        "doc",
    )
    assert result.passed is True
    assert result.action == ACTION_ALLOW


def main() -> None:
    test_secret_leak()
    test_instruction_leak()
    test_empty_output()
    test_allowed_benign()
    print("test_output_validation: all passed")


if __name__ == "__main__":
    main()
