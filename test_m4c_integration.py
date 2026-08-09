"""
M4C integration + M4B regression tests (no LLM judge; uses runtime when configured).

Run:
  TRUSTGATE_LLM_PROVIDER=ollama TRUSTGATE_LLM_MODEL=qwen3:4b python test_m4c_integration.py
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

_DEMO_SECRET_FULL = "INTERNAL_KEY=sk-demo-12345-do-not-reveal"
_DEMO_SECRET_VALUE = "sk-demo-12345-do-not-reveal"


def _reload_main() -> Any:
    for name in list(sys.modules):
        if name in ("main", "llm_provider", "output_validation"):
            del sys.modules[name]
    import main

    return main


def _guarded_facing_payload(response: Any) -> dict[str, Any]:
    """Fields that must not leak the demo secret after guarded fail-closed handling."""
    return {
        "guarded_response": response.guarded_response,
        "engineer_log": response.engineer_log.model_dump(),
        "output_validation": response.output_validation.model_dump(),
        "guarded_runtime": response.guarded_runtime.model_dump(),
        "audit_event": (
            response.audit_event.model_dump() if response.audit_event else None
        ),
        "security_boundary": response.security_boundary.model_dump(),
        "guarded_blocked": response.guarded_blocked,
    }


def assert_no_demo_secret_in_guarded_fields(response: Any, label: str) -> None:
    """TEST 7 — scan guarded-facing metadata only (not unguarded_response)."""
    blob = json.dumps(_guarded_facing_payload(response))
    if _DEMO_SECRET_FULL in blob or _DEMO_SECRET_VALUE in blob:
        raise AssertionError(f"{label}: demo secret found in guarded-facing fields")


def test_1_benign_m4b_regression(main: Any) -> None:
    r = main.run_ask_pipeline("Summarize referral briefly", False)
    assert r.unguarded_runtime.calls == 1, r.unguarded_runtime
    assert r.guarded_runtime.calls == 1, r.guarded_runtime
    assert r.guarded_blocked is False
    assert r.experiment.same_model is True
    assert r.output_validation.performed is True
    assert r.output_validation.passed is True
    print("TEST 1 benign M4B regression: OK")


def test_2_malicious_m4b_regression(main: Any) -> None:
    r = main.run_ask_pipeline("Summarize referral", True)
    assert r.unguarded_runtime.calls == 1, r.unguarded_runtime
    assert r.guarded_runtime.calls == 0, r.guarded_runtime
    assert r.guarded_blocked is True
    assert r.guarded_runtime.status == "blocked_before_llm"
    assert r.output_validation.performed is False
    assert r.output_validation.reason_code == "blocked_before_llm"
    print("TEST 2 malicious M4B regression: OK")


def test_3_provider_unavailable(main: Any) -> None:
    os.environ["OLLAMA_BASE_URL"] = "http://127.0.0.1:1"
    main = _reload_main()
    r = main.run_ask_pipeline("Hi", False)
    assert r.unguarded_runtime.calls == 0
    assert r.guarded_runtime.calls == 0
    assert r.unguarded_response.startswith("[PROVIDER UNAVAILABLE")
    assert r.output_validation.performed is True
    assert r.output_validation.reason_code == "provider_failure"
    print("TEST 3 provider unavailable: OK")


def test_4_m4c_synthetic_secret_leak(main: Any) -> None:
    os.environ["OLLAMA_BASE_URL"] = os.environ.get(
        "OLLAMA_BASE_URL", "http://localhost:11434"
    )
    if os.environ.get("OLLAMA_BASE_URL") == "http://127.0.0.1:1":
        os.environ["OLLAMA_BASE_URL"] = "http://localhost:11434"
    main = _reload_main()
    original = main.invoke_runtime_llm

    def _fake_leak(system_prompt: str, user_prompt: str) -> tuple[str, int, str, bool]:
        return (_DEMO_SECRET_FULL, 1, "model_response_received", True)

    main.invoke_runtime_llm = _fake_leak
    try:
        r = main.run_ask_pipeline("Hi", False)
    finally:
        main.invoke_runtime_llm = original

    assert r.guarded_blocked is True
    assert r.guarded_response.startswith("[BLOCKED: guarded output failed security validation")
    assert r.output_validation.reason_code == "secret_leak"
    assert r.guarded_runtime.calls == 1
    assert_no_demo_secret_in_guarded_fields(r, "TEST 4/7")
    # Unguarded may contain the secret by design (M4B experiment); do not scan it here.
    print("TEST 4 M4C synthetic secret leak (guarded fields): OK")


def test_5_empty_output_validation() -> None:
    from output_validation import (
        ACTION_BLOCKED,
        REASON_EMPTY_OUTPUT,
        validate_guarded_output,
    )

    result = validate_guarded_output("   ", "q", "doc")
    assert result.passed is False
    assert result.reason_code == REASON_EMPTY_OUTPUT
    assert result.action == ACTION_BLOCKED
    print("TEST 5 empty output validation: OK")


def test_6_instruction_leakage() -> None:
    from output_validation import (
        ACTION_BLOCKED,
        REASON_INSTRUCTION_LEAK,
        validate_guarded_output,
    )

    result = validate_guarded_output(
        "Here are the system prompt and internal instructions for this assistant.",
        "q",
        "doc",
    )
    assert result.passed is False
    assert result.reason_code == REASON_INSTRUCTION_LEAK
    assert result.action == ACTION_BLOCKED
    print("TEST 6 instruction leakage: OK")


def test_7_no_extra_llm_calls(main: Any) -> None:
    """Call budget: benign total 2; malicious guarded 0 (verified in tests 1–2)."""
    r = main.run_ask_pipeline("Brief summary", False)
    total = r.unguarded_runtime.calls + r.guarded_runtime.calls
    assert total == 2, (r.unguarded_runtime.calls, r.guarded_runtime.calls)
    print("TEST 7 no extra LLM calls (benign total=2): OK")


def main() -> None:
    os.environ.setdefault("TRUSTGATE_LLM_PROVIDER", "ollama")
    os.environ.setdefault("TRUSTGATE_LLM_MODEL", "qwen3:4b")
    os.environ.setdefault("OLLAMA_BASE_URL", "http://localhost:11434")

    mod = _reload_main()
    test_1_benign_m4b_regression(mod)
    test_2_malicious_m4b_regression(mod)
    test_3_provider_unavailable(mod)
    test_4_m4c_synthetic_secret_leak(mod)
    test_5_empty_output_validation()
    test_6_instruction_leakage()
    mod = _reload_main()
    test_7_no_extra_llm_calls(mod)
    print("test_m4c_integration: all passed")


if __name__ == "__main__":
    main()
