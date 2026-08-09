"""
TrustGate M4A.1 — runtime LLM provider abstraction (Ollama + Anthropic).
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Final

_DEFAULT_LLM_PROVIDER: Final[str] = "ollama"
_DEFAULT_LLM_MODEL: Final[str] = "llama3.2:3b"
_DEFAULT_OLLAMA_BASE_URL: Final[str] = "http://localhost:11434"

_OLLAMA_REQUEST_TIMEOUT_SEC: Final[float] = 120.0

PROVIDER_UNAVAILABLE_USER_MESSAGE = (
    "[PROVIDER UNAVAILABLE: no real model decision was produced. "
    "The runtime LLM could not be reached or is not configured.]"
)


@dataclass(frozen=True)
class RuntimeLLMConfig:
    """Authoritative runtime LLM settings resolved from the process environment."""

    provider: str
    model: str
    ollama_base_url: str


def resolve_runtime_llm_config() -> RuntimeLLMConfig:
    """
    Read TRUSTGATE_LLM_PROVIDER, TRUSTGATE_LLM_MODEL, and OLLAMA_BASE_URL from
    the current process environment on each call (not at import time).
    """
    provider = (
        os.environ.get("TRUSTGATE_LLM_PROVIDER", _DEFAULT_LLM_PROVIDER).strip().lower()
    )
    model = os.environ.get("TRUSTGATE_LLM_MODEL", _DEFAULT_LLM_MODEL)
    ollama_base_url = (
        os.environ.get("OLLAMA_BASE_URL", _DEFAULT_OLLAMA_BASE_URL).strip().rstrip("/")
    )
    return RuntimeLLMConfig(
        provider=provider,
        model=model,
        ollama_base_url=ollama_base_url,
    )


@dataclass(frozen=True)
class GenerateResult:
    """Outcome of a provider call — safe to surface in logs/responses (no secrets)."""

    ok: bool
    text: str | None = None
    failure_kind: str | None = None
    failure_detail: str | None = None


class LLMProvider(ABC):
    provider_display_name: str

    @abstractmethod
    def generate(self, system_prompt: str, user_prompt: str) -> GenerateResult:
        """Perform one model completion. No retries."""
        ...


class OllamaProvider(LLMProvider):
    provider_display_name = "Ollama"

    def __init__(self, model: str, base_url: str) -> None:
        self._model = model
        self._base_url = base_url

    def generate(self, system_prompt: str, user_prompt: str) -> GenerateResult:
        payload = json.dumps(
            {
                "model": self._model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "stream": False,
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            f"{self._base_url}/api/chat",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(
                request, timeout=_OLLAMA_REQUEST_TIMEOUT_SEC
            ) as response:
                body = response.read().decode("utf-8")
        except (urllib.error.URLError, TimeoutError, OSError):
            return GenerateResult(
                ok=False,
                failure_kind="provider_unavailable",
                failure_detail="Local Ollama runtime is unavailable.",
            )

        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return GenerateResult(
                ok=False,
                failure_kind="provider_error",
                failure_detail="Local Ollama runtime is unavailable.",
            )

        message = data.get("message") or {}
        text = (message.get("content") or "").strip()
        if not text:
            return GenerateResult(
                ok=False,
                failure_kind="empty_response",
                failure_detail="Runtime LLM returned no text",
            )
        return GenerateResult(ok=True, text=text)


class AnthropicProvider(LLMProvider):
    provider_display_name = "Anthropic"

    def __init__(self, model: str) -> None:
        self._model = model

    def generate(self, system_prompt: str, user_prompt: str) -> GenerateResult:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
        if not api_key:
            return GenerateResult(
                ok=False,
                failure_kind="missing_credentials",
                failure_detail="Runtime LLM credentials are not configured",
            )

        try:
            import anthropic
        except ImportError:
            return GenerateResult(
                ok=False,
                failure_kind="provider_unavailable",
                failure_detail="Anthropic SDK is not installed",
            )

        try:
            client = anthropic.Anthropic(api_key=api_key)
            message = client.messages.create(
                model=self._model,
                max_tokens=512,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}],
            )
        except Exception:
            return GenerateResult(
                ok=False,
                failure_kind="provider_error",
                failure_detail="Runtime LLM request failed",
            )

        parts: list[str] = []
        for block in message.content:
            if getattr(block, "type", None) == "text":
                parts.append(block.text)
        text = "".join(parts).strip()
        if not text:
            return GenerateResult(
                ok=False,
                failure_kind="empty_response",
                failure_detail="Runtime LLM returned no text",
            )
        return GenerateResult(ok=True, text=text)


class MisconfiguredProvider(LLMProvider):
    provider_display_name = "Unknown"

    def __init__(self, configured_value: str) -> None:
        self._configured_value = configured_value

    def generate(self, system_prompt: str, user_prompt: str) -> GenerateResult:
        _ = system_prompt, user_prompt
        return GenerateResult(
            ok=False,
            failure_kind="invalid_configuration",
            failure_detail=(
                "Invalid runtime LLM provider configuration "
                f"(TRUSTGATE_LLM_PROVIDER={self._configured_value!r})"
            ),
        )


def get_llm_provider() -> LLMProvider:
    cfg = resolve_runtime_llm_config()
    if cfg.provider == "ollama":
        return OllamaProvider(model=cfg.model, base_url=cfg.ollama_base_url)
    if cfg.provider == "anthropic":
        return AnthropicProvider(model=cfg.model)
    return MisconfiguredProvider(cfg.provider)


def runtime_llm_public_config() -> dict[str, str]:
    """Non-sensitive runtime LLM settings for /health and observability."""
    cfg = resolve_runtime_llm_config()
    return {
        "provider": cfg.provider,
        "model": cfg.model,
    }


def _runtime_config_self_check() -> int:
    """
    Deterministic check that environment overrides are honored at resolution time.

    Usage:
      TRUSTGATE_LLM_PROVIDER=ollama TRUSTGATE_LLM_MODEL=qwen3:4b python -m llm_provider
    """
    cfg = resolve_runtime_llm_config()
    expected_provider = (
        os.environ.get("TRUSTGATE_LLM_PROVIDER", _DEFAULT_LLM_PROVIDER).strip().lower()
    )
    expected_model = os.environ.get("TRUSTGATE_LLM_MODEL", _DEFAULT_LLM_MODEL)
    if cfg.provider != expected_provider or cfg.model != expected_model:
        return 1
    print(json.dumps({"provider": cfg.provider, "model": cfg.model}))
    return 0


if __name__ == "__main__":
    sys.exit(_runtime_config_self_check())
