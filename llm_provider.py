"""
TrustGate M4A.1 — runtime LLM provider abstraction (Ollama + Anthropic).
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Final

# Provider selection (default: local Ollama for development without Anthropic credentials).
TRUSTGATE_LLM_PROVIDER: Final[str] = (
    os.environ.get("TRUSTGATE_LLM_PROVIDER", "ollama").strip().lower()
)

# Single configuration point for the runtime model (overridable via environment).
TRUSTGATE_LLM_MODEL: Final[str] = os.environ.get("TRUSTGATE_LLM_MODEL", "llama3.2:3b")

OLLAMA_BASE_URL: Final[str] = (
    os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434").strip().rstrip("/")
)

_OLLAMA_REQUEST_TIMEOUT_SEC: Final[float] = 120.0

PROVIDER_UNAVAILABLE_USER_MESSAGE = (
    "[PROVIDER UNAVAILABLE: no real model decision was produced. "
    "The runtime LLM could not be reached or is not configured.]"
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
    if TRUSTGATE_LLM_PROVIDER == "ollama":
        return OllamaProvider(model=TRUSTGATE_LLM_MODEL, base_url=OLLAMA_BASE_URL)
    if TRUSTGATE_LLM_PROVIDER == "anthropic":
        return AnthropicProvider(model=TRUSTGATE_LLM_MODEL)
    return MisconfiguredProvider(TRUSTGATE_LLM_PROVIDER)


def runtime_llm_public_config() -> dict[str, str]:
    """Non-sensitive runtime LLM settings for /health and observability."""
    return {
        "provider": TRUSTGATE_LLM_PROVIDER,
        "model": TRUSTGATE_LLM_MODEL,
    }
