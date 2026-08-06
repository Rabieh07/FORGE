"""
Anthropic (Claude) LLM provider implementation.

Requires `pip install anthropic` and an `ANTHROPIC_API_KEY` environment
variable. Never hardcode API keys in code or config files committed to
the repository.
"""

from __future__ import annotations

import os

from .base import LLMProvider


class AnthropicProvider(LLMProvider):
    def __init__(self, model: str = "claude-sonnet-4-6", api_key: str | None = None):
        self.model = model
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not self._api_key:
            raise RuntimeError(
                "No Anthropic API key found. Set the ANTHROPIC_API_KEY "
                "environment variable or pass api_key explicitly."
            )
        try:
            import anthropic
        except ImportError as exc:
            raise RuntimeError(
                "The 'anthropic' package is required for AnthropicProvider. "
                "Install it with `pip install anthropic`."
            ) from exc
        self._client = anthropic.Anthropic(api_key=self._api_key)

    def complete(self, system_prompt: str, user_prompt: str, max_tokens: int = 1000) -> str:
        response = self._client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        return "".join(
            block.text for block in response.content if getattr(block, "type", None) == "text"
        )
