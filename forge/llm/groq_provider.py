"""
Groq LLM provider implementation.

Groq's free tier (as of mid-2026) requires no credit card and gives
access to open-weight models such as Llama 3.3 70B at roughly 30
requests/minute, 6,000 tokens/minute, 14,400 requests/day (limits are
per-organization and change over time -- check https://console.groq.com
for current figures before relying on this for an evaluation run).

Groq exposes an OpenAI-compatible endpoint, so this provider uses the
`openai` Python package pointed at Groq's base URL rather than a
Groq-specific SDK.

Requires `pip install openai` and a `GROQ_API_KEY` environment
variable (get one at https://console.groq.com/keys). Never hardcode
API keys in code or config files committed to the repository.
"""

from __future__ import annotations

import os

from .base import LLMProvider

GROQ_BASE_URL = "https://api.groq.com/openai/v1"


class GroqProvider(LLMProvider):
    def __init__(self, model: str = "llama-3.3-70b-versatile", api_key: str | None = None):
        self.model = model
        self._api_key = api_key or os.environ.get("GROQ_API_KEY")
        if not self._api_key:
            raise RuntimeError(
                "No Groq API key found. Set the GROQ_API_KEY environment "
                "variable (get a free key at https://console.groq.com/keys) "
                "or pass api_key explicitly."
            )
        try:
            import openai
        except ImportError as exc:
            raise RuntimeError(
                "The 'openai' package could not be imported for GroqProvider "
                "(Groq exposes an OpenAI-compatible endpoint). If you've "
                "already run `pip install openai`, this usually means the "
                "install went to a different Python than the one running "
                "this script. Run `python3 -m pip install openai` to "
                "install it for this exact interpreter, and check "
                "`which python3` matches where you installed it (e.g. "
                "inside an active virtualenv). "
                f"Underlying error: {exc!r}"
            ) from exc
        self._client = openai.OpenAI(api_key=self._api_key, base_url=GROQ_BASE_URL)

    def complete(self, system_prompt: str, user_prompt: str, max_tokens: int = 1000) -> str:
        response = self._client.chat.completions.create(
            model=self.model,
            max_tokens=max_tokens,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        )
        return response.choices[0].message.content or ""
