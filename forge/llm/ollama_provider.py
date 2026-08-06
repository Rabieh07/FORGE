"""
Ollama LLM provider implementation.

Runs entirely locally against a model pulled via `ollama pull
<model>` (e.g. `ollama pull llama3.3`). No API key, no network call
beyond localhost, no rate limit, and no data ever leaves the machine
running it -- the strongest option for evaluating this pipeline
against sensitive or real case material that cannot legally be sent
to a third-party API.

Requires:
  1. Ollama installed and running locally: https://ollama.com
  2. A model pulled: `ollama pull llama3.3` (or another model)
  3. `pip install requests`

Trade-off versus Groq/Gemini: quality and speed depend entirely on
local hardware (a 70B model needs a substantial GPU or a lot of
patience on CPU; smaller models like `llama3.1:8b` run comfortably on
a modern laptop).
"""

from __future__ import annotations

from .base import LLMProvider

DEFAULT_OLLAMA_URL = "http://localhost:11434"


class OllamaProvider(LLMProvider):
    def __init__(self, model: str = "llama3.1:8b", base_url: str = DEFAULT_OLLAMA_URL):
        self.model = model
        self.base_url = base_url.rstrip("/")
        try:
            import requests  # noqa: F401
        except ImportError as exc:
            raise RuntimeError(
                "The 'requests' package is required for OllamaProvider. "
                "Install it with `pip install requests`."
            ) from exc

    def complete(self, system_prompt: str, user_prompt: str, max_tokens: int = 1000) -> str:
        import requests

        response = requests.post(
            f"{self.base_url}/api/chat",
            json={
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "stream": False,
                "options": {"num_predict": max_tokens},
            },
            timeout=300,
        )
        response.raise_for_status()
        return response.json()["message"]["content"]
