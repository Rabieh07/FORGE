"""
Mock LLM provider for unit tests and offline development. Returns a
deterministic templated explanation rather than calling any real API,
so the explain.py pipeline can be exercised in CI without network
access or an API key.
"""

from __future__ import annotations

from .base import LLMProvider


class MockProvider(LLMProvider):
    def __init__(self, canned_response: str | None = None):
        self.canned_response = canned_response
        self.last_system_prompt: str | None = None
        self.last_user_prompt: str | None = None

    def complete(self, system_prompt: str, user_prompt: str, max_tokens: int = 1000) -> str:
        self.last_system_prompt = system_prompt
        self.last_user_prompt = user_prompt
        if self.canned_response is not None:
            return self.canned_response
        return (
            "[MOCK RESPONSE] Explanation would be generated here from the "
            "supplied graph JSON only. See last_user_prompt for what was sent."
        )
