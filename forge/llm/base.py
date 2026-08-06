"""
LLM provider abstraction.

The evaluation plan (RQ2: hallucination rate) requires comparing this
framework's graph-grounded LLM configuration against a raw-artifact
baseline, and possibly against more than one model. Keeping providers
behind a single interface means both configurations -- and any future
model swap -- share one call site (explain.py) rather than duplicating
prompt/response handling per provider.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class LLMProvider(ABC):
    """Minimal interface every LLM backend must implement."""

    @abstractmethod
    def complete(self, system_prompt: str, user_prompt: str, max_tokens: int = 1000) -> str:
        """Return the model's text completion for the given prompts."""
        raise NotImplementedError
