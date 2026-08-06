"""
Reproduces the paper's Section IV worked example end-to-end:
powershell.exe writes a persistence Run key, connects to a remote
host, and allocates an RWX memory region.

Run with:
    python examples/worked_example.py

Uses MockProvider by default (no API key required). Pass --groq (free,
needs GROQ_API_KEY), --anthropic (paid, needs ANTHROPIC_API_KEY), or
--ollama (free, local, needs Ollama running) for a real LLM call. See
README.md "Setting up an LLM provider" for where to put the API key.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "tests"))

from fixtures.mock_volatility_rows import MOCK_FIXTURE  # noqa: E402

from forge.env import load_env  # noqa: E402
from forge.graph_builder import build_graph, to_json_dict  # noqa: E402
from forge.inference import run_inference  # noqa: E402
from forge.llm.explain import explain_behaviors  # noqa: E402
from forge.normalizer import normalize_all  # noqa: E402
from forge.volatility_adapter import load_mock_results  # noqa: E402

load_env()  # picks up GROQ_API_KEY / ANTHROPIC_API_KEY etc. from .env if present


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--anthropic", action="store_true",
        help="Use a real Anthropic API call instead of the mock provider."
    )
    parser.add_argument(
        "--groq", action="store_true",
        help="Use Groq's free-tier API (requires GROQ_API_KEY)."
    )
    parser.add_argument(
        "--ollama", action="store_true",
        help="Use a local Ollama model (requires Ollama running locally)."
    )
    args = parser.parse_args()

    print("=" * 70)
    print("Phase 1-2: Extraction + Normalization (mock Volatility rows)")
    print("=" * 70)
    plugin_results = load_mock_results(MOCK_FIXTURE)
    ctx = normalize_all(plugin_results)
    print(f"Normalized {len(ctx.artifacts)} artifacts, "
          f"{len(ctx.relationships)} relationships.\n")

    print("=" * 70)
    print("Phase 3: Knowledge Graph Construction")
    print("=" * 70)
    graph = build_graph(ctx)
    print(f"Graph has {graph.number_of_nodes()} nodes, "
          f"{graph.number_of_edges()} edges.\n")

    print("=" * 70)
    print("Phase 4: Behavior Inference (FBO evidence patterns)")
    print("=" * 70)
    behaviors = run_inference(graph)
    for b in behaviors:
        print(f"  - {b.behavior.value:<20} rule={b.rule_id:<35} "
              f"confidence={b.confidence:.2f}")
    print()

    print("=" * 70)
    print("Phase 5/6: LLM-Assisted Reasoning (graph-only input)")
    print("=" * 70)
    if args.anthropic:
        from forge.llm.anthropic_provider import AnthropicProvider
        provider = AnthropicProvider()
    elif args.groq:
        from forge.llm.groq_provider import GroqProvider
        provider = GroqProvider()
    elif args.ollama:
        from forge.llm.ollama_provider import OllamaProvider
        provider = OllamaProvider()
    else:
        from forge.llm.mock_provider import MockProvider
        provider = MockProvider()
        print("(using MockProvider -- pass --anthropic / --groq / --ollama "
              "for a real LLM call)\n")

    # Explain the three behaviors matching the paper's worked example.
    target_rules = {
        "Persistence": "persistence_run_key_hkcu",
        "Command and Control": "c2_encoded_cmdline_and_connection",
        "Code Injection": "code_injection_malfind_flagged",
    }
    ids = [
        b.id for b in behaviors
        if target_rules.get(b.behavior.value) == b.rule_id
    ]
    explanation = explain_behaviors(graph, ids, provider)

    print("Evidence subgraph sent to the LLM:")
    print(json.dumps(explanation.graph_json, indent=2, default=str)[:1500], "...\n")
    print("Generated explanation:")
    print(explanation.text)


if __name__ == "__main__":
    main()
