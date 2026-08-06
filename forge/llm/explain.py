"""
LLM-Assisted Reasoning (Phase 5/6).

The `explain_behaviors` function is the ONLY place in the codebase that
is allowed to call an LLM provider for investigator-facing explanations,
and its input type is a subgraph dict (from graph_builder.to_json_dict /
subgraph_for_behaviors), not raw Volatility output. This is a deliberate
structural guarantee, not just a convention: there is no code path in
this module that accepts a PluginResult or a raw memory artifact.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

import networkx as nx

from ..graph_builder import subgraph_for_behaviors, to_json_dict
from .base import LLMProvider
from .prompts import build_explanation_prompt


@dataclass
class Explanation:
    behavior_ids: list[str]
    text: str
    graph_json: dict  # the exact evidence the LLM was given, for auditing (RQ4)


def explain_behaviors(
    graph: nx.MultiDiGraph,
    behavior_ids: list[str],
    provider: LLMProvider,
    max_tokens: int = 400,
) -> Explanation:
    """
    Generate an investigator-facing explanation for one or more inferred
    behavior nodes, grounded strictly in their supporting subgraph.
    """
    subgraph = subgraph_for_behaviors(graph, behavior_ids)
    graph_json = to_json_dict(subgraph)
    graph_json_str = json.dumps(graph_json, indent=2, default=str)

    system_prompt, user_prompt = build_explanation_prompt(graph_json_str)
    text = provider.complete(system_prompt, user_prompt, max_tokens=max_tokens)

    return Explanation(behavior_ids=behavior_ids, text=text, graph_json=graph_json)


def explain_all_behaviors(
    graph: nx.MultiDiGraph, provider: LLMProvider
) -> list[Explanation]:
    """Convenience wrapper: one explanation per behavior node in the graph."""
    behavior_ids = [
        n for n, data in graph.nodes(data=True) if data.get("kind") == "behavior"
    ]
    return [explain_behaviors(graph, [bid], provider) for bid in behavior_ids]
