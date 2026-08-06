"""
Knowledge Graph Construction (Phase 3).

Builds a NetworkX MultiDiGraph from the artifacts and relationships
produced by the Phase 2 normalizer. NetworkX is used rather than a
graph database for the initial prototype/evaluation: it requires no
separate service, serializes trivially to JSON for LLM prompting and
for archiving alongside evaluation runs, and is fast enough for
single-image analysis. A Neo4j-backed implementation of the same
interface (`build_graph(ctx) -> GraphHandle`) can be dropped in later
for multi-image / persistent querying without touching Phases 4-6.
"""

from __future__ import annotations

import json
from typing import Any

import networkx as nx

from .models import Artifact, InferredBehavior, Relationship
from .normalizer import NormalizationContext


def build_graph(ctx: NormalizationContext) -> nx.MultiDiGraph:
    """
    Construct a property graph from a populated NormalizationContext.
    Node attributes store the full Artifact; edge attributes store the
    Relationship's type and provenance.
    """
    graph = nx.MultiDiGraph()

    for artifact_id, artifact in ctx.artifacts.items():
        graph.add_node(
            artifact_id,
            kind="artifact",
            artifact_type=artifact.artifact_type.value,
            attributes=artifact.attributes,
            source_plugin=artifact.source_plugin,
            confidence=artifact.confidence,
            timestamp=artifact.timestamp,
        )

    for rel in ctx.relationships:
        graph.add_edge(
            rel.source_id,
            rel.target_id,
            key=rel.edge_type.value,
            kind="relationship",
            edge_type=rel.edge_type.value,
            attributes=rel.attributes,
            source_plugin=rel.source_plugin,
            confidence=rel.confidence,
        )

    return graph


def add_behavior_node(graph: nx.MultiDiGraph, behavior: InferredBehavior) -> None:
    """
    Insert a Phase 4 inferred-behavior node into the graph and connect
    it to its supporting Layer-1 artifacts via `evidence_for` edges, in
    the direction artifact -> behavior (matching Fig. 2 in the paper).
    """
    graph.add_node(
        behavior.id,
        kind="behavior",
        behavior=behavior.behavior.value,
        rule_id=behavior.rule_id,
        confidence=behavior.confidence,
        explanation_path=behavior.explanation_path,
    )
    for artifact_id in behavior.supporting_artifact_ids:
        graph.add_edge(
            artifact_id,
            behavior.id,
            key="evidence_for",
            kind="evidence_for",
            edge_type="evidence_for",
        )


def node_summary(graph: nx.MultiDiGraph, node_id: str) -> dict[str, Any]:
    """A compact, human/LLM-readable summary of a single node."""
    data = dict(graph.nodes[node_id])
    data["id"] = node_id
    return data


def to_json_dict(graph: nx.MultiDiGraph) -> dict[str, Any]:
    """
    Serialize the full graph to a plain dict (nodes + edges), suitable
    for `json.dumps`. This is the ONLY representation that should ever
    be passed to the LLM stage (Phase 5/6) -- never raw Volatility
    output. See llm/explain.py.
    """
    nodes = [node_summary(graph, n) for n in graph.nodes]
    edges = [
        {
            "source": u,
            "target": v,
            **data,
        }
        for u, v, data in graph.edges(data=True)
    ]
    return {"nodes": nodes, "edges": edges}


def subgraph_for_behaviors(
    graph: nx.MultiDiGraph, behavior_ids: list[str]
) -> nx.MultiDiGraph:
    """
    Extract the minimal subgraph needed to explain a set of behavior
    nodes: the behavior nodes themselves, their directly supporting
    Layer-1 artifacts, and the process node(s) those artifacts hang
    off of. This is the subgraph that gets serialized and handed to
    the LLM for a given explanation request, keeping prompts small and
    strictly scoped to verified evidence.
    """
    keep: set[str] = set(behavior_ids)
    for behavior_id in behavior_ids:
        for artifact_id, _, data in graph.in_edges(behavior_id, data=True):
            if data.get("edge_type") == "evidence_for":
                keep.add(artifact_id)
                # also pull in the process(es) connected to this artifact
                for src, _, edata in graph.in_edges(artifact_id, data=True):
                    if edata.get("kind") == "relationship":
                        keep.add(src)
    return graph.subgraph(keep).copy()


def save_graph(graph: nx.MultiDiGraph, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(to_json_dict(graph), f, indent=2, default=str)


def _short_id(node_id: str, length: int = 8) -> str:
    """Truncate a UUID for readable terminal output."""
    return str(node_id)[:length]


def _describe_node(graph: nx.MultiDiGraph, node_id: str) -> str:
    """
    One-line human-readable description of a node's key attributes,
    used in the text table so the printout is scannable without
    cross-referencing the raw dict.
    """
    data = graph.nodes[node_id]
    kind = data.get("kind")

    if kind == "artifact":
        attrs = data.get("attributes", {})
        artifact_type = data.get("artifact_type")
        if artifact_type == "Process":
            return f"pid={attrs.get('pid')} image={attrs.get('image_file_name')}"
        if artifact_type == "RegistryKey":
            return f"{attrs.get('hive')}\\{attrs.get('key_path')}\\{attrs.get('value_name')}"
        if artifact_type == "Socket":
            return f"{attrs.get('foreign_addr')}:{attrs.get('foreign_port')} ({attrs.get('state')})"
        if artifact_type == "MemoryRegion":
            return f"{attrs.get('start')}-{attrs.get('end')} protection={attrs.get('protection')}"
        return str(attrs)

    if kind == "behavior":
        return f"rule={data.get('rule_id')} confidence={data.get('confidence'):.2f}"

    return ""


def format_graph_text(graph: nx.MultiDiGraph) -> str:
    """
    Render the graph as a readable plain-text table: one section for
    nodes, one for edges. Intended for terminal/CLI output during
    development -- see --print-graph in cli.py. A proper visual
    rendering (SVG/HTML export) is planned for the journal version;
    this text form is the fast, dependency-free option in the
    meantime.
    """
    lines: list[str] = []

    lines.append(f"NODES ({graph.number_of_nodes()})")
    lines.append("-" * 110)
    header = f"{'id':<10} {'kind':<10} {'type/behavior':<22} {'confidence':<11} description"
    lines.append(header)
    lines.append("-" * 110)
    for node_id, data in graph.nodes(data=True):
        kind = data.get("kind", "")
        type_or_behavior = data.get("artifact_type") or data.get("behavior") or ""
        confidence = data.get("confidence")
        confidence_str = f"{confidence:.2f}" if isinstance(confidence, (int, float)) else "-"
        description = _describe_node(graph, node_id)
        lines.append(
            f"{_short_id(node_id):<10} {kind:<10} {type_or_behavior:<22} "
            f"{confidence_str:<11} {description}"
        )

    relationship_edges = [
        (s, t, d) for s, t, d in graph.edges(data=True) if d.get("kind") == "relationship"
    ]
    evidence_edges = [
        (s, t, d) for s, t, d in graph.edges(data=True) if d.get("kind") == "evidence_for"
    ]

    lines.append("")
    lines.append(f"RELATIONSHIP EDGES ({len(relationship_edges)}) -- Phase 3, from Volatility")
    lines.append("-" * 110)
    header = f"{'source':<10} {'edge_type':<16} {'target':<10} description"
    lines.append(header)
    lines.append("-" * 110)
    for source, target, data in relationship_edges:
        edge_type = data.get("edge_type", "")
        source_desc = _describe_node(graph, source)
        target_desc = _describe_node(graph, target)
        lines.append(
            f"{_short_id(source):<10} {edge_type:<16} {_short_id(target):<10} "
            f"({source_desc}) -> ({target_desc})"
        )

    if evidence_edges:
        lines.append("")
        lines.append(
            f"EVIDENCE_FOR EDGES ({len(evidence_edges)}) -- Phase 4, artifact -> behavior"
        )
        lines.append("-" * 110)
        lines.append(header)
        lines.append("-" * 110)
        for source, target, data in evidence_edges:
            source_desc = _describe_node(graph, source)
            target_desc = _describe_node(graph, target)
            lines.append(
                f"{_short_id(source):<10} {'evidence_for':<16} {_short_id(target):<10} "
                f"({source_desc}) -> ({target_desc})"
            )

    return "\n".join(lines)


def print_graph(graph: nx.MultiDiGraph) -> None:
    """Print format_graph_text(graph) directly to stdout."""
    print(format_graph_text(graph))


def subject_process_for_behavior(
    graph: nx.MultiDiGraph, behavior: InferredBehavior
) -> dict[str, Any] | None:
    """
    Find the Process node a behavior is "about", for grouping/display
    purposes -- e.g. so --verbose output can be organized by process
    instead of an unordered flat list.

    Every current rule's supporting_artifact_ids is [source, target]
    from a single matched edge (see inference.py). Preferring target
    over source, falling back to source, correctly identifies the
    relevant process for every rule currently in evidence_patterns.yaml
    without per-rule special-casing:
      - WRITES/ALLOCATES/CONNECTS_TO (target is RegistryKey/MemoryRegion/
        Socket, never a Process): falls back to source, the process.
      - SPAWNS as used by process_spawned_from_temp (source=parent,
        target=child, BOTH are processes): picks target, the child --
        which is correct, since the child is the one whose path
        attribute the rule actually matched on, not the parent.

    This heuristic does not yet generalize to compound/multi-node
    rules (not yet implemented) with more than two supporting ids or
    a different natural "subject" role; revisit when those exist.
    """
    for artifact_id in reversed(behavior.supporting_artifact_ids):
        node = graph.nodes.get(artifact_id)
        if node and node.get("kind") == "artifact" and node.get("artifact_type") == "Process":
            return {"id": artifact_id, **node}
    return None


def format_behaviors_by_process(
    graph: nx.MultiDiGraph, behaviors: list[InferredBehavior]
) -> str:
    """
    Render inferred behaviors grouped by their subject process, sorted
    by NUMBER OF BEHAVIORS PER PROCESS descending -- the process with
    the most convergent evidence (the most independent findings
    pointing at it) is shown first, instead of the flat, inference-
    order list. Ties are broken by confirmed (pslist-sourced,
    confidence 1.0) processes before placeholder/unattributed ones,
    then by PID, for stable, readable output.
    """
    groups: dict[str, list[InferredBehavior]] = {}
    process_info: dict[str, dict[str, Any]] = {}

    for behavior in behaviors:
        subject = subject_process_for_behavior(graph, behavior)
        key = subject["id"] if subject else "<no identifiable process>"
        groups.setdefault(key, []).append(behavior)
        if subject:
            process_info[key] = subject

    def sort_key(group_key: str) -> tuple:
        # Primary sort: number of behaviors in this process's group,
        # descending -- the process with the most independent findings
        # (i.e. the most convergent evidence) is shown first, since
        # that's the strongest single signal an investigator would
        # want to see immediately rather than having to scan the
        # whole list to notice it.
        behavior_count = len(groups[group_key])
        info = process_info.get(group_key)
        if info is None:
            return (-behavior_count, 2, 0, "")  # no-subject-process group sorts last among ties
        confidence = info.get("confidence", 0.0)
        pid = info.get("attributes", {}).get("pid")
        tier = 0 if confidence == 1.0 else 1  # confirmed processes before placeholders, as a tiebreak
        return (-behavior_count, tier, pid if isinstance(pid, int) else 0, "")

    lines: list[str] = []
    for group_key in sorted(groups.keys(), key=sort_key):
        info = process_info.get(group_key)
        if info:
            pid = info.get("attributes", {}).get("pid")
            image = info.get("attributes", {}).get("image_file_name")
            lines.append(f"pid={pid} image={image}")
        else:
            lines.append("(no identifiable subject process)")
        for behavior in groups[group_key]:
            lines.append(
                f"    - {behavior.behavior.value:<20} rule={behavior.rule_id:<38} "
                f"confidence={behavior.confidence:.2f}"
            )
    return "\n".join(lines)
