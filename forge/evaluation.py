"""
Evaluation utilities for RQ3 (Scalability) and RQ4 (Traceability).

These are measurement tools, not a substitute for the full evaluation
plan (RQ1: detection accuracy, RQ2: hallucination rate both require a
labeled corpus and are not implemented here) -- see the paper's
Evaluation Plan and Preliminary Real-World Observations sections for
what these numbers do and do not establish.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Callable

from .llm.explain import Explanation

# ---------------------------------------------------------------------
# RQ4: Traceability
# ---------------------------------------------------------------------

# Matches the citation format specified in llm/prompts.py's
# EXPLANATION_SYSTEM_PROMPT: "[node: <id>]". Node ids are UUIDs
# (hex digits and hyphens); the pattern is intentionally permissive
# about the id's exact shape so a citation that's ALMOST right (e.g.
# truncated, despite the prompt instructing otherwise) is still
# captured and reported as invalid, rather than silently missed by a
# too-strict regex undercounting how often the model doesn't follow
# the instruction.
_NODE_CITATION_PATTERN = re.compile(r"\[node:\s*([a-zA-Z0-9\-]+)\]")


@dataclass
class TraceabilityResult:
    """
    RQ4 measurement for one explanation: what fraction of its inline
    node-id citations resolve to a real node id in the exact subgraph
    JSON that was sent to the LLM (explanation.graph_json) -- i.e. can
    every claim be automatically traced back to verified graph
    evidence, not just plausibly-worded text.
    """
    behavior_ids: list[str]
    total_citations: int
    valid_citations: int
    invalid_citation_values: list[str]
    citation_rate: float  # valid_citations / total_citations; 0.0 if total_citations == 0
    has_any_citation: bool  # distinguishes "0/0, wrote nothing" from "cited things, none valid"


def check_traceability(explanation: Explanation) -> TraceabilityResult:
    """
    Parse an Explanation's text for [node: <id>] citations (per the
    format specified in EXPLANATION_SYSTEM_PROMPT) and check each one
    against the real node ids present in explanation.graph_json -- the
    exact, verified subgraph the LLM was given, not the full graph.
    A citation is valid only if it exactly matches a real id in that
    subgraph; a citation to a real id from a DIFFERENT part of the
    graph the model wasn't shown would still count as invalid here,
    which is the correct behavior for this measurement -- it should
    only be possible to cite what was actually provided.
    """
    real_ids = {n["id"] for n in explanation.graph_json.get("nodes", [])}
    citations = _NODE_CITATION_PATTERN.findall(explanation.text)

    valid = [c for c in citations if c in real_ids]
    invalid = [c for c in citations if c not in real_ids]

    total = len(citations)
    rate = (len(valid) / total) if total > 0 else 0.0

    return TraceabilityResult(
        behavior_ids=explanation.behavior_ids,
        total_citations=total,
        valid_citations=len(valid),
        invalid_citation_values=invalid,
        citation_rate=rate,
        has_any_citation=total > 0,
    )


def check_traceability_batch(explanations: list[Explanation]) -> dict:
    """
    Aggregate check_traceability() across multiple explanations into a
    single summary -- the actual RQ4 headline number ("what proportion
    of LLM-generated statements in the final report can be
    automatically validated against an explicit graph provenance
    path") is computed across a whole run's explanations, not one at a
    time.
    """
    results = [check_traceability(exp) for exp in explanations]
    total_citations = sum(r.total_citations for r in results)
    total_valid = sum(r.valid_citations for r in results)
    explanations_with_zero_citations = sum(1 for r in results if not r.has_any_citation)

    return {
        "per_explanation": results,
        "num_explanations": len(results),
        "explanations_with_zero_citations": explanations_with_zero_citations,
        "total_citations": total_citations,
        "total_valid_citations": total_valid,
        "overall_citation_rate": (total_valid / total_citations) if total_citations > 0 else 0.0,
    }


# ---------------------------------------------------------------------
# RQ3: Scalability
# ---------------------------------------------------------------------

@dataclass
class PhaseTiming:
    phase_name: str
    seconds: float


@dataclass
class ScalabilityReport:
    """
    RQ3 measurement for one pipeline run: wall-clock time per phase,
    plus the graph-size figures that time should be interpreted
    against (a fast run on a tiny graph and a fast run on a huge one
    mean very different things).
    """
    phase_timings: list[PhaseTiming]
    total_seconds: float
    num_artifacts: int
    num_relationships: int
    num_graph_nodes: int
    num_graph_edges: int
    num_behaviors: int

    def as_dict(self) -> dict:
        return {
            "phase_timings": {t.phase_name: t.seconds for t in self.phase_timings},
            "total_seconds": self.total_seconds,
            "num_artifacts": self.num_artifacts,
            "num_relationships": self.num_relationships,
            "num_graph_nodes": self.num_graph_nodes,
            "num_graph_edges": self.num_graph_edges,
            "num_behaviors": self.num_behaviors,
        }


class PhaseTimer:
    """
    Small helper for instrumenting a sequence of named phases with
    wall-clock timing, used by forge.cli's --benchmark flag. Not a
    general-purpose profiler -- deliberately minimal, since RQ3 only
    needs phase-level granularity (extraction / normalization / graph
    construction / inference), not line-level profiling.

    Usage:
        timer = PhaseTimer()
        with timer.phase("Extraction"):
            ... do phase 1 work ...
        with timer.phase("Normalization"):
            ... do phase 2 work ...
        report = timer.build_report(ctx, graph, behaviors)
    """

    def __init__(self) -> None:
        self._timings: list[PhaseTiming] = []

    class _PhaseContext:
        def __init__(self, timer: "PhaseTimer", name: str):
            self._timer = timer
            self._name = name
            self._start: float = 0.0

        def __enter__(self):
            self._start = time.perf_counter()
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            elapsed = time.perf_counter() - self._start
            self._timer._timings.append(PhaseTiming(phase_name=self._name, seconds=elapsed))
            return False

    def phase(self, name: str) -> "PhaseTimer._PhaseContext":
        return PhaseTimer._PhaseContext(self, name)

    def build_report(
        self,
        num_artifacts: int,
        num_relationships: int,
        num_graph_nodes: int,
        num_graph_edges: int,
        num_behaviors: int,
    ) -> ScalabilityReport:
        return ScalabilityReport(
            phase_timings=list(self._timings),
            total_seconds=sum(t.seconds for t in self._timings),
            num_artifacts=num_artifacts,
            num_relationships=num_relationships,
            num_graph_nodes=num_graph_nodes,
            num_graph_edges=num_graph_edges,
            num_behaviors=num_behaviors,
        )


def format_scalability_report(report: ScalabilityReport) -> str:
    """Human-readable rendering of a ScalabilityReport for --verbose/--benchmark output."""
    lines = ["=== RQ3: Scalability ==="]
    for t in report.phase_timings:
        lines.append(f"  {t.phase_name:<30} {t.seconds:.3f}s")
    lines.append(f"  {'TOTAL':<30} {report.total_seconds:.3f}s")
    lines.append("")
    lines.append(f"  Artifacts: {report.num_artifacts}   Relationships: {report.num_relationships}")
    lines.append(f"  Graph nodes: {report.num_graph_nodes}   Graph edges: {report.num_graph_edges}")
    lines.append(f"  Behaviors inferred: {report.num_behaviors}")
    return "\n".join(lines)


def format_traceability_report(summary: dict) -> str:
    """Human-readable rendering of a check_traceability_batch() summary."""
    lines = ["=== RQ4: Traceability ==="]
    lines.append(f"  Explanations generated: {summary['num_explanations']}")
    lines.append(f"  Explanations with zero citations: {summary['explanations_with_zero_citations']}")
    lines.append(f"  Total citations: {summary['total_citations']}")
    lines.append(f"  Valid citations: {summary['total_valid_citations']}")
    lines.append(f"  Overall citation rate: {summary['overall_citation_rate']:.1%}")
    for r in summary["per_explanation"]:
        if r.invalid_citation_values:
            lines.append(
                f"    behavior {r.behavior_ids}: INVALID citations: {r.invalid_citation_values}"
            )
    return "\n".join(lines)


# ---------------------------------------------------------------------
# RQ1: Detection Accuracy (recall only -- see paper's RQ1 methodology
# note for why precision is reported as qualitative discussion instead
# of computed here: a CTF writeup confirms specific findings are real,
# but does not label every other process on the image as benign, so
# there is no independent source for precision's denominator).
# ---------------------------------------------------------------------

@dataclass
class GroundTruthResult:
    description: str
    process_name: str
    process_pid: int | None
    expected_behavior: str | None
    mitre_technique: str | None
    detected: bool
    scorable: bool  # False for known, out-of-scope gaps (expected_behavior is None)
    matched_rule_ids: list[str] = field(default_factory=list)
    notes: str = ""


def score_recall_from_graph_json(graph_json: dict, ground_truth: dict) -> dict:
    """
    RQ1 (recall only): for each item in a ground-truth file (see
    evaluation/ground_truth/*.yaml), check whether FORGE's actual
    output (a saved graph_output.json, loaded by the caller) contains
    an evidence_for edge from the named process to a behavior node
    matching expected_behavior.

    Operates on the plain JSON dict (graph_builder.to_json_dict()'s
    output format), not a live graph object, so it can be run against
    an already-saved graph_output.json without re-running the slow
    Volatility extraction phase.

    Items with expected_behavior == None are known, out-of-scope gaps
    (no current rule attempts to detect them at all -- e.g. FORGE has
    no username/session plugin wired up) and are excluded from the
    recall percentage, since "recall" over things nothing was ever
    built to detect isn't a meaningful measurement of the rules that
    DO exist. They are still reported individually for transparency.
    """
    nodes_by_id = {n["id"]: n for n in graph_json["nodes"]}

    results: list[GroundTruthResult] = []
    for item in ground_truth["items"]:
        expected_behavior = item.get("expected_behavior")
        scorable = expected_behavior is not None

        matching_process_ids = [
            n["id"] for n in graph_json["nodes"]
            if n.get("artifact_type") == "Process"
            and n.get("attributes", {}).get("image_file_name") == item["process_name"]
            and (item.get("process_pid") is None or n.get("attributes", {}).get("pid") == item["process_pid"])
        ]

        detected = False
        matched_rule_ids: list[str] = []
        if scorable:
            for pid_node_id in matching_process_ids:
                for e in graph_json["edges"]:
                    if e.get("edge_type") != "evidence_for" or e.get("source") != pid_node_id:
                        continue
                    behavior_node = nodes_by_id.get(e["target"], {})
                    if behavior_node.get("behavior") == expected_behavior:
                        detected = True
                        matched_rule_ids.append(behavior_node.get("rule_id"))

        results.append(GroundTruthResult(
            description=item["description"],
            process_name=item["process_name"],
            process_pid=item.get("process_pid"),
            expected_behavior=expected_behavior,
            mitre_technique=item.get("mitre_technique"),
            detected=detected,
            scorable=scorable,
            matched_rule_ids=matched_rule_ids,
            notes=item.get("notes", "").strip(),
        ))

    scorable_results = [r for r in results if r.scorable]
    detected_count = sum(1 for r in scorable_results if r.detected)
    recall = (detected_count / len(scorable_results)) if scorable_results else 0.0

    return {
        "image_name": ground_truth.get("image_name"),
        "source_url": ground_truth.get("source_url"),
        "malware_family": ground_truth.get("malware_family"),
        "results": results,
        "scorable_count": len(scorable_results),
        "detected_count": detected_count,
        "recall": recall,
        "known_gap_count": len(results) - len(scorable_results),
    }


def format_recall_report(report: dict) -> str:
    """Human-readable rendering of a score_recall_from_graph_json() result."""
    lines = [f"=== RQ1: Detection Recall -- {report['image_name']} ==="]
    lines.append(f"  Malware family: {report['malware_family']}")
    lines.append(f"  Source: {report['source_url']}")
    lines.append("")
    for r in report["results"]:
        if r.scorable:
            status = "DETECTED" if r.detected else "MISSED"
            technique = f" ({r.mitre_technique})" if r.mitre_technique else ""
            lines.append(f"  [{status}] {r.description}{technique}")
            if r.detected:
                lines.append(f"           via rule(s): {', '.join(r.matched_rule_ids)}")
        else:
            lines.append(f"  [OUT OF SCOPE] {r.description} -- no current rule attempts this")
    lines.append("")
    lines.append(
        f"  Recall: {report['detected_count']}/{report['scorable_count']} "
        f"({report['recall']:.1%}) -- {report['known_gap_count']} additional known "
        f"out-of-scope item(s) not counted."
    )
    return "\n".join(lines)
