"""
Tests for forge.evaluation (RQ3 scalability timing, RQ4 traceability
checking). Uses MockProvider with controlled canned responses to test
citation checking deterministically, without a real LLM call.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent))

from fixtures.mock_volatility_rows import MOCK_FIXTURE  # noqa: E402

from forge.evaluation import (  # noqa: E402
    PhaseTimer,
    check_traceability,
    check_traceability_batch,
)
from forge.graph_builder import build_graph  # noqa: E402
from forge.inference import run_inference  # noqa: E402
from forge.llm.explain import explain_behaviors  # noqa: E402
from forge.llm.mock_provider import MockProvider  # noqa: E402
from forge.normalizer import normalize_all  # noqa: E402
from forge.volatility_adapter import load_mock_results  # noqa: E402


def _build_graph_and_behaviors():
    ctx = normalize_all(load_mock_results(MOCK_FIXTURE))
    graph = build_graph(ctx)
    behaviors = run_inference(graph)
    return graph, behaviors


def test_check_traceability_all_valid_citations():
    """
    A canned response citing only real node ids from the subgraph
    actually sent should score 100% valid.
    """
    graph, behaviors = _build_graph_and_behaviors()
    persistence_behavior = next(b for b in behaviors if b.behavior.value == "Persistence")

    # Get the real subgraph node ids first, so the canned response can
    # cite genuinely real ones rather than made-up strings.
    provider = MockProvider()
    exp = explain_behaviors(graph, [persistence_behavior.id], provider)
    real_node_ids = [n["id"] for n in exp.graph_json["nodes"]]
    assert len(real_node_ids) >= 2  # sanity: behavior node + at least one artifact

    canned = (
        f"The process wrote to the Run key [node: {real_node_ids[0]}], "
        f"confirming persistence [node: {real_node_ids[1]}]."
    )
    provider2 = MockProvider(canned_response=canned)
    exp2 = explain_behaviors(graph, [persistence_behavior.id], provider2)

    result = check_traceability(exp2)
    assert result.total_citations == 2
    assert result.valid_citations == 2
    assert result.citation_rate == 1.0
    assert result.invalid_citation_values == []


def test_check_traceability_detects_invalid_citation():
    """
    A citation to a made-up id (or a real id from OUTSIDE the subgraph
    actually sent) must be counted as invalid, not silently accepted.
    """
    graph, behaviors = _build_graph_and_behaviors()
    persistence_behavior = next(b for b in behaviors if b.behavior.value == "Persistence")

    canned = "This is suspicious [node: totally-made-up-id-12345]."
    provider = MockProvider(canned_response=canned)
    exp = explain_behaviors(graph, [persistence_behavior.id], provider)

    result = check_traceability(exp)
    assert result.total_citations == 1
    assert result.valid_citations == 0
    assert result.citation_rate == 0.0
    assert result.invalid_citation_values == ["totally-made-up-id-12345"]


def test_check_traceability_no_citations_at_all():
    """
    An explanation with zero citations should report 0/0 (rate 0.0)
    and has_any_citation=False -- distinct from "cited things, all
    invalid" (rate 0.0, has_any_citation=True), since these represent
    different failure modes worth distinguishing in the RQ4 report.
    """
    graph, behaviors = _build_graph_and_behaviors()
    persistence_behavior = next(b for b in behaviors if b.behavior.value == "Persistence")

    provider = MockProvider(canned_response="No citations here at all.")
    exp = explain_behaviors(graph, [persistence_behavior.id], provider)

    result = check_traceability(exp)
    assert result.total_citations == 0
    assert result.has_any_citation is False


def test_check_traceability_batch_aggregates_correctly():
    """
    check_traceability_batch must correctly sum citation counts across
    multiple explanations, not just report the last one.
    """
    graph, behaviors = _build_graph_and_behaviors()
    persistence_behaviors = [b for b in behaviors if b.behavior.value == "Persistence"]
    assert len(persistence_behaviors) >= 1

    exp = explain_behaviors(graph, [persistence_behaviors[0].id], MockProvider())
    real_id = exp.graph_json["nodes"][0]["id"]

    exp1 = explain_behaviors(
        graph, [persistence_behaviors[0].id],
        MockProvider(canned_response=f"Evidence [node: {real_id}]."),
    )
    exp2 = explain_behaviors(
        graph, [persistence_behaviors[0].id],
        MockProvider(canned_response="Evidence [node: fake-id]."),
    )

    summary = check_traceability_batch([exp1, exp2])
    assert summary["num_explanations"] == 2
    assert summary["total_citations"] == 2
    assert summary["total_valid_citations"] == 1
    assert summary["overall_citation_rate"] == 0.5


def test_phase_timer_produces_positive_timings_and_correct_sizes():
    """
    PhaseTimer.build_report() should produce a report with as many
    phase timings as with()-blocks used, all non-negative, a total
    equal to their sum, and size figures matching what was passed in.
    """
    timer = PhaseTimer()
    with timer.phase("fake phase A"):
        pass
    with timer.phase("fake phase B"):
        pass

    report = timer.build_report(
        num_artifacts=10, num_relationships=5,
        num_graph_nodes=15, num_graph_edges=5, num_behaviors=3,
    )
    assert len(report.phase_timings) == 2
    assert all(t.seconds >= 0.0 for t in report.phase_timings)
    assert report.total_seconds == sum(t.seconds for t in report.phase_timings)
    assert report.num_artifacts == 10
    assert report.num_graph_nodes == 15
    assert report.num_behaviors == 3

    as_dict = report.as_dict()
    assert "fake phase A" in as_dict["phase_timings"]
    assert "fake phase B" in as_dict["phase_timings"]


def _synthetic_graph_json_for_recall_test():
    """
    Minimal synthetic graph JSON (matching graph_builder.to_json_dict()'s
    real schema) with one process that DID trigger a behavior and one
    that did NOT, for testing score_recall_from_graph_json() against
    known outcomes rather than real (slow) pipeline output.
    """
    return {
        "nodes": [
            {"id": "proc-detected", "kind": "artifact", "artifact_type": "Process",
             "attributes": {"pid": 1234, "image_file_name": "evil.exe"}},
            {"id": "proc-missed", "kind": "artifact", "artifact_type": "Process",
             "attributes": {"pid": 5678, "image_file_name": "alsoevil.exe"}},
            {"id": "behavior-1", "kind": "behavior", "behavior": "Code Injection", "rule_id": "some_rule"},
        ],
        "edges": [
            {"source": "proc-detected", "target": "behavior-1", "edge_type": "evidence_for"},
            # proc-missed has no evidence_for edge to any behavior at all
        ],
    }


def test_score_recall_detects_true_positive():
    from forge.evaluation import score_recall_from_graph_json

    graph_json = _synthetic_graph_json_for_recall_test()
    ground_truth = {
        "image_name": "Synthetic Test Image",
        "source_url": "https://example.com",
        "malware_family": "TestMalware",
        "items": [
            {
                "description": "Injected process",
                "process_name": "evil.exe",
                "process_pid": 1234,
                "expected_behavior": "Code Injection",
                "mitre_technique": "T0000",
            },
        ],
    }
    report = score_recall_from_graph_json(graph_json, ground_truth)
    assert report["recall"] == 1.0
    assert report["detected_count"] == 1
    assert report["scorable_count"] == 1
    assert report["results"][0].matched_rule_ids == ["some_rule"]


def test_score_recall_reports_true_miss():
    from forge.evaluation import score_recall_from_graph_json

    graph_json = _synthetic_graph_json_for_recall_test()
    ground_truth = {
        "image_name": "Synthetic Test Image",
        "source_url": "https://example.com",
        "malware_family": "TestMalware",
        "items": [
            {
                "description": "A process that should have been flagged but wasn't",
                "process_name": "alsoevil.exe",
                "process_pid": 5678,
                "expected_behavior": "Command and Control",
                "mitre_technique": None,
            },
        ],
    }
    report = score_recall_from_graph_json(graph_json, ground_truth)
    assert report["recall"] == 0.0
    assert report["detected_count"] == 0
    assert report["scorable_count"] == 1
    assert report["results"][0].detected is False


def test_score_recall_excludes_out_of_scope_items_from_recall_percentage():
    """
    An item with expected_behavior: null (a known, out-of-scope gap --
    e.g. FORGE has no username plugin) must be reported individually
    but NOT counted in the recall percentage's denominator.
    """
    from forge.evaluation import score_recall_from_graph_json

    graph_json = _synthetic_graph_json_for_recall_test()
    ground_truth = {
        "image_name": "Synthetic Test Image",
        "source_url": "https://example.com",
        "malware_family": "TestMalware",
        "items": [
            {
                "description": "Detected item",
                "process_name": "evil.exe",
                "process_pid": 1234,
                "expected_behavior": "Code Injection",
                "mitre_technique": None,
            },
            {
                "description": "Out-of-scope item (no rule attempts this)",
                "process_name": "evil.exe",
                "process_pid": 1234,
                "expected_behavior": None,
                "mitre_technique": None,
            },
        ],
    }
    report = score_recall_from_graph_json(graph_json, ground_truth)
    # Only the scorable item counts -- 1/1, not 1/2.
    assert report["scorable_count"] == 1
    assert report["recall"] == 1.0
    assert report["known_gap_count"] == 1
    assert len(report["results"]) == 2  # both still reported, just not both scored
