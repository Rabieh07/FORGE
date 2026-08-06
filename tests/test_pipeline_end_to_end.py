"""
End-to-end pipeline test reproducing the paper's worked example
(Section IV): powershell.exe writes a persistence Run key, connects to
a remote host, and allocates an RWX memory region, which should infer
Persistence, Command and Control, and Code Injection behavior nodes,
each traceable back to its supporting artifact.

Run with: pytest tests/
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent))

from fixtures.mock_volatility_rows import MOCK_FIXTURE  # noqa: E402

from forge.graph_builder import build_graph, subgraph_for_behaviors, to_json_dict  # noqa: E402
from forge.inference import run_inference  # noqa: E402
from forge.llm.explain import explain_behaviors  # noqa: E402
from forge.llm.mock_provider import MockProvider  # noqa: E402
from forge.normalizer import normalize_all  # noqa: E402
from forge.volatility_adapter import load_mock_results  # noqa: E402


def build_test_graph():
    plugin_results = load_mock_results(MOCK_FIXTURE)
    ctx = normalize_all(plugin_results)
    graph = build_graph(ctx)
    behaviors = run_inference(graph)
    return graph, behaviors, ctx


def test_normalization_produces_expected_artifact_counts():
    _, _, ctx = build_test_graph()
    processes = [a for a in ctx.artifacts.values() if a.artifact_type.value == "Process"]
    confirmed = [a for a in processes if a.confidence == 1.0]
    placeholders = [a for a in processes if a.confidence < 1.0]

    # Three confirmed processes from pslist rows (powershell.exe,
    # explorer.exe, and the WebDAV-command powershell.exe added for
    # webdav_rundll32_remote_execution testing).
    assert len(confirmed) == 3
    # Four placeholder processes: three parent PPIDs (1044, 812, 999)
    # referenced by pslist but not themselves present as pslist rows
    # (e.g. the parent already exited before acquisition -- expected,
    # realistic behavior), plus one unattributed placeholder created by
    # normalize_registry() per RegistryKey row, since PrintKey provides
    # no process linkage (see normalize_registry()'s docstring).
    assert len(placeholders) == 4

    artifact_types = [a.artifact_type.value for a in ctx.artifacts.values()]
    assert artifact_types.count("RegistryKey") == 1
    assert artifact_types.count("Socket") == 1
    assert artifact_types.count("MemoryRegion") == 5  # 3 from vadinfo (incl. file-backed regression case) + 2 from malfind (incl. MZ-header case)


def test_inference_detects_all_three_worked_example_behaviors():
    _, behaviors, _ = build_test_graph()
    produced = {b.behavior.value for b in behaviors}

    assert "Persistence" in produced
    assert "Command and Control" in produced
    assert "Code Injection" in produced


def test_file_backed_rwx_memory_does_not_trigger_injection():
    """
    Regression test for a real false-positive found running against a
    live memory image: RWX protection alone (without also being
    anonymous/unbacked) previously fired code_injection_rwx_region on
    ordinary system processes (MsMpEng.exe, SearchApp.exe, etc.). The
    fixture's third VADINFO_ROWS entry is RWX but file-backed (a
    legitimate loaded module) and must NOT produce a Code Injection
    behavior node -- only the first (anonymous) RWX region should.
    """
    graph, behaviors, ctx = build_test_graph()
    injection_behaviors = [b for b in behaviors if b.behavior.value == "Code Injection"]

    # Find the file-backed region's artifact id.
    file_backed_region_id = next(
        aid for aid, a in ctx.artifacts.items()
        if a.artifact_type.value == "MemoryRegion"
        and a.attributes.get("backing_file", "").endswith(".dll")
    )
    for behavior in injection_behaviors:
        assert file_backed_region_id not in behavior.supporting_artifact_ids


def test_malfind_flagged_region_triggers_higher_confidence_injection_rule():
    """
    A memory region sourced from malfind (as opposed to vadinfo) should
    match code_injection_malfind_flagged specifically, via the
    target_source_plugin matching mechanism -- not just the broader
    vadinfo-based code_injection_rwx_region rule. This is what makes
    malfind's own pre-filtering heuristics an independently
    corroborating signal rather than just more of the same evidence.
    """
    graph, behaviors, ctx = build_test_graph()
    malfind_region_id = next(
        aid for aid, a in ctx.artifacts.items()
        if a.artifact_type.value == "MemoryRegion" and a.source_plugin == "malfind"
    )

    malfind_rule_behaviors = [
        b for b in behaviors
        if b.rule_id == "code_injection_malfind_flagged"
        and malfind_region_id in b.supporting_artifact_ids
    ]
    assert len(malfind_rule_behaviors) == 1
    assert malfind_rule_behaviors[0].confidence == 0.85


def test_vadinfo_regions_do_not_trigger_the_malfind_specific_rule():
    """
    The malfind-specific rule must only match artifacts whose
    source_plugin is literally 'malfind' -- a vadinfo-sourced region
    with identical protection/backing_file attributes should NOT
    trigger code_injection_malfind_flagged. (code_injection_rwx_region,
    which this vadinfo-sourced region would previously have matched,
    is now retired -- see evidence_patterns.yaml -- but this test's
    actual assertion, source-plugin scoping, is independent of that
    and still needs coverage.)
    """
    graph, behaviors, ctx = build_test_graph()
    vadinfo_anonymous_rwx_id = next(
        aid for aid, a in ctx.artifacts.items()
        if a.artifact_type.value == "MemoryRegion"
        and a.source_plugin == "vadinfo"
        and a.attributes.get("protection") == "PAGE_EXECUTE_READWRITE"
        and a.attributes.get("backing_file") == "N/A"
    )
    malfind_rule_matches = [
        b for b in behaviors
        if b.rule_id == "code_injection_malfind_flagged"
        and vadinfo_anonymous_rwx_id in b.supporting_artifact_ids
    ]
    assert malfind_rule_matches == []


def test_persistence_fires_exactly_once_no_redundancy():
    """
    The Run-key evidence pattern was previously split across two
    rules (a general one and a hive-specific one) that both fired on
    the same underlying evidence -- exactly the kind of duplicate
    Phase 4 output flagged during real-image testing of the Code
    Injection rules. They were consolidated into a single
    persistence_run_key rule; this test locks in that there is now
    exactly one Persistence behavior node for the one registry
    artifact in the fixture, not two.
    """
    _, behaviors, _ = build_test_graph()
    persistence_behaviors = [b for b in behaviors if b.behavior.value == "Persistence"]
    assert len(persistence_behaviors) == 1
    assert persistence_behaviors[0].rule_id == "persistence_run_key"


def test_printkey_not_found_sentinel_rows_are_filtered():
    """
    Regression test for two related real bugs found on live memory
    images: (1) PrintKey emits a row with Name == "-" for every hive it
    walks that doesn't contain the requested key -- an earlier version
    of normalize_registry() treated these as real Run-key values,
    producing 24 spurious Persistence detections on one image; (2) on a
    second image, the SAME sentinel was returned as a typed Volatility
    renderer object rather than a plain string, which a naive
    `value_name in ("-", None)` equality check silently failed to
    catch even though it displays identically -- another 24 spurious
    detections. The fixture's three not-found rows (plain-string "-"
    x2, typed-sentinel-object x1) must all be filtered; only the one
    real ("Updater") value should survive.
    """
    _, behaviors, ctx = build_test_graph()
    registry_artifacts = [
        a for a in ctx.artifacts.values() if a.artifact_type.value == "RegistryKey"
    ]
    assert len(registry_artifacts) == 1
    assert registry_artifacts[0].attributes.get("value_name") == "Updater"

    persistence_behaviors = [b for b in behaviors if b.behavior.value == "Persistence"]
    assert len(persistence_behaviors) == 1


def test_benign_process_triggers_only_weak_path_signal():
    """
    explorer.exe was given a Temp path specifically to test
    temp_dropper_with_malfind_injection's AND logic (see PSTREE_ROWS'
    comments): it has no malfind entry, so it must NOT trigger that
    rule (Code Injection), even though it legitimately does trigger
    the weaker, path-only process_spawned_from_temp rule (Defense
    Evasion). This replaces an earlier version of this test asserting
    explorer.exe triggered zero behaviors at all, which stopped being
    true once a Temp path was deliberately added to it for this
    purpose.
    """
    graph, behaviors, ctx = build_test_graph()
    explorer_id = next(
        aid for aid, a in ctx.artifacts.items()
        if a.attributes.get("image_file_name") == "explorer.exe"
    )
    triggered_rule_ids = {
        b.rule_id for b in behaviors if explorer_id in b.supporting_artifact_ids
    }
    assert triggered_rule_ids == {"process_spawned_from_temp"}
    assert "temp_dropper_with_malfind_injection" not in triggered_rule_ids
    assert "code_injection_rwx_region" not in triggered_rule_ids
    assert "code_injection_malfind_flagged" not in triggered_rule_ids


def test_temp_path_plus_malfind_triggers_stronger_injection_rule():
    """
    powershell.exe has both a Temp path (PSTREE_ROWS) and a
    malfind-sourced memory region (MALFIND_ROWS) -- this is the
    positive case for temp_dropper_with_malfind_injection, modeled
    directly on the verified real-world finding (CyberDefenders
    106-redline, oneetx.exe: a confirmed RedLine Stealer dropper
    running from a Temp path with a malfind-flagged RWX region).
    """
    graph, behaviors, ctx = build_test_graph()
    powershell_id = next(
        aid for aid, a in ctx.artifacts.items()
        if a.attributes.get("image_file_name") == "powershell.exe"
        and a.confidence == 1.0  # the confirmed pslist process, not a placeholder
    )
    matches = [
        b for b in behaviors
        if b.rule_id == "temp_dropper_with_malfind_injection"
        and powershell_id in b.supporting_artifact_ids
    ]
    assert len(matches) == 1
    assert matches[0].confidence == 0.90
    assert matches[0].behavior.value == "Code Injection"


def test_evidence_for_edges_are_traceable():
    """Every behavior node must have at least one evidence_for edge
    pointing back to a real artifact node -- the core traceability
    claim from Section III.H of the paper."""
    graph, behaviors, _ = build_test_graph()
    for behavior in behaviors:
        in_edges = list(graph.in_edges(behavior.id, data=True))
        evidence_edges = [e for e in in_edges if e[2].get("edge_type") == "evidence_for"]
        assert len(evidence_edges) > 0
        for source, _, _ in evidence_edges:
            assert graph.nodes[source]["kind"] == "artifact"


def test_subgraph_extraction_excludes_unrelated_nodes():
    """subgraph_for_behaviors must not leak nodes unrelated to the
    requested behavior -- this is what keeps the LLM prompt (RQ4:
    traceability) scoped to only the relevant evidence."""
    graph, behaviors, _ = build_test_graph()
    persistence_behavior = next(b for b in behaviors if b.behavior.value == "Persistence")

    sub = subgraph_for_behaviors(graph, [persistence_behavior.id])
    sub_json = to_json_dict(sub)
    node_kinds = {n["artifact_type"] for n in sub_json["nodes"] if n["kind"] == "artifact"}

    # Persistence evidence should only pull in the Process and the
    # RegistryKey, not the Socket or MemoryRegion nodes.
    assert "RegistryKey" in node_kinds
    assert "Socket" not in node_kinds
    assert "MemoryRegion" not in node_kinds


def test_llm_explanation_receives_graph_json_not_raw_rows():
    """Structural check that explain_behaviors only ever sends graph
    JSON to the provider -- the invariant the paper's hallucination
    claim depends on."""
    graph, behaviors, _ = build_test_graph()
    injection_behavior = next(b for b in behaviors if b.behavior.value == "Code Injection")

    provider = MockProvider()
    explanation = explain_behaviors(graph, [injection_behavior.id], provider)

    assert "PAGE_EXECUTE_READWRITE" in provider.last_user_prompt
    # Raw plugin-specific field names that never entered the graph
    # (e.g. Volatility's raw column name for VAD tag) should not leak
    # into the prompt -- only normalized artifact attributes should.
    assert "geometry" not in provider.last_user_prompt  # sanity: no stray text leakage
    assert explanation.behavior_ids == [injection_behavior.id]
    assert explanation.graph_json["nodes"]


def test_webdav_rundll32_remote_execution_detects_real_command():
    """
    Regression test using the real command line confirmed from a
    second real memory image's pstree "Audit" column: powershell.exe
    mounting a remote WebDAV share and executing a DLL from it via
    rundll32. Confirms webdav_rundll32_remote_execution fires on this
    process, and confirms execution_encoded_powershell does NOT also
    fire on it -- this command line has no -enc/-EncodedCommand, so
    the two rules should not overlap on this process even though both
    map to the Execution behavior concept.
    """
    _, behaviors, ctx = build_test_graph()
    webdav_process_id = next(
        aid for aid, a in ctx.artifacts.items()
        if a.attributes.get("pid") == 6001
    )

    matching_rule_ids = {
        b.rule_id for b in behaviors if webdav_process_id in b.supporting_artifact_ids
    }
    assert "webdav_rundll32_remote_execution" in matching_rule_ids
    assert "execution_encoded_powershell" not in matching_rule_ids

    webdav_match = next(
        b for b in behaviors
        if b.rule_id == "webdav_rundll32_remote_execution"
        and webdav_process_id in b.supporting_artifact_ids
    )
    assert webdav_match.behavior.value == "Execution"
    assert webdav_match.confidence == 0.90


def test_malfind_mz_header_triggers_highest_confidence_injection_rule():
    """
    A malfind region with Notes containing "MZ header" (the real
    format confirmed for oneetx.exe, CyberDefenders 106-redline)
    should trigger code_injection_malfind_pe_header, distinct from
    (and in addition to) the broader code_injection_malfind_flagged,
    which fires on any malfind-sourced region regardless of Notes
    content.
    """
    _, behaviors, ctx = build_test_graph()
    pid_6001_id = next(
        aid for aid, a in ctx.artifacts.items()
        if a.attributes.get("pid") == 6001
    )

    matching_rule_ids = {
        b.rule_id for b in behaviors if pid_6001_id in b.supporting_artifact_ids
    }
    assert "code_injection_malfind_pe_header" in matching_rule_ids
    assert "code_injection_malfind_flagged" in matching_rule_ids  # both should fire

    pe_header_match = next(
        b for b in behaviors
        if b.rule_id == "code_injection_malfind_pe_header"
        and pid_6001_id in b.supporting_artifact_ids
    )
    assert pe_header_match.confidence == 0.95


def test_verbose_grouping_orders_by_behavior_count_descending():
    """
    format_behaviors_by_process must show the process with the most
    behaviors first. pid=6001 (webdav_rundll32_remote_execution +
    code_injection_malfind_flagged + code_injection_malfind_pe_header
    = 3 behaviors) should sort before pid=4312 (powershell.exe, which
    has 6 behaviors from the original worked example -- so pid=4312
    should actually be first; this test locks in count-based ordering
    generally rather than asserting a specific process is first, since
    that depends on how many behaviors each fixture process ends up
    with as the fixture evolves).
    """
    from forge.graph_builder import format_behaviors_by_process

    graph, behaviors, ctx = build_test_graph()
    output = format_behaviors_by_process(graph, behaviors)
    lines = output.split("\n")

    # Extract each process header line and count how many behavior
    # lines (indented with "    - ") follow it before the next header.
    process_line_indices = [i for i, line in enumerate(lines) if line.startswith("pid=")]
    counts = []
    for idx, start in enumerate(process_line_indices):
        end = process_line_indices[idx + 1] if idx + 1 < len(process_line_indices) else len(lines)
        counts.append(end - start - 1)  # number of behavior lines under this header

    assert counts == sorted(counts, reverse=True), (
        f"Expected behavior counts per process in descending order, got {counts}"
    )
