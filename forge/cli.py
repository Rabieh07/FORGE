"""
End-to-end pipeline runner (Phases 1-6).

Usage:
    # Against a real memory image (requires volatility3 installed):
    python -m forge.cli --image /path/to/memory.raw --out report.json

    # Against the mock fixture (no volatility3 / memory image required),
    # useful for demos, tests, and reproducing the paper's worked example:
    python -m forge.cli --mock --out report.json

    # Narrate progress through each of the six phases as it runs:
    python -m forge.cli --mock --verbose --out report.json

    # Also call an LLM to generate investigator-facing explanations for
    # every inferred behavior (Phase 5/6). Off by default -- no LLM call,
    # no API key needed, no cost -- unless --explain is passed explicitly:
    python -m forge.cli --mock --explain --provider groq --out report.json

    # By default, only the 6 Volatility plugins whose output is actually
    # normalized are run (pslist, pstree, cmdline, netscan,
    # registry_run_keys, malfind) -- see NORMALIZED_PLUGINS in
    # volatility_adapter.py for the reasoning behind this specific set.
    # Override with --plugins for a specific subset, or --all-plugins
    # to run everything in DEFAULT_PLUGINS:
    python -m forge.cli --image memdump.mem --plugins pslist,netscan,vadinfo --out report.json
    python -m forge.cli --image memdump.mem --all-plugins --out report.json

    # RQ3 (Scalability): report wall-clock time per phase alongside
    # graph size, appended to stdout and to the output JSON:
    python -m forge.cli --image memdump.mem --benchmark --out report.json

    # RQ4 (Traceability): after --explain, check what fraction of the
    # LLM's inline [node: <id>] citations resolve to real ids in the
    # exact subgraph it was given (requires --explain):
    python -m forge.cli --mock --explain --provider groq --measure-traceability --out report.json
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

from .env import load_env
from .evaluation import (
    PhaseTimer,
    check_traceability_batch,
    format_scalability_report,
    format_traceability_report,
)
from .graph_builder import build_graph, format_behaviors_by_process, print_graph, to_json_dict
from .inference import run_inference
from .llm.explain import explain_all_behaviors
from .models import InferredBehavior
from .normalizer import normalize_all
from .volatility_adapter import (
    DEFAULT_PLUGINS,
    NORMALIZED_PLUGINS,
    VolatilityAdapter,
    load_mock_results,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)
load_env()  # picks up GROQ_API_KEY / ANTHROPIC_API_KEY etc. from .env if present


def _get_provider(name: str):
    """
    Construct an LLMProvider by name. Import kept local per-provider so
    that selecting one provider doesn't require every provider's
    optional dependency (anthropic / openai / requests) to be installed.
    """
    if name == "mock":
        from .llm.mock_provider import MockProvider
        return MockProvider()
    if name == "anthropic":
        from .llm.anthropic_provider import AnthropicProvider
        return AnthropicProvider()
    if name == "groq":
        from .llm.groq_provider import GroqProvider
        return GroqProvider()
    if name == "ollama":
        from .llm.ollama_provider import OllamaProvider
        return OllamaProvider()
    raise ValueError(f"Unknown provider: {name}")


def run_pipeline(
    image_path: str | None,
    use_mock: bool,
    verbose: bool = False,
    plugin_keys: list[str] | None = None,
):
    """
    Run Phases 1-4 (extraction through behavior inference). Returns
    (graph, behaviors, scalability_report). Phase 5/6 (LLM explanation)
    is handled separately in main() via --explain, since it's optional
    and costs money/time on real providers.

    Phase timing (RQ3) is always measured internally via PhaseTimer --
    the overhead of a few perf_counter() calls is negligible -- but
    only printed/persisted when --benchmark is passed; see main().

    plugin_keys, when running against a real image, controls which
    Volatility plugins actually run -- defaults to NORMALIZED_PLUGINS
    (the subset whose output normalize_all() actually consumes) rather
    than every plugin in DEFAULT_PLUGINS, since running unnormalized
    plugins costs real time for output that's currently discarded.
    Ignored when use_mock=True (the mock fixture always returns its
    fixed set of plugins regardless of what's requested).
    """
    timer = PhaseTimer()

    if verbose:
        print("=" * 70)
        print("Phase 1: Memory Artifact Extraction")
        print("=" * 70)

    with timer.phase("Phase 1: Extraction"):
        if use_mock:
            # Import kept local so the mock fixture (a test asset) is not a
            # hard dependency of the installed package.
            sys.path.insert(0, "tests/fixtures")
            from mock_volatility_rows import MOCK_FIXTURE  # type: ignore

            logger.info("Running pipeline against mock fixture (no memory image).")
            plugin_results = load_mock_results(MOCK_FIXTURE)
        else:
            if not image_path:
                raise SystemExit("--image is required unless --mock is set")
            adapter = VolatilityAdapter(image_path=image_path)
            keys = list(plugin_keys) if plugin_keys is not None else list(NORMALIZED_PLUGINS)
            if verbose:
                print(f"Running {len(keys)} plugin(s): {', '.join(keys)}\n")
            plugin_results = adapter.run_all(plugin_keys=keys)

    if verbose:
        print(f"Ran {len(plugin_results)} Volatility plugin(s): "
              f"{', '.join(plugin_results.keys())}\n")
        print("=" * 70)
        print("Phase 2: Artifact Normalization")
        print("=" * 70)

    with timer.phase("Phase 2: Normalization"):
        ctx = normalize_all(plugin_results)
    logger.info(
        "Normalized %d artifacts and %d relationships.",
        len(ctx.artifacts), len(ctx.relationships),
    )
    if verbose:
        print(f"Normalized {len(ctx.artifacts)} artifacts, "
              f"{len(ctx.relationships)} relationships.\n")
        print("=" * 70)
        print("Phase 3: Knowledge Graph Construction")
        print("=" * 70)

    with timer.phase("Phase 3: Graph Construction"):
        graph = build_graph(ctx)
    if verbose:
        print(f"Graph has {graph.number_of_nodes()} nodes, "
              f"{graph.number_of_edges()} edges.\n")
        print("=" * 70)
        print("Phase 4: Behavior Inference (FBO evidence patterns)")
        print("=" * 70)

    with timer.phase("Phase 4: Inference"):
        behaviors = run_inference(graph)
    logger.info("Inference produced %d behavior nodes.", len(behaviors))
    if verbose:
        print(format_behaviors_by_process(graph, behaviors))
        print()

    scalability_report = timer.build_report(
        num_artifacts=len(ctx.artifacts),
        num_relationships=len(ctx.relationships),
        num_graph_nodes=graph.number_of_nodes(),
        num_graph_edges=graph.number_of_edges(),
        num_behaviors=len(behaviors),
    )

    return graph, behaviors, scalability_report


def run_explanations(graph, behaviors: list[InferredBehavior], provider_name: str, verbose: bool):
    """Phase 5/6: call an LLM to explain every inferred behavior node. Returns the list of Explanations."""
    if verbose:
        print("=" * 70)
        print(f"Phase 5/6: LLM-Assisted Reasoning (graph-only input, provider={provider_name})")
        print("=" * 70)

    if not behaviors:
        print("No behaviors were inferred; nothing to explain.")
        return []

    try:
        provider = _get_provider(provider_name)
    except RuntimeError as exc:
        print(f"Could not initialize provider '{provider_name}': {exc}")
        print("Falling back is not automatic -- fix the provider setup "
              "(see README 'Setting up an LLM provider') and re-run.")
        raise SystemExit(1) from exc

    explanations = explain_all_behaviors(graph, provider)
    for exp in explanations:
        behavior_node = graph.nodes[exp.behavior_ids[0]]
        print(f"\n--- {behavior_node.get('behavior')} "
              f"(rule={behavior_node.get('rule_id')}) ---")
        print(exp.text)

    return explanations


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the forge pipeline.")
    parser.add_argument("--image", help="Path to a memory image (raw/vmem/etc.)")
    parser.add_argument(
        "--mock", action="store_true",
        help="Run against the bundled mock fixture instead of a real image."
    )
    parser.add_argument(
        "--out", default="graph_output.json",
        help="Path to write the resulting graph JSON."
    )
    parser.add_argument(
        "--print-graph", action="store_true",
        help="Print a readable text table of the graph's nodes and edges to stdout."
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Narrate progress through each of the six phases as it runs."
    )
    parser.add_argument(
        "--explain", action="store_true",
        help="Call an LLM to generate investigator-facing explanations for "
             "every inferred behavior (Phase 5/6). Off by default -- no LLM "
             "call, no API key needed, no cost -- unless passed explicitly."
    )
    parser.add_argument(
        "--provider", choices=["mock", "anthropic", "groq", "ollama"], default="mock",
        help="LLM provider to use with --explain (default: mock, no API "
             "key or cost; see README for provider setup)."
    )
    parser.add_argument(
        "--benchmark", action="store_true",
        help="RQ3 (Scalability): print wall-clock time per phase and "
             "graph-size figures, and include them in the output JSON "
             "under 'scalability'."
    )
    parser.add_argument(
        "--measure-traceability", action="store_true",
        help="RQ4 (Traceability): requires --explain. Checks what "
             "fraction of the LLM's inline [node: <id>] citations "
             "resolve to real ids in the exact subgraph it was given, "
             "printed and included in the output JSON under 'traceability'."
    )
    plugin_group = parser.add_mutually_exclusive_group()
    plugin_group.add_argument(
        "--plugins",
        help="Comma-separated list of Volatility plugin keys to run "
             f"(e.g. pslist,netscan,vadinfo). Default: the "
             f"{len(NORMALIZED_PLUGINS)} plugins whose output is actually "
             "normalized (see NORMALIZED_PLUGINS in volatility_adapter.py). "
             "Ignored with --mock."
    )
    plugin_group.add_argument(
        "--all-plugins", action="store_true",
        help=f"Run all {len(DEFAULT_PLUGINS)} plugins in DEFAULT_PLUGINS, "
             "including ones with no normalizer yet (their output is "
             "collected but not used in the graph). Slower; mainly useful "
             "for inspecting raw plugin output. Ignored with --mock."
    )
    args = parser.parse_args()

    if args.all_plugins:
        plugin_keys = list(DEFAULT_PLUGINS.keys())
    elif args.plugins:
        plugin_keys = [p.strip() for p in args.plugins.split(",") if p.strip()]
    else:
        plugin_keys = None  # run_pipeline() applies the NORMALIZED_PLUGINS default

    graph, behaviors, scalability_report = run_pipeline(
        args.image, args.mock, verbose=args.verbose, plugin_keys=plugin_keys
    )

    if args.benchmark:
        print()
        print(format_scalability_report(scalability_report))
        print()

    if args.print_graph:
        print()
        print_graph(graph)
        print()

    explanations = []
    if args.explain:
        explanations = run_explanations(graph, behaviors, args.provider, args.verbose)
        print()

    traceability_summary = None
    if args.measure_traceability:
        if not args.explain:
            print("--measure-traceability requires --explain (no explanations were generated).")
        else:
            traceability_summary = check_traceability_batch(explanations)
            print()
            print(format_traceability_report(traceability_summary))
            print()

    result = to_json_dict(graph)
    if args.benchmark:
        result["scalability"] = scalability_report.as_dict()
    if traceability_summary is not None:
        result["traceability"] = {
            "num_explanations": traceability_summary["num_explanations"],
            "explanations_with_zero_citations": traceability_summary["explanations_with_zero_citations"],
            "total_citations": traceability_summary["total_citations"],
            "total_valid_citations": traceability_summary["total_valid_citations"],
            "overall_citation_rate": traceability_summary["overall_citation_rate"],
        }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)
    logger.info("Wrote graph output to %s", args.out)


if __name__ == "__main__":
    main()
