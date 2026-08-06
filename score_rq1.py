"""
RQ1 (recall) scoring script. Run from the repo root:

    python3 score_rq1.py evaluation/ground_truth/redline.yaml redline_output.json
    python3 score_rq1.py evaluation/ground_truth/reveal.yaml reveal_output.json

Operates on an already-saved graph_output.json (from a prior
`forge.cli --image ... --out ...` run) -- does NOT re-run the pipeline,
so this is fast to iterate on even though the underlying Volatility
extraction takes several minutes.
"""
import json
import sys

import yaml

from forge.evaluation import format_recall_report, score_recall_from_graph_json

if len(sys.argv) != 3:
    print(f"Usage: python3 {sys.argv[0]} <ground_truth.yaml> <graph_output.json>")
    sys.exit(1)

ground_truth_path, graph_json_path = sys.argv[1], sys.argv[2]

with open(ground_truth_path, "r", encoding="utf-8") as f:
    ground_truth = yaml.safe_load(f)

with open(graph_json_path, "r", encoding="utf-8") as f:
    graph_json = json.load(f)

report = score_recall_from_graph_json(graph_json, ground_truth)
print(format_recall_report(report))
