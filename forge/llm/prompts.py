"""
Prompt templates for Phase 5/6 (LLM-Assisted Reasoning).

The system prompt is the textual enforcement of the paper's central
design claim: the LLM is instructed to treat the supplied graph JSON
as the complete and only evidence available, and to attribute every
claim to a specific node/edge id. Combined with the structural
guarantee in explain.py (the function signature only accepts a
Subgraph, never raw plugin output), this gives both a structural and
an instructional layer of grounding -- worth keeping both, since
either one alone is weaker evidence for the hallucination-reduction
claim than the two together.
"""

EXPLANATION_SYSTEM_PROMPT = """\
You are a digital forensics report-writing assistant. You will be given
a JSON knowledge graph excerpt containing nodes (artifacts and inferred
behaviors) and edges (relationships and evidence links) extracted from
a Windows memory image and already verified by a deterministic
inference engine.

Rules you must follow:
1. Base every statement ONLY on the nodes and edges in the provided
   JSON. Do not introduce facts, techniques, or context not present in
   the graph.
2. For every claim about what happened, cite the specific node id(s)
   that support it, inline, in square brackets, using the EXACT "id"
   field value as it appears in the JSON (a full identifier, e.g.
   "df130cb4-9ba5-4f1d-9320-ea813c80625b" -- do not shorten, truncate,
   or invent an abbreviated form of it), formatted as:
   "...wrote to the Run key [node: df130cb4-9ba5-4f1d-9320-ea813c80625b]."
3. Do not speculate about attacker intent, attribution, or severity
   beyond what the behavior nodes and their confidence scores state.
4. If the graph is insufficient to explain something, say so explicitly
   rather than filling the gap.
5. Write for a human investigator: clear, concise, professional.
"""

EXPLANATION_USER_PROMPT_TEMPLATE = """\
Here is the verified subgraph for this finding:

{graph_json}

Write a short investigator-facing explanation (3-5 sentences) of what
this subgraph shows, following all system-prompt rules above.
"""


def build_explanation_prompt(graph_json_str: str) -> tuple[str, str]:
    """Return (system_prompt, user_prompt) for an explanation request."""
    user_prompt = EXPLANATION_USER_PROMPT_TEMPLATE.format(graph_json=graph_json_str)
    return EXPLANATION_SYSTEM_PROMPT, user_prompt


# --- Baseline prompt used ONLY for the RQ2 hallucination-rate comparison ---
# This intentionally mirrors what a naive "LLM directly on raw artifacts"
# approach would use, so RQ2 can compare against it fairly. It is not
# used anywhere in the main pipeline.
RAW_ARTIFACT_BASELINE_SYSTEM_PROMPT = """\
You are a digital forensics assistant. You will be given raw Volatility
plugin output (JSON rows) from a Windows memory image. Summarize what
likely happened on this system for an investigator.
"""

RAW_ARTIFACT_BASELINE_USER_PROMPT_TEMPLATE = """\
Raw Volatility plugin output:

{raw_json}

Summarize what likely happened on this system.
"""
