# FORGE

**F**orensic **O**ntology-based **R**easoning over **G**raph
**E**vidence — an explainable knowledge-graph framework and
open-source tool for LLM-assisted memory forensics. Companion code
for the paper *"FORGE: A Forensic Ontology-based Reasoning over Graph
Evidence Tool for Memory Forensics"* (draft; venue TBD).

**Status: research prototype.** The pipeline runs end-to-end against
both a mock fixture and (with `volatility3` installed) real memory
images. See [Evaluation status](#evaluation-status) for RQ1/RQ3/RQ4
results against two publicly documented malware images.

## Core idea

Existing memory forensics tools (e.g., Volatility) return isolated,
low-level artifacts and leave correlation to the investigator. Existing
"LLM for forensics" approaches apply an LLM directly to that raw
output, which risks hallucinated, untraceable conclusions.

This framework instead:
1. Normalizes raw Volatility 3 plugin output into a common artifact
   schema.
2. Builds a property graph (NetworkX) modeling relationships between
   processes, registry keys, sockets, memory regions, etc.
3. Runs a **deterministic, rule-based inference engine** over the
   graph, using a declarative evidence-pattern library
   ([`forge/rules/evidence_patterns.yaml`](forge/rules/evidence_patterns.yaml))
   to produce behavior nodes (Persistence, Command and Control, Code
   Injection, ...), each with explicit supporting evidence.
4. Only *after* inference is complete does an LLM get involved — and
   only to translate the already-verified subgraph into natural
   language. **The LLM never sees raw Volatility output**, and every
   claim it makes is traceable back to a specific node/edge id.

## Architecture

```
Volatility 3 (Python API)          forge/volatility_adapter.py    [Phase 1]
        │
        ▼
Normalizer                         forge/normalizer.py            [Phase 2]
        │
        ▼
Knowledge graph (NetworkX)         forge/graph_builder.py         [Phase 3]
        │
        ▼
Rule-based inference engine        forge/inference.py             [Phase 4]
  + evidence pattern library       forge/rules/evidence_patterns.yaml
        │
        ▼
LLM explanation (graph-only input) forge/llm/                     [Phase 5/6]
```

Each phase number corresponds directly to the Methodology section of
the paper.

## Installation

```bash
git clone <this-repo>
cd forge
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

`volatility3` is only required for analyzing real memory images. The
full pipeline (normalizer → graph → inference → mock LLM explanation)
can be run and tested without it, using the bundled mock fixture.

## Quickstart (no memory image required)

```bash
python -m forge.cli --mock --out graph_output.json
```

This runs the full pipeline against a fixture modeled on the paper's
worked example (`tests/fixtures/mock_volatility_rows.py`): a
`powershell.exe` process that writes a persistence Run key, connects
to a remote host, and allocates an RWX memory region. It should detect
Persistence, Command and Control, and Code Injection behavior nodes.

Add `--print-graph` to print a readable text table of every node and
edge to stdout (nodes, Phase 3 relationship edges, and Phase 4
`evidence_for` edges are shown in separate sections):

```bash
python -m forge.cli --mock --print-graph --out graph_output.json
```

A proper visual rendering (SVG/HTML export) of the graph is planned
for the journal version of this work; the text table is the
dependency-free option in the meantime.

Add `--verbose` to narrate progress through each of the six phases as
the pipeline runs (this is the same style of output as
`examples/worked_example.py`, now available directly from the CLI):

```bash
python -m forge.cli --mock --verbose --out graph_output.json
```

By default the CLI never calls an LLM — Phases 1-4 only, no API key
needed, no cost. Add `--explain` to also run Phase 5/6, generating an
investigator-facing explanation for every inferred behavior node, and
`--provider` to choose which LLM backend to use (`mock` by default;
`groq`, `anthropic`, or `ollama` for a real explanation — see "Setting
up an LLM provider" below for where each one's key goes):

```bash
python -m forge.cli --mock --explain --provider groq --out graph_output.json

# Combine everything to see the full pipeline narrated end to end:
python -m forge.cli --mock --verbose --explain --provider groq --print-graph --out graph_output.json
```

If the chosen provider isn't configured (missing API key, package not
installed, etc.), `--explain` fails with a clear error message and a
non-zero exit code rather than falling back silently to another
provider.

## Quickstart (real memory image)

```bash
pip install volatility3
python -m forge.cli --image /path/to/memory.raw --out graph_output.json
```

Requires the memory image's OS symbol table to be available to
Volatility 3 in the usual way (see the
[Volatility 3 documentation](https://volatility3.readthedocs.io/)).

### Runtime and current scope

The default plugin set (`NORMALIZED_PLUGINS` in
`forge/volatility_adapter.py`) currently runs **6 plugins**: `pslist`,
`pstree`, `cmdline`, `netscan`, `registry_run_keys`, `malfind`. Each
was included for a specific, currently-active rule -- see
[`evidence_patterns.yaml`](forge/rules/evidence_patterns.yaml) for the
full, current rule set and the reasoning documented in each rule.

`vadinfo` is deliberately **not** included, and its corresponding rule
(`code_injection_rwx_region`) is retired (commented out, not deleted,
in `evidence_patterns.yaml`) rather than left silently unable to fire.
Real-image testing found this rule's output overlapped roughly 78%
with `code_injection_malfind_flagged`'s -- both rules matched the same
underlying evidence in most cases, `malfind` additionally catches
non-RWX suspicious regions vadinfo-based detection structurally
cannot, and running both did not clearly justify the added complexity.
See the paper's Preliminary Real-World Observations section for the
full finding. Add `vadinfo` back to `NORMALIZED_PLUGINS` and uncomment
the rule if you want to reactivate it (e.g. to compare its output
against `malfind`'s on a new image).

Override the default plugin set with `--plugins` for a specific
subset, or `--all-plugins` to run everything in `DEFAULT_PLUGINS`
(including plugins with no normalizer yet, e.g. for manual inspection):

```bash
python -m forge.cli --image memdump.mem --plugins pslist,cmdline,registry_run_keys --out graph_output.json
python -m forge.cli --image memdump.mem --all-plugins --out graph_output.json
```

**Known limitation carried by the current rule set:** `PrintKey` is not a
per-process plugin -- it lists a registry key's contents with no
indication of which process wrote a given value. Every `RegistryKey`
artifact is therefore linked to an explicitly unattributed placeholder
process (`confidence=0.3`), not a real discovered process. Persistence
detection currently works (the rule fires correctly), but the "which
process is responsible" attribution in the resulting graph is
synthetic, not evidence -- see `normalize_registry()`'s docstring in
`forge/normalizer.py` for details and the reasoning for not yet
implementing heuristic process-matching against the Run value's data.

Two things worth knowing that are about Volatility 3 itself, not
FORGE, if runtime is still an issue after narrowing plugins:
- **Symbol table caching**: the first run against a given OS build is
  usually much slower than subsequent runs, since Volatility downloads
  and converts the matching PDB/symbol table once and caches it. If
  every run feels equally slow, check whether something is clearing
  that cache between runs (Volatility's `--clear-cache` flag, or a
  cache directory being wiped).
- **Built-in parallelism**: `vol.py` itself exposes a
  `--parallelism {processes,threads,off}` flag, independent of FORGE's
  plugin selection, which may help if you're intentionally running
  many plugins (e.g. with `--all-plugins`).

## Generating an LLM explanation

```python
from forge.graph_builder import build_graph
from forge.inference import run_inference
from forge.normalizer import normalize_all
from forge.volatility_adapter import load_mock_results
from forge.llm.anthropic_provider import AnthropicProvider  # needs ANTHROPIC_API_KEY
from forge.llm.explain import explain_behaviors
from tests.fixtures.mock_volatility_rows import MOCK_FIXTURE

ctx = normalize_all(load_mock_results(MOCK_FIXTURE))
graph = build_graph(ctx)
behaviors = run_inference(graph)

provider = AnthropicProvider()
explanation = explain_behaviors(graph, [behaviors[0].id], provider)
print(explanation.text)
```

Swap in `forge/llm/mock_provider.py`'s `MockProvider` for
offline development, or implement `LLMProvider` for another API.

### Setting up an LLM provider (where your API key goes)

Anthropic's API has no standing free tier. **Groq's does** (no credit
card, generous limits as of mid-2026) — this is the easiest way to
run the pipeline against a real model at no cost.

**Step 1 — get a Groq key.**
Go to [console.groq.com/keys](https://console.groq.com/keys), sign in
(email or Google account), click "Create API Key," and copy it.

**Step 2 — put the key somewhere the code can read it.** Two options:

*Option A — `.env` file (recommended, one-time setup):*
```bash
cp .env.example .env
# open .env in an editor and paste your key on the GROQ_API_KEY= line:
#   GROQ_API_KEY=gsk_your_actual_key_here
pip install python-dotenv   # if not already installed
```
`cli.py` and `examples/worked_example.py` both call `load_env()` at
startup, which reads `.env` automatically. **`.env` is already in
`.gitignore`** — it will never be committed.

*Option B — export it in your shell (no file, per-session):*
```bash
export GROQ_API_KEY="gsk_your_actual_key_here"    # macOS/Linux
$env:GROQ_API_KEY = "gsk_your_actual_key_here"    # Windows PowerShell
```
This needs to be re-run every new terminal session unless added to
your shell profile (`~/.bashrc`, `~/.zshrc`, etc.) — `.env` is less
error-prone for repeated use.

**Step 3 — install the client and run:**
```bash
pip install openai   # Groq uses an OpenAI-compatible endpoint
python examples/worked_example.py --groq
```

The same pattern applies to the other providers — just swap the
env var name and flag:

| Provider | Env var | Where to get a key | Cost |
|---|---|---|---|
| Groq | `GROQ_API_KEY` | console.groq.com/keys | Free |
| Anthropic | `ANTHROPIC_API_KEY` | console.anthropic.com/settings/keys | Paid |
| Ollama | *(none — local)* | ollama.com, then `ollama pull llama3.1:8b` | Free |

```bash
python examples/worked_example.py --groq       # needs GROQ_API_KEY
python examples/worked_example.py --anthropic   # needs ANTHROPIC_API_KEY, paid
python examples/worked_example.py --ollama      # needs local Ollama running
```

Free-tier terms and rate limits change frequently — check
[console.groq.com](https://console.groq.com) for current limits before
relying on it for a full evaluation run.


## Running tests

```bash
pip install pytest
pytest tests/
```

Tests run entirely against the mock fixture and require neither
`volatility3` nor a real memory image nor an LLM API key.

## Evaluation status

RQ1, RQ3, and RQ4 have been executed against two publicly available,
independently documented malware memory images:

| Image | Malware family | RQ1 recall | RQ4 citation rate |
|---|---|---|---|
| CyberDefenders 106-redline | RedLine Stealer | 1/2 (50%) | 37/37 (100%) |
| CyberDefenders Reveal | StrelaStealer | 1/1 (100%) | 81/81 (100%) |

**RQ3 (Scalability):** Phases 2–4 (normalization, graph construction,
and rule-based inference — the parts attributable to FORGE rather than
Volatility) complete in under 100 milliseconds on both images. Phase 1
(Volatility extraction) dominates runtime at 192–361 seconds depending
on the image and whether symbol tables are already cached.

**RQ1 methodology note:** recall only, not precision. Each miss traces
to a specific, named rule-coverage gap documented in
`evaluation/ground_truth/`. Run the scorer against your own saved
`graph_output.json`:

```bash
python3 score_rq1.py evaluation/ground_truth/redline.yaml redline_output.json
python3 score_rq1.py evaluation/ground_truth/reveal.yaml reveal_output.json
```

**RQ2 (Hallucination rate vs. raw-artifact LLM baseline):** defined
but not yet executed — see the accompanying paper.

Contributions of additional evidence patterns or memory images with
documented ground truth are welcome — see
[`CONTRIBUTING.md`](CONTRIBUTING.md) for a concrete guide to adding a
new rule, including the column-name verification discipline this
project's own development showed is necessary before trusting any
assumed plugin schema.

## Repository layout

```
forge/
    models.py               # Artifact / Relationship / InferredBehavior types
    volatility_adapter.py   # Phase 1: Volatility 3 Python API wrapper
    normalizer.py           # Phase 2: raw rows -> standardized artifacts
    graph_builder.py        # Phase 3: NetworkX knowledge graph
    inference.py            # Phase 4: rule engine over evidence_patterns.yaml
    rules/
        evidence_patterns.yaml
    llm/
        base.py              # LLMProvider interface
        anthropic_provider.py
        mock_provider.py
        prompts.py
        explain.py           # Phase 5/6: graph-only LLM explanation
    cli.py                   # end-to-end pipeline runner
tests/
    fixtures/mock_volatility_rows.py
    test_pipeline_end_to_end.py
```

## Security / responsible use note

This is a defensive/investigative tool: it consumes memory images the
user already has lawful access to and helps correlate what they
already extracted with Volatility. It does not perform exploitation,
credential extraction beyond what standard forensic plugins already
recover, or any offensive action.

**Never commit real memory images, case data, or API keys to this
repository.** See `.gitignore`.

## Citation

See [`CITATION.cff`](CITATION.cff). The `preferred-citation` entry for
the accompanying paper is commented out until it has a venue, year,
and DOI/URL — uncomment and fill it in once accepted, and update
`repository-code` with the actual GitHub URL once this repo is pushed.

## License

Apache License 2.0 — see [LICENSE](LICENSE). Apache 2.0 includes an
explicit patent grant and patent-retaliation clause, which is why it
was chosen over a simpler permissive license like MIT: it gives both
the author and downstream users clearer legal footing if this
framework's methods (e.g. the graph-grounded inference/explanation
separation) end up embedded in commercial forensic tooling.
