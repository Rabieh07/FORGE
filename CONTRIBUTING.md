# Contributing to FORGE

FORGE's rule-based inference engine (Phase 4) is intentionally designed
to be extended without touching Python code. This guide walks through
adding a new evidence-pattern rule, using the process this project
itself followed for every rule currently in
[`forge/rules/evidence_patterns.yaml`](forge/rules/evidence_patterns.yaml).

## Before you start: the one non-negotiable rule

**Verify every column name and attribute you use against real
Volatility 3 output before writing a rule against it.** This project's
git history contains at least five real bugs caused by assuming a
plugin's column names or value types from printed CLI text or prior
knowledge, rather than checking directly. The cheapest way to check:

```bash
python3 -c "
from forge.volatility_adapter import VolatilityAdapter
adapter = VolatilityAdapter(image_path='/path/to/your/image.mem')
result = adapter.run_plugin('your_plugin_key')
print(result.columns)
print(result.rows[0])
"
```

This queries Volatility's structured `TreeGrid` data directly — the
same code path FORGE itself uses — rather than Volatility's printed
CLI table, which has repeatedly turned out to misrepresent the real
column layout (adjacent columns rendering with no visible gap, for
one confirmed example).

## Step 1: Decide what evidence you're modeling

A rule matches **one edge** in the knowledge graph — a `(source
artifact, edge type, target artifact)` triple — and optionally checks
attributes on either end. Ask:

- What `EdgeType` is this (`SPAWNS`, `WRITES`, `CONNECTS_TO`,
  `ALLOCATES`, etc.)? See `forge/models.py` for the full list.
- What artifact types are the source and target (`Process`,
  `RegistryKey`, `Socket`, `MemoryRegion`, ...)?
- What attribute(s), on which end, actually distinguish malicious from
  benign? A rule that matches too broadly (e.g. "any process with a
  network connection") will produce false positives — this project's
  own evidence-pattern file has several documented examples of exactly
  that happening on real images, and how each was narrowed.

## Step 2: Add the rule to `evidence_patterns.yaml`

```yaml
- id: your_rule_id                    # unique, snake_case, descriptive
  edge_type: SPAWNS                   # required
  source_type: Process                # optional
  target_type: Process                # optional
  source_attr_patterns:               # optional -- regex against source's attributes
    command_line: '(?i)your-pattern'
  target_attr_patterns:               # optional -- regex against target's attributes
    path: '(?i)your-pattern'
  target_source_plugin: malfind       # optional -- match only artifacts from a specific plugin
  produces: Execution                 # required -- a BehaviorConcept (see models.py)
  confidence: 0.75                    # required -- see "Setting confidence" below
  description: >
    Required. Explain what evidence this rule looks for, why it's
    meaningful, and — critically — what its known limitations or
    false-positive risks are. Every rule in this file documents real
    findings (or the absence of them) from testing against actual
    memory images; new rules should hold the same standard.
```

Patterns are Python regexes (`re.search`, case-insensitive via `(?i)`
where relevant), matched against `str(value)` of the attribute —
robust to Volatility's occasional typed sentinel objects (see
`_is_missing_value()` in `forge/normalizer.py`).

## Step 3: Add a normalizer, if the plugin isn't already wired up

If your rule needs data from a plugin FORGE doesn't already normalize,
you'll need a `normalize_<plugin>()` function in `forge/normalizer.py`.
Look at any existing one (e.g. `normalize_pstree()`) as a template —
each documents exactly which real column names were confirmed and how.
Register it in `PLUGIN_NORMALIZERS`, and add the plugin key to
`NORMALIZED_PLUGINS` in `forge/volatility_adapter.py` if you want it
included in the default run (weigh this against runtime cost — see
that file's comments for the reasoning behind the current set).

## Step 4: Test against mock data, then a real image

Add a fixture row to `tests/fixtures/mock_volatility_rows.py` modeling
the evidence your rule should catch, and — just as importantly — a
row that looks similar but *shouldn't* match, to catch an
over-broad pattern. Add a test to
`tests/test_pipeline_end_to_end.py` asserting both.

Then, if you have access to a real memory image where your rule's
target scenario is known to occur, run it there and confirm the rule
fires as expected — and just as importantly, that it *doesn't* fire
on unrelated processes. Several rules in this project were narrowed,
merged, or retired entirely after real-image testing revealed they
were too broad; expect the same iteration for new rules.

## Setting confidence

There is currently no calibration methodology — confidence values in
this file are hand-assigned based on how specific and corroborated the
evidence is (see individual rule descriptions for the reasoning behind
each one). A rough guide used so far:

- **0.5–0.6**: a single weak signal, common in legitimate use (e.g. a
  process running from a Temp directory)
- **0.7–0.85**: a signal with real but imperfect specificity, or two
  independent weak signals combined
- **0.9+**: a pattern with essentially no known legitimate use case

If you can validate your rule's actual precision against a labeled
dataset, that's a stronger basis than this heuristic — see the paper's
Evaluation Plan (RQ1) for the intended methodology, not yet executed
at scale.

## Reducing false positives on an existing rule

If you find a rule producing false positives on real data (very
plausible — several already-shipped rules have documented false
positives in their own descriptions), the preferred fix is usually
**adding a corroborating condition**, not a process-name denylist. A
denylist doesn't generalize to new images and is trivially evadable.
See `temp_dropper_with_malfind_injection` for an example of
corroborating two independent signal types on the same edge without
needing a multi-node pattern.

## What's not yet supported

- **Multi-node compound patterns** (e.g. "process A spawns process B
  AND process A connects to a socket") beyond what a single edge's
  two endpoints can express. Discussed at length but not yet
  implemented — see the paper's Future Work section.
- **Rules that combine multiple already-inferred behaviors** (e.g.
  "this process has both Persistence and Command and Control" as its
  own higher-level finding) — not yet implemented.

If you build either of these, a PR with the design decisions
documented (the way every existing rule documents its own reasoning)
is very welcome.
