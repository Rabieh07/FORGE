"""
Artifact Normalization (Phase 2).

Converts heterogeneous, plugin-specific Volatility 3 rows into the
standardized Artifact / Relationship representation defined in
models.py. Each `normalize_<plugin>` function owns the mapping for one
plugin's row schema; adding support for a new plugin means adding one
function here plus a registration entry in `PLUGIN_NORMALIZERS`, and
does not require changes to the graph builder or inference engine.

Every artifact and relationship produced here retains explicit
provenance (source plugin, and for relationships, the two artifact IDs
they connect) per the traceability requirement in Section III.H of the
paper.
"""

from __future__ import annotations

import logging
from typing import Callable

from .models import Artifact, ArtifactType, EdgeType, Relationship
from .volatility_adapter import PluginResult

logger = logging.getLogger(__name__)


def _is_missing_value(value: object) -> bool:
    """
    Returns True if `value` represents "no data" rather than a real
    field value -- either one of Volatility 3's typed renderer
    sentinel objects, or a plain string/None equivalent.

    Confirmed necessary by direct inspection of real plugin output:
    Volatility uses several DIFFERENT sentinel classes for different
    "no data" reasons, not one consistent value. A single real
    windows.pstree.PsTree row was observed with UnreadableValue for
    Handles, NotApplicableValue for ExitTime, and NotAvailableValue
    for both Cmd and Path. A fix targeting only one specific class or
    string value (as an earlier version of normalize_registry() did,
    checking only for a literal "-" string) already failed once on a
    different image where the same conceptual sentinel arrived as a
    different type -- see git history for that bug. This helper
    generalizes the check by type-name pattern rather than hardcoding
    every sentinel class Volatility happens to use, so a not-yet-seen
    sentinel type is more likely to be caught the first time rather
    than requiring another real-image bug report to discover.

    Still a heuristic, not a guarantee: a future Volatility version
    could introduce a sentinel class whose name doesn't match any of
    these substrings. If a field value looks wrong (e.g. a rule
    silently isn't matching), checking whether this function actually
    caught it is a reasonable first debugging step.
    """
    if value is None:
        return True
    type_name = type(value).__name__
    if any(
        marker in type_name
        for marker in ("NotAvailable", "NotApplicable", "Unreadable", "Unparsable", "DisassemblyUnavailable")
    ):
        return True
    text = str(value).strip()
    return text in ("", "-", "N/A")


class NormalizationContext:
    """
    Tracks artifacts created during normalization so that later plugin
    rows (e.g., netscan referencing a PID already seen in pslist) can
    be linked to the correct existing Process artifact rather than
    creating duplicates.
    """

    def __init__(self) -> None:
        self.artifacts: dict[str, Artifact] = {}
        self.relationships: list[Relationship] = []
        # PID -> Process artifact id, populated as pslist is normalized
        self._pid_index: dict[int, str] = {}

    def add_artifact(self, artifact: Artifact) -> Artifact:
        self.artifacts[artifact.id] = artifact
        return artifact

    def add_relationship(self, relationship: Relationship) -> Relationship:
        self.relationships.append(relationship)
        return relationship

    def process_artifact_for_pid(
        self, pid: int, process_name: str | None = None, source_plugin: str = ""
    ) -> Artifact:
        """
        Return the existing Process artifact for `pid`, or create a
        minimal placeholder one if pslist hasn't been normalized yet
        (or the PID is otherwise unseen). Placeholder processes are
        marked with reduced confidence so downstream consumers can
        distinguish "confirmed by pslist" from "inferred from another
        plugin's PID reference."
        """
        if pid in self._pid_index:
            return self.artifacts[self._pid_index[pid]]

        artifact = Artifact(
            artifact_type=ArtifactType.PROCESS,
            attributes={"pid": pid, "image_file_name": process_name or "<unknown>"},
            source_plugin=source_plugin,
            confidence=0.5,
            provenance={"placeholder": True},
        )
        self.add_artifact(artifact)
        self._pid_index[pid] = artifact.id
        return artifact

    def register_pid(self, pid: int, artifact: Artifact) -> None:
        self._pid_index[pid] = artifact.id


# ---------------------------------------------------------------------
# Per-plugin normalizers
# ---------------------------------------------------------------------

def normalize_pslist(result: PluginResult, ctx: NormalizationContext) -> None:
    for row in result.rows:
        pid = row.get("PID")
        artifact = Artifact(
            artifact_type=ArtifactType.PROCESS,
            attributes={
                "pid": pid,
                "ppid": row.get("PPID"),
                "image_file_name": row.get("ImageFileName"),
                "create_time": row.get("CreateTime"),
                "session_id": row.get("SessionId"),
            },
            source_plugin=result.plugin_name,
            timestamp=row.get("CreateTime"),
        )
        ctx.add_artifact(artifact)
        ctx.register_pid(pid, artifact)

        ppid = row.get("PPID")
        if ppid is not None:
            parent = ctx.process_artifact_for_pid(ppid, source_plugin=result.plugin_name)
            ctx.add_relationship(
                Relationship(
                    source_id=parent.id,
                    target_id=artifact.id,
                    edge_type=EdgeType.SPAWNS,
                    source_plugin=result.plugin_name,
                )
            )


def normalize_cmdline(result: PluginResult, ctx: NormalizationContext) -> None:
    for row in result.rows:
        pid = row.get("PID")
        process = ctx.process_artifact_for_pid(
            pid, row.get("Process"), source_plugin=result.plugin_name
        )
        # Command line is an attribute enrichment on the existing
        # Process artifact rather than a new node.
        process.attributes["command_line"] = row.get("Args")


def normalize_pstree(result: PluginResult, ctx: NormalizationContext) -> None:
    """
    Normalize windows.pstree.PsTree output -- specifically to extract
    the process's full path.

    Column names confirmed against real output from a live memory
    image (CyberDefenders 106-redline) via a direct, structured query
    (adapter.run_plugin("pstree").columns), NOT by counting positions
    in the printed CLI table -- the latter was tried first and gave a
    wrong answer, because two adjacent columns ("Audit" and "Cmd")
    render with no visible gap in the CLI's text table, making them
    look like one combined field ("AuditCmd") when read visually.
    There are 13 real columns, not 12: PID, PPID, ImageFileName,
    Offset(V), Threads, Handles, SessionId, Wow64, CreateTime,
    ExitTime, Audit, Cmd, Path.

    The process's real full path is in "Audit", not "Path" -- on the
    one real image checked, "Path" itself was consistently a
    NotAvailableValue sentinel (see _is_missing_value()), i.e. a
    genuinely different, unpopulated field for this plugin, not a
    misread of the right one.

    Audit/path is what verifiably distinguished a confirmed RedLine
    Stealer dropper (oneetx.exe, path under
    \\Users\\...\\AppData\\Local\\Temp\\...) from every earlier false
    positive in this codebase's real-image testing (MsMpEng.exe,
    SearchApp.exe, etc., all running from legitimate system paths) --
    see process_spawned_from_temp and
    temp_dropper_with_malfind_injection in evidence_patterns.yaml.
    """
    for row in result.rows:
        pid = row.get("PID")
        process = ctx.process_artifact_for_pid(
            pid, row.get("ImageFileName"), source_plugin=result.plugin_name
        )
        # Path is an attribute enrichment on the existing Process
        # artifact, same pattern as normalize_cmdline()'s command_line.
        audit_value = row.get("Audit")
        process.attributes["path"] = (
            None if _is_missing_value(audit_value) else str(audit_value)
        )

    # Diagnostic: if PID values from this plugin don't match pslist's
    # PID type/value exactly (e.g. one is int, the other some
    # Volatility-specific wrapper type), process_artifact_for_pid()
    # silently creates a NEW placeholder process instead of enriching
    # the real one -- no exception, no warning, just a path attribute
    # sitting on an orphaned duplicate node instead of the process an
    # investigator is actually looking at. This log line makes that
    # failure mode visible instead of requiring it to be inferred from
    # an empty grep result.
    enriched = sum(
        1 for row in result.rows
        if row.get("PID") in ctx._pid_index
        and ctx.artifacts[ctx._pid_index[row.get("PID")]].confidence == 1.0
    )
    logger.info(
        "normalize_pstree: processed %d row(s), %d matched a confirmed "
        "(pslist-sourced) process. If this is less than the row count "
        "and path data is missing where expected, PID values from "
        "pstree may not match pslist's PID type/value.",
        len(result.rows), enriched,
    )


_REGISTRY_COLUMN_WARNED = False


def normalize_registry(result: PluginResult, ctx: NormalizationContext) -> None:
    """
    Normalize windows.registry.printkey.PrintKey output.

    STRUCTURAL GAP, not just a column-name issue: unlike vadinfo,
    malfind, and netscan (all per-process plugins with a PID column),
    PrintKey is NOT process-scoped -- it lists a registry key's
    contents as found in a hive, with no indication of which process
    (if any) wrote a given value. This is a real limitation of the
    data source, not a bug: a static memory snapshot's registry hive
    doesn't record write provenance the way, say, an ETW trace or a
    registry-hive timeline diff would.

    Every RegistryKey artifact produced here is therefore linked via a
    WRITES edge from an explicitly unattributed placeholder Process
    artifact (image_file_name="<unattributed -- PrintKey provides no
    process linkage>", confidence=0.3), NOT a real process discovered
    elsewhere in the graph. This keeps the persistence_run_key rule
    structurally able to fire (it does not check the source process's
    identity), but the resulting Persistence behavior node's process
    attribution is synthetic, not evidence -- this should be surfaced
    to the investigator, not hidden. A real fix would need to correlate
    each Run value's data (typically an executable path/command line)
    against known processes by name/path matching, which is a
    heuristic in its own right and has NOT been implemented pending a
    decision on that approach.

    Column names (Key, Name, Data, Type) are ASSUMED based on typical
    Volatility 3 registry-plugin conventions and have NOT been
    confirmed against real PrintKey output -- same defensive/warn-once
    pattern as normalize_malfind() until verified.

    NOT-FOUND FILTERING: confirmed via real output that PrintKey emits
    one row per hive it walks when searching for the requested key,
    including hives where the key does not exist -- those rows have
    Name == "-" (a sentinel, not a real value named "-"). An earlier
    version of this function treated every row as a real Run-key
    value, including these not-found placeholders; on one real image
    this produced 24 spurious Persistence detections (one per hive
    PrintKey walked, including hives that structurally cannot contain
    a Software-then-Run key at all, e.g. SAM, HARDWARE, BCD) with zero
    real evidence behind any of them. Rows with Name in ("-", None)
    are now skipped entirely -- no artifact, no edge, no behavior.
    """
    global _REGISTRY_COLUMN_WARNED
    found_count = 0
    not_found_count = 0
    for row in result.rows:
        key_path = row.get("Key")
        value_name = row.get("Name")
        if key_path is None and not _REGISTRY_COLUMN_WARNED:
            logger.warning(
                "normalize_registry: could not find a 'Key' column in "
                "PrintKey output. Actual columns in this row: %s. "
                "Please report this so normalize_registry() can be "
                "corrected.",
                list(row.keys()),
            )
            _REGISTRY_COLUMN_WARNED = True

        # Uses the shared _is_missing_value() helper (see top of file):
        # confirmed via real output that PrintKey's not-found sentinel
        # arrives as different types on different images (a plain
        # string "-" on one image, a typed NotApplicableValue-style
        # renderer object on another), and a check narrowly targeting
        # only one of those already let 24 not-found rows through as
        # real values once before being generalized here.
        if _is_missing_value(value_name):
            not_found_count += 1
            continue
        found_count += 1

        # See docstring: this is an explicitly synthetic, unattributed
        # placeholder, not a discovered process. Each row gets its own
        # placeholder rather than sharing one, so future process-matching
        # logic can replace individual edges without restructuring.
        placeholder_process = Artifact(
            artifact_type=ArtifactType.PROCESS,
            attributes={
                "image_file_name": "<unattributed -- PrintKey provides no process linkage>",
            },
            source_plugin=result.plugin_name,
            confidence=0.3,
            provenance={"placeholder": True, "reason": "printkey_no_process_attribution"},
        )
        ctx.add_artifact(placeholder_process)

        reg_artifact = Artifact(
            artifact_type=ArtifactType.REGISTRY_KEY,
            attributes={
                "hive": row.get("Hive"),  # see docstring -- not confirmed present in PrintKey output
                "key_path": key_path,
                # str()'d for the same reason as the not-found check
                # above: PrintKey may return typed renderer objects,
                # not plain strings, and storing the raw object risks
                # the same "looks right when printed, doesn't compare
                # equal" surprise resurfacing downstream.
                "value_name": str(value_name) if not _is_missing_value(value_name) else None,
                "value_data": str(row.get("Data")) if not _is_missing_value(row.get("Data")) else None,
                "value_type": str(row.get("Type")) if not _is_missing_value(row.get("Type")) else None,
            },
            source_plugin=result.plugin_name,
        )
        ctx.add_artifact(reg_artifact)

        # Unconditionally WRITES: this plugin was specifically targeted
        # at the Run key path (see PLUGIN_CONFIG in volatility_adapter.py),
        # so every returned value represents an entry present in that
        # autorun location -- there is no "Operation" field to check
        # (PrintKey shows static key contents, not an event log).
        ctx.add_relationship(
            Relationship(
                source_id=placeholder_process.id,
                target_id=reg_artifact.id,
                edge_type=EdgeType.WRITES,
                source_plugin=result.plugin_name,
                confidence=0.3,
            )
        )

    logger.info(
        "normalize_registry: %d real value(s) found, %d not-found "
        "sentinel row(s) filtered out (one per hive PrintKey walked "
        "without locating the key).",
        found_count, not_found_count,
    )


def normalize_netscan(result: PluginResult, ctx: NormalizationContext) -> None:
    for row in result.rows:
        pid = row.get("PID")
        process = ctx.process_artifact_for_pid(
            pid, row.get("Owner"), source_plugin=result.plugin_name
        )
        socket_artifact = Artifact(
            artifact_type=ArtifactType.SOCKET,
            attributes={
                "protocol": row.get("Proto"),
                "local_addr": row.get("LocalAddr"),
                "local_port": row.get("LocalPort"),
                "foreign_addr": row.get("ForeignAddr"),
                "foreign_port": row.get("ForeignPort"),
                "state": row.get("State"),
            },
            source_plugin=result.plugin_name,
        )
        ctx.add_artifact(socket_artifact)
        ctx.add_relationship(
            Relationship(
                source_id=process.id,
                target_id=socket_artifact.id,
                edge_type=EdgeType.CONNECTS_TO,
                source_plugin=result.plugin_name,
            )
        )


def normalize_vadinfo(result: PluginResult, ctx: NormalizationContext) -> None:
    for row in result.rows:
        pid = row.get("PID")
        process = ctx.process_artifact_for_pid(
            pid, row.get("Process"), source_plugin=result.plugin_name
        )
        region_artifact = Artifact(
            artifact_type=ArtifactType.MEMORY_REGION,
            attributes={
                # NOTE: confirmed against real windows.vadinfo.VadInfo
                # output -- the plugin's actual column names are
                # "Start VPN" / "End VPN", not "Start" / "End". Using
                # the wrong keys silently produced None/None for every
                # region (caught via a real memory image run).
                "start": row.get("Start VPN"),
                "end": row.get("End VPN"),
                "protection": row.get("Protection"),
                "tag": row.get("Tag"),
                # "File" is "N/A" for anonymous (unbacked) memory and a
                # real path for file-backed regions (loaded modules,
                # mapped DLLs). This is the key signal for distinguishing
                # legitimate JIT/module memory from injected shellcode --
                # see code_injection_rwx_region in evidence_patterns.yaml,
                # which was firing on ordinary processes (MsMpEng.exe,
                # SearchApp.exe, etc.) before this field was wired in,
                # because RWX protection alone is common and benign.
                "backing_file": row.get("File"),
            },
            source_plugin=result.plugin_name,
        )
        ctx.add_artifact(region_artifact)
        ctx.add_relationship(
            Relationship(
                source_id=process.id,
                target_id=region_artifact.id,
                edge_type=EdgeType.ALLOCATES,
                source_plugin=result.plugin_name,
            )
        )


_MALFIND_COLUMN_WARNED = False


def normalize_malfind(result: PluginResult, ctx: NormalizationContext) -> None:
    """
    Normalize windows.malware.malfind.Malfind output.

    Column names confirmed against real output from a live memory
    image: PID, Process, Start VPN, End VPN, Tag, Protection,
    CommitCharge, PrivateMemory, File output, Notes, Hexdump, Disasm.
    "Start VPN"/"End VPN" match vadinfo's schema as originally assumed
    (the defensive fallback below was not needed, but is kept in case
    a different Volatility 3 version varies).

    IMPORTANT: unlike windows.vadinfo.VadInfo, malfind's output has NO
    "File" column -- only "File output", which is unrelated: it is a
    Disabled/Enabled flag for whether the plugin was asked to dump the
    region to disk (via --dump), not a backing-file path. An earlier
    version of this function fell back to "File output" when "File"
    was absent, which silently stored the literal string "Disabled"
    as backing_file for every malfind-sourced region -- caught before
    it reached the evaluation corpus, but worth noting as a second
    example (after the vadinfo Start/End bug) of why column-name
    assumptions in this codebase are treated as unverified until
    checked against real plugin output. backing_file is intentionally
    left unset (None) for malfind-sourced regions; malfind's own
    internal heuristics (which region it chooses to report at all) are
    the evidence signal here, not a file-backing attribute it doesn't
    expose. "Notes" is captured but not yet used by any rule -- it can
    contain indicators such as an embedded PE header when malfind's
    own heuristics detect one, which would be a stronger corroborating
    signal than mere presence in malfind's output; this is not yet
    implemented pending more real examples of its content/format.

    malfind's actual value here is NOT just another data source: unlike
    vadinfo (which returns every VAD entry for a process), malfind
    applies its own internal heuristics and only returns entries it
    already considers suspicious. A region appearing in malfind's
    output at all is therefore a stronger, independently corroborating
    signal than code_injection_rwx_region's vadinfo-based heuristic
    alone -- see code_injection_malfind_flagged in
    evidence_patterns.yaml. This is still a heuristic, not proof: it is
    well documented in DFIR practice that malfind requires analyst
    triage and is not injection-proof on its own (see paper Limitations).
    """
    global _MALFIND_COLUMN_WARNED
    for row in result.rows:
        pid = row.get("PID")
        process = ctx.process_artifact_for_pid(
            pid, row.get("Process"), source_plugin=result.plugin_name
        )

        start = row.get("Start VPN", row.get("Start"))
        end = row.get("End VPN", row.get("End"))
        if (start is None or end is None) and not _MALFIND_COLUMN_WARNED:
            logger.warning(
                "normalize_malfind: could not find address-range columns "
                "using known keys ('Start VPN'/'End VPN' or 'Start'/'End'). "
                "Actual columns in this row: %s. Please report this so "
                "normalize_malfind() can be corrected.",
                list(row.keys()),
            )
            _MALFIND_COLUMN_WARNED = True

        notes_value = row.get("Notes")
        region_artifact = Artifact(
            artifact_type=ArtifactType.MEMORY_REGION,
            attributes={
                "start": start,
                "end": end,
                "protection": row.get("Protection"),
                "tag": row.get("Tag"),
                # NOT row.get("File output") -- see docstring above.
                # malfind exposes no real backing-file field.
                "backing_file": None,
                "notes": None if _is_missing_value(notes_value) else str(notes_value),
            },
            source_plugin=result.plugin_name,
            confidence=1.0,
        )
        ctx.add_artifact(region_artifact)
        ctx.add_relationship(
            Relationship(
                source_id=process.id,
                target_id=region_artifact.id,
                edge_type=EdgeType.ALLOCATES,
                source_plugin=result.plugin_name,
            )
        )


PLUGIN_NORMALIZERS: dict[str, Callable[[PluginResult, NormalizationContext], None]] = {
    "pslist": normalize_pslist,
    "pstree": normalize_pstree,
    "cmdline": normalize_cmdline,
    "registry_run_keys": normalize_registry,
    "netscan": normalize_netscan,
    "vadinfo": normalize_vadinfo,
    "malfind": normalize_malfind,
}


def normalize_all(
    plugin_results: dict[str, PluginResult]
) -> NormalizationContext:
    """
    Normalize a full set of plugin results into a single
    NormalizationContext containing all artifacts and relationships.

    Plugins are processed with `pslist` first when present, since other
    normalizers rely on `ctx.process_artifact_for_pid` resolving to a
    confirmed (non-placeholder) Process artifact where possible.
    """
    ctx = NormalizationContext()
    ordered_keys = sorted(
        plugin_results.keys(), key=lambda k: 0 if k == "pslist" else 1
    )
    for key in ordered_keys:
        normalizer = PLUGIN_NORMALIZERS.get(key)
        if normalizer is None:
            logger.warning("No normalizer registered for plugin '%s'; skipping.", key)
            continue
        normalizer(plugin_results[key], ctx)
    return ctx
