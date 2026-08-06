"""
Volatility 3 adapter (Phase 1: Memory Artifact Extraction).

Design note
-----------
Volatility 3 plugins are Python objects that yield structured rows
(via a `TreeGrid`) before any text rendering occurs. This adapter
invokes plugins through Volatility's Python API directly and captures
those structured rows, rather than shelling out to the `vol3` CLI and
parsing its human-readable table output. This avoids brittleness from
column-width/formatting changes and guarantees every field Volatility
actually recovered is available to Phase 2, not just what the CLI
renderer chose to print.

This module requires the `volatility3` package (`pip install
volatility3`) and a valid memory image on disk. It is intentionally
isolated from the rest of the pipeline: `normalizer.py` consumes the
plain dict rows returned here and has no Volatility import of its own,
which keeps the normalizer (and everything downstream) unit-testable
without a real memory image or the volatility3 dependency installed.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Iterator

logger = logging.getLogger(__name__)

# Plugins used in the current evaluation (Section III.B). Extend this
# mapping as additional plugins are wired into the normalizer.
DEFAULT_PLUGINS = {
    "pslist": "windows.pslist.PsList",
    "pstree": "windows.pstree.PsTree",
    "dlllist": "windows.dlllist.DllList",
    "netscan": "windows.netscan.NetScan",
    "cmdline": "windows.cmdline.CmdLine",
    # Switched from windows.registry.userassist.UserAssist, which was
    # never correct for this purpose: UserAssist tracks program
    # EXECUTION HISTORY (what ran, how often), not registry writes --
    # it would never have detected Run-key persistence regardless of
    # whether an image actually had any. PrintKey, targeted at the Run
    # key path via PLUGIN_CONFIG below, directly lists the key's
    # contents instead. Column names and behavior have NOT yet been
    # confirmed against real output -- see normalize_registry()'s
    # docstring in normalizer.py for the same defensive/warn-once
    # pattern used for vadinfo and malfind until this is verified.
    "registry_run_keys": "windows.registry.printkey.PrintKey",
    "handles": "windows.handles.Handles",
    "vadinfo": "windows.vadinfo.VadInfo",
    # Confirmed against real output: windows.malfind.Malfind and
    # windows.malware.malfind.Malfind are both separately registered
    # plugins in this Volatility 3 version; only the windows.malware.*
    # one was confirmed to produce real output when tested directly.
    "malfind": "windows.malware.malfind.Malfind",
    "svcscan": "windows.svcscan.SvcScan",
    "driverscan": "windows.driverscan.DriverScan",
}

# Subset of DEFAULT_PLUGINS actually run by forge.cli's default.
# Historically this tracked "every plugin with a registered normalizer"
# (see normalizer.PLUGIN_NORMALIZERS), which at one point included
# netscan/vadinfo/malfind for C2 and Code Injection detection, was
# then narrowed to 3 plugins (pslist/cmdline/registry_run_keys) after
# real-image testing showed the two Code Injection rules
# (code_injection_rwx_region from vadinfo, code_injection_malfind_flagged
# from malfind) producing heavy redundant output without a
# corresponding precision gain.
#
# Expanded back to 6 (adding pstree, netscan, malfind) once each
# addition had a specific, justified purpose rather than being
# included by default "in case it's useful":
#   - pstree: feeds Process.path, used by process_spawned_from_temp
#     and temp_dropper_with_malfind_injection -- verified against a
#     real image (CyberDefenders 106-redline) to be the actual
#     discriminator between oneetx.exe (a confirmed RedLine Stealer
#     dropper, path under \Temp\) and the earlier false positives
#     (MsMpEng.exe etc., all running from legitimate system paths).
#   - netscan: needed for c2_encoded_cmdline_and_connection.
#   - malfind: reintroduced specifically for
#     temp_dropper_with_malfind_injection, which corroborates the
#     path signal with malfind's own heuristics rather than relying on
#     either alone -- a different, more specific role than malfind's
#     earlier standalone use, which produced the redundant-output
#     problem that motivated removing it before.
# vadinfo remains excluded: code_injection_rwx_region's redundancy
# with malfind (see above) has not been resolved, only sidestepped by
# giving malfind a new, more specific job. Still available via
# --plugins or --all-plugins. MUST be kept in sync with
# normalizer.PLUGIN_NORMALIZERS for whichever plugins ARE included
# here -- there's no automatic check for this since importing
# normalizer here would create a circular import (normalizer.py
# imports PluginResult from this module).
NORMALIZED_PLUGINS = (
    "pslist",
    "pstree",
    "cmdline",
    "netscan",
    "registry_run_keys",
    "malfind",
)

# Default configuration values applied automatically when running a
# given plugin key -- e.g. PrintKey needs to be told which registry
# key to print. run_plugin() merges these in before any caller-supplied
# plugin_config, so a caller can still override by passing the same
# key explicitly. PrintKey enumerates this key across all hives it
# finds in the image (each user's NTUSER.DAT as well as the machine
# SOFTWARE hive), so a single call covers what would conventionally be
# called both HKCU\...\Run and HKLM\...\Run without needing two runs.
PLUGIN_CONFIG: dict[str, dict[str, Any]] = {
    "registry_run_keys": {
        "key": "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    },
}


@dataclass
class PluginResult:
    """Raw structured output from a single Volatility 3 plugin run."""
    plugin_name: str
    columns: list[str]
    rows: list[dict[str, Any]]


class VolatilityAdapter:
    """
    Thin wrapper around the Volatility 3 Python API.

    Usage:
        adapter = VolatilityAdapter(image_path="/path/to/memory.raw")
        result = adapter.run_plugin("pslist")
        for row in result.rows:
            ...
    """

    def __init__(self, image_path: str, symbol_cache_path: str | None = None):
        self.image_path = image_path
        self.symbol_cache_path = symbol_cache_path
        self._context = None
        self._automagics = None

    # -- lazy import so this module is importable without volatility3 --
    def _ensure_context(self):
        if self._context is not None:
            return
        try:
            from volatility3 import framework
            from volatility3 import plugins as plugin_namespace
            from volatility3.framework import contexts, automagic
            from volatility3.framework.configuration import requirements
        except ImportError as exc:  # pragma: no cover - exercised only with volatility3 installed
            raise RuntimeError(
                "volatility3 is not installed. Install it with "
                "`pip install volatility3` to run against a real memory "
                "image. The rest of the pipeline (normalizer, graph "
                "builder, inference engine) can be developed and tested "
                "independently of this dependency using mock plugin "
                "output -- see tests/fixtures/."
            ) from exc

        framework.require_interface_version(2, 0, 0)
        # NOTE: must pass the top-level volatility3.plugins namespace here,
        # NOT volatility3.framework.plugins -- the latter is an internal
        # module reserved for framework machinery (e.g. construct_plugin,
        # used separately in run_plugin() below) and is guarded against
        # direct namespace-walk imports by volatility3 itself. Passing it
        # to import_files() triggers exactly the
        # "Please do not use the volatility3.framework.plugins namespace
        # directly" warning/failure seen when this was wired up incorrectly.
        failures = framework.import_files(plugin_namespace, True)
        if failures:
            logger.warning("Some Volatility plugins failed to import: %s", failures)

        self._context = contexts.Context()
        self._context.config["automagic.LayerStacker.single_location"] = (
            f"file:{self.image_path}"
        )
        self._automagics = automagic.available(self._context)

    def run_plugin(self, plugin_key: str, **plugin_config: Any) -> PluginResult:
        """
        Run a single plugin (by the short key in DEFAULT_PLUGINS, or a
        fully-qualified `module.ClassName` string) and return its
        structured rows.
        """
        self._ensure_context()
        # This import is intentionally different from the one in
        # _ensure_context(): construct_plugin() is genuine framework
        # machinery that lives in volatility3.framework.plugins (not a
        # namespace-walk import via import_files(), just a normal
        # single-module import), so it is NOT subject to the same guard
        # that blocked the plugin-discovery import above. Confirmed
        # working end-to-end across multiple real memory image runs
        # (CyberDefenders Brave, 106-redline).
        from volatility3.framework import automagic, plugins as vol_plugins
        from volatility3.framework import interfaces

        plugin_path = DEFAULT_PLUGINS.get(plugin_key, plugin_key)
        # DEFAULT_PLUGINS stores paths relative to the volatility3.plugins
        # namespace (e.g. "windows.pslist.PsList"), matching how they're
        # documented/referenced in Volatility's own plugin listing --
        # but that's not an importable path on its own ("windows" is not
        # a top-level module). Prefix with volatility3.plugins. unless
        # the caller already passed a fully-qualified override.
        if not plugin_path.startswith("volatility3."):
            plugin_path = f"volatility3.plugins.{plugin_path}"
        module_name, class_name = plugin_path.rsplit(".", 1)
        plugin_class = getattr(
            __import__(module_name, fromlist=[class_name]), class_name
        )

        automagics = automagic.choose_automagic(self._automagics, plugin_class)
        constructed = vol_plugins.construct_plugin(
            self._context,
            automagics,
            plugin_class,
            base_config_path="plugins",
            progress_callback=None,
            open_method=None,
        )
        effective_config = {**PLUGIN_CONFIG.get(plugin_key, {}), **plugin_config}
        for key, value in effective_config.items():
            constructed.config[key] = value

        columns: list[str] = []
        rows: list[dict[str, Any]] = []

        def _visitor(node, accumulator):
            row = {}
            for i, column in enumerate(constructed.generator_columns if hasattr(
                constructed, "generator_columns"
            ) else []):
                row[column] = node.values[i]
            accumulator.append(row)

        treegrid = constructed.run()
        columns = [c.name for c in treegrid.columns]

        def visitor(node, _accumulator):
            row = {columns[i]: v for i, v in enumerate(node.values)}
            rows.append(row)
            return _accumulator

        treegrid.visit(node=None, function=visitor, initial_accumulator=None)

        logger.info(
            "Plugin %s produced %d rows for image %s",
            plugin_key, len(rows), self.image_path,
        )
        return PluginResult(plugin_name=plugin_key, columns=columns, rows=rows)

    def run_all(self, plugin_keys: list[str] | None = None) -> dict[str, PluginResult]:
        """Run several plugins and return their results keyed by name."""
        keys = plugin_keys or list(DEFAULT_PLUGINS.keys())
        results = {}
        for key in keys:
            try:
                results[key] = self.run_plugin(key)
            except Exception:  # noqa: BLE001 - one plugin failing shouldn't abort the run
                logger.exception("Plugin %s failed on image %s", key, self.image_path)
        return results


def load_mock_results(fixture: dict[str, list[dict[str, Any]]]) -> dict[str, PluginResult]:
    """
    Build PluginResult objects from a plain dict of {plugin_name: [rows]},
    matching the shape used in tests/fixtures/mock_volatility_rows.py.
    This lets normalizer/graph_builder/inference code run and be tested
    end-to-end without volatility3 installed or a real memory image.
    """
    results = {}
    for plugin_name, rows in fixture.items():
        columns = list(rows[0].keys()) if rows else []
        results[plugin_name] = PluginResult(
            plugin_name=plugin_name, columns=columns, rows=rows
        )
    return results
