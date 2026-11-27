"""The settings a front end may show, with what each one accepts.

``oyst-cli config show --json`` prints the current value of each key next to this
schema, so a settings page needs no knowledge of oysterAV's config model: it draws a
row per entry and hands the person's choice to ``config set``, which validates it.
"""

from __future__ import annotations

from typing import Any

from oyst_core.config_io import config_path, load_config
from oyst_core.security_news_sources import ALLOWED_MAX_AGE_DAYS
from oyst_core.ui_theme import UI_THEME_IDS

# kind: bool | choice | int | text | list (list: comma-separated on `config set`).
_PROFILES = ["quick", "full", "integrity", "suite"]
_BACKENDS = ["auto", "clamd", "clamscan"]

SCHEMA: tuple[dict[str, Any], ...] = (
    # --- Scanning
    {
        "key": "scan.profile",
        "group": "Scanning",
        "kind": "choice",
        "choices": _PROFILES,
        "label": "Default scan",
        "help": "What a scan with no profile runs.",
    },
    {
        "key": "scan.backend",
        "group": "Scanning",
        "kind": "choice",
        "choices": _BACKENDS,
        "label": "ClamAV engine",
        "help": "clamd is faster when its daemon runs; clamscan always works.",
    },
    {
        "key": "scan.clamav_profile",
        "group": "Scanning",
        "kind": "choice",
        "choices": ["full", "linux-only"],
        "label": "File types",
        "help": "Linux-only skips Windows executables.",
    },
    {
        "key": "scan.max_filesize",
        "group": "Scanning",
        "kind": "text",
        "label": "Biggest file scanned",
        "help": "Like 25M or 100K.",
    },
    {
        "key": "scan.max_recursion",
        "group": "Scanning",
        "kind": "int",
        "min": 1,
        "label": "Archive depth",
        "help": "How deep to look inside archives in archives.",
    },
    {
        "key": "scan.max_files",
        "group": "Scanning",
        "kind": "int",
        "min": 1,
        "label": "Files per archive",
        "help": "Stops a zip bomb from running forever.",
    },
    {
        "key": "scan.apply_limits_to",
        "group": "Scanning",
        "kind": "choice",
        "choices": ["quick", "all"],
        "label": "Apply these limits to",
        "help": "Only quick scans, or every scan.",
    },
    {
        "key": "scan.exclude_dirs",
        "group": "Scanning",
        "kind": "list",
        "path": True,
        "label": "Folders to skip",
        "help": "Absolute paths, or starting with ~/.",
    },
    {
        "key": "clamav.ignore_sigs",
        "group": "Scanning",
        "kind": "list",
        "label": "Ignored signatures",
        "help": "Names of signatures that give false alarms.",
    },
    # --- Quarantine
    {
        "key": "quarantine.auto",
        "group": "Quarantine",
        "kind": "bool",
        "label": "Quarantine what scans find",
        "help": "Move infected files to the vault automatically.",
    },
    {
        "key": "quarantine.secure_wipe",
        "group": "Quarantine",
        "kind": "bool",
        "label": "Overwrite deleted files",
        "help": "Best effort: an SSD may keep the old blocks.",
    },
    # --- Real-time protection
    {
        "key": "clamonacc.enabled",
        "group": "Protection",
        "kind": "bool",
        "label": "Scan files as they are opened",
        "help": "ClamAV on-access, for the folders below.",
    },
    {
        "key": "clamonacc.prevention",
        "group": "Protection",
        "kind": "bool",
        "label": "Block infected files",
        "help": "Refuse to open a file that is found infected.",
    },
    {
        "key": "clamonacc.paths",
        "group": "Protection",
        "kind": "list",
        "path": True,
        "label": "Watched folders",
        "help": "",
    },
    {
        "key": "clamonacc.exclude_paths",
        "group": "Protection",
        "kind": "list",
        "path": True,
        "label": "Never watched",
        "help": "",
    },
    {
        "key": "maldet_monitor.enabled",
        "group": "Protection",
        "kind": "bool",
        "label": "Linux Malware Detect monitor",
        "help": "Watches for new files with maldet.",
    },
    # --- Signatures and runtime
    {
        "key": "runtime.mode",
        "group": "Updates",
        "kind": "choice",
        "choices": ["full", "lite"],
        "label": "Where scanners come from",
        "help": "Full keeps its own copies; lite uses your distribution's packages.",
    },
    {
        "key": "runtime.auto_update_signatures",
        "group": "Updates",
        "kind": "bool",
        "label": "Update signatures automatically",
        "help": "Full mode only.",
    },
    {
        "key": "fangfrisch.providers",
        "group": "Updates",
        "kind": "list",
        "choices": ["sanesecurity", "interserver", "malwarepatrol", "securiteinfo"],
        "label": "Extra signature feeds",
        "help": "Unofficial signatures, refreshed with fangfrisch.",
    },
    # --- Rootkit and audit scanners
    {
        "key": "rkhunter.skip_keypress",
        "group": "System scans",
        "kind": "bool",
        "label": "rkhunter without prompts",
        "help": "",
    },
    {
        "key": "rkhunter.disable_tests",
        "group": "System scans",
        "kind": "list",
        "label": "rkhunter tests to skip",
        "help": "Test names, like suspscan.",
    },
    {
        "key": "lynis.quick",
        "group": "System scans",
        "kind": "bool",
        "label": "Quick Lynis audit",
        "help": "Skips the pauses between tests.",
    },
    # --- News and the app itself
    {
        "key": "ui.security_news",
        "group": "Security news",
        "kind": "bool",
        "label": "Show security news",
        "help": "Advisories from your distribution and others.",
    },
    {
        "key": "ui.security_news_max_age_days",
        "group": "Security news",
        "kind": "choice",
        "choices": [str(d) for d in ALLOWED_MAX_AGE_DAYS],
        "label": "News newer than (days)",
        "help": "",
    },
    {
        "key": "ui.run_at_startup",
        "group": "App",
        "kind": "bool",
        "label": "Start oysterAV at login",
        "help": "",
    },
    {
        "key": "ui.start_minimized",
        "group": "App",
        "kind": "bool",
        "label": "Start minimised",
        "help": "",
    },
    {
        "key": "ui.minimize_to_tray",
        "group": "App",
        "kind": "bool",
        "label": "Keep running in the tray",
        "help": "",
    },
    {
        "key": "ui.theme",
        "group": "App",
        "kind": "choice",
        "choices": list(UI_THEME_IDS),
        "label": "Colour theme",
        "help": "uQ follows the active uQ theme live; the others are fixed.",
    },
)

KEYS: frozenset[str] = frozenset(item["key"] for item in SCHEMA)


def _value(flat: dict[str, Any], key: str) -> Any:
    cur: Any = flat
    for part in key.split("."):
        cur = cur[part]
    return cur


def show() -> dict[str, Any]:
    """Current values of every key in SCHEMA, the schema, and the config file's path."""
    flat = load_config().model_dump()
    values = {item["key"]: _value(flat, item["key"]) for item in SCHEMA}
    for item in SCHEMA:  # a choice is always text, so the page can find it in `choices`
        if item["kind"] == "choice":
            values[item["key"]] = str(values[item["key"]])
    return {
        "path": str(config_path()),
        "values": values,
        "schema": [dict(item) for item in SCHEMA],
    }
