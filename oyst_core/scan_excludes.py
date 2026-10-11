"""Shared path excludes for scanners (maldet + ClamAV Home scans)."""

from __future__ import annotations

from pathlib import Path

from oyst_core.config import data_dir, load_config
from oyst_core.runtime.manifest import is_full_mode, runtime_maldet_prefix


def default_scan_exclude_dirs() -> list[str]:
    """Literal path prefixes scanners should skip (self-sigs, vault, temp)."""
    excludes: list[str] = []
    vault = load_config().vault_path().expanduser().resolve()
    excludes.append(str(vault))
    excludes.append(str(data_dir() / "quarantine"))
    if is_full_mode():
        prefix = runtime_maldet_prefix()
        excludes.append(str(prefix / "sigs"))
        excludes.append(str(prefix / "pub"))
    else:
        excludes.append("/usr/local/maldetect/sigs")
        excludes.append("/usr/local/maldetect/pub")
    seen: set[str] = set()
    out: list[str] = []
    for path in excludes:
        cleaned = str(Path(path).expanduser())
        if cleaned in seen:
            continue
        seen.add(cleaned)
        out.append(cleaned)
    return out


# POSIX ERE metacharacters (clamscan --exclude-dir is an extended regex).
_ERE_SPECIAL = frozenset(".[]()*+?{}|^$\\")


def clamav_exclude_dir_regex(path: str) -> str:
    """Anchored regex matching ``path`` and its subtree only (not ``/optional``)."""
    escaped = "".join(f"\\{ch}" if ch in _ERE_SPECIAL else ch for ch in path)
    return f"^{escaped}(/|$)"


def merged_clamav_exclude_dirs() -> list[str]:
    """Config excludes plus oysterAV defaults (absolute paths only)."""
    cfg = [str(Path(p).expanduser()) for p in load_config().scan.exclude_dirs]
    defaults = default_scan_exclude_dirs()
    seen: set[str] = set()
    merged: list[str] = []
    # Relative entries ("." / "cache") would match anywhere: drop legacy ones.
    for path in cfg:
        if Path(path).is_absolute() and path not in seen:
            merged.append(path)
            seen.add(path)
    for path in defaults:
        if path not in seen:
            merged.append(path)
            seen.add(path)
    return merged


def maldet_ignore_paths_value() -> str:
    """Space-separated paths for LMD ignore_paths conf."""
    return " ".join(default_scan_exclude_dirs())
