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


def merged_clamav_exclude_dirs() -> list[str]:
    """Config excludes plus oysterAV defaults."""
    cfg = load_config().scan.exclude_dirs
    defaults = default_scan_exclude_dirs()
    seen = {str(Path(p).expanduser()) for p in cfg}
    merged = [str(Path(p).expanduser()) for p in cfg]
    for path in defaults:
        if path not in seen:
            merged.append(path)
            seen.add(path)
    return merged


def maldet_ignore_paths_value() -> str:
    """Space-separated paths for LMD ignore_paths conf."""
    return " ".join(default_scan_exclude_dirs())
