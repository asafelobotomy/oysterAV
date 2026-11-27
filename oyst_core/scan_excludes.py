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


# Folders tools rebuild or re-download on their own, skipped when scan.skip_rebuildable is on.
# Names match at any depth; home paths only under the user's home.
REBUILDABLE_DIR_NAMES = (
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".gradle",
    ".next",
)
REBUILDABLE_HOME_DIRS = (
    ".cache/pip",
    ".cache/pip-audit",
    ".cache/uv",
    ".cache/go-build",
    ".cache/yarn",
    ".cache/pnpm",
    ".cache/mesa_shader_cache",
    ".cache/thumbnails",
    ".cargo/registry",
    ".rustup/toolchains",
    ".npm/_cacache",
    ".gradle/caches",
    ".m2/repository",
)


RUST_TARGET_REGEX = "/target/(debug|release|doc|tmp|[^/]+-unknown-[^/]+)(/|$)"


def rebuildable_dir_names() -> tuple[str, ...]:
    return REBUILDABLE_DIR_NAMES if load_config().scan.skip_rebuildable else ()


def rebuildable_exclude_regexes() -> list[str]:
    """clamscan --exclude-dir regexes for rebuildable folders (empty when the option is off).
    Cargo build output is matched by its layout (``target/debug``, ``target/release``...)."""
    names = rebuildable_dir_names()
    if not names:
        return []
    alternation = "|".join("".join(f"\\{c}" if c in _ERE_SPECIAL else c for c in n) for n in names)
    home = str(Path.home())
    out = [f"/({alternation})(/|$)", RUST_TARGET_REGEX]
    out.extend(clamav_exclude_dir_regex(f"{home}/{rel}") for rel in REBUILDABLE_HOME_DIRS)
    return out


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


def clamscan_exclude_regexes() -> list[str]:
    """Every clamscan --exclude-dir regex: configured and default folders, anchored and
    escaped so /opt never hits ~/x/options/, then the rebuildable folders when enabled."""
    out = [
        clamav_exclude_dir_regex(p)
        for p in (str(Path(raw).expanduser()) for raw in merged_clamav_exclude_dirs())
        if p and Path(p).is_absolute()
    ]
    return out + rebuildable_exclude_regexes()


def maldet_ignore_paths_value() -> str:
    """Space-separated paths for LMD ignore_paths conf."""
    return " ".join(default_scan_exclude_dirs())


def path_under_any(path: str, roots: list[str]) -> bool:
    """True when ``path`` equals or sits below one of ``roots`` (plain prefix, no regex)."""
    return any(path == root or path.startswith(root.rstrip("/") + "/") for root in roots)
