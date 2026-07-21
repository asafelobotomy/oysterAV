"""Guards against quarantining scanner binaries / signature packs."""

from __future__ import annotations

from pathlib import Path

from oyst_core.packs.maldet_parse import is_maldet_self_signature_path
from oyst_core.runtime.manifest import runtime_bin_dir, runtime_root

QUARANTINE_BASENAME_DENYLIST = frozenset(
    {
        "clamdscan",
        "clamscan",
        "clamd",
        "freshclam",
        "maldet",
        "rkhunter",
        "chkrootkit",
        "lynis",
        "unhide",
        "unhide-linux",
        "fangfrisch",
        "oyst-helper",
        "oyst-cli",
    }
)

_TRUSTED_BIN_PREFIXES = (
    "/usr/bin/",
    "/usr/sbin/",
    "/bin/",
    "/sbin/",
    "/usr/local/bin/",
    "/usr/local/sbin/",
)


def quarantine_refuse_reason(path: str) -> str | None:
    """Return a reason string if path must not be auto-quarantined, else None."""
    expanded = Path(path).expanduser()
    try:
        resolved = expanded.resolve()
    except OSError:
        resolved = expanded
    name = resolved.name
    if name in QUARANTINE_BASENAME_DENYLIST:
        return f"refusing to quarantine scanner binary basename: {name}"
    text = str(resolved)
    for prefix in _TRUSTED_BIN_PREFIXES:
        if text.startswith(prefix) and "/" not in text[len(prefix) :]:
            return f"refusing to quarantine trusted bindir path: {text}"
    try:
        runtime = runtime_root().resolve()
        if resolved.is_relative_to(runtime / "bin") or resolved.is_relative_to(
            runtime_bin_dir().resolve()
        ):
            return f"refusing to quarantine runtime bindir path: {text}"
    except (OSError, ValueError, RuntimeError):
        pass
    if is_maldet_self_signature_path(text):
        return f"refusing to quarantine maldet signature pack path: {text}"
    return None
