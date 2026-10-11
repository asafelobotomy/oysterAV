"""Guards against quarantining scanner binaries / signature packs."""

from __future__ import annotations

from pathlib import Path

from oyst_core.packs.maldet_parse import is_maldet_self_signature_path, maldet_install_prefixes
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
    """Return a reason string if path must not be auto-quarantined, else None.

    Only real install/runtime locations are protected: a file merely *named*
    ``clamscan`` in ~/Downloads, or under some ``*/maldetect/sigs/`` elsewhere,
    is quarantined like any other detection.
    """
    expanded = Path(path).expanduser()
    try:
        resolved = expanded.resolve()
    except OSError:
        resolved = expanded
    text = str(resolved)
    for prefix in _TRUSTED_BIN_PREFIXES:
        if text.startswith(prefix) and "/" not in text[len(prefix) :]:
            return f"refusing to quarantine trusted bindir path: {text}"
    try:
        if resolved.is_relative_to(runtime_root().resolve()) or resolved.is_relative_to(
            runtime_bin_dir().resolve()
        ):
            return f"refusing to quarantine oysterAV runtime path: {text}"
    except (OSError, ValueError, RuntimeError):
        pass
    for root in maldet_install_prefixes():
        if resolved.parent == root and resolved.name in QUARANTINE_BASENAME_DENYLIST:
            return f"refusing to quarantine scanner binary: {text}"
    if is_maldet_self_signature_path(text):
        return f"refusing to quarantine maldet signature pack path: {text}"
    return None
