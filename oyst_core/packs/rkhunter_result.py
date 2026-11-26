"""Interpret rkhunter exit codes and output (shared by the pack and the root helper).

rkhunter --update exits 0 when nothing changed, 2 when it downloaded new data
files and 1 on a download error (rkhunter(8)). Treating 2 as a failure made
"Update all" report a failure every time rkhunter actually updated something.

rkhunter 1.4.6 also predates grep 3.8, so every run prints dozens of
"grep: warning: stray \\" and "egrep is obsolescent" lines on stderr. Those are
noise, not the result, and drowned the real message in the UI.
"""

from __future__ import annotations

import re

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_NOISE_PREFIXES = ("grep: warning:", "egrep: warning:", "fgrep: warning:")

UPDATE_NO_CHANGE = 0
UPDATE_DOWNLOAD_ERROR = 1
UPDATE_UPDATED = 2


def clean_rkhunter_output(text: str) -> str:
    """Drop grep/egrep deprecation noise and colour codes; keep the real lines."""
    lines: list[str] = []
    for raw in (text or "").splitlines():
        line = _ANSI_RE.sub("", raw).rstrip()
        if line.lstrip().startswith(_NOISE_PREFIXES):
            continue
        lines.append(line)
    return "\n".join(lines).strip()


def rkhunter_detail(stdout: str, stderr: str) -> str:
    """Prefer stdout (rkhunter's report); fall back to stderr once noise is gone."""
    out = clean_rkhunter_output(stdout)
    err = clean_rkhunter_output(stderr)
    if out and err:
        return f"{out}\n{err}"
    return out or err


def update_ok(returncode: int) -> bool:
    """``rkhunter --update`` succeeded (no change or new data files)."""
    return returncode in (UPDATE_NO_CHANGE, UPDATE_UPDATED)


def update_summary(returncode: int, detail: str) -> str:
    if returncode == UPDATE_UPDATED:
        head = "rkhunter data files updated"
    elif returncode == UPDATE_NO_CHANGE:
        head = "rkhunter data files already current"
    elif returncode == UPDATE_DOWNLOAD_ERROR:
        head = "rkhunter could not download data files (mirror unreachable?)"
    else:
        head = f"rkhunter --update failed (exit {returncode})"
    return f"{head}\n{detail}".strip() if detail else head


__all__ = [
    "UPDATE_DOWNLOAD_ERROR",
    "UPDATE_NO_CHANGE",
    "UPDATE_UPDATED",
    "clean_rkhunter_output",
    "rkhunter_detail",
    "update_ok",
    "update_summary",
]
