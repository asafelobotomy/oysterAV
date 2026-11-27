"""clamscan output: findings, per-file progress, and a quick file count for a progress total."""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from pathlib import Path

from oyst_core.models import Finding, FindingSeverity

_NOT_FILE_PREFIXES = ("ERROR:", "WARNING:", "LibClamAV", "----------- SCAN SUMMARY")


def is_file_line(line: str) -> bool:
    """One scanned file: ``<path>: OK``, ``<path>: <threat> FOUND``, ``<path>: Empty file``..."""
    return ": " in line and line.startswith("/") and not line.startswith(_NOT_FILE_PREFIXES)


def keep_line(line: str) -> bool:
    """What the parser needs: everything but the millions of clean-file lines."""
    return not line.endswith(": OK")


def count_files(paths: list[str], excluded: list[str], budget_s: float = 20.0) -> int | None:
    """Files clamscan -r will visit (no symlinks followed, excluded dirs skipped), or None
    when counting takes longer than ``budget_s`` (the scan then shows a running count)."""
    stop = time.monotonic() + budget_s
    skip = {str(Path(d)) for d in excluded}
    total = 0
    for raw in paths:
        root = Path(raw).expanduser()
        if root.is_file():
            total += 1
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [d for d in dirnames if os.path.join(dirpath, d) not in skip]
            total += len(filenames)
            if time.monotonic() > stop:
                return None
    return total


def parse_clamscan_stdout(pack: str, stdout: str) -> list[Finding]:
    """Parse ``<path>: <threat> FOUND`` lines from clamscan/clamdscan stdout.

    Paths may contain ``:`` (split on the *last* ``": "``) and newlines: a
    filename with an embedded newline prints as orphan line(s) followed by
    the result line, so orphans are re-joined onto the next result line's
    path. Only lines that *end* in `` FOUND`` are detections.
    """
    findings: list[Finding] = []
    pending: list[str] = []
    for line in stdout.split("\n"):
        if line.startswith("----------- SCAN SUMMARY"):
            break
        head, sep, status = line.rpartition(": ")
        if not sep or not head:
            if line:
                pending.append(line)
            continue
        fpath = "\n".join([*pending, head])
        pending = []
        if not status.endswith(" FOUND"):
            continue
        threat = status[: -len(" FOUND")].strip()
        findings.append(
            Finding(
                pack=pack,
                path=fpath,
                threat_name=threat or "unknown",
                severity=FindingSeverity.HIGH,
                message=line.strip(),
                raw_line=line,
            )
        )
    return findings


def file_counter(
    on_progress: Callable[[int, int | None], None], total: int | None
) -> Callable[[str], None]:
    """A clamscan line hook: counts scanned files and passes (done, total) on."""
    seen = [0]
    on_progress(0, total)

    def on_line(line: str) -> None:
        if is_file_line(line):
            seen[0] += 1
            on_progress(seen[0], total)

    return on_line
