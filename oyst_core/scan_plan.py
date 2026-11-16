"""What a scan would look at, for ``scan --dry-run --json`` (the plan document)."""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

from oyst_core.plan import change, plan_doc

# Counting is a courtesy: stop after this many files or seconds and say "at least".
_COUNT_LIMIT = 200_000
_COUNT_SECONDS = 3.0


def count_files(root: str) -> tuple[int, bool]:
    """Files under `root` (not following links) and whether the count is complete."""
    deadline = time.monotonic() + _COUNT_SECONDS
    total = 0
    stack = [root]
    while stack:
        try:
            with os.scandir(stack.pop()) as it:
                for entry in it:
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(entry.path)
                    elif entry.is_file(follow_symlinks=False):
                        total += 1
                if total >= _COUNT_LIMIT or time.monotonic() > deadline:
                    return total, False
        except OSError:
            continue
    return total, True


def scan_plan(
    privilege: dict[str, Any],
    packs: list[str],
    paths: list[str],
    *,
    walk: bool = True,
) -> dict[str, Any]:
    """The preflight document of a scan plus `summary`, `changes` and `would_refuse`.

    A scan changes nothing unless it quarantines, so the changes list what it will
    read (scanners and folders) and what will ask for a password.
    """
    changes: list[dict[str, Any]] = []
    asks = {str(s.get("id")) for s in privilege.get("privileged", [])}
    for step in privilege.get("privileged", []):
        changes.append(
            change(
                str(step.get("label") or step.get("id")),
                group="Needs your password",
                detail="Runs as root through oysterAV's helper",
            ),
        )
    for name in packs:
        if name not in asks:
            changes.append(change(name, group="Scanners", detail="Runs as you"))
    missing = [p for p in paths if not Path(p).exists()]
    total = 0
    exact = True
    for path in paths:
        if path in missing:
            continue
        if walk and Path(path).is_dir():
            count, done = count_files(path)
            total += count
            exact = exact and done
            detail = f"{count:,}{'' if done else '+'} files"
        else:
            total += 1
            detail = "1 file"
        changes.append(change(path, group="Looks at", detail=detail))
    summary = f"{total:,}{'' if exact else '+'} files, {len(packs)} scanner(s)"
    if missing:
        reason = f"Not found: {', '.join(missing)}"
        return {**privilege, **plan_doc(summary, changes, would_refuse=True, reason=reason)}
    return {**privilege, **plan_doc(summary, changes)}
