"""CLI progress reporters for install/remove operations."""

from __future__ import annotations

import json
import sys

from oyst_core.runtime.progress import ProgressCallback


def resolve_cli_progress(*, show_progress: bool, json_mode: bool) -> ProgressCallback | None:
    """Progress for long install/remove ops: human stderr by default; quiet with ``--json``."""
    callback = make_cli_progress(show_progress=show_progress, json_mode=json_mode)
    if callback is None and not json_mode:
        return make_cli_progress(show_progress=False, json_mode=False)
    return callback


def make_cli_progress(*, show_progress: bool, json_mode: bool) -> ProgressCallback | None:
    """Return a progress callback, or None when progress output is disabled.

    - `--progress`: NDJSON lines on stderr (`{"stage","percent"}`)
    - human (non-json): overwrite-style status on stderr
    - `--json` without `--progress`: no progress (clean stdout JSON only)
    """
    if not show_progress and json_mode:
        return None

    last_line_len = 0

    def report(stage: str, percent: int) -> None:
        nonlocal last_line_len
        percent = max(0, min(100, int(percent)))
        if show_progress:
            print(
                json.dumps({"stage": stage, "percent": percent}, separators=(",", ":")),
                file=sys.stderr,
                flush=True,
            )
            return
        text = f"{stage}… {percent}%"
        pad = max(0, last_line_len - len(text))
        sys.stderr.write(f"\r{text}{' ' * pad}")
        sys.stderr.flush()
        last_line_len = len(text)
        if percent >= 100:
            sys.stderr.write("\n")
            sys.stderr.flush()
            last_line_len = 0

    return report
