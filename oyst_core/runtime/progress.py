"""Progress reporting helpers for runtime install/remove."""

from __future__ import annotations

from collections.abc import Callable

type ProgressCallback = Callable[[str, int], None]


def emit_progress(on_progress: ProgressCallback | None, stage: str, percent: int) -> None:
    if on_progress is None:
        return
    on_progress(stage, max(0, min(100, int(percent))))


def map_span(
    on_progress: ProgressCallback | None,
    stage: str,
    local_percent: int,
    *,
    start: int,
    end: int,
) -> None:
    """Map a 0–100 local percent into [start, end] on the overall scale."""
    span = max(0, end - start)
    overall = start + (span * max(0, min(100, local_percent))) // 100
    emit_progress(on_progress, stage, overall)
