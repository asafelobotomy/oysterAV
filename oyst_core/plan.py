"""One preview document for every ``--dry-run --json`` that changes something.

uQ Settings renders it as a grouped confirmation sheet (``preview`` in a page's
``[[command]]``), so the window and the command line say the same thing::

    {"summary": "...", "changes": [{"group", "label", "detail", "bytes", "reversible"}],
     "would_refuse": false, "reason": ""}

Commands that already printed a dry-run document keep their own keys and add these.
"""

from __future__ import annotations

from typing import Any


def change(
    label: str,
    *,
    group: str = "",
    detail: str = "",
    size: int | None = None,
    reversible: bool | None = None,
) -> dict[str, Any]:
    """One entry of a plan; empty optional fields are left out."""
    entry: dict[str, Any] = {"label": label}
    if group:
        entry["group"] = group
    if detail:
        entry["detail"] = detail
    if size is not None:
        entry["bytes"] = int(size)
    if reversible is not None:
        entry["reversible"] = reversible
    return entry


def plan_doc(
    summary: str,
    changes: list[dict[str, Any]],
    *,
    would_refuse: bool = False,
    reason: str = "",
) -> dict[str, Any]:
    """The plan document; `reason` only matters when `would_refuse` is true."""
    return {
        "summary": summary,
        "changes": changes,
        "would_refuse": would_refuse,
        "reason": reason if would_refuse else "",
    }


def refused(reason: str) -> dict[str, Any]:
    """A plan for something oysterAV would turn down."""
    return plan_doc(reason, [], would_refuse=True, reason=reason)
