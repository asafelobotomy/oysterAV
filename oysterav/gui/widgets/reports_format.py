"""Reports formatting helpers — status badges, duration, timestamps."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from oysterav.gui.widgets.common import parse_iso


def status_label(item: dict[str, Any]) -> tuple[str, str]:
    """Return (badge text, css class) for a history list row."""
    state = str(item.get("state") or "completed")
    if state == "cancelled":
        return ("Cancelled", "warning")
    findings = int(item.get("findings_count") or 0)
    open_n = item.get("open_findings_count")
    if open_n is None:
        open_n = 0 if bool(item.get("clean", True)) else findings
    else:
        open_n = int(open_n)
    if findings == 0:
        if item.get("has_errors"):
            return ("Errors", "warning")
        return ("Clean", "success")
    if open_n == 0:
        label = f"{findings} handled" if findings != 1 else "1 handled"
        return (label, "success")
    return (f"{open_n} finding(s)", "error")


def format_duration(started: object, finished: object) -> str:
    start = parse_iso(started if isinstance(started, (str, datetime)) else None)
    end = parse_iso(finished if isinstance(finished, (str, datetime)) else None)
    if start is None or end is None:
        return "—"
    seconds = max(0, int((end - start).total_seconds()))
    if seconds < 60:
        return f"{seconds}s"
    minutes = seconds // 60
    rem = seconds % 60
    if minutes < 60:
        return f"{minutes}m {rem}s"
    hours = minutes // 60
    return f"{hours}h {minutes % 60}m"


def format_timestamp(ts: object) -> str:
    dt = parse_iso(ts if isinstance(ts, (str, datetime)) else None)
    if dt is None:
        return "—"
    return dt.strftime("%Y-%m-%d %H:%M:%S")
