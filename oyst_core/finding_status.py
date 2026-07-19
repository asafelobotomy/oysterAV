"""Open vs handled finding status helpers (no models import — avoid cycles)."""

from __future__ import annotations

from typing import Any

MALWARE_PACKS = frozenset({"clamav", "maldet"})


def finding_is_open(finding: Any) -> bool:
    if isinstance(finding, dict):
        return not bool(finding.get("quarantined")) and not bool(finding.get("resolved"))
    return not bool(getattr(finding, "quarantined", False)) and not bool(
        getattr(finding, "resolved", False)
    )


def open_findings_count(findings: list[Any]) -> int:
    return sum(1 for f in findings if finding_is_open(f))


def handled_findings_count(findings: list[Any]) -> int:
    return len(findings) - open_findings_count(findings)


def scan_is_clean(findings: list[Any]) -> bool:
    """True when there are no open (unhandled) findings."""
    return open_findings_count(findings) == 0


def summarize_report_badge(findings: list[Any], *, clean: bool | None = None) -> str:
    """Badge text for history list / report summary."""
    _ = clean
    total = len(findings)
    if total == 0:
        return "Clean"
    open_n = open_findings_count(findings)
    if open_n == 0:
        return f"{total} handled" if total != 1 else "1 handled"
    return f"{open_n} finding(s)"
