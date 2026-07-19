"""Pure helpers for presenting scan findings (no GTK)."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from oyst_core.finding_status import summarize_report_badge
from oyst_core.packs.rkhunter_resolve import OVERLAY_PATH, RESOLVABLE_THREATS, plan_resolve

_INITIAL_FINDING_CAP = 100
_COLLAPSE_THRESHOLD = 3
_MALWARE_PACKS = frozenset({"clamav", "maldet"})


@dataclass(frozen=True)
class DisplayFinding:
    """One row after collapse/grouping for UI rendering."""

    pack: str
    message: str
    path: str
    threat_name: str
    severity: str
    count: int
    raw: dict[str, Any]


def normalize_findings(raw: object) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    return [f for f in raw if isinstance(f, dict)]


def pack_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    return dict(Counter(str(f.get("pack") or "?") for f in findings))


def severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    return dict(Counter(str(f.get("severity") or "medium").lower() for f in findings))


def format_pack_breakdown(counts: dict[str, int]) -> str:
    if not counts:
        return "none"
    parts = [f"{pack} {n}" for pack, n in sorted(counts.items(), key=lambda x: (-x[1], x[0]))]
    return " · ".join(parts)


def format_severity_breakdown(counts: dict[str, int]) -> str:
    if not counts:
        return "none"
    order = ("critical", "high", "medium", "low", "info")
    parts: list[str] = []
    for key in order:
        if key in counts:
            parts.append(f"{key} {counts[key]}")
    for key, n in sorted(counts.items()):
        if key not in order:
            parts.append(f"{key} {n}")
    return " · ".join(parts)


def summarize_findings_badge(findings: list[dict[str, Any]]) -> str:
    """Short badge text for list rows / cards (open vs handled aware)."""
    return summarize_report_badge(findings)


def collapse_findings(findings: list[dict[str, Any]]) -> list[DisplayFinding]:
    """Collapse identical pack+message rows when count exceeds threshold."""
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    order: list[tuple[str, str]] = []
    for finding in findings:
        pack = str(finding.get("pack") or "?")
        message = str(finding.get("message") or finding.get("threat_name") or "Finding").strip()
        key = (pack, message)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(finding)

    out: list[DisplayFinding] = []
    for key in order:
        items = groups[key]
        first = items[0]
        count = len(items)
        if count < _COLLAPSE_THRESHOLD:
            for item in items:
                out.append(_to_display(item, count=1))
        else:
            out.append(_to_display(first, count=count))
    return out


def _to_display(finding: dict[str, Any], *, count: int) -> DisplayFinding:
    message = str(finding.get("message") or finding.get("threat_name") or "Finding").strip()
    path = str(finding.get("path") or "")
    return DisplayFinding(
        pack=str(finding.get("pack") or "?"),
        message=message,
        path=path,
        threat_name=str(finding.get("threat_name") or ""),
        severity=str(finding.get("severity") or "medium"),
        count=count,
        raw=finding,
    )


def group_by_pack(rows: list[DisplayFinding]) -> list[tuple[str, list[DisplayFinding]]]:
    buckets: dict[str, list[DisplayFinding]] = {}
    order: list[str] = []
    for row in rows:
        if row.pack not in buckets:
            buckets[row.pack] = []
            order.append(row.pack)
        buckets[row.pack].append(row)
    return [(pack, buckets[pack]) for pack in order]


def apply_finding_cap(
    rows: list[DisplayFinding],
    *,
    cap: int = _INITIAL_FINDING_CAP,
    show_all: bool = False,
) -> tuple[list[DisplayFinding], int]:
    """Return (visible rows, hidden count)."""
    if show_all or len(rows) <= cap:
        return rows, 0
    return rows[:cap], len(rows) - cap


def is_quarantinable_path(path: str, pack: str) -> bool:
    if pack not in _MALWARE_PACKS:
        return False
    if not path or path == "system":
        return False
    try:
        return Path(path).expanduser().is_file()
    except OSError:
        return False


def finding_display_quarantined(
    finding: dict[str, Any] | DisplayFinding,
    *,
    vault_paths: set[str] | None = None,
) -> bool:
    raw = finding.raw if isinstance(finding, DisplayFinding) else finding
    if bool(raw.get("quarantined")):
        return True
    path = str(raw.get("path") or "")
    pack = str(raw.get("pack") or "")
    if pack in _MALWARE_PACKS and vault_paths and path in vault_paths:
        return True
    return False


def finding_display_resolved(
    finding: dict[str, Any] | DisplayFinding,
    *,
    overlay_text: str | None = None,
) -> bool:
    raw = finding.raw if isinstance(finding, DisplayFinding) else finding
    if bool(raw.get("resolved")):
        return True
    if str(raw.get("pack") or "") != "rkhunter":
        return False
    threat = str(raw.get("threat_name") or "")
    if threat not in RESOLVABLE_THREATS:
        return False
    try:
        plan = plan_resolve(
            threat,
            path=str(raw.get("path") or ""),
            message=str(raw.get("message") or ""),
        )
    except ValueError:
        return False
    text = overlay_text
    if text is None:
        try:
            text = OVERLAY_PATH.read_text(encoding="utf-8") if OVERLAY_PATH.is_file() else ""
        except OSError:
            text = ""
    needle = f"{plan.option}={plan.value}"
    return needle in text


def is_propupd_advisory(finding: dict[str, Any] | DisplayFinding) -> bool:
    if isinstance(finding, DisplayFinding):
        pack = finding.pack
        threat = finding.threat_name
        message = finding.message
    else:
        pack = str(finding.get("pack") or "")
        threat = str(finding.get("threat_name") or "")
        message = str(finding.get("message") or "")
    if pack != "rkhunter":
        return False
    if threat == "rkhunter-advisory":
        return True
    lower = message.lower()
    return "propupd" in lower or "property file" in lower


def is_resolvable_finding(finding: dict[str, Any] | DisplayFinding) -> bool:
    """True when Reports/Scan may offer a Resolve (rkhunter whitelist) button."""
    if isinstance(finding, DisplayFinding):
        pack = finding.pack
        threat = finding.threat_name
        path = finding.path
        message = finding.message
    else:
        pack = str(finding.get("pack") or "")
        threat = str(finding.get("threat_name") or "")
        path = str(finding.get("path") or "")
        message = str(finding.get("message") or "")
    if pack != "rkhunter" or threat not in RESOLVABLE_THREATS:
        return False
    if threat == "rkhunter-ssh":
        lower = message.lower()
        return "protocol" in lower or "permitrootlogin" in lower
    if not path or path == "system":
        return False
    try:
        return Path(path).expanduser().exists()
    except OSError:
        return False


def path_exists_for_copy(path: str) -> bool:
    if not path or path == "system" or path == "process":
        return False
    try:
        p = Path(path).expanduser()
        return p.exists()
    except OSError:
        return False
