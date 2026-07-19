"""Export scan history reports to JSON or Markdown."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

from oyst_core.events import EventLog
from oyst_core.finding_status import handled_findings_count, open_findings_count

ExportFormat = Literal["json", "md"]


def _normalize_format(fmt: str) -> ExportFormat:
    cleaned = fmt.strip().lower().lstrip(".")
    if cleaned in {"json", "md", "markdown"}:
        return "json" if cleaned == "json" else "md"
    raise ValueError(f"unsupported export format: {fmt} (use json or md)")


def format_scan_markdown(scan: dict[str, Any]) -> str:
    """Render one scan result as Markdown."""
    job_id = str(scan.get("job_id") or "?")
    profile = str(scan.get("profile") or "?")
    state = str(scan.get("state") or "completed")
    clean = bool(scan.get("clean", True))
    findings_raw = scan.get("findings")
    findings: list[Any] = findings_raw if isinstance(findings_raw, list) else []
    paths_raw = scan.get("paths")
    paths: list[Any] = paths_raw if isinstance(paths_raw, list) else []
    errors_raw = scan.get("pack_errors")
    errors: list[Any] = errors_raw if isinstance(errors_raw, list) else []
    open_n = open_findings_count(findings)
    handled_n = handled_findings_count(findings)

    lines = [
        f"# oysterAV scan report — {job_id}",
        "",
        f"- **Profile:** {profile}",
        f"- **State:** {state}",
        f"- **Started:** {scan.get('started_at') or '—'}",
        f"- **Finished:** {scan.get('finished_at') or '—'}",
        f"- **Clean (no open findings):** {'yes' if clean else 'no'}",
        f"- **Findings:** {len(findings)} total · {open_n} open · {handled_n} handled",
        f"- **Paths:** {', '.join(str(p) for p in paths) if paths else '—'}",
        "",
    ]
    if findings:
        lines.append("## Findings")
        lines.append("")
        for idx, finding in enumerate(findings, start=1):
            if not isinstance(finding, dict):
                lines.append(f"{idx}. {finding}")
                continue
            pack = finding.get("pack") or "?"
            severity = finding.get("severity") or "?"
            threat = finding.get("threat_name") or ""
            path = finding.get("path") or ""
            message = finding.get("message") or threat or "Finding"
            flags: list[str] = []
            if finding.get("quarantined"):
                flags.append("quarantined")
            if finding.get("resolved"):
                flags.append("resolved")
            flag_txt = f" ({', '.join(flags)})" if flags else ""
            lines.append(f"### {idx}. [{severity}] {pack}{flag_txt}")
            lines.append("")
            lines.append(str(message))
            if path:
                lines.append(f"- Path: `{path}`")
            if threat:
                lines.append(f"- Threat: `{threat}`")
            lines.append("")
    else:
        lines.extend(["## Findings", "", "No findings.", ""])

    if errors:
        lines.append("## Pack errors")
        lines.append("")
        for err in errors:
            if isinstance(err, dict):
                pack = err.get("pack") or "?"
                msg = err.get("error") or ""
                lines.append(f"- **{pack}:** {msg}" if msg else f"- **{pack}**")
            else:
                lines.append(f"- {err}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def format_scans_markdown(scans: list[dict[str, Any]]) -> str:
    if not scans:
        return "# oysterAV scan reports\n\nNo reports.\n"
    parts = [f"# oysterAV scan reports ({len(scans)})\n"]
    for scan in scans:
        body = format_scan_markdown(scan)
        # Drop the leading H1 from each section when combining; keep as H2.
        body_lines = body.splitlines()
        if body_lines and body_lines[0].startswith("# "):
            body_lines[0] = "## " + body_lines[0][2:]
        parts.append("\n".join(body_lines))
    return "\n".join(parts).rstrip() + "\n"


def export_scan_to_path(
    job_id: str,
    path: str | Path,
    *,
    fmt: str = "json",
) -> dict[str, Any]:
    export_fmt = _normalize_format(fmt)
    scan = EventLog().get_scan(job_id)
    if scan is None:
        return {"ok": False, "error": f"scan not found: {job_id}"}
    target = Path(path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    if export_fmt == "json":
        target.write_text(json.dumps(scan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    else:
        target.write_text(format_scan_markdown(scan), encoding="utf-8")
    return {
        "ok": True,
        "path": str(target),
        "format": export_fmt,
        "job_id": job_id,
        "count": 1,
    }


def export_all_scans_to_path(
    path: str | Path,
    *,
    fmt: str = "json",
    limit: int = 500,
) -> dict[str, Any]:
    export_fmt = _normalize_format(fmt)
    scans = EventLog().list_full_scans(limit=limit)
    target = Path(path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    if export_fmt == "json":
        target.write_text(json.dumps(scans, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    else:
        target.write_text(format_scans_markdown(scans), encoding="utf-8")
    return {
        "ok": True,
        "path": str(target),
        "format": export_fmt,
        "count": len(scans),
    }
