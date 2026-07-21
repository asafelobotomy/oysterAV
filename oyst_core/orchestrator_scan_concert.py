"""Orchestrator helpers for scan-concert (privileged packs, one polkit)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from oyst_core.models import Finding, FindingSeverity, PackError
from oyst_core.privilege import (
    PRIVILEGED_SCAN_PACKS,
    build_scan_privileged_plan,
    run_privilege_concert,
)
from oyst_core.registry import PackRegistry


def ingest_scan_concert_steps(
    steps: list[dict[str, Any]],
    registry: PackRegistry,
) -> tuple[list[Finding], list[PackError]]:
    """Parse concert step reports into findings / pack errors."""
    findings: list[Finding] = []
    errors: list[PackError] = []
    for step in steps:
        name = str(step.get("pack") or "")
        if not name and str(step.get("step", "")).startswith("scan-"):
            name = str(step.get("step", ""))[len("scan-") :]
        if name not in PRIVILEGED_SCAN_PACKS:
            continue
        if step.get("ok") is False:
            errors.append(
                PackError(pack=name, error=str(step.get("message") or "failed")),
            )
            continue
        report = step.get("report_path")
        if not report:
            continue
        path = Path(str(report))
        try:
            output = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            errors.append(PackError(pack=name, error=f"cannot read report: {exc}"))
            continue
        pack = registry.get(name)
        if pack is None:
            errors.append(PackError(pack=name, error="unknown pack"))
            continue
        try:
            if name == "lynis":
                findings.extend(_lynis_findings_from_output(output))
            else:
                parse = getattr(pack, "parse_findings", None)
                if not callable(parse):
                    errors.append(PackError(pack=name, error="no parse_findings"))
                    continue
                findings.extend(parse(output))
        except Exception as exc:  # noqa: BLE001
            errors.append(PackError(pack=name, error=str(exc)))
    return findings, errors


def _lynis_findings_from_output(output: str) -> list[Finding]:
    match = re.search(r"Hardening index\s*:\s*(\d+)", output)
    score = int(match.group(1)) if match else None
    message = "Hardening audit completed"
    if score is not None:
        message = f"Hardening index: {score}"
    severity = FindingSeverity.INFO
    if isinstance(score, int) and score < 65:
        severity = FindingSeverity.MEDIUM
    return [
        Finding(
            pack="lynis",
            path="system",
            threat_name=f"hardening-index:{score}" if score is not None else "hardening-audit",
            severity=severity,
            message=message,
            raw_line=output[:500],
        ),
    ]


def run_privileged_scan_concert(
    *,
    job_id: str,
    privileged_packs: list[str],
    registry: PackRegistry,
) -> tuple[list[Finding], list[PackError], list[dict[str, Any]]]:
    """One scan-concert pkexec for privileged packs; return findings/errors/steps."""
    if not privileged_packs:
        return [], [], []
    plan = build_scan_privileged_plan(privileged_packs, job_id=job_id)
    steps = run_privilege_concert(plan, timeout=7200)
    findings, errors = ingest_scan_concert_steps(steps, registry)
    return findings, errors, steps


__all__ = [
    "ingest_scan_concert_steps",
    "run_privileged_scan_concert",
]
