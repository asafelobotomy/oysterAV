"""Pure helpers for Scan tab pack result cards (no GTK)."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from oyst_core.models import PROFILE_AUDIT_PACKS, PROFILE_PACKS, ScanProfile


class PackCardState(StrEnum):
    IDLE = "idle"
    PENDING = "pending"
    RUNNING = "running"
    SKIPPED = "skipped"
    CLEAN = "clean"
    THREATS = "threats"
    ERROR = "error"


def expected_packs_for_profile(
    profile: ScanProfile,
    custom_packs: list[str] | None = None,
) -> list[str]:
    """Packs that will run for a profile (path packs + audit packs)."""
    if profile is ScanProfile.CUSTOM:
        return list(custom_packs or [])
    path_packs = list(PROFILE_PACKS.get(profile, []))
    audit = list(PROFILE_AUDIT_PACKS.get(profile, []))
    return path_packs + audit


def pack_result_summary(
    scan: dict[str, Any],
    pack: str,
    *,
    expected: list[str],
) -> tuple[PackCardState, list[dict[str, Any]], str]:
    """Derive card state, findings, and error text for one pack from a ScanResult dict."""
    if pack not in expected:
        return PackCardState.SKIPPED, [], ""
    raw_findings = scan.get("findings")
    findings_raw: list[Any] = list(raw_findings) if isinstance(raw_findings, list) else []
    findings = [f for f in findings_raw if isinstance(f, dict) and str(f.get("pack") or "") == pack]
    raw_errors = scan.get("pack_errors")
    errors_raw: list[Any] = list(raw_errors) if isinstance(raw_errors, list) else []
    error = ""
    for err in errors_raw:
        if isinstance(err, dict) and str(err.get("pack") or "") == pack:
            error = str(err.get("error") or "error")
            break
    if error:
        return PackCardState.ERROR, findings, error
    if findings:
        return PackCardState.THREATS, findings, ""
    return PackCardState.CLEAN, findings, ""
