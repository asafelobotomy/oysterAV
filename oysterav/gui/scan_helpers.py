"""Pure helpers for Scan tab pack result cards (no GTK)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from enum import StrEnum
from typing import Any

from oyst_core.models import PROFILE_AUDIT_PACKS, PROFILE_PACKS, ScanProfile

# Friendly card titles + one-line purpose (Scan Results UX).
PACK_CARD_TITLES: dict[str, str] = {
    "clamav": "ClamAV",
    "maldet": "Malware Detect",
    "rkhunter": "Rootkit Hunter",
    "chkrootkit": "chkrootkit",
    "unhide": "Unhide",
    "lynis": "Lynis",
}

PACK_CARD_PURPOSE: dict[str, str] = {
    "clamav": "Finds malware in files",
    "maldet": "Finds malware in web and shared folders",
    "rkhunter": "Checks for rootkits and changed system files",
    "chkrootkit": "Looks for known rootkit signatures",
    "unhide": "Finds hidden processes and network ports",
    "lynis": "Reviews hardening and security settings",
}


class PackCardState(StrEnum):
    IDLE = "idle"
    EXCLUDED = "excluded"  # not in selected profile (pre-scan preview)
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"  # finished this pack; job still running
    SKIPPED = "skipped"
    CLEAN = "clean"
    THREATS = "threats"
    ERROR = "error"


def pack_card_title(pack: str) -> str:
    return PACK_CARD_TITLES.get(pack, pack)


def pack_card_purpose(pack: str) -> str:
    return PACK_CARD_PURPOSE.get(pack, "")


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


def pack_progress_status_text(
    expected: Sequence[str],
    current_pack: str,
    *,
    fallback: str = "Scanning…",
) -> str:
    """Scan Progress line: ``Pack 2 of 4 · Rootkit Hunter``."""
    if not current_pack:
        return fallback
    title = pack_card_title(current_pack)
    if not expected:
        return f"Scanning {title}"
    try:
        idx = list(expected).index(current_pack) + 1
    except ValueError:
        return f"Scanning {title}"
    return f"Pack {idx} of {len(expected)} · {title}"


def pack_card_progress_fraction(
    pack: str,
    state: PackCardState,
    expected: Sequence[str],
    overall_percent: float,
) -> float | None:
    """Per-card fill 0..1, or None to hide the bar (idle / unused packs).

    Job status percent is overall (pack steps). Map the active pack into its
    slice so the card fills left→right while that pack runs, then stays full.
    """
    if state in (PackCardState.IDLE, PackCardState.EXCLUDED, PackCardState.SKIPPED):
        return None
    if state in (
        PackCardState.DONE,
        PackCardState.CLEAN,
        PackCardState.THREATS,
        PackCardState.ERROR,
    ):
        return 1.0
    if state is PackCardState.PENDING:
        return 0.0
    if state is PackCardState.RUNNING:
        names = list(expected)
        n = max(len(names), 1)
        try:
            idx = names.index(pack)
        except ValueError:
            return 0.12
        start = (idx / n) * 100.0
        end = ((idx + 1) / n) * 100.0
        span = max(end - start, 1e-6)
        local = (float(overall_percent) - start) / span
        # Visible motion while running; never claim complete until DONE.
        return min(0.92, max(0.08, local))
    return None


def advance_pack_card_states(
    expected: Sequence[str],
    active_pack: str,
    states: Mapping[str, PackCardState],
) -> dict[str, PackCardState]:
    """Mark the active pack Running; promote previous Running → Done."""
    out = dict(states)
    if not active_pack:
        return out
    for name in expected:
        if name == active_pack:
            out[name] = PackCardState.RUNNING
        elif out.get(name) == PackCardState.RUNNING:
            out[name] = PackCardState.DONE
    return out


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
