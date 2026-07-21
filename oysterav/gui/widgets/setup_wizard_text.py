"""Pure text / gate helpers for the first-time setup wizard."""

from __future__ import annotations

from typing import Any

from oyst_core.client import OystClient

PAGE_TITLES = (
    "Welcome",
    "Security packs",
    "Preferences",
    "Scheduling",
    "Host hardening",
    "Ready",
)


def format_check_summary(setup: dict[str, Any], *, running: bool = False) -> str:
    if running:
        return "Running doctor…"
    missing_required = list(setup.get("missing_required") or [])
    missing_recommended = list(setup.get("missing_recommended") or [])
    lines: list[str] = []
    if missing_required:
        lines.append(
            f"Required missing ({len(missing_required)}): {', '.join(missing_required)}",
        )
    else:
        lines.append("All required packs are installed.")
    if missing_recommended:
        lines.append(
            f"Recommended missing ({len(missing_recommended)}): {', '.join(missing_recommended)}",
        )
    elif not missing_required:
        lines.append("All recommended packs are installed.")
    return "\n".join(lines)


def format_ready_checklist(
    setup: dict[str, Any],
    *,
    bootstrap_ran: bool,
    schedule_installed: bool,
    auto_quarantine: bool,
    full_mode: bool,
    harden_ran: bool = False,
) -> str:
    """Concise Ready-page summary of what was done vs still optional."""
    missing = list(setup.get("missing_required") or [])
    skipped = "required_packs" in set(setup.get("skipped_steps") or [])
    if missing and skipped:
        packs_line = f"Required packs: skipped ({', '.join(missing)})"
    elif missing:
        packs_line = f"Required packs: still missing ({', '.join(missing)})"
    else:
        packs_line = "Required packs: installed"
    if bootstrap_ran:
        bootstrap_line = "Runtime / signatures: done"
    elif full_mode:
        bootstrap_line = "Runtime / signatures: not run (optional — Settings → Maintenance)"
    else:
        bootstrap_line = "Runtime / signatures: lite mode (host packages)"
    schedule_line = (
        "Scheduled scan: timer installed"
        if schedule_installed
        else "Scheduled scan: not installed (optional — Settings → Scheduling)"
    )
    harden_line = (
        "Host hardenings: applied (or soft-skipped)"
        if harden_ran
        else "Host hardenings: not run (optional — Host hardening page or setup run)"
    )
    quarantine_line = f"Auto-quarantine: {'on' if auto_quarantine else 'off'}"
    next_steps = (
        "Next: Scan tab · Settings → Real-time (paths + prevention) · "
        "Settings → Maintenance (Update all)"
    )
    return "\n".join(
        [
            packs_line,
            bootstrap_line,
            schedule_line,
            harden_line,
            quarantine_line,
            "",
            next_steps,
        ],
    )


def schedule_timer_button_label(
    *,
    present: bool,
    profile: str,
    frequency: str,
) -> str:
    action = "Reinstall" if present else "Install"
    return f"{action} {frequency} {profile}-scan timer"


def should_show_wizard(client: OystClient) -> bool:
    try:
        return bool(client.setup_status().get("needs_attention", True))
    except RuntimeError:
        return True
