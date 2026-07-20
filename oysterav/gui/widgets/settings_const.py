"""Shared option/label tuples for the Settings page."""

from __future__ import annotations

from oyst_core.models import ScanProfile
from oyst_core.ui_theme import UI_THEME_IDS, UI_THEME_LABELS

SCHEDULE_PROFILE_OPTIONS = [p.value for p in ScanProfile]
SCHEDULE_PROFILE_LABELS = [
    {
        ScanProfile.QUICK: "Quick",
        ScanProfile.FULL: "Full",
        ScanProfile.INTEGRITY: "Integrity",
        ScanProfile.SUITE: "Suite",
        ScanProfile.CUSTOM: "Custom",
    }.get(p, p.value)
    for p in ScanProfile
]
BACKEND_OPTIONS = ["auto", "clamd", "clamscan"]
SCHED_BACKEND_OPTIONS = ["inherit", "auto", "clamd", "clamscan"]
SCHED_BACKEND_LABELS = [
    "Inherit (use General scan backend)",
    "auto",
    "clamd",
    "clamscan",
]
THEME_OPTIONS: list[str] = list(UI_THEME_IDS)
THEME_LABELS = [UI_THEME_LABELS[t] for t in UI_THEME_IDS]
FREQUENCY_OPTIONS = ["hourly", "daily", "weekly", "custom"]
FREQUENCY_LABELS = ["Hourly", "Daily", "Weekly", "Custom"]
WEEKDAY_OPTIONS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
WEEKDAY_LABELS = [
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
    "Sunday",
]
QUARANTINE_OPTIONS = ["auto", "on", "off"]
QUARANTINE_LABELS = ["Auto (follow General)", "Always on", "Always off"]
SCHEDULE_APPLY_DEBOUNCE_MS = 700

# Sidebar section id → label (order is navigation order).
SETTINGS_SECTIONS: tuple[tuple[str, str], ...] = (
    ("general", "General"),
    ("services", "Services"),
    ("realtime", "Real-time"),
    ("scheduling", "Scheduling"),
    ("host_audit", "Host & audit"),
    ("maintenance", "Maintenance"),
    ("packs", "Security packs"),
)
SETTINGS_SECTION_IDS = {section_id for section_id, _ in SETTINGS_SECTIONS}
