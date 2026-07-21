"""Scan tab constants — profiles, labels, presets, packs, poll."""

from __future__ import annotations

from oyst_core.models import ScanProfile

SCAN_PROFILES: list[ScanProfile] = [
    ScanProfile.QUICK,
    ScanProfile.FULL,
    ScanProfile.SUITE,
    ScanProfile.INTEGRITY,
    ScanProfile.CUSTOM,
]
PROFILE_LABELS = {
    ScanProfile.QUICK: "Quick",
    ScanProfile.FULL: "Full",
    ScanProfile.SUITE: "Suite (malware + rootkits + hardening audit)",
    ScanProfile.INTEGRITY: "Integrity (rkhunter + chkrootkit + unhide)",
    ScanProfile.CUSTOM: "Custom (choose packs)",
}

# Display order (education): malware packs first. Execution order is privileged-first
# via Privilege Concert (rkhunter → chkrootkit → unhide → lynis), then clamav/maldet.
CUSTOM_PACK_CHOICES = ("clamav", "maldet", "rkhunter", "chkrootkit", "unhide", "lynis")
RESULT_PACKS = ("clamav", "maldet", "rkhunter", "chkrootkit", "unhide", "lynis")

PATH_PRESETS = [
    ("Home", "~"),
    ("Downloads", "~/Downloads"),
    ("Desktop", "~/Desktop"),
    ("Custom", ""),
]

# Vertical rhythm for the single-column Scan layout (px).
SCAN_ACTION_INNER_GAP = 4
SCAN_ACTIONS_TO_OPTIONS_GAP = 14
SCAN_OPTIONS_TO_PROGRESS_GAP = 18
SCAN_PROGRESS_INNER_GAP = 2
SCAN_PROGRESS_TO_RESULTS_GAP = 18
SCAN_RESULTS_HEADING_GAP = 6
SCAN_PAGE_MARGIN = 8

POLL_MS = 400
