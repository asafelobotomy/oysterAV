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

CUSTOM_PACK_CHOICES = ("clamav", "maldet", "rkhunter", "chkrootkit", "unhide", "lynis")
RESULT_PACKS = ("clamav", "maldet", "rkhunter", "chkrootkit", "unhide", "lynis")

PATH_PRESETS = [
    ("Home", "~"),
    ("Downloads", "~/Downloads"),
    ("Desktop", "~/Desktop"),
    ("Custom", ""),
]

COLUMN_BREAKPOINT = 720
POLL_MS = 400
