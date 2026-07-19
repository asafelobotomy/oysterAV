"""Pure helpers for Scan tab pack result cards."""

from __future__ import annotations

from oyst_core.models import ScanProfile
from oysterav.gui.scan_helpers import (
    PackCardState,
    expected_packs_for_profile,
    pack_result_summary,
)


def test_expected_packs_quick_and_suite() -> None:
    assert expected_packs_for_profile(ScanProfile.QUICK) == ["clamav"]
    assert expected_packs_for_profile(ScanProfile.SUITE) == [
        "clamav",
        "rkhunter",
        "chkrootkit",
        "lynis",
    ]
    assert expected_packs_for_profile(ScanProfile.CUSTOM, ["maldet", "unhide"]) == [
        "maldet",
        "unhide",
    ]


def test_pack_result_summary_states() -> None:
    scan = {
        "findings": [
            {"pack": "clamav", "path": "/tmp/eicar", "threat_name": "Eicar"},
        ],
        "pack_errors": [
            {"pack": "maldet", "error": "not installed"},
        ],
    }
    expected = ["clamav", "maldet", "rkhunter"]
    state, findings, err = pack_result_summary(scan, "clamav", expected=expected)
    assert state == PackCardState.THREATS
    assert len(findings) == 1
    assert err == ""

    state, findings, err = pack_result_summary(scan, "maldet", expected=expected)
    assert state == PackCardState.ERROR
    assert err == "not installed"

    state, findings, err = pack_result_summary(scan, "rkhunter", expected=expected)
    assert state == PackCardState.CLEAN

    state, findings, err = pack_result_summary(scan, "lynis", expected=expected)
    assert state == PackCardState.SKIPPED
