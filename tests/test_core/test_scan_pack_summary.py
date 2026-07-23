"""Pure helpers for Scan tab pack result cards."""

from __future__ import annotations

from oyst_core.models import ScanProfile
from oysterav.gui.scan_helpers import (
    PackCardState,
    advance_pack_card_states,
    expected_packs_for_profile,
    pack_card_progress_fraction,
    pack_card_purpose,
    pack_card_title,
    pack_progress_status_text,
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


def test_pack_card_plain_language() -> None:
    assert pack_card_title("clamav") == "ClamAV"
    assert pack_card_title("rkhunter") == "Rootkit Hunter"
    assert "malware" in pack_card_purpose("clamav").lower()
    assert "rootkit" in pack_card_purpose("rkhunter").lower()


def test_advance_pack_card_states_promotes_running_to_done() -> None:
    expected = ["clamav", "rkhunter", "lynis"]
    states = {
        "clamav": PackCardState.RUNNING,
        "rkhunter": PackCardState.PENDING,
        "lynis": PackCardState.PENDING,
    }
    updated = advance_pack_card_states(expected, "rkhunter", states)
    assert updated["clamav"] == PackCardState.DONE
    assert updated["rkhunter"] == PackCardState.RUNNING
    assert updated["lynis"] == PackCardState.PENDING


def test_advance_pack_card_states_keeps_prior_done() -> None:
    expected = ["clamav", "rkhunter", "lynis"]
    states = {
        "clamav": PackCardState.DONE,
        "rkhunter": PackCardState.RUNNING,
        "lynis": PackCardState.PENDING,
    }
    updated = advance_pack_card_states(expected, "lynis", states)
    assert updated["clamav"] == PackCardState.DONE
    assert updated["rkhunter"] == PackCardState.DONE
    assert updated["lynis"] == PackCardState.RUNNING


def test_pack_progress_status_text() -> None:
    expected = ["clamav", "rkhunter", "lynis"]
    assert pack_progress_status_text(expected, "rkhunter") == "Pack 2 of 3 · Rootkit Hunter"
    assert pack_progress_status_text([], "clamav") == "Scanning ClamAV"


def test_pack_card_progress_fraction_lifecycle() -> None:
    expected = ["clamav", "rkhunter"]
    assert pack_card_progress_fraction("maldet", PackCardState.EXCLUDED, expected, 50.0) is None
    assert pack_card_progress_fraction("clamav", PackCardState.PENDING, expected, 0.0) == 0.0
    assert pack_card_progress_fraction("clamav", PackCardState.DONE, expected, 50.0) == 1.0
    running = pack_card_progress_fraction("clamav", PackCardState.RUNNING, expected, 0.0)
    assert running is not None
    assert 0.08 <= running <= 0.92
    # Mid-slice for first of two packs at 25% overall → halfway through slice.
    mid = pack_card_progress_fraction("clamav", PackCardState.RUNNING, expected, 25.0)
    assert mid is not None
    assert 0.45 <= mid <= 0.55
    second = pack_card_progress_fraction("rkhunter", PackCardState.RUNNING, expected, 75.0)
    assert second is not None
    assert 0.45 <= second <= 0.55
