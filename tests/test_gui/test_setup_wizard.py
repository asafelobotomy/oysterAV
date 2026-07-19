"""Tests for setup wizard helpers."""

from __future__ import annotations

from unittest.mock import MagicMock

from oysterav.gui.widgets.schedule_ui import format_timer_status
from oysterav.gui.widgets.setup_wizard import (
    PAGE_TITLES,
    format_check_summary,
    format_ready_checklist,
    schedule_timer_button_label,
    should_show_wizard,
)


def test_page_titles_are_five_without_separate_bootstrap() -> None:
    assert PAGE_TITLES == (
        "Welcome",
        "Security packs",
        "Preferences",
        "Scheduling",
        "Ready",
    )
    assert len(PAGE_TITLES) == 5
    assert "Bootstrap" not in PAGE_TITLES


def test_format_check_summary_lists_names() -> None:
    setup = {
        "missing_required": ["clamav"],
        "missing_recommended": ["lynis"],
    }
    text = format_check_summary(setup)
    assert "clamav" in text
    assert "lynis" in text
    assert format_check_summary({}, running=True) == "Running doctor…"


def test_format_check_summary_all_installed() -> None:
    setup = {"missing_required": [], "missing_recommended": []}
    text = format_check_summary(setup)
    assert "All required packs are installed." in text
    assert "All recommended packs are installed." in text


def test_format_ready_checklist() -> None:
    text = format_ready_checklist(
        {"missing_required": ["clamav"], "skipped_steps": ["required_packs"]},
        bootstrap_ran=False,
        schedule_installed=False,
        auto_quarantine=True,
        full_mode=True,
    )
    assert "skipped" in text
    assert "not run" in text
    assert "not installed" in text
    assert "Auto-quarantine: on" in text
    assert "Update all" in text


def test_schedule_timer_button_label() -> None:
    assert (
        schedule_timer_button_label(present=False, profile="full", frequency="weekly")
        == "Install weekly full-scan timer"
    )
    assert (
        schedule_timer_button_label(present=True, profile="quick", frequency="daily")
        == "Reinstall daily quick-scan timer"
    )


def test_should_show_wizard_when_needs_attention() -> None:
    client = MagicMock()
    client.setup_status.return_value = {"needs_attention": True}
    assert should_show_wizard(client) is True


def test_should_show_wizard_false_when_complete() -> None:
    client = MagicMock()
    client.setup_status.return_value = {"needs_attention": False}
    assert should_show_wizard(client) is False


def test_should_show_wizard_on_backend_error() -> None:
    client = MagicMock()
    client.setup_status.side_effect = RuntimeError("offline")
    assert should_show_wizard(client) is True


def test_format_timer_status() -> None:
    assert "enabled" in format_timer_status({"enabled": True, "active": True}).lower()
    assert "*-*-* 02:00:00" in format_timer_status(
        {"enabled": True, "active": True, "on_calendar": "*-*-* 02:00:00"},
    )
    assert "No timer" in format_timer_status({"installed": False})
    assert "not fully enabled" in format_timer_status(
        {"installed": True, "enabled": False, "active": False},
    )
    assert "not fully enabled" in format_timer_status(
        {"ok": True, "timer": "/tmp/oyst-scan.timer", "enabled": False},
    )


def test_timer_is_present_from_install_result() -> None:
    from oysterav.gui.widgets.schedule_ui import schedule_action_label, timer_is_present

    install_result = {
        "ok": True,
        "installed": True,
        "enabled": True,
        "active": True,
        "timer": "/home/user/.config/systemd/user/oyst-scan-quick.timer",
    }
    assert timer_is_present(install_result)
    assert schedule_action_label(install_result) == "Reinstall timer…"
    assert schedule_action_label({"installed": False}) == "Install timer…"
