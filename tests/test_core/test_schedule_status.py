"""Tests for schedule timer status helper."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from oyst_core.config import ScheduleConfig
from oyst_core.privileged.runner import CommandResult
from oyst_core.schedule_util import get_timer_status


def test_get_timer_status_not_installed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("oyst_core.schedule_units.Path.home", lambda: tmp_path)
    monkeypatch.setattr(
        "oyst_core.schedule_units.resolve_oyst_cli_path",
        lambda: "/usr/bin/oyst-cli",
    )
    monkeypatch.setattr(
        "oyst_core.schedule_units.load_config",
        lambda: MagicMock(schedule=ScheduleConfig()),
    )
    monkeypatch.setattr(
        "oyst_core.schedule_units.get_linger_status",
        lambda: {"linger": False},
    )
    status = get_timer_status("quick")
    assert status["installed"] is False
    assert status["enabled"] is False


def test_get_timer_status_enabled(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    base = tmp_path / ".config" / "systemd" / "user"
    base.mkdir(parents=True)
    (base / "oyst-scan.timer").write_text("[Timer]", encoding="utf-8")
    (base / "oyst-scan.service").write_text("[Service]", encoding="utf-8")
    monkeypatch.setattr("oyst_core.schedule_units.Path.home", lambda: tmp_path)
    monkeypatch.setattr(
        "oyst_core.schedule_units.resolve_oyst_cli_path",
        lambda: "/usr/bin/oyst-cli",
    )
    monkeypatch.setattr(
        "oyst_core.schedule_units.load_config",
        lambda: MagicMock(schedule=ScheduleConfig(profile="quick", time="02:00")),
    )
    monkeypatch.setattr(
        "oyst_core.schedule_units.get_linger_status",
        lambda: {"linger": True},
    )

    def fake_systemctl(args: list[str]) -> CommandResult:
        if args[:2] == ["is-enabled", "oyst-scan.timer"]:
            return CommandResult(0, "enabled", "")
        if args[:2] == ["is-active", "oyst-scan.timer"]:
            return CommandResult(0, "active", "")
        if args[:2] == ["show", "oyst-scan.timer"]:
            return CommandResult(0, "Thu 2026-07-16 02:00:00 UTC", "")
        return CommandResult(1, "", "")

    monkeypatch.setattr("oyst_core.schedule_units._run_user_systemctl", fake_systemctl)
    status = get_timer_status("quick")
    assert status["installed"] is True
    assert status["enabled"] is True
    assert status["active"] is True
    assert status["on_calendar"] == "*-*-* 02:00:00"
