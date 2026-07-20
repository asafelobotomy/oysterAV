"""Tests for schedule timer utilities."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from oyst_core.config import ScheduleConfig
from oyst_core.privileged.runner import CommandResult
from oyst_core.schedule_util import (
    apply_schedule,
    build_on_calendar,
    install_user_timer,
    resolve_oyst_cli_path,
    run_scheduled_scan,
)


def test_resolve_oyst_cli_path_prefers_existing_file(tmp_path: Path, monkeypatch) -> None:
    cli = tmp_path / "oyst-cli"
    cli.write_text("#!/bin/sh\n", encoding="utf-8")
    cli.chmod(0o755)
    with patch("oyst_core.schedule_linger.which", return_value=str(cli)):
        assert resolve_oyst_cli_path() == str(cli)


@pytest.mark.parametrize(
    ("cfg", "expected"),
    [
        (ScheduleConfig(frequency="hourly"), "hourly"),
        (ScheduleConfig(frequency="daily", time="02:30"), "*-*-* 02:30:00"),
        (
            ScheduleConfig(frequency="weekly", weekday="mon", time="03:00"),
            "Mon *-*-* 03:00:00",
        ),
        (
            ScheduleConfig(frequency="custom", on_calendar="*-*-* 04:15:00"),
            "*-*-* 04:15:00",
        ),
    ],
)
def test_build_on_calendar(cfg: ScheduleConfig, expected: str) -> None:
    assert build_on_calendar(cfg) == expected


def test_build_on_calendar_rejects_bad_time() -> None:
    with pytest.raises(ValueError, match="schedule.time"):
        build_on_calendar(ScheduleConfig(frequency="daily", time="25:00"))


def test_build_on_calendar_custom_requires_expression() -> None:
    with pytest.raises(ValueError, match="on_calendar"):
        build_on_calendar(ScheduleConfig(frequency="custom", on_calendar=""))


def test_install_user_timer_writes_schedule_run_execstart(
    tmp_path: Path,
    monkeypatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr("oyst_core.schedule_units.Path.home", lambda: home)
    cli = tmp_path / "oyst-cli"
    cli.write_text("#!/bin/sh\n", encoding="utf-8")
    cli.chmod(0o755)

    def fake_systemctl(args: list[str]) -> CommandResult:
        if args == ["daemon-reload"]:
            return CommandResult(0, "", "")
        if args == ["enable", "--now", "oyst-scan.timer"]:
            return CommandResult(0, "", "")
        if args == ["is-active", "oyst-scan.timer"]:
            return CommandResult(0, "active\n", "")
        if args == ["start", "oyst-scan.service"]:
            return CommandResult(0, "", "")
        if args[0:2] == ["show", "oyst-scan.service"]:
            return CommandResult(0, "0\n", "")
        return CommandResult(1, "", "unexpected")

    with (
        patch("oyst_core.schedule_units.resolve_oyst_cli_path", return_value=str(cli)),
        patch("oyst_core.schedule_units._run_user_systemctl", side_effect=fake_systemctl),
        patch("oyst_core.schedule_units.get_linger_status", return_value={"linger": False}),
        patch("oyst_core.schedule_units.set_config_value"),
        patch(
            "oyst_core.schedule_units.load_config",
            return_value=MagicMock(
                schedule=ScheduleConfig(enabled=True, profile="quick", time="02:00"),
            ),
        ),
        patch(
            "oyst_core.schedule_units.validate_schedule_config",
            return_value=ScheduleConfig(enabled=True, profile="quick", time="02:00"),
        ),
    ):
        result = install_user_timer("quick", smoke_test=True)

    assert result["ok"] is True
    assert result["enabled"] is True
    assert result["active"] is True
    service_text = Path(str(result["service"])).read_text(encoding="utf-8")
    assert f"ExecStart={cli} schedule run --json" in service_text
    timer_text = Path(str(result["timer"])).read_text(encoding="utf-8")
    assert "OnCalendar=*-*-* 02:00:00" in timer_text
    assert "Persistent=true" in timer_text


def test_apply_schedule_writes_units(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr("oyst_core.schedule_units.Path.home", lambda: home)
    cli = tmp_path / "oyst-cli"
    cli.write_text("#!/bin/sh\n", encoding="utf-8")
    cli.chmod(0o755)
    sched = ScheduleConfig(
        enabled=True,
        profile="full",
        frequency="daily",
        time="03:15",
        persistent=True,
    )

    def fake_systemctl(args: list[str]) -> CommandResult:
        if args == ["daemon-reload"]:
            return CommandResult(0, "", "")
        if args == ["enable", "--now", "oyst-scan.timer"]:
            return CommandResult(0, "", "")
        if args == ["is-active", "oyst-scan.timer"]:
            return CommandResult(0, "active\n", "")
        return CommandResult(1, "", "")

    with (
        patch("oyst_core.schedule_units.resolve_oyst_cli_path", return_value=str(cli)),
        patch("oyst_core.schedule_units._run_user_systemctl", side_effect=fake_systemctl),
        patch("oyst_core.schedule_units.get_linger_status", return_value={"linger": True}),
        patch("oyst_core.schedule_units.validate_schedule_config", return_value=sched),
    ):
        result = apply_schedule(smoke_test=False)

    assert result["ok"] is True
    assert result["on_calendar"] == "*-*-* 03:15:00"
    assert "schedule run --json" in Path(str(result["service"])).read_text(encoding="utf-8")


def test_install_user_timer_missing_cli() -> None:
    with (
        patch("oyst_core.schedule_units.resolve_oyst_cli_path", return_value=None),
        patch("oyst_core.schedule_units.set_config_value"),
        patch(
            "oyst_core.schedule_units.load_config",
            return_value=MagicMock(schedule=ScheduleConfig()),
        ),
        patch(
            "oyst_core.schedule_units.validate_schedule_config",
            return_value=ScheduleConfig(enabled=True),
        ),
        patch("oyst_core.schedule_units.get_linger_status", return_value={"linger": False}),
    ):
        result = install_user_timer("quick")
    assert result["ok"] is False
    assert "oyst-cli not found" in str(result["message"])


def test_run_scheduled_scan_passes_packs_and_paths() -> None:
    sched = ScheduleConfig(
        profile="custom",
        packs=["clamav"],
        paths=["/tmp/scan-me"],
        quarantine="on",
        backend="clamscan",
    )
    fake_result = MagicMock()
    fake_result.model_dump.return_value = {"job_id": "j1", "clean": True}

    with (
        patch("oyst_core.schedule_units.validate_schedule_config", return_value=sched),
        patch("oyst_core.orchestrator.JobOrchestrator") as orch_cls,
    ):
        orch = orch_cls.return_value
        orch.run_scan.return_value = (fake_result, 0)
        out = run_scheduled_scan()

    assert out["ok"] is True
    assert out["exit_code"] == 0
    orch.run_scan.assert_called_once()
    kwargs = orch.run_scan.call_args.kwargs
    assert kwargs["packs"] == ["clamav"]
    assert kwargs["paths"] == ["/tmp/scan-me"]
    assert kwargs["quarantine"] is True
    assert kwargs["backend"] == "clamscan"
