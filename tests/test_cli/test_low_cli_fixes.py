"""Low-severity audit fixes: confirm gates, exit codes, news output sanitising."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import click
import pytest
from click.testing import CliRunner

from oyst_cli.cli_group import OystGroup
from oyst_cli.commands import news_cmd
from oyst_cli.main import cli


def test_schedule_set_disabled_apply_requires_confirm() -> None:
    with (
        patch("oyst_cli.commands.schedule_cmd.update_schedule_settings") as upd,
        patch("oyst_cli.commands.schedule_cmd.apply_schedule") as apply,
    ):
        result = CliRunner().invoke(cli, ["schedule", "set", "--disabled", "--apply"])
    assert result.exit_code == 4
    upd.assert_not_called()
    apply.assert_not_called()


def test_schedule_set_disabled_apply_with_confirm_runs() -> None:
    sched = MagicMock()
    sched.model_dump.return_value = {"enabled": False}
    with (
        patch("oyst_cli.commands.schedule_cmd.update_schedule_settings", return_value=sched),
        patch(
            "oyst_cli.commands.schedule_cmd.apply_schedule",
            return_value={"ok": True, "message": "stopped"},
        ) as apply,
    ):
        result = CliRunner().invoke(
            cli, ["schedule", "set", "--disabled", "--apply", "--confirm", "--json"]
        )
    assert result.exit_code == 0, result.output
    apply.assert_called_once()


def test_schedule_set_disabled_without_apply_needs_no_confirm() -> None:
    sched = MagicMock()
    sched.model_dump.return_value = {"enabled": False}
    with patch("oyst_cli.commands.schedule_cmd.update_schedule_settings", return_value=sched):
        result = CliRunner().invoke(cli, ["schedule", "set", "--disabled", "--json"])
    assert result.exit_code == 0, result.output


def test_maldet_monitor_stop_requires_confirm() -> None:
    with patch("oyst_cli.commands.packs.maldet_cmd.MaldetPack") as pack:
        result = CliRunner().invoke(cli, ["maldet", "monitor", "stop", "--json"])
        assert result.exit_code == 4
        pack.return_value.monitor_stop.assert_not_called()
        pack.return_value.monitor_stop.return_value = (True, "monitor stopped")
        ok = CliRunner().invoke(cli, ["maldet", "monitor", "stop", "--confirm", "--json"])
    assert ok.exit_code == 0, ok.output


def test_scan_quarantine_requires_confirm() -> None:
    with patch("oyst_cli.commands.scan.JobOrchestrator") as orch:
        result = CliRunner().invoke(
            cli, ["scan", "/tmp", "--profile", "quick", "--packs", "clamav", "--quarantine"]
        )
    assert result.exit_code == 4
    assert "--quarantine" in result.output
    orch.return_value.run_scan.assert_not_called()


def test_scan_without_quarantine_needs_no_confirm() -> None:
    fake = MagicMock()
    fake.model_dump.return_value = {"clean": True}
    fake.clean = True
    fake.findings = []
    fake.pack_errors = []
    fake.job_id = "j"
    with patch("oyst_cli.commands.scan.JobOrchestrator") as orch:
        orch.return_value.run_scan.return_value = (fake, 0)
        result = CliRunner().invoke(
            cli, ["scan", "/tmp", "--profile", "quick", "--packs", "clamav"]
        )
    assert result.exit_code == 0, result.output
    orch.return_value.run_scan.assert_called_once()


def test_terminal_clear_missing_confirm_exits_4() -> None:
    with patch("oyst_cli.commands.terminal_cmd.terminal_log") as tlog:
        result = CliRunner().invoke(cli, ["terminal", "clear"])
    assert result.exit_code == 4
    tlog.clear.assert_not_called()


def _group_with(cmd_body: Any) -> click.Group:
    @click.group(cls=OystGroup)
    def root() -> None:
        pass

    @root.command("x")
    @click.option("--n", type=int, default=0)
    def x(n: int) -> None:
        cmd_body()

    return root


@pytest.mark.parametrize(
    ("body", "args", "expected"),
    [
        (lambda: None, ["x"], 0),
        (lambda: (_ for _ in ()).throw(click.ClickException("boom")), ["x"], 2),
        (lambda: (_ for _ in ()).throw(RuntimeError("kaboom")), ["x"], 2),
        (lambda: (_ for _ in ()).throw(SystemExit(1)), ["x"], 1),
        (lambda: (_ for _ in ()).throw(SystemExit(4)), ["x"], 4),
        (lambda: None, ["x", "--bogus"], 2),
        (lambda: None, ["x", "--help"], 0),
    ],
)
def test_root_group_exit_codes(body: Any, args: list[str], expected: int) -> None:
    logged: list[dict[str, Any]] = []
    with patch(
        "oyst_core.terminal_log.log_structured",
        side_effect=lambda *a, **_k: logged.append(a[3]),
    ):
        result = CliRunner().invoke(_group_with(body), args)
    assert result.exit_code == expected, result.output
    assert logged == [{"exit_code": expected}]


def test_click_exception_in_real_cli_exits_error() -> None:
    with patch(
        "oyst_cli.commands.schedule_cmd.update_schedule_settings",
        side_effect=ValueError("bad time"),
    ):
        result = CliRunner().invoke(cli, ["schedule", "set", "--time", "99:99"])
    assert result.exit_code == 2
    assert "bad time" in result.output


def test_news_text_output_strips_control_chars() -> None:
    data = {
        "items": [
            {
                "source": "s\x1b[31m",
                "title": "Evil\x1b]0;pwn\x07 title‮\x9b",
                "link": "https://e.example/\x1b[2J",
                "severity_label": "high",
            }
        ]
    }
    with patch.object(news_cmd, "list_security_news", return_value=data):
        result = CliRunner().invoke(cli, ["news", "list"])
    assert "\x1b" not in result.output
    assert "‮" not in result.output
    assert "\x9b" not in result.output
    assert "Evil]0;pwn title" in result.output
    assert news_cmd._clean("a\tb\nc\x00") == "a\tb\nc"
