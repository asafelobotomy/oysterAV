"""CLI tests."""

from __future__ import annotations

from click.testing import CliRunner

from oyst_cli.main import cli


def test_cli_help() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "oyst-cli" in result.output


def test_doctor_json() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["doctor", "--json"])
    assert result.exit_code in (0, 5)
    assert "[" in result.output


def test_status_json() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["status", "--json"])
    assert result.exit_code == 0
    assert "packs" in result.output


def test_quarantine_list() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["quarantine", "list", "--json"])
    assert result.exit_code == 0


def test_config_path() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["config", "path"])
    assert result.exit_code == 0
    assert "config.toml" in result.output


def test_config_path_json() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["config", "path", "--json"])
    assert result.exit_code == 0
    assert "path" in result.output
    assert "config.toml" in result.output


def test_scan_help_includes_examples() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--help"])
    assert result.exit_code == 0
    assert "Examples:" in result.output


def test_firewall_detect() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["firewall", "detect", "--json"])
    assert result.exit_code == 0


def test_schedule_show() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["schedule", "show"])
    assert result.exit_code == 0
    out = result.output.lower()
    assert "profile" in out or "oncalendar" in out or "timer" in out or "template" in out


def test_packs_list_json() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["packs", "list", "--json"])
    assert result.exit_code == 0
    assert "[" in result.output


def test_packs_install_unknown() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["packs", "install", "nonexistent-pack", "--json"])
    assert result.exit_code == 2


def test_packs_install_already_installed() -> None:
    from unittest.mock import patch

    from oyst_core.pack_install import InstallResult

    mock_result = InstallResult(ok=True, mode="installed", message="already there")
    with patch("oyst_cli.commands.pack_install_cmd.install_pack", return_value=mock_result):
        runner = CliRunner()
        result = runner.invoke(cli, ["packs", "install", "clamav", "--json"])
    assert result.exit_code == 0
    assert "installed" in result.output


def test_setup_status_json() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["setup", "status", "--json"])
    assert result.exit_code == 0
    assert "completed" in result.output


def test_schedule_status_json() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["schedule", "status", "--json"])
    assert result.exit_code == 0
    assert "profile" in result.output


def test_schedule_linger_json() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["schedule", "linger", "--json"])
    assert result.exit_code == 0
    assert "linger" in result.output


def test_unhide_status_json() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["unhide", "status", "--json"])
    assert result.exit_code == 0
    assert "unhide" in result.output
