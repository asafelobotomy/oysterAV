"""Pack CLI command coverage tests."""

from __future__ import annotations

from click.testing import CliRunner

from oyst_cli.main import cli
from oyst_core.registry import get_registry


def test_all_packs_have_status_cli() -> None:
    runner = CliRunner()
    status_commands = {
        "clamav": ["clamav", "status", "--json"],
        "freshclam": ["freshclam", "status", "--json"],
        "clamonacc": ["clamonacc", "status", "--json"],
        "fangfrisch": ["fangfrisch", "status", "--json"],
        "rkhunter": ["rkhunter", "status", "--json"],
        "chkrootkit": ["chkrootkit", "status", "--json"],
        "lynis": ["lynis", "status", "--json"],
        "maldet": ["maldet", "status", "--json"],
        "firewall": ["firewall", "status", "--json"],
        "fail2ban": ["fail2ban", "status", "--json"],
        "unhide": ["unhide", "status", "--json"],
    }
    for pack in get_registry().names():
        assert pack in status_commands, f"missing status CLI mapping for {pack}"
        result = runner.invoke(cli, status_commands[pack])
        assert result.exit_code == 0, result.output


def test_rkhunter_versioncheck_help() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["rkhunter", "versioncheck", "--help"])
    assert result.exit_code == 0


def test_maldet_list_and_quarantine_help() -> None:
    runner = CliRunner()
    for cmd in (["maldet", "list", "--help"], ["maldet", "quarantine", "--help"]):
        result = runner.invoke(cli, cmd)
        assert result.exit_code == 0


def test_unhide_scan_modes() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["unhide", "scan", "--help"])
    assert result.exit_code == 0
    assert "sys" in result.output
    assert "brute" in result.output


def test_fail2ban_jail_help() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["fail2ban", "jail", "--help"])
    assert result.exit_code == 0


def test_clamav_clamd_commands_help() -> None:
    runner = CliRunner()
    for cmd in (
        ["clamav", "clamd", "status", "--help"],
        ["clamav", "clamd", "ensure", "--help"],
    ):
        result = runner.invoke(cli, cmd)
        assert result.exit_code == 0, result.output


def test_firewall_ufw_help() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["firewall", "ufw", "enable", "--help"])
    assert result.exit_code == 0
    assert "--confirm" in result.output


def test_fail2ban_unban_requires_confirm() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["fail2ban", "unban", "192.0.2.1"])
    assert result.exit_code != 0
    assert "confirm" in result.output.lower()


def test_lynis_profiles_list() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["lynis", "profiles", "list", "--json"])
    assert result.exit_code == 0


def test_maldet_monitor_status() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["maldet", "monitor", "status", "--json"])
    assert result.exit_code == 0


def test_lynis_audit_scope_help() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["lynis", "audit", "--help"])
    assert result.exit_code == 0
    assert "container-host" in result.output
