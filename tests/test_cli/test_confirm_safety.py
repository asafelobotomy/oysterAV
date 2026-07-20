"""Destructive-action confirmation tests."""

from __future__ import annotations

from unittest.mock import patch

from click.testing import CliRunner

from oyst_cli.main import cli


def test_quarantine_delete_requires_confirm() -> None:
    runner = CliRunner()
    with patch("oyst_cli.commands.quarantine.QuarantineVault") as vault:
        result = runner.invoke(cli, ["quarantine", "delete", "1"])
    assert result.exit_code == 4
    vault.return_value.delete.assert_not_called()


def test_quarantine_delete_dry_run_skips_mutate() -> None:
    runner = CliRunner()

    class _Entry:
        original_path = "/tmp/x"

    with patch("oyst_cli.commands.quarantine.QuarantineVault") as vault:
        vault.return_value.get.return_value = _Entry()
        result = runner.invoke(cli, ["quarantine", "delete", "1", "--dry-run", "--json"])
    assert result.exit_code == 0
    vault.return_value.delete.assert_not_called()
    assert "dry_run" in result.output


def test_quarantine_restore_requires_confirm() -> None:
    runner = CliRunner()
    with patch("oyst_cli.commands.quarantine.QuarantineVault") as vault:
        result = runner.invoke(cli, ["quarantine", "restore", "1"])
    assert result.exit_code == 4
    vault.return_value.restore.assert_not_called()


def test_rkhunter_propupd_requires_confirm() -> None:
    runner = CliRunner()
    with patch("oyst_cli.commands.packs.rkhunter_cmd.RKHunterPack") as pack:
        result = runner.invoke(cli, ["rkhunter", "propupd", "--json"])
    assert result.exit_code == 4
    pack.return_value.propupd.assert_not_called()


def test_rkhunter_resolve_requires_confirm() -> None:
    runner = CliRunner()
    with patch("oyst_cli.commands.packs.rkhunter_cmd.run_rkhunter_resolve") as resolve:
        result = runner.invoke(
            cli,
            [
                "rkhunter",
                "resolve",
                "--threat",
                "rkhunter-ssh",
                "--message",
                "Warning: The SSH configuration option 'Protocol' has not been set.",
                "--json",
            ],
        )
    assert result.exit_code == 4
    resolve.assert_not_called()


def test_rkhunter_resolve_dry_run_json() -> None:
    runner = CliRunner()
    with patch(
        "oyst_cli.commands.packs.rkhunter_cmd.run_rkhunter_resolve",
        return_value={
            "ok": True,
            "dry_run": True,
            "option": "ALLOW_SSH_PROT_V1",
            "value": "2",
        },
    ):
        result = runner.invoke(
            cli,
            [
                "rkhunter",
                "resolve",
                "--threat",
                "rkhunter-ssh",
                "--message",
                "Warning: The SSH configuration option 'Protocol' has not been set.",
                "--dry-run",
                "--json",
            ],
        )
    assert result.exit_code == 0
    assert "ALLOW_SSH_PROT_V1" in result.output


def test_firewalld_add_port_requires_confirm() -> None:
    runner = CliRunner()
    with patch("oyst_cli.commands.packs.firewall_cmd.FirewallOps") as ops:
        result = runner.invoke(cli, ["firewall", "firewalld", "add-port", "443/tcp"])
    assert result.exit_code == 4
    ops.return_value.firewalld_port.assert_not_called()


def test_firewalld_add_port_dry_run_ok() -> None:
    runner = CliRunner()

    class _Result:
        ok = True

        def __init__(self) -> None:
            self.__dict__ = {"ok": True, "dry_run": True}

    with patch("oyst_cli.commands.packs.firewall_cmd.FirewallOps") as ops:
        ops.return_value.firewalld_port.return_value = _Result()
        result = runner.invoke(
            cli,
            ["firewall", "firewalld", "add-port", "443/tcp", "--dry-run", "--json"],
        )
    assert result.exit_code == 0
    ops.return_value.firewalld_port.assert_called_once()


def test_setup_reset_missing_confirm_exits_4() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["setup", "reset"])
    assert result.exit_code == 4
