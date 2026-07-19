"""Mocked success JSON contracts for mutating CLI commands."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from oyst_cli.main import cli


def test_fail2ban_unban_json_success() -> None:
    runner = CliRunner()
    with patch("oyst_cli.commands.packs.Fail2banPack") as pack_cls:
        pack_cls.return_value.unban.return_value = (True, "unbanned")
        result = runner.invoke(
            cli,
            ["fail2ban", "unban", "1.2.3.4", "--jail", "sshd", "--confirm", "--json"],
        )
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["ok"] is True


def test_quarantine_delete_confirm_json() -> None:
    runner = CliRunner()
    with patch("oyst_cli.commands.quarantine.QuarantineVault") as vault:
        vault.return_value.delete = MagicMock()
        result = runner.invoke(cli, ["quarantine", "delete", "3", "--confirm", "--json"])
    assert result.exit_code == 0
    vault.return_value.delete.assert_called_once_with(3)


def test_rkhunter_propupd_confirm_json() -> None:
    runner = CliRunner()
    with patch("oyst_cli.commands.packs.RKHunterPack") as pack:
        pack.return_value.propupd.return_value = (True, "props updated")
        result = runner.invoke(cli, ["rkhunter", "propupd", "--confirm", "--json"])
    assert result.exit_code == 0
    assert "ok" in result.output.lower() or "props" in result.output.lower()


def test_maintenance_post_update_json() -> None:
    runner = CliRunner()
    with patch(
        "oyst_cli.commands.maintenance.run_post_update",
        return_value=[{"step": "freshclam", "ok": True}],
    ):
        result = runner.invoke(cli, ["maintenance", "post-update", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["post_update"][0]["step"] == "freshclam"
