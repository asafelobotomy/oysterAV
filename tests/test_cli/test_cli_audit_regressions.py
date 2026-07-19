"""Second-pass CLI audit fixes."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from oyst_cli.main import cli


def test_ufw_allow_from_works_with_dry_run() -> None:
    runner = CliRunner()

    class _Result:
        ok = True

        def __init__(self) -> None:
            self.__dict__ = {"ok": True, "dry_run": True}

    with patch("oyst_cli.commands.packs.FirewallOps") as ops:
        ops.return_value.ufw_rule.return_value = _Result()
        result = runner.invoke(
            cli,
            [
                "firewall",
                "ufw",
                "allow",
                "--port",
                "22",
                "--from",
                "192.0.2.1",
                "--dry-run",
                "--json",
            ],
        )
    assert result.exit_code == 0
    ops.return_value.ufw_rule.assert_called_once()
    assert ops.return_value.ufw_rule.call_args.kwargs.get("from_addr") == "192.0.2.1"


def test_ufw_allow_requires_confirm() -> None:
    runner = CliRunner()
    with patch("oyst_cli.commands.packs.FirewallOps") as ops:
        result = runner.invoke(cli, ["firewall", "ufw", "allow", "--port", "22"])
    assert result.exit_code == 4
    ops.return_value.ufw_rule.assert_not_called()


def test_clamav_scan_tool_failure_exits_2() -> None:
    runner = CliRunner()
    res = MagicMock(returncode=2, stdout="", stderr="error")
    with patch("oyst_cli.commands.packs.ClamAVPack") as pack:
        pack.return_value.scan.return_value = res
        pack.return_value.parse_findings.return_value = []
        result = runner.invoke(cli, ["clamav", "scan", "/tmp", "--json"])
    assert result.exit_code == 2


def test_rkhunter_scan_tool_failure_exits_2() -> None:
    runner = CliRunner()
    with patch("oyst_cli.commands.packs.RKHunterPack") as pack:
        pack.return_value.scan.return_value = (False, "failed")
        pack.return_value.parse_findings.return_value = []
        result = runner.invoke(cli, ["rkhunter", "scan", "--json"])
    assert result.exit_code == 2


def test_runtime_bootstrap_no_skip_lynis_passes_false() -> None:
    runner = CliRunner()
    with patch(
        "oyst_cli.commands.runtime_cmd.run_full_runtime_bootstrap",
        return_value={"ok": True, "steps_ok": 0, "steps_total": 0, "steps": []},
    ) as boot:
        result = runner.invoke(cli, ["runtime", "bootstrap", "--no-skip-lynis", "--json"])
    assert result.exit_code == 0
    assert boot.call_args.kwargs.get("skip_lynis") is False


def test_fail2ban_reload_unban_requires_confirm() -> None:
    runner = CliRunner()
    with patch("oyst_cli.commands.packs.Fail2banPack") as pack:
        result = runner.invoke(cli, ["fail2ban", "reload", "--unban", "--json"])
    assert result.exit_code == 4
    pack.return_value.reload.assert_not_called()


def test_schedule_disable_requires_confirm() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["schedule", "disable"])
    assert result.exit_code == 4


def test_runtime_remove_requires_confirm() -> None:
    runner = CliRunner()
    with patch("oyst_cli.commands.runtime_cmd.remove_pack_runtime") as rem:
        result = runner.invoke(cli, ["runtime", "remove", "lynis", "--json"])
    assert result.exit_code == 4
    rem.assert_not_called()


def test_news_refresh_exits_2_when_errors_and_empty() -> None:
    runner = CliRunner()
    with patch(
        "oyst_cli.commands.news_cmd.list_security_news",
        return_value={"items": [], "errors": [{"source": "arch", "error": "timeout"}]},
    ):
        result = runner.invoke(cli, ["news", "refresh", "--json"])
    assert result.exit_code == 2


def test_maintenance_bootstrap_human_no_keydump() -> None:
    runner = CliRunner()
    with patch(
        "oyst_cli.commands.maintenance.run_bootstrap",
        return_value=[{"step": "freshclam", "ok": True}],
    ):
        result = runner.invoke(cli, ["maintenance", "bootstrap"])
    assert result.exit_code == 0
    assert "[{'step'" not in result.output
    assert "freshclam: OK" in result.output
