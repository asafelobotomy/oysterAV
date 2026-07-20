"""Package update detection helpers."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from oyst_cli.main import cli
from oyst_core.privileged.runner import CommandResult
from oyst_core.updates import (
    apply_all_updates,
    check_available_updates,
    format_update_status_line,
)


def test_format_update_status_line() -> None:
    assert (
        format_update_status_line(
            {"name": "rkhunter", "current": "1.4.6-1", "available": "1.4.6-2"}
        )
        == "An update for rkhunter 1.4.6-1 > 1.4.6-2 is available!"
    )


def test_check_available_updates_pacman() -> None:
    with (
        patch("oyst_core.updates.detect_distro_family", return_value="arch"),
        patch(
            "oyst_core.updates._installed_pack_names",
            return_value={"rkhunter", "clamav"},
        ),
        patch(
            "oyst_core.updates._relevant_pack_names",
            side_effect=lambda installed: set(installed),
        ),
        patch(
            "oyst_core.updates.run_command",
            return_value=CommandResult(
                0,
                "rkhunter 1.4.6-3 -> 1.4.6-4\nextra/foo 1-1 -> 2-1\n",
                "",
            ),
        ),
    ):
        result = check_available_updates()
    assert result["ok"] is True
    assert len(result["updates"]) == 1
    assert result["updates"][0]["name"] == "rkhunter"
    assert result["updates"][0]["current"] == "1.4.6-3"
    assert result["updates"][0]["available"] == "1.4.6-4"
    assert "rkhunter 1.4.6-3 > 1.4.6-4" in result["message"]


def test_check_available_updates_apt() -> None:
    with (
        patch("oyst_core.updates.detect_distro_family", return_value="debian"),
        patch("oyst_core.updates._installed_pack_names", return_value={"fail2ban"}),
        patch(
            "oyst_core.updates._relevant_pack_names",
            side_effect=lambda installed: set(installed),
        ),
        patch(
            "oyst_core.updates.run_command",
            return_value=CommandResult(
                0,
                "fail2ban/stable 1.1.0-1 amd64 [upgradable from: 1.0.2-1]\n",
                "",
            ),
        ),
    ):
        result = check_available_updates()
    assert result["updates"][0]["name"] == "fail2ban"
    assert result["updates"][0]["current"] == "1.0.2-1"
    assert result["updates"][0]["available"] == "1.1.0-1"


def test_request_updates_check() -> None:
    from oysterav.gui.rpc_actions import request_updates_check

    client = MagicMock()
    client.updates_check.return_value = {"ok": True, "updates": [], "message": ""}
    assert request_updates_check(client)["ok"] is True
    client.updates_check.assert_called_once_with()


def test_request_updates_apply() -> None:
    from oysterav.gui.rpc_actions import request_updates_apply

    client = MagicMock()
    client.updates_apply.return_value = {"ok": True, "steps": [], "message": "done"}
    assert request_updates_apply(client)["ok"] is True
    client.updates_apply.assert_called_once_with()


def _mock_pack(*, installed: bool = True) -> MagicMock:
    pack = MagicMock()
    pack.doctor.return_value = MagicMock(installed=installed)
    pack.update.return_value = (True, "ok")
    pack.refresh.return_value = (True, "ok")
    pack.update_sigs.return_value = (True, "ok")
    pack.propupd.return_value = (True, "ok")
    return pack


def test_apply_all_updates_no_packages() -> None:
    fresh = _mock_pack()
    fang = _mock_pack(installed=False)
    rkh = _mock_pack()
    maldet = _mock_pack(installed=False)
    with (
        patch(
            "oyst_core.updates.check_available_updates",
            return_value={"ok": True, "updates": [], "message": ""},
        ),
        patch("oyst_core.updates.FreshclamPack", return_value=fresh),
        patch("oyst_core.updates.FangfrischPack", return_value=fang),
        patch("oyst_core.updates.RKHunterPack", return_value=rkh),
        patch("oyst_core.updates.MaldetPack", return_value=maldet),
        patch("oyst_core.updates.EventLog"),
    ):
        result = apply_all_updates()

    assert result["ok"] is True
    steps = {s["step"]: s for s in result["steps"]}
    assert steps["packages"].get("skipped") is True
    assert steps["freshclam"]["ok"] is True
    assert steps["fangfrisch"].get("skipped") is True
    assert steps["rkhunter-update"]["ok"] is True
    assert steps["maldet-sigs"].get("skipped") is True
    assert steps["rkhunter-propupd"]["ok"] is True
    fresh.update.assert_called_once()
    rkh.update.assert_called_once()
    rkh.propupd.assert_called_once()


def test_apply_all_updates_installs_packages() -> None:
    fresh = _mock_pack()
    fang = _mock_pack()
    rkh = _mock_pack()
    maldet = _mock_pack()
    with (
        patch(
            "oyst_core.updates.check_available_updates",
            return_value={
                "ok": True,
                "updates": [
                    {
                        "kind": "pack",
                        "name": "rkhunter",
                        "package": "rkhunter",
                        "current": "1",
                        "available": "2",
                    },
                    {
                        "kind": "pack",
                        "name": "chkrootkit",
                        "package": "chkrootkit",
                        "current": "1",
                        "available": "2",
                    },
                ],
                "message": "",
            },
        ),
        patch("oyst_core.updates.detect_distro_family", return_value="arch"),
        patch(
            "oyst_core.updates.run_privileged_install",
            return_value=CommandResult(0, "ok", ""),
        ) as install,
        patch(
            "oyst_core.updates.run_privileged_aur_install",
            return_value=CommandResult(0, "ok", ""),
        ) as aur,
        patch("oyst_core.updates.FreshclamPack", return_value=fresh),
        patch("oyst_core.updates.FangfrischPack", return_value=fang),
        patch("oyst_core.updates.RKHunterPack", return_value=rkh),
        patch("oyst_core.updates.MaldetPack", return_value=maldet),
        patch("oyst_core.updates.EventLog"),
    ):
        result = apply_all_updates()

    assert result["ok"] is True
    assert result["packages_upgraded"] == ["rkhunter", "chkrootkit"]
    install.assert_called_once_with(["rkhunter"], "arch", sync=True)
    aur.assert_called_once_with(["chkrootkit"])
    fang.refresh.assert_called_once()
    maldet.update_sigs.assert_called_once()


def test_updates_apply_cli_json() -> None:
    runner = CliRunner()
    payload = {
        "ok": True,
        "updates": [],
        "packages_upgraded": [],
        "steps": [{"step": "packages", "ok": True, "skipped": True}],
        "message": "done",
    }
    with patch("oyst_cli.commands.updates_cmd.apply_all_updates", return_value=payload):
        result = runner.invoke(cli, ["updates", "apply", "--confirm", "--json"])
    assert result.exit_code == 0
    assert '"ok": true' in result.output


def test_updates_apply_cli_failure_exits_2() -> None:
    runner = CliRunner()
    payload = {
        "ok": False,
        "updates": [],
        "packages_upgraded": [],
        "steps": [{"step": "freshclam", "ok": False, "message": "boom"}],
        "message": "failed",
    }
    with patch("oyst_cli.commands.updates_cmd.apply_all_updates", return_value=payload):
        result = runner.invoke(cli, ["updates", "apply", "--confirm", "--json"])
    assert result.exit_code == 2


def test_updates_apply_requires_confirm() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["updates", "apply", "--json"])
    assert result.exit_code == 4
