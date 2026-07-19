"""CLI wiring for services, auth, and job cancel."""

from __future__ import annotations

import json
from unittest.mock import patch

from click.testing import CliRunner

from oyst_cli.main import cli


def test_job_cancel_json_success() -> None:
    runner = CliRunner()
    with patch(
        "oyst_cli.commands.job_cmd.JobOrchestrator.cancel_job",
        return_value={"ok": True, "cancelled": True, "job_id": "abc"},
    ):
        result = runner.invoke(cli, ["job", "cancel", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["ok"] is True
    assert payload["cancelled"] is True


def test_job_cancel_no_active_exits_2() -> None:
    runner = CliRunner()
    with patch(
        "oyst_cli.commands.job_cmd.JobOrchestrator.cancel_job",
        return_value={"ok": False, "cancelled": False, "message": "no active job"},
    ):
        result = runner.invoke(cli, ["job", "cancel", "--json"])
    assert result.exit_code == 2


def test_services_status_json() -> None:
    runner = CliRunner()
    fake = {"services": {"clamd": {"running": False}}, "names": ["clamd"]}
    with patch("oyst_cli.commands.services_cmd.services_status", return_value=fake):
        result = runner.invoke(cli, ["services", "status", "--json"])
    assert result.exit_code == 0
    assert json.loads(result.output)["names"] == ["clamd"]


def test_services_set_failure_exits_2() -> None:
    runner = CliRunner()
    with patch(
        "oyst_cli.commands.services_cmd.set_service",
        return_value={"ok": False, "name": "fail2ban", "message": "helper missing"},
    ):
        result = runner.invoke(cli, ["services", "set", "fail2ban", "on", "--json"])
    assert result.exit_code == 2


def test_services_set_success() -> None:
    runner = CliRunner()
    with patch(
        "oyst_cli.commands.services_cmd.set_service",
        return_value={"ok": True, "name": "fail2ban", "state": "off", "message": "ok"},
    ):
        result = runner.invoke(cli, ["services", "set", "fail2ban", "off", "--json"])
    assert result.exit_code == 0
    assert json.loads(result.output)["ok"] is True


def test_auth_status_json() -> None:
    runner = CliRunner()
    with (
        patch(
            "oyst_cli.commands.auth_cmd.helper_status",
            return_value={"installed": False},
        ),
        patch(
            "oyst_cli.commands.auth_cmd.auth_status",
            return_value={"granted": False},
        ),
    ):
        result = runner.invoke(cli, ["auth", "status", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["helper"]["installed"] is False
    assert payload["service_lifecycle"]["granted"] is False


def test_auth_grant_non_root_exits_2() -> None:
    runner = CliRunner()
    with patch(
        "oyst_cli.commands.auth_cmd.grant_service_lifecycle",
        return_value={"ok": False, "message": "must be root"},
    ):
        result = runner.invoke(cli, ["auth", "grant-service-lifecycle", "--json"])
    assert result.exit_code == 2


def test_auth_revoke_non_root_exits_2() -> None:
    runner = CliRunner()
    with patch(
        "oyst_cli.commands.auth_cmd.revoke_service_lifecycle",
        return_value={"ok": False, "message": "must be root"},
    ):
        result = runner.invoke(cli, ["auth", "revoke-service-lifecycle", "--json"])
    assert result.exit_code == 2
