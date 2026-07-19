"""CLI exit-code contract tests."""

from __future__ import annotations

from unittest.mock import patch

from click.testing import CliRunner

from oyst_cli.main import cli


def test_runtime_install_failure_exits_2() -> None:
    runner = CliRunner()
    with patch(
        "oyst_cli.commands.runtime_cmd.install_pack_runtime",
        return_value={"pack": "lynis", "ok": False, "message": "boom"},
    ):
        result = runner.invoke(cli, ["runtime", "install", "lynis", "--json"])
    assert result.exit_code == 2


def test_runtime_install_requires_pack_or_all() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["runtime", "install"])
    assert result.exit_code != 0
    assert "--all" in result.output or "pack" in result.output.lower()


def test_runtime_remove_failure_exits_2() -> None:
    runner = CliRunner()
    with patch(
        "oyst_cli.commands.runtime_cmd.remove_pack_runtime",
        return_value={"ok": False, "message": "boom"},
    ):
        result = runner.invoke(cli, ["runtime", "remove", "lynis", "--confirm", "--json"])
    assert result.exit_code == 2


def test_runtime_bootstrap_failure_exits_2() -> None:
    runner = CliRunner()
    with patch(
        "oyst_cli.commands.runtime_cmd.run_full_runtime_bootstrap",
        return_value={"ok": False, "steps_ok": 0, "steps_total": 1, "steps": []},
    ):
        result = runner.invoke(cli, ["runtime", "bootstrap", "--json"])
    assert result.exit_code == 2


def test_install_helper_failure_exits_2() -> None:
    runner = CliRunner()
    with patch(
        "oyst_cli.commands.install_helper_cmd.install_privileged_helper",
        return_value={"ok": False, "message": "denied"},
    ):
        result = runner.invoke(cli, ["install-privileged-helper", "--json"])
    assert result.exit_code == 2


def test_maintenance_bootstrap_failed_step_exits_2() -> None:
    runner = CliRunner()
    with patch(
        "oyst_cli.commands.maintenance.run_bootstrap",
        return_value=[
            {"step": "doctor-clamav", "ok": True},
            {"step": "freshclam", "ok": False, "message": "failed"},
        ],
    ):
        result = runner.invoke(cli, ["maintenance", "bootstrap", "--json"])
    assert result.exit_code == 2


def test_maintenance_bootstrap_missing_pack_exits_5() -> None:
    runner = CliRunner()
    with patch(
        "oyst_cli.commands.maintenance.run_bootstrap",
        return_value=[
            {"step": "doctor-clamav", "ok": False},
            {"step": "freshclam", "ok": False, "skipped": True},
        ],
    ):
        result = runner.invoke(cli, ["maintenance", "bootstrap", "--json"])
    assert result.exit_code == 5


def test_maintenance_post_update_failed_step_exits_2() -> None:
    runner = CliRunner()
    with patch(
        "oyst_cli.commands.maintenance.run_post_update",
        return_value=[{"step": "freshclam", "ok": False}],
    ):
        result = runner.invoke(cli, ["maintenance", "post-update", "--json"])
    assert result.exit_code == 2


def test_scan_text_output_is_human_summary_only() -> None:
    from datetime import UTC, datetime

    from oyst_core.models import ExitCode, ScanResult

    fake = ScanResult(
        job_id="j1",
        profile="quick",
        paths=["/tmp"],
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        findings=[],
        pack_errors=[],
        clean=True,
    )
    runner = CliRunner()
    with patch("oyst_cli.commands.scan.JobOrchestrator") as orch:
        orch.return_value.run_scan.return_value = (fake, ExitCode.SUCCESS)
        result = runner.invoke(cli, ["scan", "/tmp"])
    assert result.exit_code == 0
    assert "Scan j1: clean" in result.output
    assert "job_id:" not in result.output


def test_serve_help_keeps_foreground_flag() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["serve", "--help"])
    assert result.exit_code == 0
    assert "--foreground" in result.output
    assert "compatibility" in result.output.lower()


def test_serve_schema_version_mismatch_exits_2() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["serve", "--schema-version", "99999"])
    assert result.exit_code == 2
