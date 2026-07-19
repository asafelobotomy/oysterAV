"""Setup workflow tests."""

from __future__ import annotations

from unittest.mock import patch

from click.testing import CliRunner

from oyst_cli.main import cli
from oyst_core.setup_workflow import assess_setup, run_setup


def test_setup_run_non_interactive_json() -> None:
    with (
        patch(
            "oyst_core.setup_workflow.run_bootstrap",
            return_value=[{"step": "freshclam", "ok": True}],
        ),
        patch("oyst_core.setup_workflow.install_pack"),
        patch(
            "oyst_core.setup_workflow.apply_schedule",
            return_value={"ok": True, "message": "ok"},
        ),
        patch("oyst_core.setup_workflow.is_full_mode", return_value=False),
        patch("oyst_core.registry.get_registry") as mock_registry,
    ):
        mock_registry.return_value.all.return_value = []
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["setup", "run", "--skip-packs", "--skip-schedule", "--json"],
        )
    assert result.exit_code == 0
    assert "steps" in result.output
    assert "preferences" in result.output


def test_setup_run_does_not_mark_complete_on_failure() -> None:
    with (
        patch(
            "oyst_core.setup_workflow.run_bootstrap",
            return_value=[{"step": "freshclam", "ok": False}],
        ),
        patch(
            "oyst_core.setup_workflow.apply_schedule",
            return_value={"ok": True, "message": "ok"},
        ),
        patch("oyst_core.setup_workflow.is_full_mode", return_value=False),
        patch("oyst_core.setup_workflow.set_config_value") as mock_set,
        patch("oyst_core.registry.get_registry") as mock_registry,
    ):
        mock_registry.return_value.all.return_value = []
        result = run_setup(skip_packs=True, skip_schedule=True, mark_complete=True)
    assert result["marked_complete"] is False
    completed_calls = [c for c in mock_set.call_args_list if c.args[0] == "setup.completed"]
    assert not any(c.args[1] == "true" for c in completed_calls)


def test_setup_run_enable_linger_calls_helper() -> None:
    with (
        patch(
            "oyst_core.setup_workflow.run_bootstrap",
            return_value=[{"step": "freshclam", "ok": True}],
        ),
        patch("oyst_core.setup_workflow.install_pack"),
        patch(
            "oyst_core.setup_workflow.apply_schedule",
            return_value={
                "ok": True,
                "message": "timer ok",
                "linger_advisory": "enable linger",
            },
        ),
        patch(
            "oyst_core.setup_workflow.enable_user_linger",
            return_value={"ok": True, "message": "linger on"},
        ),
        patch("oyst_core.setup_workflow.is_full_mode", return_value=False),
        patch("oyst_core.registry.get_registry") as mock_registry,
    ):
        mock_registry.return_value.all.return_value = []
        result = run_setup(skip_packs=True, enable_linger=True)
    assert any(step.get("step") == "linger" for step in result["steps"])


def test_assess_setup_includes_needs_attention() -> None:
    data = assess_setup()
    assert "needs_attention" in data
    assert "missing_required" in data


def test_assess_setup_honors_skipped_required_packs_when_completed() -> None:
    with (
        patch(
            "oyst_core.doctor_cache.doctor_all",
            return_value=[
                {"name": "clamav", "tier": "required", "installed": False},
                {"name": "freshclam", "tier": "required", "installed": True},
            ],
        ),
        patch("oyst_core.setup_workflow.load_config") as mock_cfg,
    ):
        cfg = mock_cfg.return_value
        cfg.setup.completed = True
        cfg.setup.completed_at = "2026-01-01"
        cfg.setup.skipped_steps = ["required_packs"]
        data = assess_setup()
    assert data["needs_attention"] is False
    assert "clamav" in data["missing_required"]


def test_assess_setup_still_needs_attention_when_missing_and_not_skipped() -> None:
    with (
        patch(
            "oyst_core.doctor_cache.doctor_all",
            return_value=[
                {"name": "clamav", "tier": "required", "installed": False},
            ],
        ),
        patch("oyst_core.setup_workflow.load_config") as mock_cfg,
    ):
        cfg = mock_cfg.return_value
        cfg.setup.completed = True
        cfg.setup.completed_at = "2026-01-01"
        cfg.setup.skipped_steps = []
        data = assess_setup()
    assert data["needs_attention"] is True


def test_setup_check_help() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["setup", "check", "--help"])
    assert result.exit_code == 0


def test_setup_check_json_exits_1_when_needs_attention() -> None:
    runner = CliRunner()
    with patch(
        "oyst_cli.commands.setup_cmd.assess_setup",
        return_value={
            "needs_attention": True,
            "completed": False,
            "missing_required": ["clamav"],
            "recommended_action": "oyst-cli setup run",
        },
    ):
        result = runner.invoke(cli, ["setup", "check", "--json"])
    assert result.exit_code == 1
    assert "needs_attention" in result.output


def test_setup_check_json_exits_0_when_ok() -> None:
    runner = CliRunner()
    with patch(
        "oyst_cli.commands.setup_cmd.assess_setup",
        return_value={
            "needs_attention": False,
            "completed": True,
            "missing_required": [],
        },
    ):
        result = runner.invoke(cli, ["setup", "check", "--json"])
    assert result.exit_code == 0


def test_setup_reset_requires_confirm() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["setup", "reset"])
    assert result.exit_code == 4


def test_status_assess_json() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["status", "assess", "--json"])
    assert result.exit_code == 0
    assert "severity" in result.output


def test_audit_list_json() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["audit", "list", "--json"])
    assert result.exit_code == 0
    assert "[" in result.output


def test_runtime_bootstrap_help() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["runtime", "bootstrap", "--help"])
    assert result.exit_code == 0
    assert "one-shot" in result.output.lower()
    assert "Examples:" in result.output


def test_config_get_dump_json() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["config", "get", "--json"])
    assert result.exit_code == 0
    assert "quarantine" in result.output
