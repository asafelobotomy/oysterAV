"""Setup workflow tests: assessing the setup, and the setup/status/config commands."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

import oyst_core
from oyst_cli.main import cli
from oyst_core.setup_workflow import assess_setup

_HELPER_OK = {"installed": True, "policy_current": True}
_FP = str(Path(oyst_core.__file__).resolve().parent)


def test_assess_setup_includes_needs_attention() -> None:
    with patch("oyst_core.setup_workflow.helper_status", return_value=_HELPER_OK):
        data = assess_setup()
    assert "needs_attention" in data
    assert "missing_required" in data
    assert "helper_missing" in data
    assert "install_mismatch" in data


def test_assess_setup_honors_skipped_required_packs_when_completed() -> None:
    with (
        patch(
            "oyst_core.setup_workflow.doctor_all",
            return_value=[
                {"name": "clamav", "tier": "required", "installed": False},
                {"name": "freshclam", "tier": "required", "installed": True},
            ],
        ),
        patch("oyst_core.setup_workflow.load_config") as mock_cfg,
        patch(
            "oyst_core.setup_workflow.host_daily_signatures_present",
            return_value=True,
        ),
        patch("oyst_core.setup_workflow.helper_status", return_value=_HELPER_OK),
    ):
        cfg = mock_cfg.return_value
        cfg.setup.completed = True
        cfg.setup.completed_at = "2026-01-01"
        cfg.setup.skipped_steps = ["required_packs"]
        cfg.setup.completed_install = _FP
        data = assess_setup()
    assert data["needs_attention"] is False
    assert "clamav" in data["missing_required"]


def test_assess_setup_still_needs_attention_when_missing_and_not_skipped() -> None:
    with (
        patch(
            "oyst_core.setup_workflow.doctor_all",
            return_value=[
                {"name": "clamav", "tier": "required", "installed": False},
            ],
        ),
        patch("oyst_core.setup_workflow.load_config") as mock_cfg,
        patch(
            "oyst_core.setup_workflow.host_daily_signatures_present",
            return_value=True,
        ),
        patch("oyst_core.setup_workflow.helper_status", return_value=_HELPER_OK),
    ):
        cfg = mock_cfg.return_value
        cfg.setup.completed = True
        cfg.setup.completed_at = "2026-01-01"
        cfg.setup.skipped_steps = []
        cfg.setup.completed_install = _FP
        data = assess_setup()
    assert data["needs_attention"] is True


def test_assess_setup_needs_attention_when_signatures_missing() -> None:
    with (
        patch(
            "oyst_core.setup_workflow.doctor_all",
            return_value=[
                {"name": "clamav", "tier": "required", "installed": True},
                {"name": "freshclam", "tier": "required", "installed": True},
            ],
        ),
        patch("oyst_core.setup_workflow.load_config") as mock_cfg,
        patch(
            "oyst_core.setup_workflow.host_daily_signatures_present",
            return_value=False,
        ),
        patch("oyst_core.setup_workflow.helper_status", return_value=_HELPER_OK),
    ):
        cfg = mock_cfg.return_value
        cfg.setup.completed = True
        cfg.setup.completed_at = "2026-01-01"
        cfg.setup.skipped_steps = []
        cfg.setup.completed_install = _FP
        data = assess_setup()
    assert data["needs_attention"] is True
    assert data["missing_signatures"] is True


def test_assess_setup_helper_missing() -> None:
    with (
        patch(
            "oyst_core.setup_workflow.doctor_all",
            return_value=[
                {"name": "clamav", "tier": "required", "installed": True},
            ],
        ),
        patch("oyst_core.setup_workflow.load_config") as mock_cfg,
        patch(
            "oyst_core.setup_workflow.host_daily_signatures_present",
            return_value=True,
        ),
        patch(
            "oyst_core.setup_workflow.helper_status",
            return_value={"installed": False, "policy_current": False},
        ),
    ):
        cfg = mock_cfg.return_value
        cfg.setup.completed = True
        cfg.setup.completed_at = "2026-01-01"
        cfg.setup.skipped_steps = []
        cfg.setup.completed_install = _FP
        data = assess_setup()
    assert data["helper_missing"] is True
    assert data["needs_attention"] is True


def test_assess_setup_install_mismatch_when_fingerprint_differs() -> None:
    with (
        patch(
            "oyst_core.setup_workflow.doctor_all",
            return_value=[
                {"name": "clamav", "tier": "required", "installed": True},
            ],
        ),
        patch("oyst_core.setup_workflow.load_config") as mock_cfg,
        patch(
            "oyst_core.setup_workflow.host_daily_signatures_present",
            return_value=True,
        ),
        patch("oyst_core.setup_workflow.helper_status", return_value=_HELPER_OK),
    ):
        cfg = mock_cfg.return_value
        cfg.setup.completed = True
        cfg.setup.completed_at = "2026-01-01"
        cfg.setup.skipped_steps = []
        cfg.setup.completed_install = "/other/install/oyst_core"
        data = assess_setup()
    assert data["install_mismatch"] is True
    assert data["needs_attention"] is True


def test_assess_setup_legacy_empty_fingerprint_ok_when_healthy() -> None:
    with (
        patch(
            "oyst_core.setup_workflow.doctor_all",
            return_value=[
                {"name": "clamav", "tier": "required", "installed": True},
            ],
        ),
        patch("oyst_core.setup_workflow.load_config") as mock_cfg,
        patch(
            "oyst_core.setup_workflow.host_daily_signatures_present",
            return_value=True,
        ),
        patch("oyst_core.setup_workflow.helper_status", return_value=_HELPER_OK),
    ):
        cfg = mock_cfg.return_value
        cfg.setup.completed = True
        cfg.setup.completed_at = "2026-01-01"
        cfg.setup.skipped_steps = []
        cfg.setup.completed_install = ""
        data = assess_setup()
    assert data["install_mismatch"] is False
    assert data["needs_attention"] is False


def test_assess_setup_legacy_empty_fingerprint_mismatch_if_helper_missing() -> None:
    with (
        patch(
            "oyst_core.setup_workflow.doctor_all",
            return_value=[
                {"name": "clamav", "tier": "required", "installed": True},
            ],
        ),
        patch("oyst_core.setup_workflow.load_config") as mock_cfg,
        patch(
            "oyst_core.setup_workflow.host_daily_signatures_present",
            return_value=True,
        ),
        patch(
            "oyst_core.setup_workflow.helper_status",
            return_value={"installed": True, "policy_current": False},
        ),
    ):
        cfg = mock_cfg.return_value
        cfg.setup.completed = True
        cfg.setup.completed_at = "2026-01-01"
        cfg.setup.skipped_steps = []
        cfg.setup.completed_install = ""
        data = assess_setup()
    assert data["helper_missing"] is True
    assert data["install_mismatch"] is True
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
