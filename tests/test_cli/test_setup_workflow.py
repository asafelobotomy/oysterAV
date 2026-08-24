"""Setup workflow tests."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

import oyst_core
from oyst_cli.main import cli
from oyst_core.maintenance import bootstrap_critical_ok
from oyst_core.models import PackTier
from oyst_core.setup_workflow import assess_setup, run_setup

_HELPER_OK = {"installed": True, "policy_current": True}
_FP = str(Path(oyst_core.__file__).resolve().parent)


def test_bootstrap_critical_ok_requires_freshclam() -> None:
    assert bootstrap_critical_ok([{"step": "doctor-clamav", "ok": True}]) is True
    assert (
        bootstrap_critical_ok(
            [
                {"step": "doctor-clamav", "ok": True},
                {"step": "freshclam", "ok": False},
            ]
        )
        is False
    )
    assert (
        bootstrap_critical_ok(
            [
                {"step": "doctor-clamav", "ok": False},
                {"step": "freshclam", "ok": True},
            ]
        )
        is True
    )
    assert (
        bootstrap_critical_ok(
            [{"step": "freshclam", "ok": False, "skipped": True}],
        )
        is True
    )


def test_setup_run_non_interactive_json() -> None:
    with (
        patch(
            "oyst_core.setup_workflow.run_bootstrap",
            return_value=[{"step": "freshclam", "ok": True}],
        ),
        patch(
            "oyst_core.setup_workflow.apply_schedule",
            return_value={"ok": True, "message": "ok"},
        ),
        patch("oyst_core.setup_workflow.is_full_mode", return_value=False),
        patch(
            "oyst_core.setup_workflow.run_setup_concert",
            return_value=[
                {"step": "harden-clamd", "ok": True},
                {"step": "firewall-ensure", "ok": True, "skipped": True},
            ],
        ),
        patch("oyst_core.registry.get_registry") as mock_registry,
    ):
        mock_registry.return_value.all.return_value = []
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["setup", "run", "--skip-packs", "--skip-schedule", "--confirm", "--json"],
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
        patch(
            "oyst_core.setup_workflow.run_setup_concert",
            return_value=[
                {"step": "harden-clamd", "ok": True},
                {"step": "firewall-ensure", "ok": True, "skipped": True},
            ],
        ),
        patch("oyst_core.setup_workflow.set_config_value") as mock_set,
        patch("oyst_core.registry.get_registry") as mock_registry,
    ):
        mock_registry.return_value.all.return_value = []
        result = run_setup(skip_packs=True, skip_schedule=True, mark_complete=True)
    assert result["marked_complete"] is False
    completed_calls = [c for c in mock_set.call_args_list if c.args[0] == "setup.completed"]
    assert not any(c.args[1] == "true" for c in completed_calls)


def test_setup_run_doctor_ok_freshclam_fail_blocks_complete() -> None:
    """UX-17: doctor success must not mask freshclam failure for mark-complete."""
    with (
        patch(
            "oyst_core.setup_workflow.run_bootstrap",
            return_value=[
                {"step": "doctor-clamav", "ok": True},
                {"step": "freshclam", "ok": False, "message": "cvd fail"},
            ],
        ),
        patch(
            "oyst_core.setup_workflow.apply_schedule",
            return_value={"ok": True, "message": "ok"},
        ),
        patch("oyst_core.setup_workflow.is_full_mode", return_value=False),
        patch(
            "oyst_core.setup_workflow.run_setup_concert",
            return_value=[
                {"step": "harden-clamd", "ok": True},
                {"step": "firewall-ensure", "ok": True, "skipped": True},
            ],
        ),
        patch("oyst_core.setup_workflow.set_config_value") as mock_set,
        patch("oyst_core.registry.get_registry") as mock_registry,
    ):
        mock_registry.return_value.all.return_value = []
        result = run_setup(skip_packs=True, skip_schedule=True, mark_complete=True)
    assert result["marked_complete"] is False
    assert result["can_mark_complete"] is False
    maint = next(s for s in result["steps"] if s.get("step") == "maintenance-bootstrap")
    assert maint.get("ok") is False
    completed_calls = [c for c in mock_set.call_args_list if c.args[0] == "setup.completed"]
    assert not any(c.args[1] == "true" for c in completed_calls)


def test_setup_run_packs_gate_does_not_auto_skip() -> None:
    """UX-16: missing required packs after concert → packs-gate fail, no skip honor."""
    pack = MagicMock()
    pack.doctor.return_value.model_dump.return_value = {
        "name": "clamav",
        "tier": PackTier.REQUIRED.value,
        "installed": False,
    }

    with (
        patch(
            "oyst_core.setup_workflow.run_bootstrap",
            return_value=[{"step": "freshclam", "ok": True}],
        ),
        patch(
            "oyst_core.setup_workflow.apply_schedule",
            return_value={"ok": True, "message": "ok"},
        ),
        patch("oyst_core.setup_workflow.is_full_mode", return_value=False),
        patch(
            "oyst_core.setup_workflow.run_setup_concert",
            return_value=[
                {"step": "harden-clamd", "ok": True},
                {"step": "firewall-ensure", "ok": True, "skipped": True},
            ],
        ),
        patch("oyst_core.setup_workflow.set_config_value") as mock_set,
        patch("oyst_core.setup_workflow.get_registry") as mock_registry,
    ):
        mock_registry.return_value.all.return_value = [pack]
        result = run_setup(skip_packs=False, skip_schedule=True, mark_complete=True)
    gate = next(s for s in result["steps"] if s.get("step") == "packs-gate")
    assert gate.get("ok") is False
    assert gate.get("skipped") is not True
    assert result["marked_complete"] is False
    skip_calls = [c for c in mock_set.call_args_list if c.args[0] == "setup.skipped_steps"]
    assert not skip_calls


def test_setup_run_harden_clamd_fail_blocks_complete() -> None:
    with (
        patch(
            "oyst_core.setup_workflow.run_bootstrap",
            return_value=[{"step": "freshclam", "ok": True}],
        ),
        patch(
            "oyst_core.setup_workflow.apply_schedule",
            return_value={"ok": True, "message": "ok"},
        ),
        patch("oyst_core.setup_workflow.is_full_mode", return_value=False),
        patch(
            "oyst_core.setup_workflow.run_setup_concert",
            return_value=[
                {"step": "harden-clamd", "ok": False, "message": "no cvd"},
                {"step": "firewall-ensure", "ok": True, "skipped": True},
            ],
        ),
        patch("oyst_core.setup_workflow.set_config_value"),
        patch("oyst_core.registry.get_registry") as mock_registry,
    ):
        mock_registry.return_value.all.return_value = []
        result = run_setup(skip_packs=True, skip_schedule=True, mark_complete=True)
    assert result["marked_complete"] is False
    assert result["can_mark_complete"] is False
    clamd = next(s for s in result["steps"] if s.get("step") == "harden-clamd")
    assert clamd.get("soft_fail") is not True


def test_setup_run_linger_fail_blocks_complete() -> None:
    with (
        patch(
            "oyst_core.setup_workflow.run_bootstrap",
            return_value=[{"step": "freshclam", "ok": True}],
        ),
        patch(
            "oyst_core.setup_workflow.apply_schedule",
            return_value={"ok": True, "message": "ok"},
        ),
        patch("oyst_core.setup_workflow.is_full_mode", return_value=False),
        patch(
            "oyst_core.setup_workflow.run_setup_concert",
            return_value=[
                {"step": "harden-clamd", "ok": True},
                {"step": "firewall-ensure", "ok": True, "skipped": True},
                {"step": "linger", "ok": False, "message": "linger denied"},
            ],
        ),
        patch("oyst_core.setup_workflow.set_config_value"),
        patch("oyst_core.registry.get_registry") as mock_registry,
    ):
        mock_registry.return_value.all.return_value = []
        result = run_setup(
            skip_packs=True,
            skip_schedule=True,
            enable_linger=True,
            mark_complete=True,
        )
    assert result["marked_complete"] is False


def test_setup_run_stores_install_fingerprint_on_complete() -> None:
    with (
        patch(
            "oyst_core.setup_workflow.run_bootstrap",
            return_value=[{"step": "freshclam", "ok": True}],
        ),
        patch(
            "oyst_core.setup_workflow.apply_schedule",
            return_value={"ok": True, "message": "ok"},
        ),
        patch("oyst_core.setup_workflow.is_full_mode", return_value=False),
        patch(
            "oyst_core.setup_workflow.run_setup_concert",
            return_value=[
                {"step": "harden-clamd", "ok": True},
                {"step": "firewall-ensure", "ok": True, "skipped": True},
            ],
        ),
        patch("oyst_core.setup_workflow.set_config_value") as mock_set,
        patch("oyst_core.registry.get_registry") as mock_registry,
    ):
        mock_registry.return_value.all.return_value = []
        result = run_setup(skip_packs=True, skip_schedule=True, mark_complete=True)
    assert result["marked_complete"] is True
    fp_calls = [c for c in mock_set.call_args_list if c.args[0] == "setup.completed_install"]
    assert fp_calls
    assert fp_calls[-1].args[1] == _FP


def test_setup_run_enable_linger_via_concert() -> None:
    with (
        patch(
            "oyst_core.setup_workflow.run_bootstrap",
            return_value=[{"step": "freshclam", "ok": True}],
        ),
        patch(
            "oyst_core.setup_workflow.apply_schedule",
            return_value={
                "ok": True,
                "message": "timer ok",
                "linger_advisory": "enable linger",
            },
        ),
        patch("oyst_core.setup_workflow.is_full_mode", return_value=False),
        patch(
            "oyst_core.setup_workflow.run_setup_concert",
            return_value=[
                {"step": "harden-clamd", "ok": True},
                {"step": "firewall-ensure", "ok": True, "skipped": True},
                {"step": "linger", "ok": True, "message": "linger enabled"},
            ],
        ) as concert,
        patch("oyst_core.registry.get_registry") as mock_registry,
    ):
        mock_registry.return_value.all.return_value = []
        result = run_setup(skip_packs=True, enable_linger=True)
    assert concert.call_args.kwargs.get("enable_linger") is True
    assert any(step.get("step") == "linger" for step in result["steps"])


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
