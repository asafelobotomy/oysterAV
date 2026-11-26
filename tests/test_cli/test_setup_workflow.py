"""Setup workflow tests."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

import oyst_core
from oyst_cli.main import cli
from oyst_core.maintenance import bootstrap_critical_ok
from oyst_core.models import PackTier
from oyst_core.setup_workflow import run_setup

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
