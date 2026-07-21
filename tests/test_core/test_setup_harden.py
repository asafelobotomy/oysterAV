"""Tests for first-run safe hardenings."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from oyst_core.setup_harden import apply_safe_hardenings


def test_apply_safe_hardenings_single_helper_call() -> None:
    helper_payload = {
        "steps": [
            {"step": "harden-clamd", "ok": True, "message": "ok"},
            {"step": "harden-fdpass", "ok": True, "message": "fdpass"},
            {"step": "harden-virusevent", "ok": True, "message": "ve"},
            {"step": "harden-disable-cache", "ok": True, "message": "dc"},
            {"step": "harden-rkhunter-defaults", "ok": True, "message": "rkh"},
        ],
    }
    mock_res = MagicMock(returncode=0, stdout=json.dumps(helper_payload), stderr="")
    with (
        patch("oyst_core.setup_harden.ClamAVPack") as clam_cls,
        patch(
            "oyst_core.setup_harden.fdpass_status",
            return_value={"unit": "clamav-clamonacc", "fdpass": False},
        ),
        patch("oyst_core.setup_harden.install_wrapper", return_value={}),
        patch(
            "oyst_core.setup_harden.virusevent_status",
            return_value={"conf_path": "/etc/clamav/clamd.conf", "configured": False},
        ),
        patch(
            "oyst_core.setup_harden.recommended_virus_event_command",
            return_value="/home/u/.local/share/oysterav/oyst-virusevent",
        ),
        patch("oyst_core.setup_harden.wrapper_path", return_value="/x/oyst-virusevent"),
        patch(
            "oyst_core.setup_harden.probe_onaccess_prevention",
            return_value={"conf_path": "/etc/clamav/clamd.conf", "disable_cache": False},
        ),
        patch("oyst_core.setup_harden.which", return_value="/usr/bin/rkhunter"),
        patch(
            "oyst_core.setup_harden.load_config",
            return_value=MagicMock(rkhunter=MagicMock(disable_tests=["apps"])),
        ),
        patch("oyst_core.setup_harden.DEFAULTS_OVERLAY_PATH") as overlay,
        patch(
            "oyst_core.privilege.run.run_privileged_helper",
            return_value=mock_res,
        ) as helper,
        patch("oyst_core.setup_harden.SecurityAudit"),
        patch("oyst_core.privilege.run.SecurityAudit"),
        patch("oyst_core.setup_harden._append_restart_flags"),
    ):
        clam = clam_cls.return_value
        clam.clamd_status.return_value = {"running": False, "unit": "clamav-daemon"}
        clam.clamd_unit.return_value = "clamav-daemon"
        overlay.is_file.return_value = False
        steps = apply_safe_hardenings(confirm=True)

    helper.assert_called_once()
    assert helper.call_args.args[0] == "setup-harden"
    argv = helper.call_args.args[1]
    assert any(a.startswith("--clamd-enable=") for a in argv)
    assert any(a.startswith("--fdpass-unit=") for a in argv)
    assert any(a.startswith("--ve-conf=") for a in argv)
    assert any(a.startswith("--dc-conf=") for a in argv)
    assert "--rkh" in argv
    names = [s["step"] for s in steps]
    assert names == [
        "harden-clamd",
        "harden-fdpass",
        "harden-virusevent",
        "harden-disable-cache",
        "harden-rkhunter-defaults",
    ]
    assert all(s.get("ok") for s in steps)


def test_apply_safe_hardenings_skips_without_helper() -> None:
    with (
        patch("oyst_core.setup_harden.ClamAVPack") as clam_cls,
        patch(
            "oyst_core.setup_harden.fdpass_status",
            return_value={"unit": None, "message": "no unit"},
        ),
        patch("oyst_core.setup_harden.install_wrapper", return_value={}),
        patch(
            "oyst_core.setup_harden.virusevent_status",
            return_value={
                "owned_by_oysterav": True,
                "configured": True,
                "conf_path": "/etc/clamav/clamd.conf",
            },
        ),
        patch(
            "oyst_core.setup_harden.probe_onaccess_prevention",
            return_value={"disable_cache": True},
        ),
        patch("oyst_core.setup_harden.which", return_value=None),
        patch("oyst_core.privilege.run.run_privileged_helper") as helper,
    ):
        clam_cls.return_value.clamd_status.return_value = {"running": True, "unit": "clamav-daemon"}
        steps = apply_safe_hardenings(confirm=True)
    helper.assert_not_called()
    assert all(s.get("ok") for s in steps)
    assert all(s.get("skipped") for s in steps)


def test_apply_safe_hardenings_soft_fails_local() -> None:
    with (
        patch("oyst_core.setup_harden.ClamAVPack") as clam_cls,
        patch(
            "oyst_core.setup_harden.fdpass_status",
            return_value={"unit": "clamav-clamonacc", "fdpass": False},
        ),
        patch("oyst_core.setup_harden.install_wrapper", return_value={}),
        patch(
            "oyst_core.setup_harden.virusevent_status",
            return_value={"handoff": True, "message": "foreign VirusEvent"},
        ),
        patch(
            "oyst_core.setup_harden.probe_onaccess_prevention",
            return_value={
                "conf_path": "/etc/clamav/clamd.conf",
                "disable_cache": False,
                "conflict_sidecars": ["/etc/clamav/clamd.conf.rpmnew"],
            },
        ),
        patch("oyst_core.setup_harden.which", return_value=None),
        patch(
            "oyst_core.privilege.run.run_privileged_helper",
            return_value=MagicMock(
                returncode=0,
                stdout=json.dumps(
                    {
                        "steps": [
                            {
                                "step": "harden-clamd",
                                "ok": False,
                                "soft_fail": True,
                                "message": "x",
                            },
                            {
                                "step": "harden-fdpass",
                                "ok": False,
                                "soft_fail": True,
                                "message": "polkit denied",
                            },
                        ],
                    },
                ),
                stderr="",
            ),
        ),
        patch("oyst_core.setup_harden.SecurityAudit"),
        patch("oyst_core.privilege.run.SecurityAudit"),
        patch("oyst_core.setup_harden._append_restart_flags"),
    ):
        clam = clam_cls.return_value
        clam.clamd_status.return_value = {"running": False, "unit": "clamav-daemon"}
        clam.clamd_unit.return_value = "clamav-daemon"
        steps = apply_safe_hardenings(confirm=True)
    by_name = {s["step"]: s for s in steps}
    assert by_name["harden-virusevent"].get("soft_fail") is True
    assert by_name["harden-disable-cache"].get("soft_fail") is True
    assert by_name["harden-rkhunter-defaults"].get("skipped") is True


def test_setup_run_includes_harden_and_firewall() -> None:
    from oyst_core.setup_workflow import run_setup

    with (
        patch(
            "oyst_core.setup_workflow.run_bootstrap",
            return_value=[{"step": "freshclam", "ok": True}],
        ),
        patch("oyst_core.setup_workflow.is_full_mode", return_value=False),
        patch("oyst_core.setup_workflow.run_setup_concert") as concert,
        patch("oyst_core.registry.get_registry") as mock_registry,
    ):
        concert.return_value = [
            {"step": "harden-clamd", "ok": True},
            {"step": "firewall-ensure", "ok": True, "skipped": True},
        ]
        mock_registry.return_value.all.return_value = []
        result = run_setup(skip_packs=True, skip_schedule=True, mark_complete=True)
    concert.assert_called_once()
    assert concert.call_args.kwargs.get("skip_harden") is False
    assert concert.call_args.kwargs.get("enable_firewall") is True
    assert any(s.get("step") == "harden-clamd" for s in result["steps"])
    assert any(s.get("step") == "firewall-ensure" for s in result["steps"])
    assert result["marked_complete"] is True


def test_setup_run_skip_harden() -> None:
    from oyst_core.setup_workflow import run_setup

    with (
        patch(
            "oyst_core.setup_workflow.run_bootstrap",
            return_value=[{"step": "freshclam", "ok": True}],
        ),
        patch("oyst_core.setup_workflow.is_full_mode", return_value=False),
        patch("oyst_core.setup_workflow.run_setup_concert") as concert,
        patch("oyst_core.registry.get_registry") as mock_registry,
    ):
        concert.return_value = []
        mock_registry.return_value.all.return_value = []
        result = run_setup(
            skip_packs=True,
            skip_schedule=True,
            skip_harden=True,
            enable_firewall=False,
            mark_complete=True,
        )
    concert.assert_called_once()
    assert concert.call_args.kwargs.get("skip_harden") is True
    assert concert.call_args.kwargs.get("enable_firewall") is False
    assert any(s.get("step") == "harden" and s.get("skipped") for s in result["steps"])
    assert any(s.get("step") == "firewall-ensure" and s.get("skipped") for s in result["steps"])
