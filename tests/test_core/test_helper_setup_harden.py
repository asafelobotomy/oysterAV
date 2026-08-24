"""Tests for setup-harden helper concert."""

from __future__ import annotations

import json
from unittest.mock import patch

from oyst_core.privileged.helper_setup_harden import collect_harden_steps, run_setup_harden
from oyst_core.privileged.oyst_helper import run_helper_argv


def test_run_setup_harden_emits_json_steps(capsys) -> None:
    with (
        patch(
            "oyst_core.privileged.helper_setup_harden._run_cmd",
            return_value=(0, "ok"),
        ),
        patch("oyst_core.privileged.helper_setup_harden.ensure_fdpass_dropin"),
        patch(
            "oyst_core.privileged.helper_setup_harden.ensure_host_daily_signatures",
            return_value="signatures present",
        ),
        patch("oyst_core.privileged.helper_setup_harden.wait_for_clamd_ready"),
        patch("oyst_core.privileged.helper_setup_harden.apply_disable_tests_overlay") as rkh,
        patch("oyst_core.privileged.helper_setup_harden._ensure_virusevent"),
        patch("oyst_core.privileged.helper_setup_harden._ensure_system_wrapper"),
        patch("oyst_core.privileged.helper_setup_harden._ensure_disable_cache"),
        patch("oyst_core.privileged.helper_setup_harden.restart_clam_stack"),
        patch(
            "oyst_core.privileged.helper_setup_harden._validate_conf_path",
            side_effect=lambda p: __import__("pathlib").Path(p),
        ),
        patch(
            "oyst_core.privileged.helper_setup_harden._validate_wrapper_cmd",
            side_effect=lambda c: c,
        ),
    ):
        rkh.return_value = {"ok": True, "message": "rkh ok"}
        rc = run_setup_harden(
            [
                "--clamd-enable=clamav-daemon",
                "--fdpass-unit=clamav-clamonacc",
                "--ve-conf=/etc/clamav/clamd.conf",
                "--ve-cmd=/usr/lib/oysterav/oyst-virusevent",
                "--dc-conf=/etc/clamav/clamd.conf",
                "--rkh",
                "--rkh-tests=apps",
                "--clamd-unit=clamav-daemon",
            ],
        )
    assert rc == 0
    payload = json.loads(capsys.readouterr().out.strip())
    names = [s["step"] for s in payload["steps"]]
    assert "harden-clamd" in names
    assert "harden-fdpass" in names
    assert "harden-virusevent" in names
    assert "harden-disable-cache" in names
    assert "harden-rkhunter-defaults" in names


def test_harden_clamd_waits_for_socket() -> None:
    with (
        patch(
            "oyst_core.privileged.helper_setup_harden._run_cmd",
            return_value=(0, "ok"),
        ),
        patch(
            "oyst_core.privileged.helper_setup_harden.ensure_host_daily_signatures",
            return_value="signatures present",
        ),
        patch("oyst_core.privileged.helper_setup_harden.wait_for_clamd_ready") as wait,
        patch(
            "oyst_core.privileged.helper_setup_harden.apply_firewall_lifecycle_flags",
            return_value=[],
        ),
    ):
        steps = collect_harden_steps(
            ["--clamd-enable=clamav-daemon", "--socket=/run/clamav/clamd.ctl"],
        )
    assert steps[0]["step"] == "harden-clamd"
    assert steps[0]["ok"] is True
    wait.assert_called_once_with(sockets=["/run/clamav/clamd.ctl"])


def test_harden_gates_later_clam_steps_when_clamd_fails() -> None:
    with (
        patch(
            "oyst_core.privileged.helper_setup_harden._run_cmd",
            return_value=(1, "unit failed"),
        ),
        patch(
            "oyst_core.privileged.helper_setup_harden.ensure_host_daily_signatures",
            return_value="signatures present",
        ),
        patch("oyst_core.privileged.helper_setup_harden.wait_for_clamd_ready") as wait,
        patch("oyst_core.privileged.helper_setup_harden.ensure_fdpass_dropin") as fdpass,
        patch("oyst_core.privileged.helper_setup_harden._ensure_virusevent") as ve,
        patch("oyst_core.privileged.helper_setup_harden._ensure_disable_cache") as dc,
        patch("oyst_core.privileged.helper_setup_harden.restart_clam_stack") as restart,
        patch(
            "oyst_core.privileged.helper_setup_harden.apply_firewall_lifecycle_flags",
            return_value=[],
        ),
        patch("oyst_core.privileged.helper_setup_harden.apply_disable_tests_overlay") as rkh,
    ):
        rkh.return_value = {"ok": True, "message": "rkh ok"}
        steps = collect_harden_steps(
            [
                "--clamd-enable=clamav-daemon",
                "--fdpass-unit=clamav-clamonacc",
                "--ve-conf=/etc/clamav/clamd.conf",
                "--ve-cmd=/usr/lib/oysterav/oyst-virusevent",
                "--dc-conf=/etc/clamav/clamd.conf",
                "--rkh",
            ],
        )
    by_name = {s["step"]: s for s in steps}
    assert by_name["harden-clamd"]["ok"] is False
    assert by_name["harden-fdpass"]["message"] == "skipped: clamd not ready"
    assert by_name["harden-fdpass"].get("soft_fail") is True
    assert by_name["harden-virusevent"]["message"] == "skipped: clamd not ready"
    assert by_name["harden-disable-cache"]["message"] == "skipped: clamd not ready"
    assert by_name["harden-rkhunter-defaults"]["ok"] is True
    wait.assert_not_called()
    fdpass.assert_not_called()
    ve.assert_not_called()
    dc.assert_not_called()
    restart.assert_not_called()


def test_harden_without_clamd_enable_does_not_gate() -> None:
    with (
        patch("oyst_core.privileged.helper_setup_harden.ensure_fdpass_dropin") as fdpass,
        patch(
            "oyst_core.privileged.helper_setup_harden.apply_firewall_lifecycle_flags",
            return_value=[],
        ),
    ):
        steps = collect_harden_steps(["--fdpass-unit=clamav-clamonacc"])
    assert steps[0]["step"] == "harden-fdpass"
    assert steps[0]["ok"] is True
    fdpass.assert_called_once_with("clamav-clamonacc")


def test_oyst_helper_dispatches_setup_harden() -> None:
    with patch(
        "oyst_core.privileged.helper_concert.run_setup_harden",
        return_value=0,
    ) as harden:
        assert run_helper_argv(["setup-harden", "--rkh"]) == 0
    harden.assert_called_once_with(["--rkh"])


def test_oyst_helper_dispatches_setup_concert() -> None:
    with patch(
        "oyst_core.privileged.helper_concert.run_setup_concert",
        return_value=0,
    ) as concert:
        assert run_helper_argv(["setup-concert", "--propupd"]) == 0
    concert.assert_called_once_with(["--propupd"])
