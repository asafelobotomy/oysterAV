"""Tests for setup-harden helper concert."""

from __future__ import annotations

import json
from unittest.mock import patch

from oyst_core.privileged.helper_setup_harden import run_setup_harden
from oyst_core.privileged.oyst_helper import run_helper_argv


def test_run_setup_harden_emits_json_steps(capsys) -> None:
    with (
        patch(
            "oyst_core.privileged.helper_setup_harden._run_cmd",
            return_value=(0, "ok"),
        ),
        patch("oyst_core.privileged.helper_setup_harden.ensure_fdpass_dropin"),
        patch("oyst_core.privileged.helper_setup_harden.apply_disable_tests_overlay") as rkh,
        patch("oyst_core.privileged.helper_setup_harden._ensure_virusevent"),
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
                "--ve-cmd=/home/u/.local/share/oysterav/oyst-virusevent",
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
