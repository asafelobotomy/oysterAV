"""Tests for ORD-01 harden argv re-probe after pack install."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from oyst_core.privileged.helper_harden_reprobe import augment_harden_argv_after_install


def test_augment_adds_clamd_and_conf_after_clamav_install(tmp_path: Path) -> None:
    conf = tmp_path / "clamd.conf"
    conf.write_text("User clamav\n", encoding="utf-8")
    ve = tmp_path / "oyst-virusevent"
    ve.write_text("#!/bin/sh\n", encoding="utf-8")
    with (
        patch(
            "oyst_core.privileged.helper_harden_reprobe.probe_clamd_unit",
            return_value="clamav-daemon",
        ),
        patch(
            "oyst_core.privileged.helper_harden_reprobe.probe_clamd_conf",
            return_value=str(conf),
        ),
        patch("oyst_core.privileged.helper_harden_reprobe._VE_CMD", str(ve)),
    ):
        out = augment_harden_argv_after_install(
            ["--family=arch"],
            [{"step": "install-clamav", "ok": True}],
        )
    assert "--clamd-enable=clamav-daemon" in out
    assert "--clamd-unit=clamav-daemon" in out
    assert f"--ve-conf={conf}" in out
    assert f"--ve-cmd={ve}" in out
    assert f"--dc-conf={conf}" in out


def test_augment_adds_fdpass_and_rkh() -> None:
    with patch(
        "oyst_core.privileged.helper_harden_reprobe.probe_clamonacc_unit",
        return_value="clamav-clamonacc",
    ):
        out = augment_harden_argv_after_install(
            [],
            [
                {"step": "install-clamonacc", "ok": True},
                {"step": "install-rkhunter", "ok": True},
            ],
        )
    assert "--fdpass-unit=clamav-clamonacc" in out
    assert "--rkh" in out


def test_augment_skips_when_flags_already_present() -> None:
    out = augment_harden_argv_after_install(
        [
            "--clamd-enable=clamd@scan",
            "--fdpass-unit=clamav-clamonacc",
            "--ve-conf=/etc/clamav/clamd.conf",
            "--dc-conf=/etc/clamav/clamd.conf",
            "--rkh",
        ],
        [
            {"step": "install-clamav", "ok": True},
            {"step": "install-clamonacc", "ok": True},
            {"step": "install-rkhunter", "ok": True},
        ],
    )
    assert out.count("--clamd-enable=clamd@scan") == 1
    assert "--clamd-enable=clamav-daemon" not in out
    assert out.count("--rkh") == 1


def test_augment_ignores_failed_installs() -> None:
    out = augment_harden_argv_after_install(
        [],
        [{"step": "install-clamav", "ok": False, "soft_fail": True}],
    )
    assert out == []
