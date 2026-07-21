"""Unit tests for setup concert helper dispatch."""

from __future__ import annotations

from unittest.mock import patch

from oyst_core.privileged.helper_setup_concert import _install_maldet, _install_official_packs


def test_helper_setup_concert_maldet_requires_tarball_flags() -> None:
    steps = _install_maldet(["--maldet-script=/tmp/x/install.sh", "--maldet-sha=" + "a" * 64])
    assert steps and steps[0]["ok"] is False
    assert "maldet-script is removed" in str(steps[0].get("message"))


def test_helper_setup_concert_maldet_incomplete_flags() -> None:
    steps = _install_maldet(["--maldet-tarball=/tmp/oyst-maldet-x/t.tar.gz"])
    assert steps and steps[0]["ok"] is False
    assert "maldet-tarball" in str(steps[0].get("message"))


def test_helper_setup_concert_official_install_builds_argv() -> None:
    with (
        patch(
            "oyst_core.privileged.helper_setup_concert.resolve_trusted_argv",
            side_effect=lambda a: a,
        ),
        patch(
            "oyst_core.privileged.helper_setup_concert._run_cmd",
            return_value=(0, "ok"),
        ),
    ):
        steps = _install_official_packs(
            ["--family=arch", "--install=clamav:clamav,clamav-daemon"],
        )
    assert steps
    assert steps[0]["ok"] is True
    assert steps[0]["step"] == "install-clamav"
