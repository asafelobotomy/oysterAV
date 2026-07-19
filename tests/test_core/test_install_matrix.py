"""Tests for install strategy integration matrix."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from oyst_core.pack_install import install_pack
from oyst_core.privileged.runner import CommandResult


def test_maldet_aur_then_tarball_fallback() -> None:
    mock_pack = MagicMock()
    before = MagicMock()
    before.installed = False
    after = MagicMock()
    after.installed = True
    mock_pack.doctor.side_effect = [before, before, after]
    with (
        patch("oyst_core.pack_install.get_registry") as reg,
        patch("oyst_core.pack_install.is_full_mode", return_value=False),
        patch("oyst_core.pack_install.resolve_install_strategy", return_value=("aur", ["maldet"])),
        patch("oyst_core.pack_install.run_privileged_aur_install") as aur_install,
        patch("oyst_core.pack_install.install_maldet_tarball") as tarball,
    ):
        reg.return_value.get.return_value = mock_pack
        aur_install.return_value = CommandResult(1, "", "AUR build failed")
        tarball.return_value = CommandResult(0, "installed", "")
        result = install_pack("maldet", confirm_aur=True)
    assert result.ok is True
    assert result.strategy == "aur"
    tarball.assert_called_once()


def test_install_result_fields_on_failure() -> None:
    mock_pack = MagicMock()
    status = MagicMock()
    status.installed = False
    status.install_hint = "sudo paru -S chkrootkit"
    mock_pack.doctor.side_effect = [status, status]
    with (
        patch("oyst_core.pack_install.get_registry") as reg,
        patch("oyst_core.pack_install.is_full_mode", return_value=False),
        patch(
            "oyst_core.pack_install.resolve_install_strategy",
            return_value=("aur", ["chkrootkit"]),
        ),
        patch("oyst_core.pack_install.run_privileged_aur_install") as aur_install,
    ):
        reg.return_value.get.return_value = mock_pack
        aur_install.return_value = CommandResult(1, "", "cancelled")
        result = install_pack("chkrootkit", confirm_aur=True)
    assert result.ok is False
    assert result.strategy == "aur"
    assert result.reason == "install_failed"
