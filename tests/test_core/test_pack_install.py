"""Tests for pack installation."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from oyst_core.pack_install import (
    install_pack,
    resolve_install_strategy,
)
from oyst_core.privileged.runner import CommandResult


def test_install_pack_already_installed() -> None:
    mock_pack = MagicMock()
    mock_pack.doctor.return_value.installed = True
    with patch("oyst_core.pack_install.get_registry") as reg:
        reg.return_value.get.return_value = mock_pack
        result = install_pack("clamav")
    assert result.ok is True
    assert result.mode == "installed"


def test_install_pack_maldet_aur_confirm() -> None:
    mock_pack = MagicMock()
    mock_pack.doctor.return_value.installed = False
    mock_pack.doctor.return_value.install_hint = "sudo paru -S maldet"
    with (
        patch("oyst_core.pack_install.get_registry") as reg,
        patch("oyst_core.pack_install.is_full_mode", return_value=False),
        patch("oyst_core.pack_install.resolve_install_strategy", return_value=("aur", ["maldet"])),
    ):
        reg.return_value.get.return_value = mock_pack
        result = install_pack("maldet")
    assert result.ok is False
    assert result.mode == "aur_confirm"
    assert result.requires_confirmation is True
    assert result.aur_available is True


def test_install_pack_command_fallback() -> None:
    mock_pack = MagicMock()
    status = MagicMock()
    status.installed = False
    status.install_hint = "sudo apt install rkhunter"
    mock_pack.doctor.side_effect = [status, status]
    with (
        patch("oyst_core.pack_install.get_registry") as reg,
        patch("oyst_core.pack_install.is_full_mode", return_value=False),
        patch("oyst_core.pack_install.run_privileged_install") as run_install,
        patch(
            "oyst_core.pack_install.resolve_install_strategy",
            return_value=("official", ["rkhunter"]),
        ),
    ):
        reg.return_value.get.return_value = mock_pack
        run_install.return_value = CommandResult(1, "", "pkexec denied")
        result = install_pack("rkhunter")
    assert result.ok is False
    assert result.mode == "command"
    assert "sudo apt install rkhunter" in result.install_hint


def test_install_pack_auto_success() -> None:
    mock_pack = MagicMock()
    before = MagicMock()
    before.installed = False
    before.install_hint = "sudo apt install chkrootkit"
    after = MagicMock()
    after.installed = True
    mock_pack.doctor.side_effect = [before, after]
    with (
        patch("oyst_core.pack_install.get_registry") as reg,
        patch("oyst_core.pack_install.is_full_mode", return_value=False),
        patch("oyst_core.pack_install.run_privileged_install") as run_install,
        patch(
            "oyst_core.pack_install.resolve_install_strategy",
            return_value=("official", ["chkrootkit"]),
        ),
    ):
        reg.return_value.get.return_value = mock_pack
        run_install.return_value = CommandResult(0, "installed", "")
        result = install_pack("chkrootkit")
    assert result.ok is True
    assert result.mode == "auto"


def test_resolve_install_strategy_arch_aur_only() -> None:
    with (
        patch("oyst_core.pack_install.detect_distro_family", return_value="arch"),
        patch("oyst_core.pack_install._pacman_package_available", return_value=False),
        patch("oyst_core.pack_install._aur_package_available", return_value=True),
    ):
        strategy, packages = resolve_install_strategy("chkrootkit", "arch")
    assert strategy == "aur"
    assert packages == ["chkrootkit"]


def test_resolve_install_strategy_maldet_tarball_without_aur_helper() -> None:
    with (
        patch("oyst_core.pack_install.detect_distro_family", return_value="arch"),
        patch("oyst_core.pack_install._pacman_package_available", return_value=False),
        patch("oyst_core.pack_install.detect_aur_helper", return_value=None),
    ):
        strategy, _packages = resolve_install_strategy("maldet", "arch")
    assert strategy == "tarball"


def test_install_pack_full_mode_runtime() -> None:
    mock_pack = MagicMock()
    before = MagicMock()
    before.installed = False
    after = MagicMock()
    after.installed = True
    mock_pack.doctor.side_effect = [before, after]
    with (
        patch("oyst_core.pack_install.get_registry") as reg,
        patch("oyst_core.pack_install.is_full_mode", return_value=True),
        patch(
            "oyst_core.pack_install.install_pack_runtime",
            return_value={"ok": True, "message": "runtime ok"},
        ),
    ):
        reg.return_value.get.return_value = mock_pack
        result = install_pack("lynis")
    assert result.ok is True
    assert result.mode == "runtime"
    assert result.strategy == "runtime"


def test_install_pack_full_mode_fangfrisch_uses_runtime() -> None:
    """fangfrisch is a RUNTIME_PACK — full mode installs via private pip venv."""
    mock_pack = MagicMock()
    before = MagicMock()
    before.installed = False
    after = MagicMock()
    after.installed = True
    mock_pack.doctor.side_effect = [before, after]
    with (
        patch("oyst_core.pack_install.get_registry") as reg,
        patch("oyst_core.pack_install.is_full_mode", return_value=True),
        patch(
            "oyst_core.pack_install.install_pack_runtime",
            return_value={"ok": True, "message": "fangfrisch runtime ok"},
        ) as runtime_install,
    ):
        reg.return_value.get.return_value = mock_pack
        result = install_pack("fangfrisch")
    runtime_install.assert_called_once()
    assert result.ok is True
    assert result.mode == "runtime"
