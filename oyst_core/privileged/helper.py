"""Privileged helper interface (polkit/systemd integration)."""

from __future__ import annotations

import os
from collections.abc import Sequence
from pathlib import Path

from oyst_core.privileged.install_privileged_helper import resolve_installed_helper_path
from oyst_core.privileged.runner import (
    CommandResult,
    run_install_command,
    which,
)


def detect_aur_helper() -> str | None:
    return which("paru") or which("yay")


def resolve_helper_path() -> str | None:
    """Absolute path to oyst-helper (polkit exec.path), preferring /usr/lib then legacy."""
    installed = resolve_installed_helper_path()
    if installed is not None and os.access(installed, os.X_OK):
        return str(installed)
    return which("oyst-helper")


def run_privileged(
    argv: Sequence[str],
    *,
    timeout: int = 3600,
    cwd: str | None = None,
) -> CommandResult:
    """Run a command that may require elevated privileges via oyst-helper only."""
    helper = resolve_helper_path()
    pkexec = which("pkexec")
    if not helper or not pkexec:
        return CommandResult(1, "", "pkexec and oyst-helper required for privileged operation")
    try:
        return run_install_command(
            ["pkexec", helper, "run", *argv],
            timeout=timeout,
            cwd=cwd,
        )
    except (ValueError, OSError) as exc:
        return CommandResult(1, "", str(exc))


def run_privileged_helper(
    subcommand: str,
    argv: Sequence[str],
    *,
    timeout: int = 3600,
) -> CommandResult:
    """Run a validated oyst-helper subcommand (firewall, fail2ban, systemctl, etc.)."""
    helper = resolve_helper_path()
    pkexec = which("pkexec")
    if helper and pkexec:
        try:
            return run_install_command(
                ["pkexec", helper, subcommand, *argv],
                timeout=timeout,
            )
        except (ValueError, OSError) as exc:
            return CommandResult(1, "", str(exc))
    return CommandResult(1, "", "pkexec and oyst-helper required for privileged operation")


def run_privileged_install_script(script_path: str) -> CommandResult:
    """Run a vetted install.sh via oyst-helper only (no raw pkexec bash)."""
    helper = resolve_helper_path()
    pkexec = which("pkexec")
    script = str(Path(script_path).resolve())
    if not helper or not pkexec:
        return CommandResult(1, "", "pkexec and oyst-helper required for install script")
    try:
        return run_install_command(
            ["pkexec", helper, "install-script", script],
            timeout=1800,
        )
    except (ValueError, OSError) as exc:
        return CommandResult(1, "", str(exc))


def _build_install_argv(packages: list[str], family: str, *, sync: bool = True) -> list[str] | None:
    if family == "arch":
        argv = ["pacman", "-S", "--noconfirm", *packages]
        if sync:
            argv = ["pacman", "-Sy", "--noconfirm", *packages]
        return argv
    if family == "fedora":
        return ["dnf", "install", "-y", *packages]
    if which("apt-get"):
        return ["apt-get", "install", "-y", *packages]
    if which("apt"):
        return ["apt", "install", "-y", *packages]
    return None


def run_privileged_install(
    packages: list[str],
    family: str,
    *,
    sync: bool = True,
) -> CommandResult:
    """Attempt install via pkexec + distro package manager."""
    argv = _build_install_argv(packages, family, sync=sync)
    if argv is None:
        return CommandResult(1, "", "No supported package manager found")
    return run_privileged(argv, timeout=1800)


def run_aur_install(packages: list[str]) -> CommandResult:
    """Install AUR packages as the current user.

    paru/yay refuse AUR builds as root, so we must not wrap them in pkexec.
    The helper elevates only when talking to pacman (polkit/sudo), as usual.
    """
    helper = detect_aur_helper()
    if helper is None:
        return CommandResult(1, "", "No AUR helper found (install paru or yay)")
    argv = [helper, "-S", "--noconfirm", "--needed", *packages]
    try:
        return run_install_command(argv, timeout=3600)
    except (ValueError, OSError) as exc:
        return CommandResult(1, "", str(exc))


def run_privileged_aur_install(packages: list[str]) -> CommandResult:
    """Install packages from the AUR (user-mode; name kept for call-site stability)."""
    return run_aur_install(packages)


def run_privileged_linger(username: str) -> CommandResult:
    """Enable systemd user lingering for scheduled scans."""
    return run_privileged(["loginctl", "enable-linger", username], timeout=60)


def run_privileged_linger_disable(username: str) -> CommandResult:
    """Disable systemd user lingering for the named user."""
    return run_privileged(["loginctl", "disable-linger", username], timeout=60)
