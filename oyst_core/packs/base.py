"""Pack protocol and shared utilities."""

from __future__ import annotations

import platform
from abc import ABC, abstractmethod
from typing import Any

from oyst_core.models import PackStatus, PackTier
from oyst_core.privileged.runner import version_gte, which


def distro_install_hint(pack: str) -> str:
    """Return install command hints for common distros."""
    hints: dict[str, dict[str, str]] = {
        "clamav": {
            "debian": "sudo apt install clamav clamav-daemon",
            "arch": "sudo pacman -S clamav",
            "fedora": "sudo dnf install clamav clamav-update",
        },
        "freshclam": {
            "debian": "sudo apt install clamav-freshclam",
            "arch": "sudo pacman -S clamav",
            "fedora": "sudo dnf install clamav-update",
        },
        "rkhunter": {
            "debian": "sudo apt install rkhunter",
            "arch": "sudo pacman -S rkhunter",
            "fedora": "sudo dnf install rkhunter",
        },
        "chkrootkit": {
            "debian": "sudo apt install chkrootkit",
            "arch": "sudo paru -S chkrootkit  # AUR-only on Arch",
            "fedora": "sudo dnf install chkrootkit",
        },
        "lynis": {
            "debian": "sudo apt install lynis",
            "arch": "sudo pacman -S lynis",
            "fedora": "sudo dnf install lynis",
        },
        "maldet": {
            "debian": (
                "See https://rfxn.com/projects/linux-malware-detect"
                " (or: sudo paru -S maldet on Arch)"
            ),
            "arch": "sudo paru -S maldet  # AUR, or tarball from rfxn.com",
            "fedora": "See https://rfxn.com/projects/linux-malware-detect",
        },
        "unhide": {
            "debian": "sudo apt install unhide unhide.rb",
            "arch": "sudo pacman -S unhide",
            "fedora": "sudo dnf install unhide",
        },
        "fail2ban": {
            "debian": "sudo apt install fail2ban",
            "arch": "sudo pacman -S fail2ban",
            "fedora": "sudo dnf install fail2ban",
        },
        "clamonacc": {
            "debian": "sudo apt install clamav-daemon",
            "arch": "sudo pacman -S clamav",
            "fedora": "sudo dnf install clamav clamav-update",
        },
        "firewall": {
            "debian": "sudo apt install ufw",
            "arch": "sudo pacman -S ufw",
            "fedora": "sudo dnf install firewalld",
        },
        "fangfrisch": {
            "debian": "sudo apt install fangfrisch",
            "arch": "sudo paru -S python-fangfrisch  # AUR",
            "fedora": "Install fangfrisch via pipx or your package manager",
        },
    }
    family = _detect_family()
    pack_hints = hints.get(pack, {})
    return pack_hints.get(
        family,
        pack_hints.get("debian", f"Install {pack} via your package manager"),
    )


def detect_distro_family() -> str:
    try:
        if which("pacman") and platform.system() == "Linux":
            return "arch"
        if Path_exists("/etc/fedora-release") or Path_exists("/etc/redhat-release"):
            return "fedora"
    except Exception:
        pass
    return "debian"


def _detect_family() -> str:
    return detect_distro_family()


def Path_exists(p: str) -> bool:
    from pathlib import Path

    return Path(p).exists()


def resolve_pack_binary(pack_name: str, preferred: str | None = None) -> tuple[str | None, str]:
    from oyst_core.runtime.resolver import resolve_pack_tool

    resolved = resolve_pack_tool(pack_name, preferred)
    return resolved.path, resolved.source


class Pack(ABC):
    name: str
    tier: PackTier
    system_bins: list[str]
    min_version: str | None = None

    @abstractmethod
    def doctor(self) -> PackStatus:
        raise NotImplementedError

    def _base_status(
        self,
        installed: bool,
        version: str | None = None,
        message: str = "",
    ) -> PackStatus:
        ok = True
        if self.min_version and version:
            ok = version_gte(version, self.min_version)
        return PackStatus(
            name=self.name,
            tier=self.tier,
            installed=installed,
            version=version,
            min_version=self.min_version,
            version_ok=ok if installed else False,
            message=message,
            install_hint=distro_install_hint(self.name) if not installed else "",
        )

    def scan_paths(
        self,
        paths: list[str],
        backend: str = "auto",
        profile: str = "quick",
    ) -> list[Any]:
        """Run pack scan; subclasses implement."""
        _ = (paths, backend, profile)
        return []
