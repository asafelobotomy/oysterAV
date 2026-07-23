"""Host package-manager upgrade queries for Update all."""

from __future__ import annotations

import re

from oyst_core.pack_install import PACK_PACKAGES
from oyst_core.privileged.runner import run_command
from oyst_core.registry import get_registry
from oyst_core.services import SERVICE_NAMES, services_status

# Logical service → oysterAV pack name (for enabled-service filtering).
_SERVICE_TO_PACK: dict[str, str] = {
    "clamd": "clamav",
    "clamonacc": "clamonacc",
    "freshclam-timer": "freshclam",
    "fail2ban": "fail2ban",
    "maldet-monitor": "maldet",
}

_PACMAN_QU_RE = re.compile(
    r"^(\S+)\s+(\S+)\s+->\s+(\S+)\s*$",
)
_APT_UPGRADABLE_RE = re.compile(
    r"^(\S+)/[^\s]+\s+(\S+)\s+\S+\s+\[upgradable from:\s*(\S+)\]",
    re.IGNORECASE,
)
_DNF_LINE_RE = re.compile(
    r"^(\S+)\s+(\S+)\s+(\S+)\s*$",
)


def installed_pack_names() -> set[str]:
    names: set[str] = set()
    for pack in get_registry().all():
        try:
            status = pack.doctor()
        except (OSError, ValueError, RuntimeError):
            continue
        if status.installed:
            names.add(pack.name)
    return names


def relevant_pack_names(installed: set[str]) -> set[str]:
    """Installed packs, plus packs tied to enabled services."""
    relevant = set(installed)
    try:
        status = services_status()
    except (OSError, ValueError, RuntimeError):
        return relevant
    services = status.get("services")
    if not isinstance(services, dict):
        return relevant
    for svc_name in SERVICE_NAMES:
        info = services.get(svc_name)
        if not isinstance(info, dict):
            continue
        if not (info.get("enabled") or info.get("running")):
            continue
        pack = _SERVICE_TO_PACK.get(svc_name)
        if pack:
            relevant.add(pack)
    return relevant


def tracked_packages(family: str, pack_names: set[str]) -> dict[str, str]:
    """Map distro package name → oysterAV display name (first pack wins)."""
    tracked: dict[str, str] = {}
    for pack_name in sorted(pack_names):
        packages = PACK_PACKAGES.get(pack_name, {}).get(family, [])
        for pkg in packages:
            tracked.setdefault(pkg, pack_name)
    return tracked


def query_package_upgrades(family: str) -> list[tuple[str, str, str]]:
    if family == "arch":
        return _query_pacman_upgrades()
    if family == "debian":
        return _query_apt_upgrades()
    if family == "fedora":
        return _query_dnf_upgrades()
    return []


def _query_pacman_upgrades() -> list[tuple[str, str, str]]:
    for argv in (["checkupdates"], ["pacman", "-Qu"]):
        try:
            res = run_command(argv, timeout=60)
        except (ValueError, OSError):
            continue
        text = (res.stdout or "") + "\n" + (res.stderr or "")
        out: list[tuple[str, str, str]] = []
        for line in text.splitlines():
            match = _PACMAN_QU_RE.match(line.strip())
            if match:
                out.append((match.group(1), match.group(2), match.group(3)))
        if out or argv[0] == "checkupdates":
            return out
    return []


def _query_apt_upgrades() -> list[tuple[str, str, str]]:
    try:
        res = run_command(["apt", "list", "--upgradable"], timeout=90)
    except (ValueError, OSError):
        return []
    out: list[tuple[str, str, str]] = []
    for line in (res.stdout or "").splitlines():
        match = _APT_UPGRADABLE_RE.match(line.strip())
        if not match:
            continue
        out.append((match.group(1), match.group(3), match.group(2)))
    return out


def _query_dnf_upgrades() -> list[tuple[str, str, str]]:
    try:
        res = run_command(["dnf", "check-update", "--quiet"], timeout=120)
    except (ValueError, OSError):
        return []
    out: list[tuple[str, str, str]] = []
    for line in (res.stdout or "").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("Last metadata"):
            continue
        match = _DNF_LINE_RE.match(stripped)
        if not match:
            continue
        name = match.group(1)
        available = match.group(2)
        current = _rpm_installed_version(name) or "?"
        out.append((name, current, available))
    return out


def _rpm_installed_version(package: str) -> str | None:
    try:
        res = run_command(["rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", package], timeout=15)
    except (ValueError, OSError):
        return None
    if res.returncode != 0:
        return None
    text = (res.stdout or "").strip()
    return text or None


__all__ = [
    "installed_pack_names",
    "query_package_upgrades",
    "relevant_pack_names",
    "tracked_packages",
]
