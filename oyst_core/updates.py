"""Detect and apply pack/service package updates plus signature refresh."""

from __future__ import annotations

import re
from typing import Any

from oyst_core.events import EventLog
from oyst_core.pack_install import PACK_AUR_ONLY_ARCH, PACK_PACKAGES
from oyst_core.packs.base import detect_distro_family
from oyst_core.packs.fangfrisch import FangfrischPack
from oyst_core.packs.freshclam import FreshclamPack
from oyst_core.packs.maldet import MaldetPack
from oyst_core.packs.rkhunter import RKHunterPack
from oyst_core.privileged.helper import run_privileged_aur_install, run_privileged_install
from oyst_core.privileged.runner import CommandResult, run_command
from oyst_core.registry import get_registry
from oyst_core.runtime.bootstrap import update_runtime
from oyst_core.runtime.manifest import is_full_mode
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


def format_update_status_line(update: dict[str, Any]) -> str:
    """Status-bar copy for one available update."""
    name = str(update.get("name") or "pack")
    current = str(update.get("current") or "?")
    available = str(update.get("available") or "?")
    return f"An update for {name} {current} > {available} is available!"


def check_available_updates() -> dict[str, Any]:
    """Return available updates for installed packs / enabled related services.

    Uses the host package manager only (no polkit). Full-mode private runtime
    packs without a system package are skipped.
    """
    family = detect_distro_family()
    installed_packs = _installed_pack_names()
    relevant_packs = _relevant_pack_names(installed_packs)
    tracked_packages = _tracked_packages(family, relevant_packs)
    if not tracked_packages:
        return {"ok": True, "updates": [], "message": ""}

    raw = _query_package_upgrades(family)
    updates: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    for pkg, current, available in raw:
        if pkg not in tracked_packages:
            continue
        display = tracked_packages[pkg]
        if display in seen_names:
            continue
        seen_names.add(display)
        updates.append(
            {
                "kind": "pack",
                "name": display,
                "package": pkg,
                "current": current,
                "available": available,
            }
        )

    message = format_update_status_line(updates[0]) if updates else ""
    return {"ok": True, "updates": updates, "message": message}


def apply_all_updates() -> dict[str, Any]:
    """Check package upgrades, install them, then refresh definitions and baseline.

    Steps (skipped when the tool is not installed):
    packages → freshclam/runtime → fangfrisch → rkhunter --update →
    maldet sigs → rkhunter --propupd
    """
    events = EventLog()
    check = check_available_updates()
    updates_raw = check.get("updates") or []
    updates = [u for u in updates_raw if isinstance(u, dict)]
    steps: list[dict[str, Any]] = []

    pkg_step = _apply_package_upgrades(updates)
    steps.append(pkg_step)

    steps.append(_step_freshclam_or_runtime())
    steps.append(_step_fangfrisch())
    steps.append(_step_rkhunter_update())
    steps.append(_step_maldet_sigs())
    steps.append(_step_rkhunter_propupd())

    failed = [s for s in steps if not s.get("ok") and not s.get("skipped")]
    ok = not failed
    if ok:
        message = (
            f"Update all finished ({sum(1 for s in steps if s.get('ok'))}/{len(steps)} steps OK)"
        )
    else:
        names = ", ".join(str(s.get("step") or "?") for s in failed)
        message = f"Update all finished with failures: {names}"
    result = {
        "ok": ok,
        "updates": updates,
        "packages_upgraded": list(pkg_step.get("packages") or []),
        "steps": steps,
        "message": message,
    }
    events.log("updates", "apply completed", {"ok": ok, "steps": [s.get("step") for s in steps]})
    return result


def _apply_package_upgrades(updates: list[dict[str, Any]]) -> dict[str, Any]:
    packages = _unique_packages(updates)
    if not packages:
        return {
            "step": "packages",
            "ok": True,
            "skipped": True,
            "packages": [],
            "message": "No package upgrades",
        }

    family = detect_distro_family()
    official, aur = _split_official_and_aur(packages, updates, family)
    messages: list[str] = []
    ok = True

    if official:
        res = run_privileged_install(official, family, sync=True)
        messages.append(_command_message("install", res))
        if res.returncode != 0:
            ok = False

    if aur:
        res = run_privileged_aur_install(aur)
        messages.append(_command_message("aur", res))
        if res.returncode != 0:
            ok = False

    return {
        "step": "packages",
        "ok": ok,
        "packages": packages,
        "message": "; ".join(messages)[:500] if messages else "Packages upgraded",
    }


def _unique_packages(updates: list[dict[str, Any]]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in updates:
        pkg = str(item.get("package") or "").strip()
        if not pkg or pkg in seen:
            continue
        seen.add(pkg)
        out.append(pkg)
    return out


def _split_official_and_aur(
    packages: list[str],
    updates: list[dict[str, Any]],
    family: str,
) -> tuple[list[str], list[str]]:
    pack_by_pkg = {
        str(item.get("package")): str(item.get("name") or "")
        for item in updates
        if item.get("package")
    }
    official: list[str] = []
    aur: list[str] = []
    for pkg in packages:
        pack_name = pack_by_pkg.get(pkg, "")
        if family == "arch" and pack_name in PACK_AUR_ONLY_ARCH:
            aur.append(pkg)
        else:
            official.append(pkg)
    return official, aur


def _command_message(label: str, res: CommandResult) -> str:
    detail = (res.stderr or res.stdout or "").strip()
    if res.returncode == 0:
        return f"{label}: ok" if not detail else f"{label}: ok ({detail[:120]})"
    return f"{label}: failed ({detail[:200] or f'exit {res.returncode}'})"


def _step_freshclam_or_runtime() -> dict[str, Any]:
    fresh = FreshclamPack()
    if fresh.doctor().installed:
        ok, msg = fresh.update()
        return {"step": "freshclam", "ok": ok, "message": str(msg)[:200]}
    if is_full_mode():
        result = update_runtime()
        return {
            "step": "runtime.update",
            "ok": bool(result.get("ok")),
            "message": str(result.get("message", result.get("clamav", "")))[:200],
        }
    return {"step": "freshclam", "ok": True, "skipped": True, "message": "freshclam not installed"}


def _step_fangfrisch() -> dict[str, Any]:
    fang = FangfrischPack()
    if fang.doctor().installed:
        ok, msg = fang.refresh()
        return {"step": "fangfrisch", "ok": ok, "message": str(msg)[:200]}
    return {"step": "fangfrisch", "ok": True, "skipped": True}


def _step_rkhunter_update() -> dict[str, Any]:
    rkh = RKHunterPack()
    if rkh.doctor().installed:
        ok, msg = rkh.update()
        return {"step": "rkhunter-update", "ok": ok, "message": str(msg)[:200]}
    return {"step": "rkhunter-update", "ok": True, "skipped": True}


def _step_maldet_sigs() -> dict[str, Any]:
    maldet = MaldetPack()
    if maldet.doctor().installed:
        ok, msg = maldet.update_sigs()
        return {"step": "maldet-sigs", "ok": ok, "message": str(msg)[:200]}
    return {"step": "maldet-sigs", "ok": True, "skipped": True}


def _step_rkhunter_propupd() -> dict[str, Any]:
    rkh = RKHunterPack()
    if rkh.doctor().installed:
        ok, msg = rkh.propupd()
        return {"step": "rkhunter-propupd", "ok": ok, "message": str(msg)[:200]}
    return {"step": "rkhunter-propupd", "ok": True, "skipped": True}


def _installed_pack_names() -> set[str]:
    names: set[str] = set()
    for pack in get_registry().all():
        try:
            status = pack.doctor()
        except (OSError, ValueError, RuntimeError):
            continue
        if status.installed:
            names.add(pack.name)
    return names


def _relevant_pack_names(installed: set[str]) -> set[str]:
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


def _tracked_packages(family: str, pack_names: set[str]) -> dict[str, str]:
    """Map distro package name → oysterAV display name (first pack wins)."""
    tracked: dict[str, str] = {}
    for pack_name in sorted(pack_names):
        packages = PACK_PACKAGES.get(pack_name, {}).get(family, [])
        for pkg in packages:
            tracked.setdefault(pkg, pack_name)
    return tracked


def _query_package_upgrades(family: str) -> list[tuple[str, str, str]]:
    if family == "arch":
        return _query_pacman_upgrades()
    if family == "debian":
        return _query_apt_upgrades()
    if family == "fedora":
        return _query_dnf_upgrades()
    return []


def _query_pacman_upgrades() -> list[tuple[str, str, str]]:
    # Prefer checkupdates (safe, no root) when present.
    for argv in (["checkupdates"], ["pacman", "-Qu"]):
        try:
            res = run_command(argv, timeout=60)
        except (ValueError, OSError):
            continue
        # checkupdates exits 2 when updates exist; pacman -Qu exits 0/1.
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
        # apt: name, new_version, old_version
        out.append((match.group(1), match.group(3), match.group(2)))
    return out


def _query_dnf_upgrades() -> list[tuple[str, str, str]]:
    try:
        res = run_command(["dnf", "check-update", "--quiet"], timeout=120)
    except (ValueError, OSError):
        return []
    # dnf returns 100 when updates are available.
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
        # dnf check-update does not print the installed version; probe it.
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
