"""Detect and apply pack/service package updates plus signature refresh."""

from __future__ import annotations

from typing import Any

from oyst_core.events import EventLog
from oyst_core.pack_install import PACK_AUR_ONLY_ARCH
from oyst_core.packs.base import detect_distro_family
from oyst_core.packs.fangfrisch import FangfrischPack
from oyst_core.packs.freshclam import FreshclamPack
from oyst_core.packs.maldet import MaldetPack
from oyst_core.packs.rkhunter import RKHunterPack
from oyst_core.privilege import build_update_all_plan, run_privilege_concert
from oyst_core.privilege.plan import PrivilegePlan
from oyst_core.privileged.helper import run_privileged_aur_install
from oyst_core.privileged.runner import CommandResult
from oyst_core.runtime.bootstrap import update_runtime
from oyst_core.runtime.manifest import is_full_mode
from oyst_core.updates_query import (
    installed_pack_names,
    query_package_upgrades,
    relevant_pack_names,
    tracked_packages,
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
    installed_packs = installed_pack_names()
    relevant_packs = relevant_pack_names(installed_packs)
    tracked = tracked_packages(family, relevant_packs)
    if not tracked:
        return {"ok": True, "updates": [], "message": ""}

    raw = query_package_upgrades(family)
    updates: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    for pkg, current, available in raw:
        if pkg not in tracked:
            continue
        display = tracked[pkg]
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


def plan_update_all() -> PrivilegePlan:
    """Build the PrivilegePlan for Update all (GUI/CLI disclosure)."""
    check = check_available_updates()
    updates_raw = check.get("updates") or []
    updates = [u for u in updates_raw if isinstance(u, dict)]
    family = detect_distro_family()
    packages = _unique_packages(updates)
    official, _aur = _split_official_and_aur(packages, updates, family)
    rkh = RKHunterPack()
    rkh_installed = bool(rkh.doctor().installed)
    return build_update_all_plan(
        official_packages=official,
        family=family,
        include_rkh_update=rkh_installed,
        include_rkh_propupd=rkh_installed,
    )


def apply_all_updates() -> dict[str, Any]:
    """Check package upgrades, elevate once for packages+rkh, then refresh definitions.

    Steps: update-concert (official packages, rkhunter --update/--propupd) →
    AUR (user-mode) → freshclam/runtime → fangfrisch → maldet sigs.
    """
    events = EventLog()
    check = check_available_updates()
    updates_raw = check.get("updates") or []
    updates = [u for u in updates_raw if isinstance(u, dict)]
    steps: list[dict[str, Any]] = []

    family = detect_distro_family()
    packages = _unique_packages(updates)
    official, aur = _split_official_and_aur(packages, updates, family)
    rkh = RKHunterPack()
    rkh_installed = bool(rkh.doctor().installed)
    plan = build_update_all_plan(
        official_packages=official,
        family=family,
        include_rkh_update=rkh_installed,
        include_rkh_propupd=rkh_installed,
    )
    if plan.needs_elevation:
        concert_steps = run_privilege_concert(plan)
        steps.extend(_normalize_concert_steps(concert_steps))
    else:
        steps.append(
            {
                "step": "packages",
                "ok": True,
                "skipped": True,
                "packages": packages,
                "message": "No elevated package upgrades",
            }
        )

    if aur:
        steps.append(_apply_aur_upgrades(aur))

    steps.append(_step_freshclam_or_runtime())
    steps.append(_step_fangfrisch())
    if not rkh_installed:
        steps.append(_step_rkhunter_update())
    steps.append(_step_maldet_sigs())
    if not rkh_installed:
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
        "packages_upgraded": list(official) + list(aur),
        "steps": steps,
        "message": message,
    }
    events.log("updates", "apply completed", {"ok": ok, "steps": [s.get("step") for s in steps]})
    return result


def _normalize_concert_steps(raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        step = dict(item)
        if "step" not in step and "id" in step:
            step["step"] = step["id"]
        out.append(step)
    return out


def _apply_aur_upgrades(packages: list[str]) -> dict[str, Any]:
    if not packages:
        return {
            "step": "packages-aur",
            "ok": True,
            "skipped": True,
            "packages": [],
            "message": "No AUR upgrades",
        }
    res = run_privileged_aur_install(packages)
    return {
        "step": "packages-aur",
        "ok": res.returncode == 0,
        "packages": packages,
        "message": _command_message("aur", res),
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
