"""User-space orchestration for single-auth setup-concert (packs + harden + linger)."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from oyst_core.audit import SecurityAudit
from oyst_core.pack_install import InstallResult, resolve_install_strategy
from oyst_core.pack_sources import stage_maldet_install_script
from oyst_core.packs.base import detect_distro_family
from oyst_core.privilege.recipes import build_setup_plan
from oyst_core.privilege.run import run_privilege_concert
from oyst_core.privileged.runner import CommandResult, which
from oyst_core.registry import get_registry
from oyst_core.runtime.bootstrap import RUNTIME_PACKS, install_pack_runtime
from oyst_core.runtime.manifest import is_full_mode
from oyst_core.schedule_linger import current_username
from oyst_core.setup_harden import prepare_harden_argv


def _step(
    name: str,
    *,
    ok: bool,
    message: str = "",
    skipped: bool = False,
    soft_fail: bool = False,
    mode: str = "",
) -> dict[str, Any]:
    out: dict[str, Any] = {"step": name, "ok": ok}
    if message:
        out["message"] = message
    if skipped:
        out["skipped"] = True
    if soft_fail and not ok and not skipped:
        out["soft_fail"] = True
    if mode:
        out["mode"] = mode
    return out


def plan_official_installs(
    pack_names: list[str],
    *,
    confirm_aur: bool = False,
) -> tuple[list[dict[str, Any]], list[str], str, Path | None]:
    """Return (local_steps, install_flags, family, maldet_work_dir)."""
    local: list[dict[str, Any]] = []
    install_flags: list[str] = []
    family = detect_distro_family()
    work_dir: Path | None = None
    registry = get_registry()

    for name in pack_names:
        pack = registry.get(name)
        if pack is None:
            local.append(_step(f"install-{name}", ok=False, message="unknown pack", soft_fail=True))
            continue
        if pack.doctor().installed:
            local.append(
                _step(
                    f"install-{name}",
                    ok=True,
                    skipped=True,
                    message=f"{name} already installed",
                    mode="installed",
                ),
            )
            continue
        if is_full_mode() and name in RUNTIME_PACKS:
            runtime_res = install_pack_runtime(name)
            ok = bool(runtime_res.get("ok")) and pack.doctor().installed
            local.append(
                _step(
                    f"install-{name}",
                    ok=ok,
                    message=str(runtime_res.get("message", ""))[:500],
                    soft_fail=not ok,
                    mode="runtime",
                ),
            )
            continue

        strategy, packages = resolve_install_strategy(name, family)
        if strategy == "unavailable":
            local.append(
                _step(
                    f"install-{name}",
                    ok=False,
                    message="No automated packages for this distro",
                    soft_fail=True,
                    mode="command",
                ),
            )
            continue
        if strategy == "aur":
            if not confirm_aur:
                local.append(
                    _step(
                        f"install-{name}",
                        ok=False,
                        message=f"{name} is only available in the AUR on this system",
                        soft_fail=True,
                        mode="aur_confirm",
                    ),
                )
            else:
                # AUR cannot use oysterAV polkit concert (paru/yay own auth).
                local.append(
                    _step(
                        f"install-{name}",
                        ok=False,
                        message="AUR installs stay outside setup-concert (use pack install)",
                        soft_fail=True,
                        mode="aur",
                    ),
                )
            continue
        if strategy == "tarball" and name == "maldet":
            staged = stage_maldet_install_script()
            if isinstance(staged, CommandResult):
                local.append(
                    _step(
                        "install-maldet",
                        ok=False,
                        message=(staged.stderr or staged.stdout or "stage failed")[:500],
                        soft_fail=True,
                        mode="tarball",
                    ),
                )
            else:
                tarball, tarball_sha, _install_sh, work_dir = staged
                install_flags.append(f"--maldet-tarball={tarball}")
                install_flags.append(f"--maldet-sha={tarball_sha}")
            continue
        if strategy == "official" and packages:
            install_flags.append(f"--install={name}:{','.join(packages)}")
    return local, install_flags, family, work_dir


def build_concert_argv(
    *,
    pack_names: list[str] | None = None,
    confirm_aur: bool = False,
    skip_harden: bool = False,
    enable_firewall: bool = True,
    force_lockout: bool = False,
    propupd: bool = False,
    enable_linger: bool = False,
    harden_include: frozenset[str] | None = None,
) -> tuple[list[dict[str, Any]], list[str], Path | None]:
    """Prepare local steps + one setup-concert argv; optional maldet work_dir to clean."""
    local: list[dict[str, Any]] = []
    argv: list[str] = []
    work_dir: Path | None = None

    if pack_names:
        pack_local, install_flags, family, work_dir = plan_official_installs(
            pack_names,
            confirm_aur=confirm_aur,
        )
        local.extend(pack_local)
        if install_flags:
            argv.append(f"--family={family}")
            argv.extend(install_flags)

    if propupd:
        will_rkh = bool(which("rkhunter")) or any(a.startswith("--install=rkhunter:") for a in argv)
        if will_rkh:
            argv.append("--propupd")
        else:
            local.append(
                _step(
                    "rkhunter-propupd",
                    ok=True,
                    skipped=True,
                    message="rkhunter not installed",
                ),
            )

    if not skip_harden:
        harden_local, harden_argv = prepare_harden_argv(
            with_firewall=enable_firewall,
            force_lockout=force_lockout,
            include=harden_include,
        )
        local.extend(harden_local)
        argv.extend(harden_argv)
    elif enable_firewall:
        from oyst_core.packs.firewall import FirewallPack

        det = FirewallPack().detect()
        if det.get("conflict"):
            local.append(
                _step(
                    "firewall-ensure",
                    ok=False,
                    message="Multiple firewall managers active; resolve UFW vs firewalld first",
                    soft_fail=True,
                ),
            )
        elif str(det.get("active", "none")) in ("ufw", "firewalld"):
            local.append(
                _step(
                    "firewall-ensure",
                    ok=True,
                    skipped=True,
                    message=f"{det.get('active')} already active",
                ),
            )
        elif not det.get("ufw") and not det.get("firewalld"):
            local.append(
                _step(
                    "firewall-ensure",
                    ok=True,
                    skipped=True,
                    message="no UFW or firewalld binary installed",
                ),
            )
        else:
            argv.append("--with-firewall")
            if force_lockout:
                argv.append("--force-lockout")

    if enable_linger:
        argv.append(f"--linger-user={current_username()}")

    return local, argv, work_dir


def run_setup_concert(
    *,
    pack_names: list[str] | None = None,
    confirm_aur: bool = False,
    skip_harden: bool = False,
    enable_firewall: bool = True,
    force_lockout: bool = False,
    propupd: bool = False,
    enable_linger: bool = False,
    harden_include: frozenset[str] | None = None,
) -> list[dict[str, Any]]:
    """One polkit prompt for official/tarball packs + propupd + harden + linger."""
    local, argv, work_dir = build_concert_argv(
        pack_names=pack_names,
        confirm_aur=confirm_aur,
        skip_harden=skip_harden,
        enable_firewall=enable_firewall,
        force_lockout=force_lockout,
        propupd=propupd,
        enable_linger=enable_linger,
        harden_include=harden_include,
    )
    try:
        if not argv:
            return local
        plan = build_setup_plan(argv)
        helper_steps = run_privilege_concert(plan, timeout=3600)
        if helper_steps and not any(s.get("ok") for s in helper_steps):
            failed = next((s for s in helper_steps if not s.get("ok")), helper_steps[0])
            SecurityAudit().log(
                "setup.concert",
                "failed",
                success=False,
                data={"error": str(failed.get("message") or "")},
            )
        else:
            SecurityAudit().log(
                "setup.concert",
                "ok",
                success=True,
                data={"steps": [s.get("step") for s in helper_steps]},
            )
        return [*local, *helper_steps]
    finally:
        if work_dir is not None:
            shutil.rmtree(work_dir, ignore_errors=True)


def install_result_from_step(step: dict[str, Any]) -> InstallResult:
    """Map a concert install-* step to InstallResult for audit callers."""
    return InstallResult(
        ok=bool(step.get("ok")),
        mode=str(step.get("mode") or "auto"),
        message=str(step.get("message") or ""),
        strategy=str(step.get("mode") or ""),
    )


__all__ = [
    "build_concert_argv",
    "install_result_from_step",
    "plan_official_installs",
    "run_setup_concert",
]
