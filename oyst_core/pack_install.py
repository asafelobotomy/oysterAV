"""Hybrid pack installation via distro package managers."""

from __future__ import annotations

from pydantic import BaseModel

from oyst_core.audit import SecurityAudit
from oyst_core.pack_sources import install_maldet_tarball
from oyst_core.packs.base import detect_distro_family, distro_install_hint
from oyst_core.privileged.helper import (
    detect_aur_helper,
    run_privileged_aur_install,
    run_privileged_install,
)
from oyst_core.privileged.runner import run_command
from oyst_core.registry import get_registry
from oyst_core.runtime.bootstrap import RUNTIME_PACKS, install_pack_runtime
from oyst_core.runtime.manifest import is_full_mode
from oyst_core.runtime.progress import ProgressCallback, emit_progress

PACK_PACKAGES: dict[str, dict[str, list[str]]] = {
    "clamav": {
        "debian": ["clamav", "clamav-daemon"],
        "arch": ["clamav"],
        "fedora": ["clamav", "clamav-update"],
    },
    "freshclam": {
        "debian": ["clamav-freshclam"],
        "arch": ["clamav"],
        "fedora": ["clamav-update"],
    },
    "clamonacc": {
        "debian": ["clamav-daemon"],
        "arch": ["clamav"],
        "fedora": ["clamav", "clamav-update"],
    },
    "rkhunter": {
        "debian": ["rkhunter"],
        "arch": ["rkhunter"],
        "fedora": ["rkhunter"],
    },
    "chkrootkit": {
        "debian": ["chkrootkit"],
        "arch": ["chkrootkit"],
        "fedora": ["chkrootkit"],
    },
    "lynis": {
        "debian": ["lynis"],
        "arch": ["lynis"],
        "fedora": ["lynis"],
    },
    "unhide": {
        "debian": ["unhide", "unhide.rb"],
        "arch": ["unhide"],
        "fedora": ["unhide"],
    },
    "firewall": {
        "debian": ["ufw"],
        "arch": ["ufw"],
        "fedora": ["firewalld"],
    },
    "fail2ban": {
        "debian": ["fail2ban"],
        "arch": ["fail2ban"],
        "fedora": ["fail2ban"],
    },
    "maldet": {
        "arch": ["maldet"],
        "debian": [],
        "fedora": [],
    },
    "fangfrisch": {
        "debian": ["fangfrisch"],
        "arch": ["python-fangfrisch"],
        "fedora": [],
    },
}

PACK_AUR_ONLY_ARCH = frozenset({"chkrootkit", "maldet", "fangfrisch"})


class InstallResult(BaseModel):
    ok: bool
    mode: str
    message: str = ""
    install_hint: str = ""
    strategy: str = ""
    requires_confirmation: bool = False
    aur_available: bool = False
    reason: str = ""


def _aur_install_hint(packages: list[str]) -> str:
    helper = detect_aur_helper() or "paru"
    pkgs = " ".join(packages)
    return f"sudo {helper} -S {pkgs}"


def _pacman_package_available(package: str) -> bool:
    res = run_command(["pacman", "-Si", package], timeout=30)
    return res.returncode == 0 and "Repository" in res.stdout


def _aur_package_available(package: str) -> bool:
    helper = detect_aur_helper()
    if not helper:
        return False
    res = run_command([helper, "-Si", package], timeout=60)
    return res.returncode == 0 and "Repository" in res.stdout and "aur" in res.stdout.lower()


def resolve_install_strategy(pack_name: str, family: str) -> tuple[str, list[str]]:
    """Return strategy (official|aur|tarball|unavailable) and package list."""
    packages = PACK_PACKAGES.get(pack_name, {}).get(family, [])
    if pack_name == "maldet" and not packages:
        return "tarball", []

    if not packages:
        return "unavailable", []

    if family != "arch":
        return "official", packages

    primary = packages[0]
    if _pacman_package_available(primary):
        return "official", packages
    if pack_name == "maldet" and not detect_aur_helper():
        return "tarball", packages
    if pack_name in PACK_AUR_ONLY_ARCH or _aur_package_available(primary):
        return "aur", packages
    if pack_name == "maldet":
        return "tarball", packages
    return "unavailable", packages


def install_pack(
    name: str,
    *,
    confirm_aur: bool = False,
    on_progress: ProgressCallback | None = None,
) -> InstallResult:
    """Attempt hybrid install: official repo, AUR (with confirm), or tarball."""
    audit = SecurityAudit()
    registry = get_registry()
    pack = registry.get(name)
    if pack is None:
        return InstallResult(
            ok=False,
            mode="command",
            message=f"Unknown pack: {name}",
            reason="unknown_pack",
        )

    status = pack.doctor()
    if status.installed:
        emit_progress(on_progress, "install", 100)
        result = InstallResult(
            ok=True,
            mode="installed",
            message=f"{name} is already installed",
            strategy="installed",
        )
        audit.log("pack.install", name, success=True, data={"mode": "installed"})
        return result

    if is_full_mode() and name in RUNTIME_PACKS:
        emit_progress(on_progress, "runtime", 5)
        runtime_res = install_pack_runtime(name, on_progress=on_progress)
        status_after = pack.doctor()
        if runtime_res.get("ok") and status_after.installed:
            result = InstallResult(
                ok=True,
                mode="runtime",
                message=str(runtime_res.get("message", f"Installed {name} to runtime")),
                strategy="runtime",
            )
            audit.log("pack.install", name, success=True, data={"mode": "runtime"})
            return result
        result = InstallResult(
            ok=False,
            mode="command",
            message=str(runtime_res.get("message", "Runtime install failed"))[:500],
            install_hint=hint if (hint := status.install_hint or distro_install_hint(name)) else "",
            strategy="runtime",
            reason="runtime_install_failed",
        )
        audit.log("pack.install", name, success=False, data={"mode": "runtime"})
        return result

    hint = status.install_hint or distro_install_hint(name)
    family = detect_distro_family()
    emit_progress(on_progress, "resolve", 10)
    strategy, packages = resolve_install_strategy(name, family)

    if strategy == "unavailable":
        return InstallResult(
            ok=False,
            mode="command",
            message="No automated packages for this distro",
            install_hint=hint,
            strategy=strategy,
            reason="unavailable",
        )

    if strategy == "aur" and not confirm_aur:
        aur_hint = _aur_install_hint(packages)
        return InstallResult(
            ok=False,
            mode="aur_confirm",
            message=f"{name} is only available in the AUR on this system",
            install_hint=aur_hint,
            strategy="aur",
            requires_confirmation=True,
            aur_available=True,
            reason="aur_confirmation_required",
        )

    install_res = None
    emit_progress(on_progress, strategy, 30)
    if strategy == "official":
        install_res = run_privileged_install(packages, family, sync=True)
        emit_progress(on_progress, "install", 80)
    elif strategy == "aur":
        install_res = run_privileged_aur_install(packages)
        emit_progress(on_progress, "install", 80)
    elif strategy == "tarball" and name == "maldet":
        install_res = install_maldet_tarball()
        emit_progress(on_progress, "install", 80)

    status_after = pack.doctor()
    if not status_after.installed and strategy == "aur" and name == "maldet":
        install_res = install_maldet_tarball()
        status_after = pack.doctor()
    if status_after.installed:
        emit_progress(on_progress, "install", 100)
        if name == "maldet":
            ensure = getattr(pack, "ensure_clamav_integration", None)
            if callable(ensure):
                ensure()
        if name == "fangfrisch":
            ensure_cfg = getattr(pack, "ensure_config", None)
            initdb = getattr(pack, "initdb", None)
            if callable(ensure_cfg):
                ensure_cfg()
            if callable(initdb):
                initdb()
        result = InstallResult(
            ok=True,
            mode="auto" if strategy == "official" else strategy,
            message=f"Installed {name}",
            strategy=strategy,
        )
        audit.log("pack.install", name, success=True, data={"strategy": strategy})
        return result

    if install_res is None:
        detail = "Install failed"
    else:
        detail = (
            install_res.stderr or install_res.stdout or "Install failed or was cancelled"
        ).strip()

    fallback_hint = hint
    if strategy == "aur":
        fallback_hint = _aur_install_hint(packages)
    elif strategy == "tarball" and name == "maldet":
        fallback_hint = "See https://rfxn.com/projects/linux-malware-detect"

    result = InstallResult(
        ok=False,
        mode="command",
        message=detail[:500],
        install_hint=fallback_hint,
        strategy=strategy,
        reason="install_failed",
    )
    audit.log("pack.install", name, success=False, data={"strategy": strategy})
    return result


def list_packs() -> list[dict[str, object]]:
    """Return doctor status for all packs grouped by tier."""
    return [p.doctor().model_dump() for p in get_registry().all()]
