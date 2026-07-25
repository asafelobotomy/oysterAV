"""Managed firewall backend selection (UFW / firewalld soft swap)."""

from __future__ import annotations

from pathlib import Path

from oyst_core.packs.base import detect_distro_family
from oyst_core.packs.firewall import invalidate_firewall_detect_cache
from oyst_core.packs.firewall_ops import FirewallResult
from oyst_core.privileged.helper import run_privileged_helper
from oyst_core.privileged.runner import which
from oyst_core.setup_harden import parse_helper_steps

_BACKEND_BINARY = {"ufw": "ufw", "firewalld": "firewall-cmd"}
_BACKEND_PACKAGE = {"ufw": "ufw", "firewalld": "firewalld"}


def recommended_managed_backend() -> str:
    """Distro default: firewalld on Fedora/RHEL/SUSE family; else UFW."""
    if detect_distro_family() == "fedora":
        return "firewalld"
    try:
        text = Path("/etc/os-release").read_text(encoding="utf-8").lower()
    except OSError:
        text = ""
    if "suse" in text or "opensuse" in text:
        return "firewalld"
    return "ufw"


def select_managed_backend(
    backend: str,
    *,
    force_lockout: bool = False,
    dry_run: bool = False,
) -> FirewallResult:
    """Soft-swap to ufw|firewalld|none via one setup-harden polkit prompt."""
    choice = backend.strip().lower()
    if choice not in {"ufw", "firewalld", "none"}:
        return FirewallResult(ok=False, message="backend must be ufw|firewalld|none")
    argv: list[str] = []
    need_install = choice in _BACKEND_BINARY and not which(_BACKEND_BINARY[choice])
    if need_install:
        argv.append(f"--install-firewall={choice}")
    argv.append(f"--select-firewall={choice}")
    if force_lockout:
        argv.append("--force-lockout")
    if dry_run:
        msg = "dry-run"
        if need_install:
            msg = f"dry-run (would install {_BACKEND_PACKAGE[choice]})"
        return FirewallResult(ok=True, message=msg, argv=["setup-harden", *argv])
    res = run_privileged_helper("setup-harden", argv, timeout=300)
    invalidate_firewall_detect_cache()
    helper_steps = parse_helper_steps(res.stdout or "")
    install_step = next((s for s in helper_steps if s.get("step") == "firewall-install"), None)
    if install_step is not None and not install_step.get("ok"):
        return FirewallResult(
            ok=False,
            message=str(install_step.get("message") or "firewall install failed"),
            argv=["setup-harden", *argv],
        )
    fw_step = next((s for s in helper_steps if s.get("step") == "firewall-select"), None)
    if fw_step is not None:
        ok = bool(fw_step.get("ok"))
        skipped = bool(fw_step.get("skipped"))
        return FirewallResult(
            ok=ok or skipped,
            skipped=skipped,
            message=str(fw_step.get("message") or ""),
            argv=["setup-harden", *argv],
        )
    msg = (res.stderr or res.stdout or "firewall select failed").strip()
    return FirewallResult(ok=res.returncode == 0, message=msg, argv=["setup-harden", *argv])
