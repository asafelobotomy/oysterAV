"""Root firewall ensure / select / optional package install (setup-harden)."""

from __future__ import annotations

import os
import subprocess
from collections.abc import Sequence
from typing import Any

from oyst_core.packs.base import detect_distro_family
from oyst_core.packs.firewall import FirewallPack, invalidate_firewall_detect_cache
from oyst_core.privileged.helper_clamd import _parse_flag
from oyst_core.privileged.helper_firewall import _build_ufw_argv
from oyst_core.privileged.helper_fw_enable import ensure_firewalld, ensure_ufw
from oyst_core.privileged.helper_services import _build_systemctl_argv
from oyst_core.privileged.helper_validate import (
    _validate_package_name,
    _validate_run_argv,
    resolve_trusted_argv,
)

_BACKEND_PACKAGE = {"ufw": "ufw", "firewalld": "firewalld"}


def _secure_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k in ("LANG", "LC_ALL", "TZ")}
    env["PATH"] = "/usr/bin:/usr/sbin:/bin:/sbin"
    env["HOME"] = "/root"
    return env


def _has_bool(argv: Sequence[str], name: str) -> bool:
    return f"--{name}" in argv


def _step(
    name: str,
    *,
    ok: bool,
    message: str = "",
    skipped: bool = False,
    soft_fail: bool = False,
) -> dict[str, Any]:
    out: dict[str, Any] = {"step": name, "ok": ok}
    if message:
        out["message"] = message
    if skipped:
        out["skipped"] = True
    if soft_fail and not ok and not skipped:
        out["soft_fail"] = True
    return out


def _run_cmd(cmd: list[str]) -> tuple[int, str]:
    resolved = resolve_trusted_argv(cmd)
    proc = subprocess.run(
        resolved,
        check=False,
        capture_output=True,
        text=True,
        env=_secure_env(),
    )
    detail = (proc.stderr or proc.stdout or "").strip()
    return proc.returncode, detail


def _family_install_argv(family: str, packages: list[str]) -> list[str]:
    pkgs = [_validate_package_name(p) for p in packages]
    if not pkgs:
        raise ValueError("no packages to install")
    if family == "arch":
        return _validate_run_argv(["pacman", "-Sy", "--noconfirm", *pkgs])
    if family == "fedora":
        return _validate_run_argv(["dnf", "install", "-y", *pkgs])
    if family in ("debian", "ubuntu"):
        return _validate_run_argv(["apt-get", "install", "-y", *pkgs])
    raise ValueError(f"unsupported install family: {family}")


def install_firewall_package_as_root(backend: str) -> dict[str, Any]:
    """Install ufw or firewalld via distro package manager (already root)."""
    choice = backend.strip().lower()
    if choice not in _BACKEND_PACKAGE:
        return _step(
            "firewall-install",
            ok=False,
            message="install-firewall must be ufw|firewalld",
            soft_fail=True,
        )
    package = _BACKEND_PACKAGE[choice]
    try:
        family = detect_distro_family()
        cmd = resolve_trusted_argv(_family_install_argv(family, [package]))
    except ValueError as exc:
        return _step("firewall-install", ok=False, message=str(exc), soft_fail=True)
    rc, detail = _run_cmd(cmd)
    invalidate_firewall_detect_cache()
    return _step(
        "firewall-install",
        ok=rc == 0,
        message=detail or ("installed" if rc == 0 else f"failed to install {package}"),
        soft_fail=rc != 0,
    )


def _root_managed_pref() -> str:
    try:
        from oyst_core.config_access import get_config_value

        raw = get_config_value("firewall.managed_backend")
    except Exception:
        return ""
    if raw is None or raw in {"", "None", "null"}:
        return ""
    return str(raw).strip().lower()


def ensure_firewall_as_root(*, force_lockout: bool = False) -> dict[str, Any]:
    """SSH-safe enable using prefer/recommend order (same as userspace ensure)."""
    invalidate_firewall_detect_cache()
    det = FirewallPack().detect()
    if det.get("conflict"):
        return _step(
            "firewall-ensure",
            ok=False,
            message="Multiple firewall managers active; resolve UFW vs firewalld first",
            soft_fail=True,
        )
    active = str(det.get("active", "none"))
    if active in ("ufw", "firewalld"):
        return _step(
            "firewall-ensure",
            ok=True,
            skipped=True,
            message=f"Managed firewall already on ({active})",
        )
    prefer_ufw = bool(det.get("ufw"))
    prefer_fw = bool(det.get("firewalld"))
    if not prefer_ufw and not prefer_fw:
        return _step(
            "firewall-ensure",
            ok=True,
            skipped=True,
            message="no UFW or firewalld binary installed",
        )
    pref = _root_managed_pref()
    if pref == "none":
        return _step(
            "firewall-ensure",
            ok=True,
            skipped=True,
            message="firewall.managed_backend is none; skipping ensure",
        )
    if pref == "ufw" and prefer_ufw:
        target = "ufw"
    elif pref == "firewalld" and prefer_fw:
        target = "firewalld"
    else:
        from oyst_core.packs.firewall_select import recommended_managed_backend

        rec = recommended_managed_backend()
        if rec == "ufw" and prefer_ufw:
            target = "ufw"
        elif rec == "firewalld" and prefer_fw:
            target = "firewalld"
        else:
            target = "ufw" if prefer_ufw else "firewalld"
    step = select_firewall_as_root(target, force_lockout=force_lockout)
    step["step"] = "firewall-ensure"
    return step


def select_firewall_as_root(backend: str, *, force_lockout: bool = False) -> dict[str, Any]:
    """Soft-swap to one managed backend. Restarts peer if enable fails after stop."""
    choice = backend.strip().lower()
    if choice not in {"ufw", "firewalld", "none"}:
        return _step(
            "firewall-select",
            ok=False,
            message="backend must be ufw|firewalld|none",
            soft_fail=True,
        )
    invalidate_firewall_detect_cache()
    det = FirewallPack().detect()
    if choice == "none":
        return _select_none(det)
    if choice == "ufw" and not det.get("ufw"):
        return _step("firewall-select", ok=False, message="ufw is not installed", soft_fail=True)
    if choice == "firewalld" and not det.get("firewalld"):
        return _step(
            "firewall-select",
            ok=False,
            message="firewalld is not installed",
            soft_fail=True,
        )
    peer_stopped: str | None = None
    if choice == "ufw" and (det.get("firewalld_active") or det.get("conflict")):
        rc, detail = _run_cmd(_build_systemctl_argv(["stop", "firewalld"]))
        if rc != 0:
            return _step(
                "firewall-select",
                ok=False,
                message=detail or "could not stop firewalld",
                soft_fail=True,
            )
        peer_stopped = "firewalld"
    if choice == "firewalld" and (det.get("ufw_active") or det.get("conflict")):
        rc, detail = _run_cmd(_build_ufw_argv(["disable"]))
        if rc != 0:
            return _step(
                "firewall-select",
                ok=False,
                message=detail or "could not disable UFW",
                soft_fail=True,
            )
        peer_stopped = "ufw"
    invalidate_firewall_detect_cache()
    det2 = FirewallPack().detect()
    if det2.get("conflict"):
        if peer_stopped:
            _restart_peer(peer_stopped)
        return _step(
            "firewall-select",
            ok=False,
            message="firewall conflict remains after stop; resolve manually",
            soft_fail=True,
        )
    active = str(det2.get("active", "none"))
    if active == choice:
        return _step(
            "firewall-select",
            ok=True,
            skipped=True,
            message=f"{choice} already active",
        )
    step = (
        _ensure_ufw(force_lockout=force_lockout)
        if choice == "ufw"
        else _ensure_firewalld(force_lockout=force_lockout)
    )
    step["step"] = "firewall-select"
    if not step.get("ok") and not step.get("skipped") and peer_stopped:
        _restart_peer(peer_stopped)
        prior = str(step.get("message") or "enable failed")
        step["message"] = f"{prior}; restored {peer_stopped}"
    invalidate_firewall_detect_cache()
    return step


def _restart_peer(peer: str) -> None:
    if peer == "firewalld":
        _run_cmd(_build_systemctl_argv(["start", "firewalld"]))
    elif peer == "ufw":
        _run_cmd(_build_ufw_argv(["enable"]))
    invalidate_firewall_detect_cache()


def _select_none(det: dict[str, object]) -> dict[str, Any]:
    msgs: list[str] = []
    if det.get("ufw_active") or str(det.get("active")) == "ufw":
        rc, detail = _run_cmd(_build_ufw_argv(["disable"]))
        if rc != 0:
            return _step(
                "firewall-select",
                ok=False,
                message=detail or "could not disable UFW",
                soft_fail=True,
            )
        msgs.append("ufw disabled")
    if det.get("firewalld_active") or str(det.get("active")) == "firewalld" or det.get("conflict"):
        rc, detail = _run_cmd(_build_systemctl_argv(["stop", "firewalld"]))
        if rc != 0:
            return _step(
                "firewall-select",
                ok=False,
                message=detail or "could not stop firewalld",
                soft_fail=True,
            )
        msgs.append("firewalld stopped")
    invalidate_firewall_detect_cache()
    if not msgs:
        return _step(
            "firewall-select",
            ok=True,
            skipped=True,
            message="no managed firewall was active",
        )
    return _step("firewall-select", ok=True, message="; ".join(msgs))


def _ensure_ufw(*, force_lockout: bool) -> dict[str, Any]:
    return ensure_ufw(force_lockout=force_lockout, run_cmd=_run_cmd)


def _ensure_firewalld(*, force_lockout: bool) -> dict[str, Any]:
    return ensure_firewalld(force_lockout=force_lockout, run_cmd=_run_cmd)


def apply_firewall_lifecycle_flags(argv: Sequence[str]) -> list[dict[str, Any]]:
    """Handle --install-firewall / --select-firewall / --with-firewall from harden argv."""
    steps: list[dict[str, Any]] = []
    install_fw = _parse_flag(argv, "install-firewall")
    select_fw = _parse_flag(argv, "select-firewall")
    force_lockout = _has_bool(argv, "force-lockout")
    with_firewall = _has_bool(argv, "with-firewall")

    if install_fw:
        steps.append(install_firewall_package_as_root(install_fw))
        if not steps[-1].get("ok"):
            return steps

    if select_fw:
        steps.append(select_firewall_as_root(select_fw, force_lockout=force_lockout))
        return steps

    if with_firewall:
        steps.append(ensure_firewall_as_root(force_lockout=force_lockout))
    return steps


__all__ = [
    "apply_firewall_lifecycle_flags",
    "ensure_firewall_as_root",
    "install_firewall_package_as_root",
    "select_firewall_as_root",
]
