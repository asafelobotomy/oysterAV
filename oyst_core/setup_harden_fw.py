"""Firewall argv prep for harden / setup-concert (select vs ensure)."""

from __future__ import annotations

from typing import Any

from oyst_core.packs.firewall import FirewallPack
from oyst_core.privileged.runner import which


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


def prepare_firewall_argv(
    argv: list[str],
    local: list[dict[str, Any]],
    *,
    with_firewall: bool,
    force_lockout: bool,
    firewall_backend: str | None = None,
) -> None:
    """Append --select-firewall (preferred) or legacy --with-firewall flags."""
    backend = (firewall_backend or "").strip().lower()
    if backend in {"ufw", "firewalld", "none"}:
        _prepare_firewall_select(
            argv,
            local,
            backend=backend,
            force_lockout=force_lockout,
        )
        return
    if not with_firewall:
        return
    target = _resolve_ensure_target()
    if target is None:
        # Local skip/soft-fail already recorded by resolver side effects via detect
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
            return
        active = str(det.get("active", "none"))
        if active in ("ufw", "firewalld"):
            local.append(
                _step(
                    "firewall-ensure",
                    ok=True,
                    skipped=True,
                    message=f"{active} already active",
                ),
            )
            return
        local.append(
            _step(
                "firewall-ensure",
                ok=True,
                skipped=True,
                message="no UFW or firewalld binary installed"
                if not det.get("ufw") and not det.get("firewalld")
                else "firewall.managed_backend is none; skipping ensure",
            ),
        )
        return
    _prepare_firewall_select(
        argv,
        local,
        backend=target,
        force_lockout=force_lockout,
    )


def _managed_pref() -> str:
    from oyst_core.config_access import get_config_value

    raw = get_config_value("firewall.managed_backend")
    if raw is None or raw in {"", "None", "null"}:
        return ""
    return raw.strip().lower()


def _resolve_ensure_target() -> str | None:
    """Same preference/recommend resolution as userspace ensure_firewall_enabled."""
    from oyst_core.packs.firewall_select import recommended_managed_backend

    det = FirewallPack().detect()
    if det.get("conflict"):
        return None
    active = str(det.get("active", "none"))
    if active in ("ufw", "firewalld"):
        return None
    prefer_ufw = bool(det.get("ufw"))
    prefer_fw = bool(det.get("firewalld"))
    if not prefer_ufw and not prefer_fw:
        return None
    pref = _managed_pref()
    if pref == "none":
        return None
    if pref == "ufw" and prefer_ufw:
        return "ufw"
    if pref == "firewalld" and prefer_fw:
        return "firewalld"
    rec = recommended_managed_backend()
    if rec == "ufw" and prefer_ufw:
        return "ufw"
    if rec == "firewalld" and prefer_fw:
        return "firewalld"
    return "ufw" if prefer_ufw else "firewalld"


def _prepare_firewall_select(
    argv: list[str],
    local: list[dict[str, Any]],
    *,
    backend: str,
    force_lockout: bool,
) -> None:
    """Emit --install-firewall / --select-firewall for one-auth wizard/setup paths."""
    if backend == "none":
        argv.append("--select-firewall=none")
        return
    binary = "ufw" if backend == "ufw" else "firewall-cmd"
    det = FirewallPack().detect()
    if det.get("conflict"):
        local.append(
            _step(
                "firewall-select",
                ok=False,
                message="Multiple firewall managers active; resolve UFW vs firewalld first",
                soft_fail=True,
            ),
        )
        return
    active = str(det.get("active", "none"))
    if active == backend:
        local.append(
            _step(
                "firewall-select",
                ok=True,
                skipped=True,
                message=f"{backend} already active",
            ),
        )
        return
    if not which(binary):
        argv.append(f"--install-firewall={backend}")
    argv.append(f"--select-firewall={backend}")
    if force_lockout:
        argv.append("--force-lockout")


__all__ = ["prepare_firewall_argv"]
