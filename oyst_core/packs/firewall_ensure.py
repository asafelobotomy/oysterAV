"""Managed firewall enable / disable (SSH-safe, preference-aware)."""

from __future__ import annotations

from oyst_core.packs.firewall import FirewallPack, invalidate_firewall_detect_cache
from oyst_core.packs.firewall_ops import FirewallOps, FirewallResult


def ensure_firewall_enabled(
    *,
    force_lockout: bool = False,
    dry_run: bool = False,
) -> FirewallResult:
    """Enable UFW or firewalld when installed but inactive (SSH-safe)."""
    from oyst_core.config_access import get_config_value
    from oyst_core.packs.firewall_select import (
        recommended_managed_backend,
        select_managed_backend,
    )

    pack = FirewallPack()
    invalidate_firewall_detect_cache()
    det = pack.detect()
    if det.get("conflict"):
        return FirewallResult(
            ok=False,
            message="Multiple firewall managers active; resolve UFW vs firewalld first",
        )
    active = str(det.get("active", "none"))
    if active in ("ufw", "firewalld"):
        return FirewallResult(ok=True, skipped=True, message=f"{active} already active")
    prefer_ufw = bool(det.get("ufw"))
    prefer_fw = bool(det.get("firewalld"))
    if not prefer_ufw and not prefer_fw:
        return FirewallResult(
            ok=True,
            skipped=True,
            message="no UFW or firewalld binary installed",
        )
    raw_pref = get_config_value("firewall.managed_backend")
    # Unset default serializes as the string "None"; explicit keep-as-is is "none".
    if raw_pref is None or raw_pref in {"", "None", "null"}:
        pref_raw = ""
    else:
        pref_raw = raw_pref.strip().lower()
    if pref_raw == "none":
        return FirewallResult(
            ok=True,
            skipped=True,
            message="firewall.managed_backend is none; skipping ensure",
        )
    if pref_raw in {"ufw", "firewalld"}:
        if (pref_raw == "ufw" and prefer_ufw) or (pref_raw == "firewalld" and prefer_fw):
            return select_managed_backend(
                pref_raw,
                force_lockout=force_lockout,
                dry_run=dry_run,
            )
    rec = recommended_managed_backend()
    if rec == "ufw" and prefer_ufw:
        target = "ufw"
    elif rec == "firewalld" and prefer_fw:
        target = "firewalld"
    elif prefer_ufw:
        target = "ufw"
    else:
        target = "firewalld"
    return select_managed_backend(
        target,
        force_lockout=force_lockout,
        dry_run=dry_run,
    )


def set_managed_enabled(
    enabled: bool,
    *,
    force_lockout: bool = False,
    dry_run: bool = False,
) -> FirewallResult:
    """Enable or stop oysterAV-managed firewall (UFW / firewalld only)."""
    if enabled:
        return ensure_firewall_enabled(force_lockout=force_lockout, dry_run=dry_run)
    ops = FirewallOps()
    invalidate_firewall_detect_cache()
    det = ops._pack.detect()
    if det.get("conflict"):
        return FirewallResult(
            ok=False,
            message="Multiple firewall managers active; resolve UFW vs firewalld first",
        )
    active = str(det.get("active", "none"))
    if active == "ufw":
        return ops.ufw_lifecycle("disable", dry_run=dry_run)
    if active == "firewalld":
        return ops.firewalld_lifecycle("disable", dry_run=dry_run)
    return FirewallResult(
        ok=True,
        skipped=True,
        message=f"no managed firewall to disable (active={active})",
    )
