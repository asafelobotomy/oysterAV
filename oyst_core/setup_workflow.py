"""Guided first-run setup workflow (CLI equivalent of setup wizard)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import oyst_core
from oyst_core.audit import SecurityAudit
from oyst_core.config import load_config, set_config_value
from oyst_core.doctor_cache import doctor_all
from oyst_core.maintenance import bootstrap_critical_ok, run_bootstrap
from oyst_core.models import PackTier
from oyst_core.privilege.priority import sort_pack_names
from oyst_core.privileged.helper_clamd_unit import host_daily_signatures_present
from oyst_core.privileged.install_privileged_helper import helper_status
from oyst_core.registry import get_registry
from oyst_core.runtime.manifest import is_full_mode
from oyst_core.runtime_full_bootstrap import run_full_runtime_bootstrap
from oyst_core.schedule_util import apply_schedule
from oyst_core.setup_concert import run_setup_concert

# Soft UI marking only — do not alone allow mark-complete when failed.
_SOFT_FAIL_STEPS = frozenset(
    {
        "schedule",
        "rkhunter-propupd",
        "harden-fdpass",
        "harden-virusevent",
        "harden-disable-cache",
        "harden-rkhunter-defaults",
        "setup-concert",
    }
)

# Failed (not ok, not skipped) steps that block setup.completed.
_BLOCKS_COMPLETE = frozenset(
    {
        "packs-gate",
        "maintenance-bootstrap",
        "maintenance",
        "signatures",
        "harden-clamd",
        "firewall-ensure",
        "firewall-select",
        "firewall-install",
        "linger",
    }
)


def _install_fingerprint() -> str:
    return str(Path(oyst_core.__file__).resolve().parent)


def _missing_pack_names(packs: list[dict[str, Any]], tier: PackTier) -> list[str]:
    return [
        str(p.get("name", "?"))
        for p in packs
        if p.get("tier") == tier.value and not p.get("installed")
    ]


def assess_setup() -> dict[str, Any]:
    """Return setup state plus whether first-run attention is still needed.

    Missing required packs keep the wizard open unless the user explicitly skipped
    them (``setup.skipped_steps`` contains ``required_packs``) **and** marked
    setup complete. That lets "Continue anyway" + Finish dismiss first-run without
    leaving the gate stuck forever.

    ClamAV installed without host daily signatures also needs attention: Arch-family
    ``clamav-daemon`` units skip start until ``/var/lib/clamav/daily.*`` exists.

    Helper missing/outdated and install-path mismatch (UX-01/02) reopen attention.
    """
    cfg = load_config()
    packs = doctor_all()
    missing_required = _missing_pack_names(packs, PackTier.REQUIRED)
    missing_recommended = _missing_pack_names(packs, PackTier.RECOMMENDED)
    skipped = set(cfg.setup.skipped_steps)
    packs_skip_honored = cfg.setup.completed and "required_packs" in skipped
    clamav_ready = any(p.get("name") == "clamav" and p.get("installed") for p in packs) or any(
        p.get("name") == "freshclam" and p.get("installed") for p in packs
    )
    missing_signatures = clamav_ready and not host_daily_signatures_present()
    helper = helper_status()
    helper_missing = (not bool(helper.get("installed"))) or (not bool(helper.get("policy_current")))
    stored = (cfg.setup.completed_install or "").strip()
    current_fp = _install_fingerprint()
    if cfg.setup.completed and stored:
        install_mismatch = stored != current_fp
    elif cfg.setup.completed and not stored:
        # Legacy configs: mismatch only when other gates already need attention.
        install_mismatch = helper_missing or missing_signatures
    else:
        install_mismatch = False
    needs_attention = (
        (not cfg.setup.completed)
        or (bool(missing_required) and not packs_skip_honored)
        or missing_signatures
        or helper_missing
        or install_mismatch
    )
    return {
        "completed": cfg.setup.completed,
        "completed_at": cfg.setup.completed_at,
        "skipped_steps": cfg.setup.skipped_steps,
        "needs_attention": needs_attention,
        "missing_required": missing_required,
        "missing_recommended": missing_recommended,
        "missing_signatures": missing_signatures,
        "helper_missing": helper_missing,
        "install_mismatch": install_mismatch,
        "recommended_action": ("oyst-cli setup run" if needs_attention else None),
    }


def reset_setup() -> dict[str, Any]:
    """Clear setup completion so guided setup can run again."""
    set_config_value("setup.completed", "false")
    set_config_value("setup.skipped_steps", "")
    set_config_value("setup.completed_install", "")
    return assess_setup()


def _step_blocks_complete(step: dict[str, Any]) -> bool:
    if step.get("ok") or step.get("skipped"):
        return False
    return str(step.get("step", "")) in _BLOCKS_COMPLETE


def _is_hard_failure(step: dict[str, Any]) -> bool:
    if step.get("ok") or step.get("skipped"):
        return False
    if _step_blocks_complete(step):
        return True
    name = str(step.get("step", ""))
    if name in _SOFT_FAIL_STEPS or name.startswith("rkhunter-") or name.startswith("install-"):
        return False
    if name.startswith("harden-"):
        return False
    return True


def _can_mark_complete(steps: list[dict[str, Any]]) -> bool:
    """Allow completion only when no security blocker steps failed."""
    return not any(_step_blocks_complete(s) for s in steps)


def run_setup(
    *,
    skip_packs: bool = False,
    skip_schedule: bool = False,
    skip_bootstrap: bool = False,
    skip_harden: bool = False,
    confirm_aur: bool = False,
    auto_quarantine: bool | None = None,
    schedule_profile: str = "quick",
    full_bootstrap: bool = True,
    enable_linger: bool = False,
    enable_firewall: bool = True,
    mark_complete: bool = True,
    packs: list[str] | None = None,
    harden_include: list[str] | None = None,
    firewall_backend: str | None = None,
) -> dict[str, Any]:
    """Run guided setup mirroring the GTK setup wizard.

    Privileged pack install, propupd, harden/firewall, and linger share one
    polkit prompt via ``setup-concert`` (AUR/runtime installs stay outside).

    When ``packs`` is set, install only those names (Install All / targeted batch).
    ``firewall_backend`` (ufw|firewalld|none) selects via one concert instead of
    a bare ensure when set.
    """
    audit = SecurityAudit()
    steps: list[dict[str, Any]] = []
    linger_advisory: str | None = None

    packs_status = [p.doctor().model_dump() for p in get_registry().all()]
    steps.append({"step": "doctor", "ok": True, "packs": len(packs_status)})

    install_targets: list[str] = []
    if packs is not None:
        install_targets = sort_pack_names([str(n) for n in packs if str(n).strip()])
    elif not skip_packs:
        missing_required = _missing_pack_names(packs_status, PackTier.REQUIRED)
        missing_recommended = _missing_pack_names(packs_status, PackTier.RECOMMENDED)
        install_targets = missing_required + [
            n for n in missing_recommended if n not in missing_required
        ]
    else:
        set_config_value("setup.skipped_steps", "required_packs")
        steps.append({"step": "install-packs", "ok": True, "skipped": True})

    want_propupd = not skip_bootstrap and not (is_full_mode() and full_bootstrap)
    want_packs = packs is not None or not skip_packs
    include = frozenset(harden_include) if harden_include is not None else None
    targets = install_targets if want_packs else None

    def _run_bootstrap_steps() -> None:
        if is_full_mode() and full_bootstrap:
            bootstrap_result = run_full_runtime_bootstrap(
                skip_install=False,
                update_signatures=True,
                run_maintenance=True,
                skip_lynis=True,
            )
            steps.extend(bootstrap_result.get("steps", []))
            return
        maint = run_bootstrap(skip_lynis=True, skip_rkhunter_propupd=True)
        steps.append(
            {
                "step": "maintenance-bootstrap",
                "ok": bootstrap_critical_ok(maint),
                "details": maint,
            }
        )

    # UX-06: when packs are already present, refresh signatures before harden concert.
    early_bootstrap = not skip_bootstrap and not (targets or [])
    if early_bootstrap:
        _run_bootstrap_steps()

    concert_steps = run_setup_concert(
        pack_names=targets,
        confirm_aur=confirm_aur,
        skip_harden=skip_harden,
        enable_firewall=enable_firewall,
        propupd=want_propupd,
        enable_linger=enable_linger,
        harden_include=include,
        firewall_backend=firewall_backend,
    )
    steps.extend(concert_steps)
    for cstep in concert_steps:
        name = str(cstep.get("step", ""))
        if name.startswith("install-"):
            audit.log(
                "pack.install",
                f"setup: {name.removeprefix('install-')}",
                success=bool(cstep.get("ok")),
                data={"mode": cstep.get("mode", "concert")},
            )

    if want_packs and packs is None:
        packs_status = [p.doctor().model_dump() for p in get_registry().all()]
        if _missing_pack_names(packs_status, PackTier.REQUIRED):
            # Explicit skip only via skip_packs=True — never auto-honor packs skip.
            steps.append({"step": "packs-gate", "ok": False})

    if not skip_bootstrap and not early_bootstrap:
        _run_bootstrap_steps()
    elif skip_bootstrap:
        steps.append({"step": "bootstrap", "ok": True, "skipped": True})

    if skip_harden and not enable_firewall:
        if not any(s.get("step") == "firewall-ensure" for s in steps):
            steps.append({"step": "firewall-ensure", "ok": True, "skipped": True})
    if skip_harden and not any(str(s.get("step", "")).startswith("harden-") for s in steps):
        steps.append({"step": "harden", "ok": True, "skipped": True})

    if auto_quarantine is not None:
        set_config_value("quarantine.auto", "true" if auto_quarantine else "false")
    cfg = load_config()
    steps.append({"step": "preferences", "ok": True, "auto_quarantine": cfg.quarantine.auto})

    if not skip_schedule:
        set_config_value("schedule.profile", schedule_profile)
        set_config_value("schedule.enabled", "true")
        set_config_value("schedule.frequency", "daily")
        set_config_value("schedule.time", "02:00")
        sched = apply_schedule(smoke_test=True)
        ok = bool(sched.get("ok"))
        raw_linger_advisory = sched.get("linger_advisory")
        if isinstance(raw_linger_advisory, str):
            linger_advisory = raw_linger_advisory.strip() or None
        step: dict[str, Any] = {
            "step": "schedule",
            "ok": ok,
            "message": sched.get("message", ""),
        }
        if not ok:
            step["soft_fail"] = True
            step["message"] = (
                f"{step['message']} (non-fatal: schedule can be fixed later with "
                "`oyst-cli schedule apply`)"
            ).strip()
        if linger_advisory:
            step["linger_advisory"] = linger_advisory
        steps.append(step)
        # Linger is applied inside setup-concert when enable_linger=True.
    else:
        steps.append({"step": "schedule", "ok": True, "skipped": True})

    can_complete = _can_mark_complete(steps)
    completed = False
    if mark_complete and can_complete:
        set_config_value("setup.completed", "true")
        set_config_value("setup.completed_install", _install_fingerprint())
        completed = True

    for step in steps:
        name = str(step.get("step", ""))
        if (
            not step.get("ok")
            and not step.get("skipped")
            and name not in _BLOCKS_COMPLETE
            and (
                name in _SOFT_FAIL_STEPS
                or name == "rkhunter-propupd"
                or name.startswith("harden-")
                or name.startswith("install-")
            )
        ):
            step["soft_fail"] = True

    hard_failed = [s for s in steps if _is_hard_failure(s)]
    overall_ok = not hard_failed
    audit.log(
        "setup.run",
        "completed" if completed else "partial",
        success=overall_ok,
        data={"steps": len(steps), "marked_complete": completed},
    )

    cfg = load_config()
    ok_count = sum(1 for s in steps if s.get("ok"))
    result: dict[str, Any] = {
        "ok": overall_ok,
        "completed": cfg.setup.completed,
        "marked_complete": completed,
        "can_mark_complete": can_complete,
        "steps": steps,
        "steps_ok": ok_count,
        "steps_total": len(steps),
    }
    if linger_advisory and not enable_linger:
        result["linger_advisory"] = linger_advisory
        result["linger_hint"] = "oyst-cli schedule enable-linger"
    return result
