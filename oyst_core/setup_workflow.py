"""Guided first-run setup workflow (CLI equivalent of setup wizard)."""

from __future__ import annotations

from typing import Any

from oyst_core.audit import SecurityAudit
from oyst_core.config import load_config, set_config_value
from oyst_core.maintenance import run_bootstrap
from oyst_core.models import PackTier
from oyst_core.privilege.priority import sort_pack_names
from oyst_core.registry import get_registry
from oyst_core.runtime.manifest import is_full_mode
from oyst_core.runtime_full_bootstrap import run_full_runtime_bootstrap
from oyst_core.schedule_util import apply_schedule
from oyst_core.setup_concert import run_setup_concert

_SOFT_FAIL_STEPS = frozenset(
    {
        "schedule",
        "linger",
        "rkhunter-propupd",
        "harden-clamd",
        "harden-fdpass",
        "harden-virusevent",
        "harden-disable-cache",
        "harden-rkhunter-defaults",
        "firewall-ensure",
        "setup-concert",
    }
)


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
    """
    from oyst_core.doctor_cache import doctor_all

    cfg = load_config()
    packs = doctor_all()
    missing_required = _missing_pack_names(packs, PackTier.REQUIRED)
    missing_recommended = _missing_pack_names(packs, PackTier.RECOMMENDED)
    skipped = set(cfg.setup.skipped_steps)
    packs_skip_honored = cfg.setup.completed and "required_packs" in skipped
    needs_attention = (not cfg.setup.completed) or (
        bool(missing_required) and not packs_skip_honored
    )
    return {
        "completed": cfg.setup.completed,
        "completed_at": cfg.setup.completed_at,
        "skipped_steps": cfg.setup.skipped_steps,
        "needs_attention": needs_attention,
        "missing_required": missing_required,
        "missing_recommended": missing_recommended,
        "recommended_action": ("oyst-cli setup run" if needs_attention else None),
    }


def reset_setup() -> dict[str, Any]:
    """Clear setup completion so guided setup can run again."""
    set_config_value("setup.completed", "false")
    set_config_value("setup.skipped_steps", "")
    return assess_setup()


def _is_hard_failure(step: dict[str, Any]) -> bool:
    if step.get("ok") or step.get("skipped") or step.get("soft_fail"):
        return False
    name = str(step.get("step", ""))
    if name in _SOFT_FAIL_STEPS or name.startswith("rkhunter-") or name.startswith("install-"):
        return False
    if name.startswith("harden-"):
        return False
    return True


def _can_mark_complete(steps: list[dict[str, Any]]) -> bool:
    """Allow completion when only soft failures or missing packs remain."""
    failed = [s for s in steps if _is_hard_failure(s)]
    if not failed:
        return True
    return len(failed) == 1 and failed[0].get("step") == "packs-gate"


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
) -> dict[str, Any]:
    """Run guided setup mirroring the GTK setup wizard.

    Privileged pack install, propupd, harden/firewall, and linger share one
    polkit prompt via ``setup-concert`` (AUR/runtime installs stay outside).

    When ``packs`` is set, install only those names (Install All / targeted batch).
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
    concert_steps = run_setup_concert(
        pack_names=install_targets if want_packs else None,
        confirm_aur=confirm_aur,
        skip_harden=skip_harden,
        enable_firewall=enable_firewall,
        propupd=want_propupd,
        enable_linger=enable_linger,
        harden_include=include,
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
            set_config_value("setup.skipped_steps", "required_packs")
            steps.append({"step": "packs-gate", "ok": False, "skipped": True})

    if not skip_bootstrap:
        if is_full_mode() and full_bootstrap:
            bootstrap_result = run_full_runtime_bootstrap(
                skip_install=False,
                update_signatures=True,
                run_maintenance=True,
                skip_lynis=True,
            )
            steps.extend(bootstrap_result.get("steps", []))
        else:
            maint = run_bootstrap(skip_lynis=True, skip_rkhunter_propupd=True)
            steps.append({"step": "maintenance-bootstrap", "ok": any(s.get("ok") for s in maint)})
    else:
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
        completed = True

    for step in steps:
        name = str(step.get("step", ""))
        if (
            not step.get("ok")
            and not step.get("skipped")
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
