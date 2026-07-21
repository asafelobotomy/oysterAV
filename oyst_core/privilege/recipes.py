"""Privilege concert recipe builders."""

from __future__ import annotations

from oyst_core.privilege.plan import (
    LOCAL_SCAN_PACKS,
    PRIVILEGED_SCAN_PACKS,
    PrivilegePlan,
    PrivilegeStep,
)
from oyst_core.privilege.priority import (
    PRIORITY_HARDEN,
    PRIORITY_PROPUPD,
    PRIORITY_REQUIRED,
    harden_step_priority,
    pack_priority,
    sort_pack_names,
    update_step_priority,
)

_SCAN_LABELS = {
    "rkhunter": "rkhunter rootkit check",
    "chkrootkit": "chkrootkit scan",
    "unhide": "unhide hidden-process scan",
    "lynis": "Lynis system audit",
    "clamav": "ClamAV malware scan",
    "maldet": "Linux Malware Detect scan",
}

_UPDATE_STEP_LABELS = {
    "packages": "Upgrade security-related packages",
    "freshclam": "Refresh ClamAV signatures (freshclam)",
    "runtime-signatures": "Refresh runtime ClamAV signatures",
    "fangfrisch": "Refresh Fangfrisch signature providers",
    "rkhunter-update": "Update rkhunter data files",
    "maldet-sigs": "Update Linux Malware Detect signatures",
    "rkhunter-propupd": "Refresh rkhunter property baseline",
}


def build_scan_privileged_plan(
    packs: list[str],
    *,
    job_id: str,
    unhide_mode: str = "sys",
) -> PrivilegePlan:
    """Plan one scan-concert for integrity/audit packs; local malware packs after."""
    privileged = [p for p in packs if p in PRIVILEGED_SCAN_PACKS]
    order = ["rkhunter", "chkrootkit", "unhide", "lynis"]
    privileged = [p for p in order if p in privileged]
    local = [p for p in packs if p in LOCAL_SCAN_PACKS]

    priv_steps = [
        PrivilegeStep(
            id=p,
            label=_SCAN_LABELS.get(p, p),
            privileged=True,
            priority=pack_priority(p),
        )
        for p in privileged
    ]
    local_steps = [
        PrivilegeStep(
            id=p,
            label=_SCAN_LABELS.get(p, p),
            privileged=False,
            priority=pack_priority(p),
        )
        for p in local
    ]

    helper_argv: list[str] = [f"--job-id={job_id}"]
    for name in privileged:
        helper_argv.append(f"--pack={name}")
    if "unhide" in privileged:
        helper_argv.append(f"--unhide-mode={unhide_mode}")
    if "rkhunter" in privileged:
        helper_argv.append("--rkh-overlay")

    summary = (
        "Integrity and audit scanners run first (one admin authentication), "
        "then malware scanners continue without further password prompts."
        if privileged and local
        else (
            "Integrity and audit scanners require one admin authentication."
            if privileged
            else "No administrator authentication is required for this scan."
        )
    )

    return PrivilegePlan(
        recipe="scan-privileged",
        title="Start scan",
        summary=summary,
        argv1="scan-concert",
        helper_argv=helper_argv if privileged else [],
        privileged_steps=priv_steps,
        local_steps=local_steps,
    )


def split_scan_packs(packs: list[str]) -> tuple[list[str], list[str]]:
    """Return (privileged_ordered, local_in_input_order)."""
    order = ["rkhunter", "chkrootkit", "unhide", "lynis"]
    privileged = [p for p in order if p in packs and p in PRIVILEGED_SCAN_PACKS]
    local = [p for p in packs if p in LOCAL_SCAN_PACKS]
    return privileged, local


def build_setup_plan(
    helper_argv: list[str],
    *,
    step_labels: list[tuple[str, str]] | None = None,
) -> PrivilegePlan:
    """Plan for setup-concert (install packs + harden + linger).

    ``step_labels`` is optional (id, label) pairs for Auto-Install disclosure.
    """
    if step_labels:
        steps = [
            PrivilegeStep(
                id=sid,
                label=label,
                priority=PRIORITY_REQUIRED + i,
            )
            for i, (sid, label) in enumerate(step_labels)
        ]
    else:
        steps = [
            PrivilegeStep(
                id="setup",
                label="Install packs and apply recommended host hardenings",
                priority=PRIORITY_REQUIRED,
            ),
        ]
    return PrivilegePlan(
        recipe="setup",
        title="Auto-Install",
        summary=(
            "Administrator authentication is required once to install security packs "
            "and apply recommended host hardenings."
        ),
        argv1="setup-concert",
        helper_argv=list(helper_argv),
        privileged_steps=steps if helper_argv else [],
    )


def build_harden_plan(
    helper_argv: list[str],
    *,
    step_ids: list[str] | None = None,
) -> PrivilegePlan:
    """Plan for setup-harden (safe host hardenings only)."""
    labels = {
        "harden-clamd": "Ensure clamd is enabled and running",
        "harden-fdpass": "Ensure clamonacc --fdpass",
        "harden-virusevent": "Ensure VirusEvent bridge",
        "harden-disable-cache": "Ensure DisableCache for on-access",
        "harden-rkhunter-defaults": "Ensure rkhunter DISABLE_TESTS defaults",
        "firewall-ensure": "Enable host firewall (SSH-safe)",
        "harden": "Apply recommended ClamAV, rkhunter, and firewall defaults",
    }
    ids = list(step_ids) if step_ids else ["harden"]
    steps = [
        PrivilegeStep(
            id=sid,
            label=labels.get(sid, sid),
            priority=harden_step_priority(sid) if sid != "harden" else PRIORITY_HARDEN,
        )
        for sid in ids
    ]
    return PrivilegePlan(
        recipe="harden",
        title="Apply hardenings",
        summary=(
            "Administrator authentication is required once to apply recommended host hardenings."
        ),
        argv1="setup-harden",
        helper_argv=list(helper_argv),
        privileged_steps=steps if helper_argv else [],
    )


def build_rkhunter_resolve_plan(
    directives: list[tuple[str, str]],
) -> PrivilegePlan:
    """Plan one rkhunter-whitelist set-many write (existing argv1; no new polkit action)."""
    n = len(directives)
    shown = [f"{opt}={val}" for opt, val in directives[:8]]
    extra = f" (+{n - 8} more)" if n > 8 else ""
    listed = ", ".join(shown) + extra if shown else "no directives"
    label = f"Write {n} whitelist directive(s): {listed}"
    helper_argv = ["set-many", *[f"{opt}={val}" for opt, val in directives]] if directives else []
    return PrivilegePlan(
        recipe="resolve-rkhunter",
        title="Resolve rkhunter findings",
        summary=(
            "Administrator authentication is required once to update the oysterAV "
            "rkhunter whitelist overlay. Does not edit sshd_config or delete files."
        ),
        argv1="rkhunter-whitelist",
        helper_argv=helper_argv,
        privileged_steps=(
            [
                PrivilegeStep(
                    id="whitelist-set-many",
                    label=label,
                    priority=PRIORITY_HARDEN,
                )
            ]
            if directives
            else []
        ),
    )


def build_install_packs_plan(
    pack_names: list[str],
    *,
    tiers: dict[str, str] | None = None,
    elevate: bool = True,
) -> PrivilegePlan:
    """Plan Install All for missing packs (priority-ordered)."""
    ordered = sort_pack_names(pack_names, tiers=tiers)
    steps = [
        PrivilegeStep(
            id=f"install-{name}",
            label=f"Install {name}",
            privileged=elevate,
            priority=pack_priority(name, tier=(tiers or {}).get(name)),
        )
        for name in ordered
    ]
    if elevate:
        summary = (
            "Administrator authentication is required once to install the selected "
            "security packs (required first, then recommended, then optional)."
        )
        helper_argv: list[str] = []
        argv1 = ""
    else:
        summary = (
            "Install selected packs into the private runtime. "
            "No administrator password is required for this step."
        )
        helper_argv = []
        argv1 = ""
    return PrivilegePlan(
        recipe="install-packs",
        title="Install All",
        summary=summary,
        argv1=argv1,
        helper_argv=helper_argv,
        privileged_steps=steps if elevate else [],
        local_steps=steps if not elevate else [],
        disclosure_only=True,
    )


def build_update_all_plan(
    *,
    package_names: list[str] | None = None,
    step_ids: list[str] | None = None,
    needs_package_elevation: bool = False,
) -> PrivilegePlan:
    """Disclosure plan for Update all (packages + signature/baseline pipeline)."""
    pkgs = list(package_names or [])
    default_steps = [
        "packages",
        "freshclam",
        "fangfrisch",
        "rkhunter-update",
        "maldet-sigs",
        "rkhunter-propupd",
    ]
    steps_ids = list(step_ids or default_steps)
    priv: list[PrivilegeStep] = []
    local: list[PrivilegeStep] = []
    if pkgs and needs_package_elevation:
        shown = ", ".join(pkgs[:6]) + (f" (+{len(pkgs) - 6} more)" if len(pkgs) > 6 else "")
        priv.append(
            PrivilegeStep(
                id="packages",
                label=f"Upgrade packages: {shown}" if shown else "Upgrade packages",
                priority=update_step_priority("packages"),
            )
        )
    for sid in steps_ids:
        if sid == "packages" and needs_package_elevation:
            continue
        label = _UPDATE_STEP_LABELS.get(sid, sid)
        step = PrivilegeStep(
            id=sid,
            label=label,
            privileged=False,
            priority=(PRIORITY_PROPUPD if sid == "rkhunter-propupd" else update_step_priority(sid)),
        )
        local.append(step)
    summary = (
        "Update all upgrades related packages (one authentication when needed), "
        "then refreshes signatures and baselines without further password prompts."
        if needs_package_elevation
        else "Update all refreshes signatures and baselines. No package upgrades need elevation."
    )
    return PrivilegePlan(
        recipe="update-all",
        title="Update all",
        summary=summary,
        argv1="",
        helper_argv=[],
        privileged_steps=priv,
        local_steps=local,
        disclosure_only=True,
    )
