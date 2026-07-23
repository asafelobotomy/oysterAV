"""Update-all privilege concert recipe builder."""

from __future__ import annotations

from oyst_core.privilege.plan import PrivilegePlan, PrivilegeStep
from oyst_core.privilege.priority import PRIORITY_PROPUPD, update_step_priority

_UPDATE_STEP_LABELS = {
    "packages": "Upgrade security-related packages",
    "freshclam": "Refresh ClamAV signatures (freshclam)",
    "runtime-signatures": "Refresh runtime ClamAV signatures",
    "fangfrisch": "Refresh Fangfrisch signature providers",
    "rkhunter-update": "Update rkhunter data files",
    "maldet-sigs": "Update Linux Malware Detect signatures",
    "rkhunter-propupd": "Refresh rkhunter property baseline",
}


def build_update_all_plan(
    *,
    official_packages: list[str] | None = None,
    family: str = "",
    include_rkh_update: bool = False,
    include_rkh_propupd: bool = False,
    package_names: list[str] | None = None,
    step_ids: list[str] | None = None,
    needs_package_elevation: bool = False,
) -> PrivilegePlan:
    """Plan Update all: one update-concert for elevated steps, then local refreshes.

    Legacy kwargs ``package_names`` / ``needs_package_elevation`` still accepted for
    callers that only disclose package names without building helper argv.
    """
    official = list(official_packages or [])
    if not official and needs_package_elevation and package_names:
        official = list(package_names)
    default_local = [
        "freshclam",
        "fangfrisch",
        "maldet-sigs",
    ]
    if step_ids:
        local_ids = [
            sid
            for sid in step_ids
            if sid
            not in (
                "packages",
                "rkhunter-update",
                "rkhunter-propupd",
                "runtime-signatures",
            )
        ]
    else:
        local_ids = list(default_local)

    helper_argv: list[str] = []
    priv: list[PrivilegeStep] = []
    if official:
        if family:
            helper_argv.append(f"--family={family}")
        helper_argv.append(f"--upgrade={','.join(official)}")
        shown = ", ".join(official[:6]) + (
            f" (+{len(official) - 6} more)" if len(official) > 6 else ""
        )
        priv.append(
            PrivilegeStep(
                id="packages",
                label=f"Upgrade packages: {shown}" if shown else "Upgrade packages",
                priority=update_step_priority("packages"),
            )
        )
    if include_rkh_update:
        helper_argv.append("--rkh-update")
        priv.append(
            PrivilegeStep(
                id="rkhunter-update",
                label=_UPDATE_STEP_LABELS["rkhunter-update"],
                priority=update_step_priority("rkhunter-update"),
            )
        )
    if include_rkh_propupd:
        helper_argv.append("--rkh-propupd")
        priv.append(
            PrivilegeStep(
                id="rkhunter-propupd",
                label=_UPDATE_STEP_LABELS["rkhunter-propupd"],
                priority=PRIORITY_PROPUPD,
            )
        )

    local: list[PrivilegeStep] = []
    for sid in local_ids:
        if sid in {s.id for s in priv}:
            continue
        local.append(
            PrivilegeStep(
                id=sid,
                label=_UPDATE_STEP_LABELS.get(sid, sid),
                privileged=False,
                priority=update_step_priority(sid),
            )
        )

    if helper_argv:
        summary = (
            "Administrator authentication is required once to upgrade packages and "
            "refresh rkhunter data/baseline, then signatures continue without further "
            "password prompts."
        )
        return PrivilegePlan(
            recipe="update-all",
            title="Update all",
            summary=summary,
            argv1="update-concert",
            helper_argv=helper_argv,
            privileged_steps=priv,
            local_steps=local,
        )

    summary = "Update all refreshes signatures and baselines. No package upgrades need elevation."
    return PrivilegePlan(
        recipe="update-all",
        title="Update all",
        summary=summary,
        argv1="",
        helper_argv=[],
        privileged_steps=[],
        local_steps=local,
        disclosure_only=True,
    )


__all__ = ["build_update_all_plan"]
