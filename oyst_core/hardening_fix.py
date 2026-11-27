"""The Harden button: one sysctl drop-in with the safe values from ``oyst_core.hardening``.

The file's text is computed here, in the root-owned install, by the helper itself
(``oyst-helper sysctl-harden apply``); the caller only says ``apply`` or ``revert``, so it can
never choose a key or a value. A setting that is already stricter than oysterAV's value keeps
its current value, so applying never loosens anything.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from oyst_core.hardening import SYSCTL_RULES, _read, _sysctl_path
from oyst_core.plan import change, plan_doc, refused

DROPIN = Path("/etc/sysctl.d/90-oysterav-hardening.conf")
HEADER = (
    "# Written by oysterAV (Security page > System > Harden). Remove it to undo after a reboot."
)
ACTIONS = ("apply", "revert")
# Settings the kernel won't let go of until a reboot once they're on.
ONE_WAY = frozenset({"kernel.kexec_load_disabled"})


def dropin_values(root: Path = Path("/")) -> dict[str, int]:
    """Key -> value for every rule this kernel has, never looser than the current value."""
    out: dict[str, int] = {}
    for rule in SYSCTL_RULES:
        raw = _read(_sysctl_path(root, rule.key))
        if raw is None or not raw.lstrip("-").isdigit():
            continue
        current = int(raw)
        other = _read(_sysctl_path(root, rule.also)) if rule.also else None
        if other is not None and other.isdigit():
            current = max(current, int(other))  # what the kernel actually uses
        out[rule.key] = max(current, rule.want) if rule.at_least else min(current, rule.want)
    return out


def dropin_text(root: Path = Path("/")) -> str:
    lines = [HEADER]
    lines.extend(f"{key} = {value}" for key, value in dropin_values(root).items())
    return "\n".join(lines) + "\n"


def _weak(key: str, now: int, root: Path) -> bool:
    rule = next(r for r in SYSCTL_RULES if r.key == key)
    other = _read(_sysctl_path(root, rule.also)) if rule.also else None
    if other is not None and other.isdigit():
        now = max(now, int(other))
    return now < rule.want if rule.at_least else now > rule.want


def changed_keys(root: Path = Path("/")) -> list[tuple[str, int, int]]:
    """(key, now, after) for the settings applying would change."""
    out: list[tuple[str, int, int]] = []
    for key, value in dropin_values(root).items():
        raw = _read(_sysctl_path(root, key)) or "0"
        if int(raw) != value and _weak(key, int(raw), root):
            out.append((key, int(raw), value))
    return out


def harden_plan(action: str, root: Path = Path("/")) -> dict[str, Any]:
    if action == "revert":
        if not (root / DROPIN.relative_to("/")).is_file():
            return refused("oysterAV's hardening file isn't there: nothing to undo.")
        return plan_doc(
            "Remove oysterAV's kernel hardening file. The settings go back at the next reboot.",
            [change(f"Delete {DROPIN}", group="Kernel settings", reversible=True)],
        )
    todo = changed_keys(root)
    if not todo:
        return refused("Every kernel setting oysterAV checks is already hardened.")
    changes = [
        change(
            f"{key}: {now} → {after}",
            group="Kernel settings",
            detail="Stays until the next reboot even if undone." if key in ONE_WAY else "",
            reversible=key not in ONE_WAY,
        )
        for key, now, after in todo
    ]
    summary = f"Write {DROPIN} and apply {len(todo)} kernel setting(s) now. Asks for your password."
    return plan_doc(summary, changes)


def run_harden(action: str) -> dict[str, Any]:
    """Run ``oyst-helper sysctl-harden <action>`` (one polkit prompt)."""
    from oyst_core.audit import SecurityAudit
    from oyst_core.privileged.helper import run_privileged_helper

    if action not in ACTIONS:
        return {"ok": False, "error": "action must be apply or revert"}
    res = run_privileged_helper("sysctl-harden", [action], timeout=120)
    ok = res.returncode == 0
    SecurityAudit().log("sysctl-harden", action, success=ok)
    if not ok:
        return {"ok": False, "error": (res.stderr or res.stdout or "helper failed").strip()[:500]}
    message = (
        "Kernel hardening is on."
        if action == "apply"
        else "Removed oysterAV's hardening file; the old settings return at the next reboot."
    )
    return {"ok": True, "message": message}


__all__ = ["ACTIONS", "DROPIN", "dropin_text", "harden_plan", "run_harden"]
