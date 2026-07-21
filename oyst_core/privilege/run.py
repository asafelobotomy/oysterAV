"""Run a privilege concert via oyst-helper (one polkit prompt)."""

from __future__ import annotations

import json
from typing import Any

from oyst_core.audit import SecurityAudit
from oyst_core.privilege.plan import PrivilegePlan
from oyst_core.privileged.helper import run_privileged_helper


def _parse_helper_steps(stdout: str) -> list[dict[str, Any]]:
    text = (stdout or "").strip()
    if not text:
        return []
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return []
    raw = payload.get("steps") if isinstance(payload, dict) else None
    if not isinstance(raw, list):
        return []
    return [s for s in raw if isinstance(s, dict)]


def run_privilege_concert(
    plan: PrivilegePlan,
    *,
    timeout: int = 7200,
) -> list[dict[str, Any]]:
    """Execute plan.helper_argv under plan.argv1; return helper step dicts."""
    if plan.disclosure_only:
        raise ValueError(
            f"privilege plan {plan.recipe!r} is disclosure-only; "
            "execute via the feature's own RPC/CLI path",
        )
    if not plan.needs_elevation:
        return []
    res = run_privileged_helper(plan.argv1, plan.to_helper_argv(), timeout=timeout)
    steps = _parse_helper_steps(res.stdout or "")
    ok = res.returncode == 0
    SecurityAudit().log(
        "privilege.concert",
        plan.recipe,
        success=ok,
        data={
            "argv1": plan.argv1,
            "steps": [s.get("step") for s in steps],
            "returncode": res.returncode,
        },
    )
    if res.returncode != 0 and not steps:
        err = (res.stderr or res.stdout or f"{plan.argv1} failed").strip()
        return [{"step": plan.recipe, "ok": False, "message": err, "soft_fail": True}]
    return steps
