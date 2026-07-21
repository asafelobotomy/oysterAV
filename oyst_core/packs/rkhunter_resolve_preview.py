"""Preview PrivilegePlan for rkhunter Resolve (no elevation)."""

from __future__ import annotations

from collections.abc import Sequence

from oyst_core.packs.rkhunter_resolve_plan import (
    ResolvePlan,
    path_allowed_for_resolve,
    plan_resolve,
)
from oyst_core.privilege.plan import PrivilegePlan
from oyst_core.privilege.recipes import build_rkhunter_resolve_plan


def collect_resolve_directives(
    findings: Sequence[dict[str, object]],
    *,
    force: bool = False,
) -> tuple[list[tuple[str, str]], list[str], list[dict[str, object]], list[ResolvePlan]]:
    """Plan findings into deduped directives; return (directives, errors, items, plans)."""
    planned: list[tuple[dict[str, object], ResolvePlan]] = []
    errors: list[str] = []
    for raw in findings:
        threat = str(raw.get("threat_name") or "")
        path = str(raw.get("path") or "")
        message = str(raw.get("message") or "")
        try:
            plan = plan_resolve(threat, path=path, message=message)
            if plan.requires_path:
                path_allowed_for_resolve(plan.value, plan.threat_name, force=force)
        except ValueError as exc:
            errors.append(f"{threat or path or 'finding'}: {exc}")
            continue
        planned.append((raw, plan))

    items: list[dict[str, object]] = []
    directives: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    resolve_plans: list[ResolvePlan] = []
    for raw, plan in planned:
        items.append(
            {
                "ok": True,
                "threat_name": plan.threat_name,
                "path": str(raw.get("path") or ""),
                "message": str(raw.get("message") or ""),
                "option": plan.option,
                "value": plan.value,
                "explanation": plan.explanation,
            }
        )
        key = (plan.option, plan.value)
        if key not in seen:
            seen.add(key)
            directives.append(key)
            resolve_plans.append(plan)
    return directives, errors, items, resolve_plans


def preview_rkhunter_resolve_plan(
    findings: Sequence[dict[str, object]],
    *,
    force: bool = False,
) -> tuple[PrivilegePlan | None, list[str]]:
    """Build disclosure plan without elevating; errors are soft planning failures."""
    directives, errors, _items, _plans = collect_resolve_directives(findings, force=force)
    if not directives:
        return None, errors
    return build_rkhunter_resolve_plan(directives), errors


__all__ = ["collect_resolve_directives", "preview_rkhunter_resolve_plan"]
