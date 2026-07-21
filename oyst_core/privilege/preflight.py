"""Human-readable privilege concert preflight text."""

from __future__ import annotations

from oyst_core.privilege.plan import PrivilegePlan


def preflight_body(plan: PrivilegePlan) -> str:
    """Dialog / CLI body: inform once, then one admin authentication."""
    lines = [plan.summary.strip(), ""]
    privileged = plan.ordered_privileged_steps()
    local = plan.ordered_local_steps()
    if privileged:
        lines.append("Administrator authentication is required once for:")
        for step in privileged:
            lines.append(f"  • {step.label}")
        lines.append("")
    if local:
        lines.append("Then continues without further password prompts for:")
        for step in local:
            lines.append(f"  • {step.label}")
        lines.append("")
    lines.append("You will not be asked again until this action finishes.")
    return "\n".join(lines).strip()


def preflight_dict(plan: PrivilegePlan) -> dict[str, object]:
    privileged = plan.ordered_privileged_steps()
    local = plan.ordered_local_steps()
    return {
        "recipe": plan.recipe,
        "title": plan.title,
        "summary": plan.summary,
        "needs_elevation": plan.needs_elevation,
        "privileged": [{"id": s.id, "label": s.label, "priority": s.priority} for s in privileged],
        "local": [{"id": s.id, "label": s.label, "priority": s.priority} for s in local],
        "body": preflight_body(plan),
    }
