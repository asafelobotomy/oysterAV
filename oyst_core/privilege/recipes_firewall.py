"""Privilege concert plan for batched UFW rule mutations."""

from __future__ import annotations

import json
from typing import Any

from oyst_core.privilege.plan import PrivilegePlan, PrivilegeStep
from oyst_core.privilege.priority import PRIORITY_HARDEN

# Keep in sync with helper_firewall_batch.MAX_BATCH_RULES
MAX_BATCH_RULES = 32


def _rule_label(rule: dict[str, Any], index: int) -> str:
    action = str(rule.get("action") or "?")
    port = str(rule.get("port") or "?")
    proto = str(rule.get("proto") or "tcp")
    if action == "delete":
        verb = str(rule.get("rule_action") or "allow")
        return f"{index}. Delete {verb} {port}/{proto}"
    label = f"{index}. {action.title()} {port}/{proto}"
    from_addr = rule.get("from_addr")
    if from_addr:
        label += f" from {from_addr}"
    return label


def build_ufw_batch_plan(rules: list[dict[str, Any]]) -> PrivilegePlan:
    """One ``firewall`` helper call applying many UFW rules (single polkit auth)."""
    if not rules:
        raise ValueError("at least one rule required")
    if len(rules) > MAX_BATCH_RULES:
        raise ValueError(f"at most {MAX_BATCH_RULES} rules per batch")
    helper_argv = ["ufw", "batch"]
    steps: list[PrivilegeStep] = []
    for i, rule in enumerate(rules, start=1):
        payload = json.dumps(rule, separators=(",", ":"), sort_keys=True)
        helper_argv.append(f"--rule={payload}")
        steps.append(
            PrivilegeStep(
                id=f"ufw-rule-{i}",
                label=_rule_label(rule, i),
                priority=PRIORITY_HARDEN + i,
            ),
        )
    n = len(rules)
    return PrivilegePlan(
        recipe="firewall-ufw-batch",
        title="Apply firewall rules",
        summary=(
            f"Administrator authentication is required once to apply {n} UFW rule(s). "
            "Rules run in order; later rules are skipped if an earlier one fails."
        ),
        argv1="firewall",
        helper_argv=helper_argv,
        privileged_steps=steps,
    )


__all__ = ["MAX_BATCH_RULES", "build_ufw_batch_plan"]
