"""Userspace batch UFW mutations (single privilege concert)."""

from __future__ import annotations

from typing import Any

from oyst_core.packs.firewall import FirewallPack, invalidate_firewall_detect_cache
from oyst_core.packs.firewall_ops import FirewallResult
from oyst_core.privilege.recipes_firewall import MAX_BATCH_RULES, build_ufw_batch_plan
from oyst_core.privilege.run import run_privilege_concert
from oyst_core.privileged.helper_firewall_batch import parse_ufw_batch_rules
from oyst_core.privileged.validators import validate_port


def _lockout_blocked(rules: list[dict[str, str]], *, force_lockout: bool) -> str | None:
    if force_lockout:
        return None
    for rule in rules:
        if rule.get("port") != "22":
            continue
        if rule["action"] in {"deny", "delete"}:
            return "refusing to delete/deny SSH port 22; use --force-lockout-risk"
    return None


def normalize_batch_rules(rules: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Validate GUI/RPC rule dicts via the same helper parser."""
    if not rules:
        raise ValueError("at least one rule required")
    if len(rules) > MAX_BATCH_RULES:
        raise ValueError(f"at most {MAX_BATCH_RULES} rules per batch")
    # Reuse helper normalization by encoding then parsing.
    import json

    argv = [
        f"--rule={json.dumps(r, separators=(',', ':'), sort_keys=True)}" for r in rules
    ]
    return parse_ufw_batch_rules(argv)


def ufw_batch(
    rules: list[dict[str, Any]],
    *,
    force_lockout: bool = False,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Apply many UFW rules with one polkit authentication."""
    pack = FirewallPack()
    invalidate_firewall_detect_cache()
    det = pack.detect()
    if det.get("conflict"):
        return {
            "ok": False,
            "message": "Multiple firewall managers active; resolve conflict first",
            "steps": [],
        }
    if str(det.get("active", "none")) != "ufw":
        return {
            "ok": False,
            "message": "UFW batch requires active UFW backend",
            "steps": [],
        }
    try:
        normalized = normalize_batch_rules(rules)
    except ValueError as exc:
        return {"ok": False, "message": str(exc), "steps": []}
    blocked = _lockout_blocked(normalized, force_lockout=force_lockout)
    if blocked:
        return {"ok": False, "message": blocked, "steps": []}
    plan = build_ufw_batch_plan(normalized)
    if dry_run:
        return {
            "ok": True,
            "message": "dry-run",
            "dry_run": True,
            "steps": [
                {"step": s.id, "ok": True, "message": s.label, "soft_fail": False}
                for s in plan.ordered_privileged_steps()
            ],
            "plan": {"title": plan.title, "summary": plan.summary, "recipe": plan.recipe},
        }
    steps = run_privilege_concert(plan, timeout=300)
    failed = [s for s in steps if not s.get("ok")]
    invalidate_firewall_detect_cache()
    ok = not failed
    msg = "ok" if ok else str(failed[0].get("message") or "batch failed")
    return {"ok": ok, "message": msg, "steps": steps}


def result_as_firewall(result: dict[str, Any]) -> FirewallResult:
    """Adapt batch dict for older callers expecting FirewallResult."""
    return FirewallResult(
        ok=bool(result.get("ok")),
        message=str(result.get("message") or ""),
        skipped=False,
    )


def ssh_port_in_rules(rules: list[dict[str, Any]]) -> bool:
    """True when any rule targets port 22 with delete/deny."""
    for rule in rules:
        try:
            port = validate_port(str(rule.get("port") or ""))
        except ValueError:
            continue
        if port == "22" and str(rule.get("action") or "") in {"deny", "delete"}:
            return True
    return False


__all__ = [
    "normalize_batch_rules",
    "result_as_firewall",
    "ssh_port_in_rules",
    "ufw_batch",
]
