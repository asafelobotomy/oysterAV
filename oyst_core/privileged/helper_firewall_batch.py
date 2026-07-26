"""Batch UFW rule apply under one oyst-helper firewall invocation."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Sequence
from typing import Any

from oyst_core.privileged.helper_firewall import _build_ufw_argv
from oyst_core.privileged.helper_validate import resolve_trusted_argv
from oyst_core.privileged.validators import (
    UFW_DELETE_VERBS,
    UFW_RULE_ACTIONS,
    validate_cidr,
    validate_ip,
    validate_port,
    validate_proto,
)

# Keep in sync with recipes_firewall.MAX_BATCH_RULES
MAX_BATCH_RULES = 32
MAX_RULE_JSON = 512


def _secure_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k in ("LANG", "LC_ALL", "TZ")}
    env["PATH"] = "/usr/bin:/usr/sbin:/bin:/sbin"
    env["HOME"] = "/root"
    return env


def _step(
    name: str,
    *,
    ok: bool,
    message: str = "",
    soft_fail: bool = False,
) -> dict[str, Any]:
    out: dict[str, Any] = {"step": name, "ok": ok}
    if message:
        out["message"] = message
    if soft_fail and not ok:
        out["soft_fail"] = True
    return out


def _run_cmd(cmd: list[str]) -> tuple[int, str]:
    resolved = resolve_trusted_argv(cmd)
    proc = subprocess.run(
        resolved,
        check=False,
        capture_output=True,
        text=True,
        env=_secure_env(),
    )
    detail = (proc.stderr or proc.stdout or "").strip()
    return proc.returncode, detail


def _normalize_rule(raw: object, index: int) -> dict[str, str]:
    if not isinstance(raw, dict):
        raise ValueError(f"rule {index}: expected object")
    action = str(raw.get("action") or "").strip().lower()
    if action not in UFW_RULE_ACTIONS:
        raise ValueError(f"rule {index}: action must be allow|deny|limit|delete")
    port = validate_port(str(raw.get("port") or "").strip())
    proto = validate_proto(str(raw.get("proto") or "tcp").strip())
    out: dict[str, str] = {"action": action, "port": port, "proto": proto}
    from_addr = raw.get("from_addr")
    if from_addr is not None and str(from_addr).strip():
        src = str(from_addr).strip()
        out["from_addr"] = validate_cidr(src) if "/" in src else validate_ip(src)
    if action == "delete":
        verb = str(raw.get("rule_action") or "allow").strip().lower()
        if verb not in UFW_DELETE_VERBS:
            raise ValueError(f"rule {index}: rule_action must be allow|deny|limit|reject")
        out["rule_action"] = verb
    elif raw.get("rule_action") is not None:
        raise ValueError(f"rule {index}: rule_action only valid with delete")
    unknown = set(raw) - {"action", "port", "proto", "from_addr", "rule_action"}
    if unknown:
        raise ValueError(f"rule {index}: unknown fields: {', '.join(sorted(unknown))}")
    return out


def _rule_to_ufw_argv(rule: dict[str, str]) -> list[str]:
    argv = ["ufw", rule["action"], "--port", rule["port"], "--proto", rule["proto"]]
    if "from_addr" in rule:
        argv.extend(["--from", rule["from_addr"]])
    if rule["action"] == "delete":
        argv.extend(["--rule-action", rule.get("rule_action", "allow")])
    return _build_ufw_argv(argv[1:])


def _label(rule: dict[str, str]) -> str:
    port_proto = f"{rule['port']}/{rule['proto']}"
    if rule["action"] == "delete":
        return f"delete {rule.get('rule_action', 'allow')} {port_proto}"
    base = f"{rule['action']} {port_proto}"
    if "from_addr" in rule:
        return f"{base} from {rule['from_addr']}"
    return base


def parse_ufw_batch_rules(argv: Sequence[str]) -> list[dict[str, str]]:
    """Parse and validate ``--rule=<json>`` flags (all-or-nothing before exec)."""
    raw_items = [item[len("--rule=") :] for item in argv if item.startswith("--rule=")]
    other = [item for item in argv if not item.startswith("--rule=")]
    if other:
        raise ValueError(f"unexpected ufw batch args: {' '.join(other)}")
    if not raw_items:
        raise ValueError("ufw batch requires at least one --rule=…")
    if len(raw_items) > MAX_BATCH_RULES:
        raise ValueError(f"ufw batch limited to {MAX_BATCH_RULES} rules")
    rules: list[dict[str, str]] = []
    for i, raw in enumerate(raw_items, start=1):
        if len(raw) > MAX_RULE_JSON:
            raise ValueError(f"rule {i}: JSON too large")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"rule {i}: invalid JSON") from exc
        rule = _normalize_rule(payload, i)
        _rule_to_ufw_argv(rule)  # pre-build to catch argv errors early
        rules.append(rule)
    return rules


def run_ufw_batch(argv: Sequence[str]) -> int:
    """Apply validated UFW rules sequentially; print JSON ``{\"steps\":[…]}``."""
    try:
        rules = parse_ufw_batch_rules(argv)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    steps: list[dict[str, Any]] = []
    failed = False
    for i, rule in enumerate(rules, start=1):
        step_id = f"ufw-rule-{i}"
        label = _label(rule)
        if failed:
            steps.append(
                _step(
                    step_id,
                    ok=False,
                    message=f"skipped after failure ({label})",
                    soft_fail=True,
                ),
            )
            continue
        try:
            cmd = resolve_trusted_argv(_rule_to_ufw_argv(rule))
            rc, detail = _run_cmd(cmd)
            ok = rc == 0
            if not ok:
                failed = True
            steps.append(
                _step(
                    step_id,
                    ok=ok,
                    message=detail or (label if ok else f"{label} failed"),
                    soft_fail=not ok,
                ),
            )
        except (OSError, ValueError) as exc:
            failed = True
            steps.append(_step(step_id, ok=False, message=str(exc), soft_fail=True))
    print(json.dumps({"steps": steps}, separators=(",", ":")))
    return 1 if failed else 0


__all__ = ["MAX_BATCH_RULES", "parse_ufw_batch_rules", "run_ufw_batch"]
