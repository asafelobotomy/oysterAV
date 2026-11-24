"""The changes uQ Settings' Firewall tab can make, each with a plan for its confirmation sheet.

Every function takes ``dry_run``: then it changes nothing and returns a plan document
(``oyst_core.plan``); otherwise ``{"ok", "message"}``. What needs root goes through oysterAV's
polkit helper (one password prompt per change). Port 22 is guarded only while this computer can be
reached over SSH (``ssh_in_use``): on a desktop with no SSH server nothing can lock anyone out.
"""

from __future__ import annotations

from typing import Any

from oyst_core.packs.firewall_view import firewall_overview
from oyst_core.plan import change, plan_doc, refused
from oyst_core.privileged.validators import (
    port_range_covers,
    validate_cidr,
    validate_ip,
    validate_port_range,
    validate_port_spec,
    validate_proto,
    validate_service_name,
    validate_zone,
)

NAMES = {"ufw": "UFW", "firewalld": "firewalld"}
RULE_ACTIONS = ("allow", "deny", "limit")
VERBS = {"allow": "Allow", "deny": "Block", "limit": "Limit", "reject": "Reject"}
SSH_REASON = (
    "This computer runs an SSH server and this would block SSH (port 22). Add an Allow rule for "
    "port 22 first, or change it from a terminal."
)


def _fail(message: str) -> dict[str, Any]:
    return {"ok": False, "message": message}


def _done(result: Any, message: str) -> dict[str, Any]:
    """A FirewallResult or a batch dict as {ok, message}; oysterAV's own words when it failed."""
    ok = bool(result.get("ok")) if isinstance(result, dict) else bool(result.ok)
    said = str(result.get("message") if isinstance(result, dict) else result.message)
    return {"ok": ok, "message": message if ok else (said or "The change failed.")}


def _source(value: str) -> str | None:
    """ "anywhere" -> None, else a checked address or network."""
    text = value.strip()
    if text.lower() in {"", "any", "anywhere"}:
        return None
    return validate_cidr(text) if "/" in text else validate_ip(text)


def _rule(action: str, port: str, proto: str, source: str) -> dict[str, Any]:
    if action not in RULE_ACTIONS:
        raise ValueError("A rule can allow, block or limit.")
    rule: dict[str, Any] = {
        "action": action,
        "port": validate_port_range(port),
        "proto": validate_proto(proto),
    }
    src = _source(source)
    if src:
        rule["from_addr"] = src
    return rule


def rule_words(rule: dict[str, Any]) -> str:
    """ "Allow 8080/tcp from anywhere"; a range reads 1714-1764/udp."""
    port = str(rule["port"]).replace(":", "-")
    where = rule.get("from_addr") or "anywhere"
    return f"{VERBS[rule['action']]} {port}/{rule['proto']} from {where}"


def _same(row: dict[str, Any], rule: dict[str, Any]) -> bool:
    return (
        row.get("action") == rule["action"]
        and row.get("port") == rule["port"]
        and row.get("proto") == rule["proto"]
        and row.get("direction") == "in"
        and (row.get("source") or "anywhere") == (rule.get("from_addr") or "anywhere")
    )


def _ufw_ready(view: dict[str, Any]) -> str:
    """Why UFW rules can't change now ("" when they can)."""
    if view["conflict"]:
        return "UFW and firewalld are both running. Turn one off first."
    if view["backend"] != "ufw":
        return "These rules are UFW's, and UFW isn't the firewall here."
    if not view["on"]:
        return "Turn the firewall on first."
    return ""


def _blocks_ssh(rule: dict[str, Any]) -> bool:
    return (
        rule["action"] == "deny"
        and port_range_covers(rule["port"], 22)
        and not rule.get("from_addr")
    )


def power(state: str, *, dry_run: bool = False) -> dict[str, Any]:
    """Turn the firewall on (UFW or firewalld, whichever is set up) or off."""
    from oyst_core.packs.firewall_ensure import ensure_firewall_enabled, set_managed_enabled

    view = firewall_overview()
    name = NAMES.get(view["backend"], "the firewall")
    want_on = state == "on"
    if view["conflict"]:
        problem = "UFW and firewalld are both running. Turn one off from a terminal first."
    elif view["backend"] == "none":
        problem = "No firewall program is installed. Install UFW (Bindle's Security group has it)."
    elif view["on"] == want_on:
        problem = f"The firewall is already {state}."
    else:
        problem = ""
    if dry_run:
        if problem:
            return refused(problem)
        changes = [change(f"Turn {name} {state}", group="Firewall", reversible=True)]
        if want_on and view["ssh_in_use"]:
            changes.append(change("Let SSH (port 22) in, so you aren't locked out", group="Rules"))
        if want_on and view["backend"] == "ufw" and view["defaults"]:
            d = view["defaults"]
            changes.append(
                change(
                    f"Incoming connections: {d.get('incoming', '?')}, "
                    f"outgoing: {d.get('outgoing', '?')}",
                    group="Rules",
                    detail="Your default rules and your list of rules apply again.",
                )
            )
        summary = (
            f"Turn the firewall {state}. oysterAV asks for your password once."
            if want_on
            else "Turn the firewall off. Every connection is let in until you turn it on again."
        )
        return plan_doc(summary, changes)
    if problem:
        return _fail(problem)
    force = not view["ssh_in_use"]
    if want_on:
        res = ensure_firewall_enabled(force_lockout=force)
    else:
        res = set_managed_enabled(False, force_lockout=force)
    return _done(res, f"The firewall is {state}.")


def use(backend: str, *, dry_run: bool = False) -> dict[str, Any]:
    """Make UFW or firewalld the firewall (stops the other one)."""
    from oyst_core.packs.firewall_select import select_managed_backend

    view = firewall_overview()
    if backend not in NAMES:
        problem = "Choose UFW or firewalld."
    elif view["on"] and view["active"] == backend and not view["conflict"]:
        problem = f"{NAMES[backend]} is already the firewall."
    else:
        problem = ""
    if dry_run:
        if problem:
            return refused(problem)
        other = "firewalld" if backend == "ufw" else "ufw"
        changes = []
        if not view["installed"].get(backend):
            changes.append(change(f"Install {NAMES[backend]}", group="Programs"))
        if view["installed"].get(other):
            changes.append(change(f"Stop {NAMES[other]}", group="Firewall", reversible=True))
        changes.append(change(f"Start {NAMES[backend]}", group="Firewall", reversible=True))
        if view["ssh_in_use"]:
            changes.append(change("Let SSH (port 22) in, so you aren't locked out", group="Rules"))
        return plan_doc(
            f"Use {NAMES[backend]} as the firewall. "
            f"Your {NAMES[other]} rules stay saved but stop applying.",
            changes,
        )
    if problem:
        return _fail(problem)
    res = select_managed_backend(backend, force_lockout=not view["ssh_in_use"])
    return _done(res, f"{NAMES[backend]} is the firewall now.")


def policy(direction: str, choice: str, *, dry_run: bool = False) -> dict[str, Any]:
    """Set UFW's default for incoming, outgoing or routed connections."""
    from oyst_core.packs.firewall_ops import FirewallOps

    view = firewall_overview()
    now = view["defaults"].get(direction, "")
    problem = _ufw_ready(view)
    if not problem and now == choice:
        problem = f"{direction.title()} connections are already set to {choice}."
    risky = direction == "incoming" and choice in {"deny", "reject"} and view["ssh_in_use"]
    ops = FirewallOps()
    if not problem and risky and not ops._ssh_allowed("ufw"):
        problem = SSH_REASON
    if dry_run:
        if problem:
            return refused(problem)
        return plan_doc(
            f"{direction.title()} connections: {choice}. oysterAV asks for your password once.",
            [
                change(
                    f"{direction.title()} connections: {choice}",
                    group="Default rules",
                    detail=f"Now: {now or 'unknown'}. Your own rules still come first.",
                    reversible=True,
                )
            ],
        )
    if problem:
        return _fail(problem)
    res = ops.ufw_default(direction, choice, force_lockout=not view["ssh_in_use"])
    return _done(res, f"{direction.title()} connections: {choice}.")


def _batch(rules: list[dict[str, Any]], view: dict[str, Any], message: str) -> dict[str, Any]:
    from oyst_core.packs.firewall_batch import ufw_batch

    return _done(ufw_batch(rules, force_lockout=not view["ssh_in_use"]), message)


def rule_add(
    action: str, port: str, proto: str, source: str, *, dry_run: bool = False
) -> dict[str, Any]:
    """Add one UFW rule for incoming connections."""
    view = firewall_overview()
    try:
        rule = _rule(action, port, proto, source)
    except ValueError as exc:
        return refused(str(exc)) if dry_run else _fail(str(exc))
    problem = _ufw_ready(view)
    if not problem and any(_same(r, rule) for r in view["rules"]):
        problem = "That rule is already there."
    if not problem and view["ssh_in_use"] and _blocks_ssh(rule):
        problem = SSH_REASON
    if dry_run:
        if problem:
            return refused(problem)
        return plan_doc(
            f"{rule_words(rule)}. oysterAV asks for your password once.",
            [
                change(
                    rule_words(rule),
                    group="Add a rule",
                    detail="Incoming connections",
                    reversible=True,
                )
            ],
        )
    if problem:
        return _fail(problem)
    return _batch([rule], view, "Rule added.")


def _delete(rule: dict[str, Any]) -> dict[str, Any]:
    out = {
        "action": "delete",
        "rule_action": rule["action"],
        "port": rule["port"],
        "proto": rule["proto"],
    }
    if rule.get("from_addr"):
        out["from_addr"] = rule["from_addr"]
    return out


def _removes_ssh(rule: dict[str, Any]) -> bool:
    return rule["action"] in {"allow", "limit"} and port_range_covers(rule["port"], 22)


def rule_remove(
    action: str, port: str, proto: str, source: str, *, dry_run: bool = False
) -> dict[str, Any]:
    """Remove one UFW rule (both its IPv4 and IPv6 halves)."""
    view = firewall_overview()
    try:
        rule = _rule(action, port, proto, source)
    except ValueError as exc:
        return refused(str(exc)) if dry_run else _fail(str(exc))
    problem = _ufw_ready(view)
    if not problem and not any(_same(r, rule) and r.get("removable") for r in view["rules"]):
        problem = "That rule isn't in the list any more."
    if not problem and view["ssh_in_use"] and _removes_ssh(rule):
        problem = SSH_REASON
    if dry_run:
        if problem:
            return refused(problem)
        return plan_doc(
            f"Remove the rule “{rule_words(rule)}”. oysterAV asks for your password once.",
            [change(rule_words(rule), group="Remove a rule", reversible=True)],
        )
    if problem:
        return _fail(problem)
    return _batch([_delete(rule)], view, "Rule removed.")


def rule_change(old: list[str], new: list[str], *, dry_run: bool = False) -> dict[str, Any]:
    """Replace one UFW rule with another: the new one is added first, then the old one removed."""
    view = firewall_overview()
    try:
        before = _rule(*old)
        after = _rule(*new)
    except (TypeError, ValueError) as exc:
        return refused(str(exc)) if dry_run else _fail(str(exc))
    problem = _ufw_ready(view)
    if not problem and before == after:
        problem = "Nothing changed."
    elif not problem and not any(_same(r, before) and r.get("editable") for r in view["rules"]):
        problem = "That rule isn't in the list any more."
    elif not problem and any(_same(r, after) for r in view["rules"]):
        problem = "The new rule is already there."
    loses_ssh = _removes_ssh(before) and not _removes_ssh(after)
    if not problem and view["ssh_in_use"] and (_blocks_ssh(after) or loses_ssh):
        problem = SSH_REASON
    if dry_run:
        if problem:
            return refused(problem)
        return plan_doc(
            "Change one rule. oysterAV asks for your password once.",
            [
                change(rule_words(after), group="Add", reversible=True),
                change(rule_words(before), group="Remove", reversible=True),
            ],
        )
    if problem:
        return _fail(problem)
    return _batch([after, _delete(before)], view, "Rule changed.")


def zone_open(
    kind: str, op: str, zone: str, value: str, *, dry_run: bool = False
) -> dict[str, Any]:
    """firewalld: open or close a port (``8080/tcp``) or a service (``ssh``) in one zone."""
    from oyst_core.packs.firewall_ops import FirewallOps

    view = firewall_overview()
    try:
        zone_name = validate_zone(zone)
        item = validate_port_spec(value) if kind == "port" else validate_service_name(value)
        if kind == "port" and "/" not in item:
            raise ValueError("Say which protocol: 8080/tcp or 8080/udp.")
    except ValueError as exc:
        return refused(str(exc)) if dry_run else _fail(str(exc))
    zones = {z["name"]: z for z in view["zones"]}
    key = "ports" if kind == "port" else "services"
    if view["conflict"]:
        problem = "UFW and firewalld are both running. Turn one off first."
    elif view["active"] != "firewalld":
        problem = "firewalld isn't running."
    elif zone_name not in zones:
        problem = f"There is no zone called {zone_name}."
    elif op == "add" and item in zones[zone_name][key]:
        problem = f"{item} is already open in {zone_name}."
    elif op == "remove" and item not in zones[zone_name][key]:
        problem = f"{item} isn't open in {zone_name}."
    elif op == "remove" and view["ssh_in_use"] and item in {"ssh", "22/tcp"}:
        problem = SSH_REASON
    else:
        problem = ""
    verb = "Open" if op == "add" else "Close"
    if dry_run:
        if problem:
            return refused(problem)
        return plan_doc(
            f"{verb} {item} in the {zone_name} zone. oysterAV asks for your password once.",
            [
                change(
                    f"{verb} {item}",
                    group=f"Zone {zone_name}",
                    detail="Saved, and applied now",
                    reversible=True,
                )
            ],
        )
    if problem:
        return _fail(problem)
    ops = FirewallOps()
    force = not view["ssh_in_use"]
    if kind == "port":
        res = ops.firewalld_port(f"{op}-port", item, zone=zone_name, force_lockout=force)
    else:
        res = ops.firewalld_service(f"{op}-service", item, zone=zone_name, force_lockout=force)
    return _done(res, f"{item} is {'open' if op == 'add' else 'closed'} in {zone_name}.")


__all__ = [
    "power",
    "policy",
    "rule_add",
    "rule_change",
    "rule_remove",
    "rule_words",
    "use",
    "zone_open",
]
