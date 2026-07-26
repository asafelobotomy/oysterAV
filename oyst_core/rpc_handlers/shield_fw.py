"""RPC handlers for Shield tab: firewall rules + fail2ban control."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from oyst_core.rpc_errors import RpcValidationError

if TYPE_CHECKING:
    from oyst_core.packs.firewall_ops import FirewallResult
    from oyst_core.rpc_handlers import RpcContext


def _fw_dict(result: FirewallResult) -> dict[str, Any]:
    return {
        "ok": result.ok,
        "message": result.message,
        "argv": result.argv,
        "skipped": result.skipped,
    }


def handle_firewall_ensure_enable(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.packs.firewall_ops import FirewallOps

    return _fw_dict(
        FirewallOps().ensure_firewall_enabled(
            force_lockout=bool(params.get("force_lockout_risk", False)),
            dry_run=bool(params.get("dry_run", False)),
        ),
    )


def handle_firewall_set_enabled(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.packs.firewall_ops import FirewallOps

    if "enabled" not in params:
        raise RpcValidationError("enabled required")
    return _fw_dict(
        FirewallOps().set_managed_enabled(
            bool(params.get("enabled")),
            force_lockout=bool(params.get("force_lockout_risk", False)),
            dry_run=bool(params.get("dry_run", False)),
        ),
    )


def handle_firewall_select(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.packs.firewall_select import select_managed_backend

    backend = str(params.get("backend") or "").strip()
    if backend not in {"ufw", "firewalld", "none"}:
        raise RpcValidationError("backend must be ufw|firewalld|none")
    return _fw_dict(
        select_managed_backend(
            backend,
            force_lockout=bool(params.get("force_lockout_risk", False)),
            dry_run=bool(params.get("dry_run", False)),
        ),
    )


def handle_firewall_recommend(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.packs.firewall import FirewallPack
    from oyst_core.packs.firewall_select import recommended_managed_backend

    det = FirewallPack().detect()
    return {
        "recommended": recommended_managed_backend(),
        "detect": det,
    }


def handle_firewall_rules(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.packs.firewall import FirewallPack
    from oyst_core.packs.firewall_ops import FirewallOps
    from oyst_core.packs.firewall_ufw_read import (
        parse_ufw_status_entries,
        ufw_rule_entries_from_files,
    )

    text = FirewallOps().verbose_status()
    entries: list[dict[str, object]] = []
    if str(FirewallPack().detect().get("active", "none")) == "ufw":
        entries = parse_ufw_status_entries(text) or ufw_rule_entries_from_files()
    return {
        "rules": text,
        "entries": entries,
        "verbose": bool(params.get("verbose", True)),
    }


def handle_firewall_export(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.packs.firewall_ops import FirewallOps

    return FirewallOps().export_rules()


def handle_firewall_ufw_rule(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.packs.firewall_ops import FirewallOps

    action = str(params.get("action") or "").strip()
    if action not in {"allow", "deny", "limit", "delete"}:
        raise RpcValidationError("action must be allow|deny|limit|delete")
    port = params.get("port")
    rule_action = params.get("rule_action")
    return _fw_dict(
        FirewallOps().ufw_rule(
            action,
            port=str(port) if port is not None else None,
            proto=str(params.get("proto") or "tcp"),
            from_addr=(str(params["from_addr"]) if params.get("from_addr") else None),
            rule_action=(str(rule_action) if rule_action is not None else None),
            dry_run=bool(params.get("dry_run", False)),
            force_lockout=bool(params.get("force_lockout_risk", False)),
        ),
    )


def handle_firewall_ufw_batch(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.packs.firewall_batch import ufw_batch

    rules_raw = params.get("rules")
    if not isinstance(rules_raw, list) or not rules_raw:
        raise RpcValidationError("rules must be a non-empty list")
    rules = [r for r in rules_raw if isinstance(r, dict)]
    if len(rules) != len(rules_raw):
        raise RpcValidationError("each rule must be an object")
    return ufw_batch(
        rules,
        force_lockout=bool(params.get("force_lockout_risk", False)),
        dry_run=bool(params.get("dry_run", False)),
    )


def handle_firewall_ufw_default(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.packs.firewall_ops import FirewallOps

    direction = str(params.get("direction") or "").strip()
    policy = str(params.get("policy") or "").strip()
    if direction not in {"incoming", "outgoing", "routed"}:
        raise RpcValidationError("direction must be incoming|outgoing|routed")
    if policy not in {"allow", "deny", "reject"}:
        raise RpcValidationError("policy must be allow|deny|reject")
    return _fw_dict(
        FirewallOps().ufw_default(
            direction,
            policy,
            dry_run=bool(params.get("dry_run", False)),
            force_lockout=bool(params.get("force_lockout_risk", False)),
        ),
    )


def handle_firewall_firewalld_port(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.packs.firewall_ops import FirewallOps

    action = str(params.get("action") or "").strip()
    if action not in {"add-port", "remove-port"}:
        raise RpcValidationError("action must be add-port|remove-port")
    return _fw_dict(
        FirewallOps().firewalld_port(
            action,
            str(params.get("port_spec") or ""),
            zone=str(params.get("zone") or "public"),
            dry_run=bool(params.get("dry_run", False)),
            force_lockout=bool(params.get("force_lockout_risk", False)),
        ),
    )


def handle_firewall_firewalld_service(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.packs.firewall_ops import FirewallOps

    action = str(params.get("action") or "").strip()
    if action not in {"add-service", "remove-service"}:
        raise RpcValidationError("action must be add-service|remove-service")
    return _fw_dict(
        FirewallOps().firewalld_service(
            action,
            str(params.get("service") or ""),
            zone=str(params.get("zone") or "public"),
            dry_run=bool(params.get("dry_run", False)),
            force_lockout=bool(params.get("force_lockout_risk", False)),
        ),
    )


def handle_firewall_firewalld_reload(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.packs.firewall_ops import FirewallOps

    return _fw_dict(
        FirewallOps().firewalld_reload(dry_run=bool(params.get("dry_run", False))),
    )


def handle_firewall_firewalld_rich_rule(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.packs.firewall_ops import FirewallOps

    action = str(params.get("action") or "").strip()
    if action not in {"add", "remove"}:
        raise RpcValidationError("action must be add|remove")
    rule = str(params.get("rule") or "").strip()
    if not rule:
        raise RpcValidationError("rule required")
    fw_action = "add-rich-rule" if action == "add" else "remove-rich-rule"
    return _fw_dict(
        FirewallOps().firewalld_rich_rule(
            fw_action,
            rule,
            zone=str(params.get("zone") or "public"),
            dry_run=bool(params.get("dry_run", False)),
            force_lockout=bool(params.get("force_lockout_risk", False)),
        ),
    )


def handle_fail2ban_status(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.packs.fail2ban import Fail2banPack

    return Fail2banPack().service_status()


def handle_fail2ban_banned(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.packs.fail2ban import Fail2banPack

    return Fail2banPack().banned()


def handle_fail2ban_jail(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.packs.fail2ban import Fail2banPack

    name = str(params.get("name") or "").strip()
    if not name:
        raise RpcValidationError("name required")
    return Fail2banPack().jail_status(name)


def handle_fail2ban_jail_enable(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.packs.fail2ban import Fail2banPack

    name = str(params.get("name") or "").strip()
    if not name:
        raise RpcValidationError("name required")
    ok, msg = Fail2banPack().set_jail_enabled(name, enabled=True)
    return {"ok": ok, "message": msg, "name": name}


def handle_fail2ban_jail_disable(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.packs.fail2ban import Fail2banPack

    name = str(params.get("name") or "").strip()
    if not name:
        raise RpcValidationError("name required")
    ok, msg = Fail2banPack().set_jail_enabled(name, enabled=False)
    return {"ok": ok, "message": msg, "name": name}


def handle_fail2ban_reload(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.packs.fail2ban import Fail2banPack

    ok, msg = Fail2banPack().reload(unban=bool(params.get("unban", False)))
    return {"ok": ok, "message": msg, "unban": bool(params.get("unban", False))}
