"""RPC handlers for Shield tab: firewall rules + fail2ban control."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from oyst_core.rpc_errors import RpcValidationError
from oyst_core.rpc_handlers.params import opt_bool, opt_str

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


def _jail_name(params: dict[str, Any]) -> str:
    from oyst_core.privileged.validators import validate_jail

    name = (opt_str(params, "name") or "").strip()
    if not name:
        raise RpcValidationError("name required")
    try:
        return validate_jail(name)
    except ValueError as exc:
        raise RpcValidationError(str(exc)) from exc


def handle_firewall_ensure_enable(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.packs.firewall_ops import FirewallOps

    return _fw_dict(
        FirewallOps().ensure_firewall_enabled(
            force_lockout=opt_bool(params, "force_lockout_risk"),
            dry_run=opt_bool(params, "dry_run"),
        ),
    )


def handle_firewall_set_enabled(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.packs.firewall_ops import FirewallOps

    if params.get("enabled") is None:
        raise RpcValidationError("enabled required")
    return _fw_dict(
        FirewallOps().set_managed_enabled(
            opt_bool(params, "enabled"),
            force_lockout=opt_bool(params, "force_lockout_risk"),
            dry_run=opt_bool(params, "dry_run"),
        ),
    )


def handle_firewall_select(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.packs.firewall_select import select_managed_backend

    backend = (opt_str(params, "backend") or "").strip()
    if backend not in {"ufw", "firewalld", "none"}:
        raise RpcValidationError("backend must be ufw|firewalld|none")
    return _fw_dict(
        select_managed_backend(
            backend,
            force_lockout=opt_bool(params, "force_lockout_risk"),
            dry_run=opt_bool(params, "dry_run"),
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
        "verbose": opt_bool(params, "verbose", True),
    }


def handle_firewall_export(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.packs.firewall_ops import FirewallOps

    return FirewallOps().export_rules()


def handle_firewall_ufw_rule(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.packs.firewall_ops import FirewallOps

    action = (opt_str(params, "action") or "").strip()
    if action not in {"allow", "deny", "limit", "delete"}:
        raise RpcValidationError("action must be allow|deny|limit|delete")
    port = opt_str(params, "port")
    rule_action = opt_str(params, "rule_action")
    return _fw_dict(
        FirewallOps().ufw_rule(
            action,
            port=port,
            proto=opt_str(params, "proto") or "tcp",
            from_addr=opt_str(params, "from_addr"),
            rule_action=rule_action,
            dry_run=opt_bool(params, "dry_run"),
            force_lockout=opt_bool(params, "force_lockout_risk"),
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
        force_lockout=opt_bool(params, "force_lockout_risk"),
        dry_run=opt_bool(params, "dry_run"),
    )


def handle_firewall_ufw_default(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.packs.firewall_ops import FirewallOps

    direction = (opt_str(params, "direction") or "").strip()
    policy = (opt_str(params, "policy") or "").strip()
    if direction not in {"incoming", "outgoing", "routed"}:
        raise RpcValidationError("direction must be incoming|outgoing|routed")
    if policy not in {"allow", "deny", "reject"}:
        raise RpcValidationError("policy must be allow|deny|reject")
    return _fw_dict(
        FirewallOps().ufw_default(
            direction,
            policy,
            dry_run=opt_bool(params, "dry_run"),
            force_lockout=opt_bool(params, "force_lockout_risk"),
        ),
    )


def handle_firewall_firewalld_port(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.packs.firewall_ops import FirewallOps

    action = (opt_str(params, "action") or "").strip()
    if action not in {"add-port", "remove-port"}:
        raise RpcValidationError("action must be add-port|remove-port")
    return _fw_dict(
        FirewallOps().firewalld_port(
            action,
            opt_str(params, "port_spec") or "",
            zone=opt_str(params, "zone") or "public",
            dry_run=opt_bool(params, "dry_run"),
            force_lockout=opt_bool(params, "force_lockout_risk"),
        ),
    )


def handle_firewall_firewalld_service(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.packs.firewall_ops import FirewallOps

    action = (opt_str(params, "action") or "").strip()
    if action not in {"add-service", "remove-service"}:
        raise RpcValidationError("action must be add-service|remove-service")
    return _fw_dict(
        FirewallOps().firewalld_service(
            action,
            opt_str(params, "service") or "",
            zone=opt_str(params, "zone") or "public",
            dry_run=opt_bool(params, "dry_run"),
            force_lockout=opt_bool(params, "force_lockout_risk"),
        ),
    )


def handle_firewall_firewalld_reload(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.packs.firewall_ops import FirewallOps

    return _fw_dict(
        FirewallOps().firewalld_reload(dry_run=opt_bool(params, "dry_run")),
    )


def handle_firewall_firewalld_rich_rule(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.packs.firewall_ops import FirewallOps

    action = (opt_str(params, "action") or "").strip()
    if action not in {"add", "remove"}:
        raise RpcValidationError("action must be add|remove")
    rule = (opt_str(params, "rule") or "").strip()
    if not rule:
        raise RpcValidationError("rule required")
    fw_action = "add-rich-rule" if action == "add" else "remove-rich-rule"
    return _fw_dict(
        FirewallOps().firewalld_rich_rule(
            fw_action,
            rule,
            zone=opt_str(params, "zone") or "public",
            dry_run=opt_bool(params, "dry_run"),
            force_lockout=opt_bool(params, "force_lockout_risk"),
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

    name = _jail_name(params)
    return Fail2banPack().jail_status(name)


def handle_fail2ban_jail_enable(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.packs.fail2ban import Fail2banPack

    name = _jail_name(params)
    ok, msg = Fail2banPack().set_jail_enabled(name, enabled=True)
    return {"ok": ok, "message": msg, "name": name}


def handle_fail2ban_jail_disable(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.packs.fail2ban import Fail2banPack

    name = _jail_name(params)
    ok, msg = Fail2banPack().set_jail_enabled(name, enabled=False)
    return {"ok": ok, "message": msg, "name": name}


def handle_fail2ban_reload(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.packs.fail2ban import Fail2banPack

    ok, msg = Fail2banPack().reload(unban=opt_bool(params, "unban"))
    return {"ok": ok, "message": msg, "unban": opt_bool(params, "unban")}
