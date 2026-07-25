"""Shared RPC method handlers for serve and client local fallback."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from oyst_core.audit import SecurityAudit
from oyst_core.events import EventLog
from oyst_core.orchestrator import JobOrchestrator
from oyst_core.rpc_errors import RpcNotFoundError
from oyst_core.rpc_handlers import config_schedule, data, jobs, status_pack, system
from oyst_core.rpc_handlers import shield_fw as shield_fw

Handler = Callable[[dict[str, Any], "RpcContext"], Any]


class RpcContext:
    def __init__(
        self,
        *,
        orchestrator: JobOrchestrator | None = None,
        event_log: EventLog | None = None,
        audit: SecurityAudit | None = None,
    ) -> None:
        self.orchestrator = orchestrator or JobOrchestrator()
        self.event_log = event_log or EventLog()
        self.audit = audit or SecurityAudit()


HANDLERS: dict[str, Handler] = {
    "status": status_pack.handle_status,
    "status.assess": status_pack.handle_status_assess,
    "pack.doctor": status_pack.handle_pack_doctor,
    "pack.install": status_pack.handle_pack_install,
    "setup.status": status_pack.handle_setup_status,
    "setup.run": status_pack.handle_setup_run,
    "job.start": jobs.handle_job_start,
    "job.cancel": jobs.handle_job_cancel,
    "job.clear": jobs.handle_job_clear,
    "job.status": jobs.handle_job_status,
    "rkhunter.scan": jobs.handle_rkhunter_scan,
    "rkhunter.update": jobs.handle_rkhunter_update,
    "rkhunter.propupd": jobs.handle_rkhunter_propupd,
    "rkhunter.resolve": jobs.handle_rkhunter_resolve,
    "quarantine.list": data.handle_quarantine_list,
    "quarantine.restore": data.handle_quarantine_restore,
    "quarantine.delete": data.handle_quarantine_delete,
    "quarantine.verify": data.handle_quarantine_verify,
    "quarantine.add": data.handle_quarantine_add,
    "desktop.status": data.handle_desktop_status,
    "maintenance.bootstrap": data.handle_maintenance_bootstrap,
    "maintenance.post-update": data.handle_maintenance_post_update,
    "history.list": data.handle_history_list,
    "history.get": data.handle_history_get,
    "history.handle_open": data.handle_history_handle_open,
    "history.delete": data.handle_history_delete,
    "history.delete_all": data.handle_history_delete_all,
    "history.export": data.handle_history_export,
    "history.export_all": data.handle_history_export_all,
    "audit.list": data.handle_audit_list,
    "terminal.list": data.handle_terminal_list,
    "terminal.clear": data.handle_terminal_clear,
    "terminal.export": data.handle_terminal_export,
    "config.get": config_schedule.handle_config_get,
    "config.set": config_schedule.handle_config_set,
    "schedule.install": config_schedule.handle_schedule_install,
    "schedule.apply": config_schedule.handle_schedule_apply,
    "schedule.status": config_schedule.handle_schedule_status,
    "schedule.run": config_schedule.handle_schedule_run,
    "schedule.linger": config_schedule.handle_schedule_linger,
    "schedule.enable_linger": config_schedule.handle_schedule_enable_linger,
    "runtime.status": system.handle_runtime_status,
    "runtime.install": system.handle_runtime_install,
    "runtime.remove": system.handle_runtime_remove,
    "runtime.update": system.handle_runtime_update,
    "runtime.bootstrap": system.handle_runtime_bootstrap,
    "firewall.status": system.handle_firewall_status,
    "firewall.ensure_enable": shield_fw.handle_firewall_ensure_enable,
    "firewall.set_enabled": shield_fw.handle_firewall_set_enabled,
    "firewall.select": shield_fw.handle_firewall_select,
    "firewall.recommend": shield_fw.handle_firewall_recommend,
    "firewall.rules": shield_fw.handle_firewall_rules,
    "firewall.export": shield_fw.handle_firewall_export,
    "firewall.ufw_rule": shield_fw.handle_firewall_ufw_rule,
    "firewall.ufw_default": shield_fw.handle_firewall_ufw_default,
    "firewall.firewalld_port": shield_fw.handle_firewall_firewalld_port,
    "firewall.firewalld_service": shield_fw.handle_firewall_firewalld_service,
    "firewall.firewalld_reload": shield_fw.handle_firewall_firewalld_reload,
    "firewall.firewalld_rich_rule": shield_fw.handle_firewall_firewalld_rich_rule,
    "fail2ban.unban": system.handle_fail2ban_unban,
    "fail2ban.status": shield_fw.handle_fail2ban_status,
    "fail2ban.banned": shield_fw.handle_fail2ban_banned,
    "fail2ban.jail": shield_fw.handle_fail2ban_jail,
    "fail2ban.jail_enable": shield_fw.handle_fail2ban_jail_enable,
    "fail2ban.jail_disable": shield_fw.handle_fail2ban_jail_disable,
    "fail2ban.reload": shield_fw.handle_fail2ban_reload,
    "clamav.clamd.ensure": system.handle_clamav_clamd_ensure,
    "services.status": system.handle_services_status,
    "services.set": system.handle_services_set,
    "auth.status": system.handle_auth_status,
    "helper.install": system.handle_helper_install,
    "auth.grant_service_lifecycle": system.handle_auth_grant_service_lifecycle,
    "auth.revoke_service_lifecycle": system.handle_auth_revoke_service_lifecycle,
    "clamonacc.status": system.handle_clamonacc_status,
    "clamonacc.start": system.handle_clamonacc_start,
    "clamonacc.stop": system.handle_clamonacc_stop,
    "clamonacc.enable": system.handle_clamonacc_enable,
    "clamonacc.disable": system.handle_clamonacc_disable,
    "clamonacc.add_path": system.handle_clamonacc_add_path,
    "clamonacc.remove_path": system.handle_clamonacc_remove_path,
    "clamonacc.ensure_fdpass": system.handle_clamonacc_ensure_fdpass,
    "clamonacc.ensure_prevention": system.handle_clamonacc_ensure_prevention,
    "virusevent.status": system.handle_virusevent_status,
    "virusevent.ensure": system.handle_virusevent_ensure,
    "clamav.ensure_disable_cache": system.handle_clamav_ensure_disable_cache,
    "news.list": system.handle_news_list,
    "news.refresh": system.handle_news_refresh,
    "updates.check": system.handle_updates_check,
    "updates.apply": system.handle_updates_apply,
}

RPC_METHODS: frozenset[str] = frozenset(HANDLERS)


def dispatch_rpc(
    method: str,
    params: dict[str, Any],
    *,
    orchestrator: JobOrchestrator | None = None,
    event_log: EventLog | None = None,
    audit: SecurityAudit | None = None,
) -> Any:
    from oyst_core.terminal_log import log_rpc_call

    handler = HANDLERS.get(method)
    if handler is None:
        raise RpcNotFoundError(f"unknown method: {method}")
    ctx = RpcContext(orchestrator=orchestrator, event_log=event_log, audit=audit)
    try:
        result = handler(params, ctx)
    except Exception as exc:
        log_rpc_call(method, params, ok=False, result={"message": str(exc)})
        raise
    log_rpc_call(method, params, ok=True, result=result)
    return result
