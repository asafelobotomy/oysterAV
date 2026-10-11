"""RPC handlers: quarantine, history, audit, desktop, maintenance."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from oyst_core.quarantine import QuarantineVault
from oyst_core.rpc_errors import RpcNotFoundError
from oyst_core.rpc_handlers.params import opt_bool, opt_int, opt_limit, opt_str, req_int, req_str

if TYPE_CHECKING:
    from oyst_core.rpc_handlers import RpcContext


def handle_quarantine_list(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    return [e.model_dump(mode="json") for e in QuarantineVault().list_entries()]


def _require_entry(vault: QuarantineVault, entry_id: int) -> Any:
    entry = vault.get(entry_id)
    if not entry:
        raise RpcNotFoundError(f"quarantine entry not found: {entry_id}")
    return entry


def handle_quarantine_restore(params: dict[str, Any], _ctx: RpcContext) -> Any:
    entry_id = req_int(params, "id")
    vault = QuarantineVault()
    entry = _require_entry(vault, entry_id)
    if opt_bool(params, "dry_run"):
        return {"ok": True, "dry_run": True, "id": entry_id, "path": entry.original_path}
    return str(vault.restore(entry_id))


def handle_quarantine_delete(params: dict[str, Any], _ctx: RpcContext) -> Any:
    entry_id = req_int(params, "id")
    vault = QuarantineVault()
    _require_entry(vault, entry_id)
    if opt_bool(params, "dry_run"):
        return {"ok": True, "dry_run": True, "id": entry_id}
    vault.delete(entry_id)
    return True


def handle_quarantine_verify(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    vault = QuarantineVault()
    bad = vault.verify()
    orphans = vault.list_orphans()
    return {
        "invalid_entries": bad,
        "orphans": orphans,
        "orphan_count": len(orphans),
        "ok": len(bad) == 0 and len(orphans) == 0,
    }


def handle_quarantine_add(params: dict[str, Any], ctx: RpcContext) -> Any:
    from oyst_core.history_actions import quarantine_and_patch

    path = req_str(params, "path")
    if opt_bool(params, "dry_run"):
        from oyst_core.quarantine_guards import quarantine_refuse_reason

        refuse = quarantine_refuse_reason(path)
        return {
            "ok": refuse is None,
            "dry_run": True,
            "path": path,
            "refuse": refuse,
        }
    entry = quarantine_and_patch(
        path,
        opt_str(params, "threat_name") or opt_str(params, "threat") or "",
        job_id=opt_str(params, "job_id"),
        pack=opt_str(params, "pack") or "",
        message=opt_str(params, "message") or "",
    )
    ctx.audit.log("quarantine.add", path, success=True)
    return entry


def handle_desktop_status(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.desktop_util import autostart_status

    return autostart_status()


def handle_maintenance_bootstrap(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.maintenance import run_bootstrap

    return run_bootstrap(skip_lynis=opt_bool(params, "skip_lynis"))


def handle_maintenance_post_update(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.maintenance import run_post_update

    return run_post_update()


def handle_history_list(params: dict[str, Any], ctx: RpcContext) -> Any:
    return ctx.event_log.history(limit=opt_limit(params, 20))


def handle_history_get(params: dict[str, Any], ctx: RpcContext) -> Any:
    job_id = opt_str(params, "job_id") or ""
    if not job_id:
        raise RpcNotFoundError("scan not found: (missing job_id)")
    scan = ctx.event_log.get_scan(job_id)
    if scan is None:
        raise RpcNotFoundError(f"scan not found: {job_id}")
    return scan


def handle_history_handle_open(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.history_actions import handle_open_findings

    return handle_open_findings(
        opt_str(params, "job_id") or "",
        quarantine=opt_bool(params, "quarantine"),
        resolve=opt_bool(params, "resolve"),
        force=opt_bool(params, "force"),
    )


def handle_history_delete(params: dict[str, Any], ctx: RpcContext) -> Any:
    return ctx.event_log.delete_scan(opt_str(params, "job_id") or "")


def handle_history_delete_all(_params: dict[str, Any], ctx: RpcContext) -> Any:
    return ctx.event_log.delete_all_scans()


def handle_history_export(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.history_export import export_scan_to_path

    return export_scan_to_path(
        opt_str(params, "job_id") or "",
        opt_str(params, "path") or "",
        fmt=opt_str(params, "format") or "json",
    )


def handle_history_export_all(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.history_export import export_all_scans_to_path

    return export_all_scans_to_path(
        opt_str(params, "path") or "",
        fmt=opt_str(params, "format") or "json",
        limit=opt_limit(params, 500),
    )


def handle_audit_list(params: dict[str, Any], ctx: RpcContext) -> Any:
    return ctx.audit.list_entries(limit=opt_limit(params, 50))


def handle_terminal_list(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core import terminal_log

    layers_raw = params.get("layers")
    layers: list[str] | None
    if layers_raw is None:
        layers = ["structured"]
    elif isinstance(layers_raw, list):
        layers = [str(x) for x in layers_raw]
    else:
        layers = ["structured"]
    include_all = opt_bool(params, "all_layers")
    return terminal_log.list_entries(
        limit=opt_limit(params, 500),
        since_id=max(0, opt_int(params, "since_id", 0)),
        layers=None if include_all else layers,
    )


def handle_terminal_clear(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core import terminal_log
    from oyst_core.rpc_errors import RpcValidationError

    if not opt_bool(params, "confirm"):
        raise RpcValidationError("terminal.clear requires confirm=true")
    return terminal_log.clear()


def handle_terminal_export(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core import terminal_log

    return terminal_log.export(
        opt_str(params, "path") or "",
        fmt=opt_str(params, "format") or "txt",
    )
