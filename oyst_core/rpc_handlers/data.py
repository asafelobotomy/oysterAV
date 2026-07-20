"""RPC handlers: quarantine, history, audit, desktop, maintenance."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from oyst_core.quarantine import QuarantineVault
from oyst_core.rpc_errors import RpcNotFoundError

if TYPE_CHECKING:
    from oyst_core.rpc_handlers import RpcContext


def handle_quarantine_list(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    return [e.model_dump(mode="json") for e in QuarantineVault().list_entries()]


def handle_quarantine_restore(params: dict[str, Any], _ctx: RpcContext) -> Any:
    return str(QuarantineVault().restore(int(params["id"])))


def handle_quarantine_delete(params: dict[str, Any], _ctx: RpcContext) -> Any:
    QuarantineVault().delete(int(params["id"]))
    return True


def handle_quarantine_verify(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    bad = QuarantineVault().verify()
    return {"invalid_entries": bad, "ok": len(bad) == 0}


def handle_quarantine_add(params: dict[str, Any], ctx: RpcContext) -> Any:
    from oyst_core.history_actions import quarantine_and_patch

    entry = quarantine_and_patch(
        str(params["path"]),
        str(params.get("threat_name") or params.get("threat") or ""),
        job_id=str(params["job_id"]) if params.get("job_id") else None,
        pack=str(params.get("pack") or ""),
        message=str(params.get("message") or ""),
    )
    ctx.audit.log("quarantine.add", str(params["path"]), success=True)
    return entry


def handle_desktop_status(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.desktop_util import autostart_status

    return autostart_status()


def handle_maintenance_bootstrap(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.maintenance import run_bootstrap

    return run_bootstrap(skip_lynis=bool(params.get("skip_lynis")))


def handle_maintenance_post_update(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.maintenance import run_post_update

    return run_post_update()


def handle_history_list(params: dict[str, Any], ctx: RpcContext) -> Any:
    return ctx.event_log.history(limit=int(params.get("limit", 20)))


def handle_history_get(params: dict[str, Any], ctx: RpcContext) -> Any:
    job_id = str(params.get("job_id") or "")
    if not job_id:
        raise RpcNotFoundError("scan not found: (missing job_id)")
    scan = ctx.event_log.get_scan(job_id)
    if scan is None:
        raise RpcNotFoundError(f"scan not found: {job_id}")
    return scan


def handle_history_handle_open(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.history_actions import handle_open_findings

    return handle_open_findings(
        str(params.get("job_id") or ""),
        quarantine=bool(params.get("quarantine", False)),
        resolve=bool(params.get("resolve", False)),
        force=bool(params.get("force", False)),
    )


def handle_history_delete(params: dict[str, Any], ctx: RpcContext) -> Any:
    return ctx.event_log.delete_scan(str(params.get("job_id") or ""))


def handle_history_delete_all(_params: dict[str, Any], ctx: RpcContext) -> Any:
    return ctx.event_log.delete_all_scans()


def handle_history_export(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.history_export import export_scan_to_path

    return export_scan_to_path(
        str(params.get("job_id") or ""),
        str(params.get("path") or ""),
        fmt=str(params.get("format") or "json"),
    )


def handle_history_export_all(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.history_export import export_all_scans_to_path

    return export_all_scans_to_path(
        str(params.get("path") or ""),
        fmt=str(params.get("format") or "json"),
        limit=int(params.get("limit", 500)),
    )


def handle_audit_list(params: dict[str, Any], ctx: RpcContext) -> Any:
    return ctx.audit.list_entries(limit=int(params.get("limit", 50)))
