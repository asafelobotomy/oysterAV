"""RPC handlers: jobs and rkhunter."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from oyst_core.config import load_config
from oyst_core.models import ScanProfile
from oyst_core.pack_jobs import (
    run_rkhunter_propupd,
    run_rkhunter_resolve,
    run_rkhunter_scan,
    run_rkhunter_update,
)

if TYPE_CHECKING:
    from oyst_core.rpc_handlers import RpcContext


def handle_job_start(params: dict[str, Any], ctx: RpcContext) -> Any:
    scan_profile = ScanProfile(params.get("profile", "quick"))
    cfg = load_config()
    backend = str(params.get("backend", cfg.scan.backend))
    scan_result, code = ctx.orchestrator.run_scan(
        profile=scan_profile,
        paths=params.get("paths"),
        packs=params.get("packs"),
        quarantine=bool(params.get("quarantine")),
        backend=backend,
    )
    return {"scan": scan_result.model_dump(mode="json"), "exit_code": int(code)}


def handle_job_cancel(params: dict[str, Any], ctx: RpcContext) -> Any:
    return ctx.orchestrator.cancel_job(
        params.get("job_id"),
        force=bool(params.get("force", False)),
    )


def handle_job_clear(_params: dict[str, Any], ctx: RpcContext) -> Any:
    return ctx.orchestrator.clear_job()


def handle_job_status(_params: dict[str, Any], ctx: RpcContext) -> Any:
    return ctx.orchestrator.job_status()


def handle_rkhunter_scan(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    return run_rkhunter_scan()


def handle_rkhunter_update(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    return run_rkhunter_update()


def handle_rkhunter_propupd(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    return run_rkhunter_propupd()


def handle_rkhunter_resolve(params: dict[str, Any], _ctx: RpcContext) -> Any:
    return run_rkhunter_resolve(
        str(params.get("threat_name") or ""),
        path=str(params.get("path") or ""),
        message=str(params.get("message") or ""),
        force=bool(params.get("force", False)),
        dry_run=bool(params.get("dry_run", False)),
        job_id=str(params["job_id"]) if params.get("job_id") else None,
    )
