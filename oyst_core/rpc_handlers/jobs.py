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
from oyst_core.rpc_errors import RpcValidationError
from oyst_core.rpc_handlers.params import opt_bool, opt_str

if TYPE_CHECKING:
    from oyst_core.rpc_handlers import RpcContext


def _opt_str_list(params: dict[str, Any], name: str) -> list[str] | None:
    raw = params.get(name)
    if raw is None:
        return None
    if not isinstance(raw, list) or not all(isinstance(x, str) for x in raw):
        raise RpcValidationError(f"{name} must be a list of strings")
    return list(raw)


def handle_job_start(params: dict[str, Any], ctx: RpcContext) -> Any:
    profile = opt_str(params, "profile") or "quick"
    try:
        scan_profile = ScanProfile(profile)
    except ValueError as exc:
        raise RpcValidationError(f"invalid scan profile: {profile}") from exc
    cfg = load_config()
    backend = opt_str(params, "backend") or cfg.scan.backend
    scan_result, code = ctx.orchestrator.run_scan(
        profile=scan_profile,
        paths=_opt_str_list(params, "paths"),
        packs=_opt_str_list(params, "packs"),
        quarantine=opt_bool(params, "quarantine"),
        backend=backend,
        job_id=opt_str(params, "job_id"),
    )
    return {"scan": scan_result.model_dump(mode="json"), "exit_code": int(code)}


def handle_job_cancel(params: dict[str, Any], ctx: RpcContext) -> Any:
    return ctx.orchestrator.cancel_job(
        opt_str(params, "job_id"),
        force=opt_bool(params, "force"),
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
        opt_str(params, "threat_name") or "",
        path=opt_str(params, "path") or "",
        message=opt_str(params, "message") or "",
        force=opt_bool(params, "force"),
        dry_run=opt_bool(params, "dry_run"),
        job_id=opt_str(params, "job_id"),
    )
