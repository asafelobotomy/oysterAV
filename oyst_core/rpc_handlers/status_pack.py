"""RPC handlers: status, packs, setup."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from oyst_core import rpc_progress
from oyst_core.config import setup_status
from oyst_core.rpc_handlers.params import opt_bool, opt_str, req_str

if TYPE_CHECKING:
    from oyst_core.rpc_handlers import RpcContext


def handle_status(_params: dict[str, Any], ctx: RpcContext) -> Any:
    return ctx.orchestrator.aggregate_status()


def handle_status_assess(_params: dict[str, Any], ctx: RpcContext) -> Any:
    from oyst_core.health import assess_health

    return assess_health(ctx.orchestrator.aggregate_status())


def handle_pack_doctor(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.doctor_cache import doctor_all

    return doctor_all()


def handle_pack_install(params: dict[str, Any], ctx: RpcContext) -> Any:
    from oyst_core.doctor_cache import invalidate_doctor_cache
    from oyst_core.pack_install import install_pack

    name = req_str(params, "name")
    try:
        install_result = install_pack(
            name,
            confirm_aur=opt_bool(params, "confirm_aur"),
            on_progress=rpc_progress.callback_for(params),
        )
    finally:
        rpc_progress.finish(params)
    invalidate_doctor_cache()
    ctx.audit.log(
        "pack.install",
        name,
        success=install_result.ok,
        data={"mode": install_result.mode, "strategy": install_result.strategy},
    )
    return install_result.model_dump()


def handle_setup_status(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    return setup_status()


def handle_setup_run(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.doctor_cache import invalidate_doctor_cache
    from oyst_core.setup_workflow import run_setup

    raw_packs = params.get("packs")
    packs: list[str] | None = None
    if isinstance(raw_packs, list):
        packs = [str(p) for p in raw_packs if str(p).strip()]

    raw_include = params.get("harden_include")
    harden_include: list[str] | None = None
    if isinstance(raw_include, list):
        harden_include = [str(s) for s in raw_include if str(s).strip()]

    raw_fw = params.get("firewall_backend")
    firewall_backend: str | None = None
    if isinstance(raw_fw, str) and raw_fw.strip():
        firewall_backend = raw_fw.strip().lower()

    result = run_setup(
        skip_packs=opt_bool(params, "skip_packs"),
        skip_schedule=opt_bool(params, "skip_schedule"),
        skip_bootstrap=opt_bool(params, "skip_bootstrap"),
        skip_harden=opt_bool(params, "skip_harden"),
        confirm_aur=opt_bool(params, "confirm_aur"),
        auto_quarantine=params.get("auto_quarantine"),
        schedule_profile=opt_str(params, "schedule_profile") or "quick",
        full_bootstrap=opt_bool(params, "full_bootstrap", True),
        enable_linger=opt_bool(params, "enable_linger"),
        enable_firewall=opt_bool(params, "enable_firewall", True),
        mark_complete=opt_bool(params, "mark_complete", True),
        packs=packs,
        harden_include=harden_include,
        firewall_backend=firewall_backend,
    )
    invalidate_doctor_cache()
    return result


def handle_setup_reset(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.setup_workflow import reset_setup

    return reset_setup()
