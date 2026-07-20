"""RPC handlers: status, packs, setup."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from oyst_core.config import setup_status

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

    install_result = install_pack(
        str(params["name"]),
        confirm_aur=bool(params.get("confirm_aur", False)),
    )
    invalidate_doctor_cache()
    ctx.audit.log(
        "pack.install",
        str(params["name"]),
        success=install_result.ok,
        data={"mode": install_result.mode, "strategy": install_result.strategy},
    )
    return install_result.model_dump()


def handle_setup_status(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    return setup_status()


def handle_setup_run(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.doctor_cache import invalidate_doctor_cache
    from oyst_core.setup_workflow import run_setup

    result = run_setup(
        skip_packs=bool(params.get("skip_packs", False)),
        skip_schedule=bool(params.get("skip_schedule", False)),
        skip_bootstrap=bool(params.get("skip_bootstrap", False)),
        confirm_aur=bool(params.get("confirm_aur", False)),
        auto_quarantine=params.get("auto_quarantine"),
        schedule_profile=str(params.get("schedule_profile", "quick")),
        full_bootstrap=bool(params.get("full_bootstrap", True)),
        enable_linger=bool(params.get("enable_linger", False)),
        mark_complete=bool(params.get("mark_complete", True)),
    )
    invalidate_doctor_cache()
    return result
