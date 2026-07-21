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

    raw_packs = params.get("packs")
    packs: list[str] | None = None
    if isinstance(raw_packs, list):
        packs = [str(p) for p in raw_packs if str(p).strip()]

    raw_include = params.get("harden_include")
    harden_include: list[str] | None = None
    if isinstance(raw_include, list):
        harden_include = [str(s) for s in raw_include if str(s).strip()]

    result = run_setup(
        skip_packs=bool(params.get("skip_packs", False)),
        skip_schedule=bool(params.get("skip_schedule", False)),
        skip_bootstrap=bool(params.get("skip_bootstrap", False)),
        skip_harden=bool(params.get("skip_harden", False)),
        confirm_aur=bool(params.get("confirm_aur", False)),
        auto_quarantine=params.get("auto_quarantine"),
        schedule_profile=str(params.get("schedule_profile", "quick")),
        full_bootstrap=bool(params.get("full_bootstrap", True)),
        enable_linger=bool(params.get("enable_linger", False)),
        enable_firewall=bool(params.get("enable_firewall", True)),
        mark_complete=bool(params.get("mark_complete", True)),
        packs=packs,
        harden_include=harden_include,
    )
    invalidate_doctor_cache()
    return result
