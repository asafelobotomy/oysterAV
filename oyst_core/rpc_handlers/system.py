"""RPC handlers: runtime, firewall, services, auth, clamonacc, news, updates."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal

from oyst_core import rpc_progress
from oyst_core.rpc_errors import RpcValidationError
from oyst_core.rpc_handlers.params import opt_bool, opt_str, req_str
from oyst_core.runtime_full_bootstrap import run_full_runtime_bootstrap
from oyst_core.services import SERVICE_NAMES, set_service

if TYPE_CHECKING:
    from oyst_core.rpc_handlers import RpcContext


def _news_sources(params: dict[str, Any]) -> list[str] | None:
    from oyst_core.security_news import normalize_source_ids

    raw_sources = params.get("sources")
    if isinstance(raw_sources, list):
        return normalize_source_ids([str(s) for s in raw_sources])
    if isinstance(raw_sources, str) and raw_sources.strip():
        return normalize_source_ids(
            [s.strip() for s in raw_sources.split(",") if s.strip()],
        )
    return None


def handle_runtime_status(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.runtime.bootstrap import runtime_status

    return runtime_status()


def handle_runtime_install(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.runtime.bootstrap import bootstrap_runtime, install_pack_runtime

    pack = opt_str(params, "pack")
    on_progress = rpc_progress.callback_for(params)
    try:
        if pack:
            return install_pack_runtime(pack, on_progress=on_progress)
        packs_raw = params.get("packs")
        pack_list: list[str] | None = None
        if isinstance(packs_raw, list) and packs_raw:
            pack_list = [str(p) for p in packs_raw if str(p).strip()]
        results = bootstrap_runtime(pack_list, on_progress=on_progress)
    finally:
        rpc_progress.finish(params)
    ok_count = sum(1 for r in results if r.get("ok"))
    return {
        "ok": ok_count == len(results) and bool(results),
        "results": results,
        "message": f"Installed {ok_count}/{len(results)} runtime packs",
    }


def handle_runtime_remove(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.runtime.bootstrap import remove_pack_runtime

    try:
        return remove_pack_runtime(
            req_str(params, "pack"), on_progress=rpc_progress.callback_for(params)
        )
    finally:
        rpc_progress.finish(params)


def handle_runtime_update(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.runtime.bootstrap import update_runtime

    return update_runtime()


def handle_runtime_bootstrap(params: dict[str, Any], _ctx: RpcContext) -> Any:
    try:
        return run_full_runtime_bootstrap(
            skip_install=opt_bool(params, "skip_install"),
            update_signatures=opt_bool(params, "update_signatures", True),
            run_maintenance=opt_bool(params, "run_maintenance", True),
            skip_lynis=opt_bool(params, "skip_lynis", True),
            on_progress=rpc_progress.callback_for(params),
        )
    finally:
        rpc_progress.finish(params)


def handle_progress_get(params: dict[str, Any], _ctx: RpcContext) -> Any:
    token = req_str(params, "token")
    if not rpc_progress.valid_token(token):
        raise RpcValidationError("invalid progress token")
    return rpc_progress.get(token)


def handle_firewall_status(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.packs.firewall import FirewallPack

    return FirewallPack().status()


def handle_fail2ban_unban(params: dict[str, Any], ctx: RpcContext) -> Any:
    from oyst_core.packs.fail2ban import Fail2banPack

    ip = req_str(params, "ip")
    jail = opt_str(params, "jail")
    ok, msg = Fail2banPack().unban(
        ip,
        jail=jail,
        ignore=opt_bool(params, "ignore"),
        persist=opt_bool(params, "persist"),
    )
    ctx.audit.log("fail2ban.unban", ip, success=ok, data={"jail": jail})
    return {"ok": ok, "message": msg}


def handle_clamav_clamd_ensure(_params: dict[str, Any], ctx: RpcContext) -> Any:
    from oyst_core.packs.clamav import ClamAVPack

    ok, msg = ClamAVPack().clamd_ensure()
    ctx.audit.log("clamav.clamd", "ensure", success=ok)
    return {"ok": ok, "message": msg, "status": ClamAVPack().clamd_status()}


def handle_services_status(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.services import services_status

    return services_status()


def handle_services_set(params: dict[str, Any], _ctx: RpcContext) -> Any:
    name = opt_str(params, "name") or ""
    state = opt_str(params, "state") or ""
    if name not in SERVICE_NAMES:
        raise RpcValidationError(f"unknown service: {name}")
    if state not in ("on", "off"):
        raise RpcValidationError("state must be on or off")
    state_lit: Literal["on", "off"] = "on" if state == "on" else "off"
    return set_service(name, state_lit, boot=opt_bool(params, "boot"))


def handle_auth_status(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.privileged.auth_grant import auth_status
    from oyst_core.privileged.install_privileged_helper import helper_status

    return {"helper": helper_status(), "service_lifecycle": auth_status()}


def handle_helper_install(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.privileged.elevate_cli import install_helper_elevated

    return install_helper_elevated()


def handle_auth_grant_service_lifecycle(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.privileged.elevate_cli import grant_service_lifecycle_elevated

    return grant_service_lifecycle_elevated(opt_str(params, "user"))


def handle_auth_revoke_service_lifecycle(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.privileged.elevate_cli import revoke_service_lifecycle_elevated

    return revoke_service_lifecycle_elevated()


def handle_clamonacc_status(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.packs.clamonacc import ClamonaccPack

    return ClamonaccPack().doctor().model_dump()


def handle_clamonacc_start(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.packs.clamonacc import ClamonaccPack

    ok, msg = ClamonaccPack().start()
    return {"ok": ok, "message": msg}


def handle_clamonacc_stop(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.packs.clamonacc import ClamonaccPack

    ok, msg = ClamonaccPack().stop()
    return {"ok": ok, "message": msg}


def handle_clamonacc_enable(_params: dict[str, Any], ctx: RpcContext) -> Any:
    from oyst_core.packs.clamonacc import ClamonaccPack

    ok, msg = ClamonaccPack().enable()
    ctx.audit.log("clamonacc", "enable", success=ok)
    return {"ok": ok, "message": msg}


def handle_clamonacc_disable(_params: dict[str, Any], ctx: RpcContext) -> Any:
    from oyst_core.packs.clamonacc import ClamonaccPack

    ok, msg = ClamonaccPack().disable()
    ctx.audit.log("clamonacc", "disable", success=ok)
    return {"ok": ok, "message": msg}


def handle_clamonacc_add_path(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.packs.clamonacc import ClamonaccPack

    ClamonaccPack().add_path(req_str(params, "path"))
    return True


def handle_clamonacc_remove_path(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.packs.clamonacc import ClamonaccPack

    ClamonaccPack().remove_path(req_str(params, "path"))
    return True


def handle_clamonacc_ensure_fdpass(_params: dict[str, Any], ctx: RpcContext) -> Any:
    from oyst_core.packs.clamd_ensure import ensure_fdpass

    result = ensure_fdpass(confirm=True)
    ctx.audit.log("clamonacc.ensure_fdpass", "rpc", success=bool(result.get("ok")))
    return result


def handle_clamonacc_ensure_prevention(_params: dict[str, Any], ctx: RpcContext) -> Any:
    from oyst_core.packs.clamd_ensure import ensure_prevention

    result = ensure_prevention(confirm=True)
    ctx.audit.log("clamonacc.ensure_prevention", "rpc", success=bool(result.get("ok")))
    return result


def handle_virusevent_status(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.virusevent import virusevent_status

    return virusevent_status()


def handle_virusevent_ensure(params: dict[str, Any], ctx: RpcContext) -> Any:
    from oyst_core.packs.clamd_ensure import ensure_virusevent

    result = ensure_virusevent(
        confirm=True,
        force_wrapper=opt_bool(params, "force_wrapper"),
    )
    ctx.audit.log("clamav.ensure_virusevent", "rpc", success=bool(result.get("ok")))
    return result


def handle_clamav_ensure_disable_cache(_params: dict[str, Any], ctx: RpcContext) -> Any:
    from oyst_core.packs.clamd_ensure import ensure_disable_cache

    result = ensure_disable_cache(confirm=True)
    ctx.audit.log("clamav.ensure_disable_cache", "rpc", success=bool(result.get("ok")))
    return result


def handle_news_list(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.security_news import list_security_news

    return list_security_news(
        force_refresh=opt_bool(params, "force"),
        sources=_news_sources(params),
    )


def handle_news_refresh(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.security_news import list_security_news

    return list_security_news(force_refresh=True, sources=_news_sources(params))


def handle_updates_check(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.updates import check_available_updates

    return check_available_updates()


def handle_updates_apply(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.updates import apply_all_updates

    return apply_all_updates(confirm_aur=params.get("confirm_aur") is True)
