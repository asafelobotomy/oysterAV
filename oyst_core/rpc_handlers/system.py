"""RPC handlers: runtime, firewall, services, auth, clamonacc, news, updates."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal

from oyst_core.rpc_errors import RpcValidationError
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

    pack = params.get("pack")
    if pack:
        return install_pack_runtime(str(pack))
    return bootstrap_runtime()


def handle_runtime_remove(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.runtime.bootstrap import remove_pack_runtime

    return remove_pack_runtime(str(params["pack"]))


def handle_runtime_update(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.runtime.bootstrap import update_runtime

    return update_runtime()


def handle_runtime_bootstrap(params: dict[str, Any], _ctx: RpcContext) -> Any:
    return run_full_runtime_bootstrap(
        skip_install=bool(params.get("skip_install", False)),
        update_signatures=bool(params.get("update_signatures", True)),
        run_maintenance=bool(params.get("run_maintenance", True)),
        skip_lynis=bool(params.get("skip_lynis", True)),
    )


def handle_firewall_status(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.packs.firewall import FirewallPack

    return FirewallPack().status()


def handle_fail2ban_unban(params: dict[str, Any], ctx: RpcContext) -> Any:
    from oyst_core.packs.fail2ban import Fail2banPack

    ok, msg = Fail2banPack().unban(
        str(params["ip"]),
        jail=params.get("jail"),
        ignore=bool(params.get("ignore", False)),
        persist=bool(params.get("persist", False)),
    )
    ctx.audit.log(
        "fail2ban.unban",
        str(params["ip"]),
        success=ok,
        data={"jail": params.get("jail")},
    )
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
    name = str(params.get("name", ""))
    state = str(params.get("state", ""))
    if name not in SERVICE_NAMES:
        raise RpcValidationError(f"unknown service: {name}")
    if state not in ("on", "off"):
        raise RpcValidationError("state must be on or off")
    state_lit: Literal["on", "off"] = "on" if state == "on" else "off"
    return set_service(name, state_lit, boot=bool(params.get("boot", False)))


def handle_auth_status(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.privileged.auth_grant import auth_status
    from oyst_core.privileged.install_privileged_helper import helper_status

    return {"helper": helper_status(), "service_lifecycle": auth_status()}


def handle_helper_install(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.privileged.elevate_cli import install_helper_elevated

    return install_helper_elevated()


def handle_auth_grant_service_lifecycle(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.privileged.elevate_cli import grant_service_lifecycle_elevated

    user = params.get("user")
    return grant_service_lifecycle_elevated(str(user) if user is not None else None)


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

    ClamonaccPack().add_path(str(params["path"]))
    return True


def handle_clamonacc_remove_path(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.packs.clamonacc import ClamonaccPack

    ClamonaccPack().remove_path(str(params["path"]))
    return True


def handle_news_list(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.security_news import list_security_news

    return list_security_news(
        force_refresh=bool(params.get("force", False)),
        sources=_news_sources(params),
    )


def handle_news_refresh(params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.security_news import list_security_news

    return list_security_news(force_refresh=True, sources=_news_sources(params))


def handle_updates_check(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.updates import check_available_updates

    return check_available_updates()


def handle_updates_apply(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    from oyst_core.updates import apply_all_updates

    return apply_all_updates()
