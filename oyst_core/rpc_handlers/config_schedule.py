"""RPC handlers: config and schedule."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from oyst_core.config import get_config_value, load_config, set_config_value
from oyst_core.rpc_errors import RpcNotFoundError
from oyst_core.schedule_util import (
    apply_schedule,
    enable_linger,
    get_linger_status,
    get_schedule_status,
    install_user_timer,
    run_scheduled_scan,
)

if TYPE_CHECKING:
    from oyst_core.rpc_handlers import RpcContext


def handle_config_get(params: dict[str, Any], _ctx: RpcContext) -> Any:
    key = params.get("key")
    if key:
        val = get_config_value(str(key))
        if val is None:
            raise RpcNotFoundError(f"unknown config key: {key}")
        return val
    return load_config().model_dump()


def handle_config_set(params: dict[str, Any], _ctx: RpcContext) -> Any:
    set_config_value(str(params["key"]), str(params["value"]))
    return True


def handle_schedule_install(params: dict[str, Any], _ctx: RpcContext) -> Any:
    return install_user_timer(str(params.get("profile", "quick")), smoke_test=True)


def handle_schedule_apply(params: dict[str, Any], _ctx: RpcContext) -> Any:
    return apply_schedule(smoke_test=bool(params.get("smoke_test", False)))


def handle_schedule_status(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    return get_schedule_status()


def handle_schedule_run(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    return run_scheduled_scan()


def handle_schedule_linger(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    return get_linger_status()


def handle_schedule_enable_linger(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    return enable_linger()
