"""RPC handlers: config and schedule."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from oyst_core.config import get_config_value, load_config, set_config_value
from oyst_core.rpc_errors import RpcNotFoundError, RpcValidationError
from oyst_core.rpc_handlers.params import opt_bool, opt_str, req_str
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
    key = opt_str(params, "key")
    if key:
        val = get_config_value(key)
        if val is None:
            raise RpcNotFoundError(f"unknown config key: {key}")
        return val
    return load_config().model_dump()


def handle_config_set(params: dict[str, Any], _ctx: RpcContext) -> Any:
    key = req_str(params, "key")
    raw_value = params.get("value")
    if isinstance(raw_value, bool):
        value = "true" if raw_value else "false"
    else:
        value = req_str(params, "value", allow_empty=True)
    try:
        set_config_value(key, value)
    except (KeyError, ValueError, TypeError) as exc:
        detail = exc.args[0] if exc.args else exc
        raise RpcValidationError(f"invalid config value for {key}: {detail}") from exc
    return True


def handle_schedule_install(params: dict[str, Any], _ctx: RpcContext) -> Any:
    return install_user_timer(opt_str(params, "profile") or "quick", smoke_test=True)


def handle_schedule_apply(params: dict[str, Any], _ctx: RpcContext) -> Any:
    return apply_schedule(smoke_test=opt_bool(params, "smoke_test"))


def handle_schedule_status(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    return get_schedule_status()


def handle_schedule_run(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    return run_scheduled_scan()


def handle_schedule_linger(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    return get_linger_status()


def handle_schedule_enable_linger(_params: dict[str, Any], _ctx: RpcContext) -> Any:
    return enable_linger()
