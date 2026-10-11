"""Typed RPC parameter accessors and log redaction.

Bad client input must surface as ``validation_error`` rather than a
``KeyError``/``ValueError``/``TypeError`` that the server reports as
``internal_error``.
"""

from __future__ import annotations

from typing import Any

from oyst_core.rpc_errors import RpcValidationError

LIMIT_MIN = 1
LIMIT_MAX = 10_000
_MISSING = object()
_TRUE_STRINGS = frozenset({"true", "1", "yes", "on"})
_FALSE_STRINGS = frozenset({"false", "0", "no", "off", ""})

# Methods whose param *values* must never reach the transcript log.
_REDACT_VALUE_METHODS = frozenset({"config.set"})
_LOG_MAX_STR = 512
_LOG_MAX_ITEMS = 50
_LOG_MAX_DEPTH = 4


def _get(params: dict[str, Any], name: str, default: Any) -> Any:
    if not isinstance(params, dict):
        raise RpcValidationError("params must be an object")
    value = params.get(name, _MISSING)
    if value is _MISSING or value is None:
        if default is _MISSING:
            raise RpcValidationError(f"{name} required")
        return default
    return value


def req_str(params: dict[str, Any], name: str, *, allow_empty: bool = False) -> str:
    """Required string param (numbers are accepted and stringified)."""
    value = _get(params, name, _MISSING)
    if isinstance(value, bool) or not isinstance(value, str | int | float):
        raise RpcValidationError(f"{name} must be a string")
    text = str(value)
    if not allow_empty and not text.strip():
        raise RpcValidationError(f"{name} required")
    return text


def opt_str(params: dict[str, Any], name: str, default: str | None = None) -> str | None:
    """Optional string param; ``None``/missing/empty → ``default``."""
    value = _get(params, name, None)
    if value is None or value == "":
        return default
    if isinstance(value, bool) or not isinstance(value, str | int | float):
        raise RpcValidationError(f"{name} must be a string")
    return str(value)


def _to_int(name: str, value: Any) -> int:
    if isinstance(value, bool):
        raise RpcValidationError(f"{name} must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    raise RpcValidationError(f"{name} must be an integer")


def req_int(params: dict[str, Any], name: str) -> int:
    return _to_int(name, _get(params, name, _MISSING))


def opt_int(params: dict[str, Any], name: str, default: int) -> int:
    return _to_int(name, _get(params, name, default))


def opt_bool(params: dict[str, Any], name: str, default: bool = False) -> bool:
    value = _get(params, name, default)
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in _TRUE_STRINGS:
            return True
        if lowered in _FALSE_STRINGS:
            return False
    raise RpcValidationError(f"{name} must be a boolean")


def opt_limit(params: dict[str, Any], default: int, name: str = "limit") -> int:
    """Row limit clamped to ``LIMIT_MIN..LIMIT_MAX`` (``-1`` is not "unlimited")."""
    return max(LIMIT_MIN, min(LIMIT_MAX, opt_int(params, name, default)))


def truncate_for_log(value: Any, depth: int = 0) -> Any:
    """Bound strings, containers and nesting depth for transcript logging."""
    if isinstance(value, str):
        if len(value) > _LOG_MAX_STR:
            return value[:_LOG_MAX_STR] + f"…[+{len(value) - _LOG_MAX_STR} chars]"
        return value
    if depth >= _LOG_MAX_DEPTH and isinstance(value, dict | list | tuple):
        return "…[nested]"
    if isinstance(value, dict):
        items = list(value.items())
        out = {str(k): truncate_for_log(v, depth + 1) for k, v in items[:_LOG_MAX_ITEMS]}
        if len(items) > _LOG_MAX_ITEMS:
            out["…"] = f"[+{len(items) - _LOG_MAX_ITEMS} keys]"
        return out
    if isinstance(value, list | tuple):
        seq = [truncate_for_log(v, depth + 1) for v in value[:_LOG_MAX_ITEMS]]
        if len(value) > _LOG_MAX_ITEMS:
            seq.append(f"…[+{len(value) - _LOG_MAX_ITEMS} items]")
        return seq
    return value


def loggable_params(method: str, params: Any) -> Any:
    """Params safe for the transcript: redacted values, truncated size."""
    if not isinstance(params, dict):
        return truncate_for_log(params)
    if method in _REDACT_VALUE_METHODS:
        return {k: (truncate_for_log(v) if k == "key" else "[redacted]") for k, v in params.items()}
    return truncate_for_log(params)
