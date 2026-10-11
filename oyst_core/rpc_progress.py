"""Progress channel for long RPC methods (install / runtime) — server side.

A client that wants live progress sends ``progress_token`` with the long call
and polls ``progress.get`` on separate connections while it runs. State lives
in the serving process only; tokens are random, short-lived and bounded.
"""

from __future__ import annotations

import re
import threading
import time
from typing import Any

from oyst_core.runtime.progress import ProgressCallback

_TOKEN_RE = re.compile(r"^[0-9a-f]{32}$")
_MAX_TOKENS = 64
_TTL_SEC = 3600.0
_lock = threading.Lock()
_state: dict[str, dict[str, Any]] = {}


def valid_token(token: object) -> bool:
    return isinstance(token, str) and bool(_TOKEN_RE.fullmatch(token))


def _prune(now: float) -> None:
    for key in [k for k, v in _state.items() if now - float(v["updated"]) > _TTL_SEC]:
        del _state[key]
    while len(_state) >= _MAX_TOKENS:
        oldest = min(_state, key=lambda k: float(_state[k]["updated"]))
        del _state[oldest]


def update(token: str, stage: str, percent: int, *, done: bool = False) -> None:
    now = time.monotonic()
    with _lock:
        entry = _state.get(token)
        if entry is None:
            _prune(now)
            entry = {"seq": 0}
            _state[token] = entry
        entry.update(
            seq=int(entry["seq"]) + 1,
            stage=str(stage)[:200],
            percent=max(0, min(100, int(percent))),
            done=done,
            updated=now,
        )


def get(token: str) -> dict[str, Any]:
    with _lock:
        entry = _state.get(token)
        if entry is None:
            return {"seq": 0, "stage": "", "percent": 0, "done": False}
        return {k: entry[k] for k in ("seq", "stage", "percent", "done")}


def callback_for(params: dict[str, Any]) -> ProgressCallback | None:
    """Progress callback bound to the request's token, or None when not requested."""
    token = params.get("progress_token")
    if not valid_token(token):
        return None
    bound = str(token)
    update(bound, "", 0)

    def _cb(stage: str, percent: int) -> None:
        update(bound, stage, percent)

    return _cb


def finish(params: dict[str, Any]) -> None:
    token = params.get("progress_token")
    if valid_token(token):
        current = get(str(token))
        update(str(token), str(current.get("stage") or ""), int(current["percent"]), done=True)


__all__ = ["callback_for", "finish", "get", "update", "valid_token"]
