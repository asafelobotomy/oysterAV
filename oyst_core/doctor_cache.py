"""Short-lived cache for full-registry doctor snapshots.

Startup fans out status / setup / pack.doctor RPCs that each re-run every pack's
doctor(). Caching for a few seconds keeps the UI responsive without stale data
across normal interactive use.
"""

from __future__ import annotations

import threading
import time
from typing import Any

from oyst_core.registry import get_registry

_LOCK = threading.Lock()
_CACHE: list[dict[str, Any]] | None = None
_CACHE_AT = 0.0
DEFAULT_TTL_SEC = 5.0


def doctor_all(*, ttl_sec: float = DEFAULT_TTL_SEC, force: bool = False) -> list[dict[str, Any]]:
    """Return ``pack.doctor().model_dump()`` for every registered pack."""
    global _CACHE, _CACHE_AT
    now = time.monotonic()
    with _LOCK:
        if not force and _CACHE is not None and (now - _CACHE_AT) < ttl_sec:
            return [dict(row) for row in _CACHE]
        packs = [p.doctor().model_dump() for p in get_registry().all()]
        _CACHE = packs
        _CACHE_AT = now
        return [dict(row) for row in packs]


def invalidate_doctor_cache() -> None:
    """Drop cached doctor results (after install/remove/setup mutations)."""
    global _CACHE, _CACHE_AT
    with _LOCK:
        _CACHE = None
        _CACHE_AT = 0.0
