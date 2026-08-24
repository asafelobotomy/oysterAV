"""Shared maintenance workflows for CLI and GUI."""

from __future__ import annotations

from typing import Any

from oyst_core.events import EventLog
from oyst_core.models import PackTier
from oyst_core.packs.fangfrisch import FangfrischPack
from oyst_core.packs.freshclam import FreshclamPack
from oyst_core.packs.lynis import LynisPack
from oyst_core.packs.rkhunter import RKHunterPack
from oyst_core.registry import get_registry


def bootstrap_critical_ok(steps: list[dict[str, Any]] | list[dict[str, object]]) -> bool:
    """True when freshclam succeeded or was skipped (not installed).

    Doctor-* success alone must not mask a freshclam failure. Skipped freshclam
    (binary missing) counts as OK for bootstrap aggregation.
    """
    fresh = next((s for s in steps if s.get("step") == "freshclam"), None)
    if fresh is None:
        return True
    if fresh.get("skipped"):
        return True
    return bool(fresh.get("ok"))


def run_bootstrap(
    *,
    skip_lynis: bool = False,
    skip_rkhunter_propupd: bool = False,
) -> list[dict[str, object]]:
    events = EventLog()
    steps: list[dict[str, object]] = []

    for pack in get_registry().all():
        if pack.tier == PackTier.REQUIRED:
            status = pack.doctor()
            steps.append({"step": f"doctor-{pack.name}", "ok": status.installed})

    fresh = FreshclamPack()
    if fresh.doctor().installed:
        ok, msg = fresh.update()
        steps.append({"step": "freshclam", "ok": ok, "message": msg[:200]})
    else:
        steps.append({"step": "freshclam", "ok": False, "skipped": True})

    fang = FangfrischPack()
    if fang.doctor().installed:
        ok, msg = fang.refresh()
        steps.append({"step": "fangfrisch", "ok": ok, "message": msg[:200]})
    else:
        steps.append({"step": "fangfrisch", "ok": True, "skipped": True})

    if skip_rkhunter_propupd:
        steps.append({"step": "rkhunter-propupd", "ok": True, "skipped": True})
    else:
        rkh = RKHunterPack()
        if rkh.doctor().installed:
            ok, msg = rkh.propupd()
            steps.append({"step": "rkhunter-propupd", "ok": ok, "message": msg[:200]})
        else:
            steps.append({"step": "rkhunter-propupd", "ok": False, "skipped": True})

    if not skip_lynis:
        lynis = LynisPack()
        if lynis.doctor().installed:
            ok, _output, score = lynis.audit()
            steps.append({"step": "lynis", "ok": ok, "hardening_index": score})
        else:
            steps.append({"step": "lynis", "ok": False, "skipped": True})

    events.log("maintenance", "bootstrap completed", {"steps": steps})
    return steps


def run_post_update() -> list[dict[str, object]]:
    events = EventLog()
    steps: list[dict[str, object]] = []

    fresh = FreshclamPack()
    if fresh.doctor().installed:
        ok, _ = fresh.update()
        steps.append({"step": "freshclam", "ok": ok})

    fang = FangfrischPack()
    if fang.doctor().installed:
        ok, msg = fang.refresh()
        steps.append({"step": "fangfrisch", "ok": ok, "message": msg[:120]})
    else:
        steps.append({"step": "fangfrisch", "ok": True, "skipped": True})

    rkh = RKHunterPack()
    if rkh.doctor().installed:
        ok, msg = rkh.propupd()
        steps.append({"step": "rkhunter-propupd", "ok": ok, "message": msg[:120]})

    events.log("maintenance", "post-update completed", {"steps": steps})
    return steps
