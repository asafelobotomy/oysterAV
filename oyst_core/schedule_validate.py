"""Schedule config validation helpers."""

from __future__ import annotations

from oyst_core.config import ScheduleConfig, load_config
from oyst_core.models import ScanProfile
from oyst_core.schedule_time import build_on_calendar as _build_on_calendar


def validate_packs(packs: list[str]) -> list[str]:
    from oyst_core.registry import get_registry

    registry = get_registry()
    cleaned = [p.strip() for p in packs if p.strip()]
    unknown = [p for p in cleaned if registry.get(p) is None]
    if unknown:
        msg = f"unknown schedule packs: {', '.join(unknown)}"
        raise ValueError(msg)
    return cleaned


def validate_schedule_config(cfg: ScheduleConfig | None = None) -> ScheduleConfig:
    sched = (cfg or load_config().schedule).model_copy(deep=True)
    try:
        ScanProfile(sched.profile)
    except ValueError as exc:
        msg = f"invalid schedule.profile: {sched.profile}"
        raise ValueError(msg) from exc
    if sched.profile == ScanProfile.CUSTOM.value and not sched.packs:
        msg = "schedule.packs required when schedule.profile=custom"
        raise ValueError(msg)
    sched.packs = validate_packs(sched.packs)
    _build_on_calendar(sched)
    if sched.backend not in ("inherit", "auto", "clamd", "clamscan"):
        msg = "schedule.backend must be inherit|auto|clamd|clamscan"
        raise ValueError(msg)
    return sched
