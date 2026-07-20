"""Pure schedule time / OnCalendar parsing (no config I/O)."""

from __future__ import annotations

import re

from oyst_core.config_models import ScheduleConfig

WEEKDAYS = {
    "mon": "Mon",
    "tue": "Tue",
    "wed": "Wed",
    "thu": "Thu",
    "fri": "Fri",
    "sat": "Sat",
    "sun": "Sun",
    "monday": "Mon",
    "tuesday": "Tue",
    "wednesday": "Wed",
    "thursday": "Thu",
    "friday": "Fri",
    "saturday": "Sat",
    "sunday": "Sun",
}

TIME_RE = re.compile(r"^([01]?\d|2[0-3]):([0-5]\d)$")

# Backward-compatible private aliases
_WEEKDAYS = WEEKDAYS
_TIME_RE = TIME_RE


def parse_schedule_time(value: str) -> tuple[int, int]:
    match = TIME_RE.match(value.strip())
    if not match:
        msg = f"invalid schedule.time (expected HH:MM): {value}"
        raise ValueError(msg)
    return int(match.group(1)), int(match.group(2))


def sanitize_on_calendar(value: str) -> str:
    """Reject values that could inject systemd unit sections."""
    cleaned = value.strip()
    if not cleaned:
        raise ValueError("schedule.on_calendar must not be empty")
    if any(ch in cleaned for ch in ("\n", "\r", "\0")):
        raise ValueError("schedule.on_calendar must not contain newlines")
    if "[" in cleaned or "]" in cleaned:
        raise ValueError("schedule.on_calendar must not contain section markers")
    if len(cleaned) > 128:
        raise ValueError("schedule.on_calendar too long")
    # Allow systemd calendar chars: alnum, space, * - : , / .
    if not re.fullmatch(r"[A-Za-z0-9*:\-./, ]+", cleaned):
        raise ValueError("schedule.on_calendar contains invalid characters")
    return cleaned


def build_on_calendar(cfg: ScheduleConfig) -> str:
    """Map ScheduleConfig to a systemd OnCalendar expression."""
    freq = cfg.frequency
    if freq == "hourly":
        return "hourly"
    if freq == "custom":
        raw = cfg.on_calendar.strip()
        if not raw:
            msg = "schedule.on_calendar required when frequency=custom"
            raise ValueError(msg)
        return sanitize_on_calendar(raw)
    hour, minute = parse_schedule_time(cfg.time)
    if freq == "daily":
        return f"*-*-* {hour:02d}:{minute:02d}:00"
    if freq == "weekly":
        day_key = cfg.weekday.strip().lower()
        day = WEEKDAYS.get(day_key)
        if day is None:
            msg = f"invalid schedule.weekday: {cfg.weekday}"
            raise ValueError(msg)
        return f"{day} *-*-* {hour:02d}:{minute:02d}:00"
    msg = f"invalid schedule.frequency: {freq}"
    raise ValueError(msg)
