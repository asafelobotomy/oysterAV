"""Systemd user timer helpers for scheduled scans.

Re-export façade — implementations live in schedule_time / schedule_linger / schedule_units.
"""

from __future__ import annotations

from oyst_core.schedule_linger import (
    disable_linger,
    enable_linger,
    escape_systemd_exec_arg,
    get_linger_status,
    is_flatpak,
    resolve_oyst_cli_path,
)
from oyst_core.schedule_time import (
    TIME_RE,
    WEEKDAYS,
    parse_schedule_time,
    sanitize_on_calendar,
)
from oyst_core.schedule_units import (
    LEGACY_PROFILES,
    UNIT_SERVICE,
    UNIT_TIMER,
    apply_schedule,
    build_on_calendar,
    get_schedule_status,
    get_timer_status,
    install_user_timer,
    run_scheduled_scan,
    update_schedule_settings,
    validate_schedule_config,
)

__all__ = [
    "LEGACY_PROFILES",
    "TIME_RE",
    "UNIT_SERVICE",
    "UNIT_TIMER",
    "WEEKDAYS",
    "apply_schedule",
    "build_on_calendar",
    "disable_linger",
    "enable_linger",
    "escape_systemd_exec_arg",
    "get_linger_status",
    "get_schedule_status",
    "get_timer_status",
    "install_user_timer",
    "is_flatpak",
    "parse_schedule_time",
    "resolve_oyst_cli_path",
    "run_scheduled_scan",
    "sanitize_on_calendar",
    "update_schedule_settings",
    "validate_schedule_config",
]
