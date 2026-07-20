"""Config get/set accessors and setup status."""

from __future__ import annotations

import warnings
from datetime import UTC, datetime
from typing import Any, cast

from oyst_core.config_io import load_config, save_config
from oyst_core.config_models import (
    _MAX_FILESIZE_RE,
    _RKHUNTER_TEST_RE,
    _SIG_NAME_RE,
    KNOWN_FANGFRISCH_PROVIDERS,
    ApplyLimitsTo,
    ClamavProfile,
    OysterConfig,
    RuntimeMode,
    ScheduleBackend,
    ScheduleConfig,
    ScheduleFrequency,
    ScheduleQuarantine,
)
from oyst_core.ui_theme import UI_THEME_ID_SET, UiThemeId


def effective_scan_backend(cfg: OysterConfig | None = None) -> str:
    """Backend for interactive / manual scans."""
    return (cfg or load_config()).scan.backend


def effective_schedule_backend(
    cfg: OysterConfig | None = None,
    *,
    schedule: ScheduleConfig | None = None,
) -> str:
    """Backend for the systemd timer — inherit uses scan.backend."""
    c = cfg or load_config()
    sched = schedule if schedule is not None else c.schedule
    if sched.backend == "inherit":
        return c.scan.backend
    return sched.backend


_CLAMAV_PROFILE_ALIAS_MSG = (
    "runtime.clamav_profile is deprecated; use scan.clamav_profile "
    "(alias removed in oysterAV 0.3.0)"
)


def get_config_value(key: str) -> str | None:
    if key == "runtime.clamav_profile":
        warnings.warn(_CLAMAV_PROFILE_ALIAS_MSG, DeprecationWarning, stacklevel=2)
        # Deprecated alias for scan.clamav_profile
        key = "scan.clamav_profile"
    cfg = load_config()
    flat = cfg.model_dump()
    parts = key.split(".")
    cur: Any = flat
    for part in parts:
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    if isinstance(cur, bool):
        return "true" if cur else "false"
    if isinstance(cur, list):
        return ",".join(str(v) for v in cur)
    return str(cur)


def _parse_bool(value: str) -> bool:
    return value.lower() in ("true", "1", "yes")


def _parse_csv(value: str) -> list[str]:
    return [s.strip() for s in value.split(",") if s.strip()]


def _parse_path_csv(value: str, *, key: str) -> list[str]:
    """Parse comma-separated paths; reject control chars and leading dashes."""
    paths: list[str] = []
    for raw in value.split(","):
        item = raw.strip()
        if not item:
            continue
        if any(ch in item for ch in ("\n", "\r", "\0")):
            raise ValueError(f"{key}: path entries must not contain control characters")
        if item.startswith("-"):
            raise ValueError(f"{key}: path entries must not start with '-'")
        paths.append(item)
    return paths


def _parse_exclude_dirs_csv(value: str) -> list[str]:
    """Parse scan.exclude_dirs as fixed path prefixes (no regex operators)."""
    paths = _parse_path_csv(value, key="scan.exclude_dirs")
    # Allow '.' in paths (e.g. ~/.cache); block regex operators.
    forbidden = set("*+?[](){}|^$\\")
    for item in paths:
        if any(ch in forbidden for ch in item):
            raise ValueError(
                "scan.exclude_dirs entries must be literal path prefixes (no regex metacharacters)",
            )
    return paths


def set_config_value(key: str, value: str) -> None:
    cfg = load_config()
    old: str | None = None
    try:
        old = get_config_value(key)
    except KeyError:
        old = None
    if key == "quarantine.auto":
        cfg.quarantine.auto = _parse_bool(value)
    elif key == "scan.profile":
        cfg.scan.profile = value
    elif key == "scan.backend":
        cfg.scan.backend = value
    elif key == "scan.clamav_profile":
        if value not in ("full", "linux-only"):
            raise KeyError("scan.clamav_profile must be 'full' or 'linux-only'")
        cfg.scan.clamav_profile = cast(ClamavProfile, value)
    elif key == "runtime.clamav_profile":
        warnings.warn(_CLAMAV_PROFILE_ALIAS_MSG, DeprecationWarning, stacklevel=2)
        # Deprecated alias — PE mode lives under scan (not runtime.mode).
        if value not in ("full", "linux-only"):
            raise KeyError("scan.clamav_profile must be 'full' or 'linux-only'")
        cfg.scan.clamav_profile = cast(ClamavProfile, value)
    elif key == "scan.max_filesize":
        if not _MAX_FILESIZE_RE.match(value.strip()):
            raise KeyError("scan.max_filesize must look like 25M or 100K")
        cfg.scan.max_filesize = value.strip()
    elif key == "scan.max_recursion":
        try:
            parsed = int(value)
        except ValueError as exc:
            raise KeyError("scan.max_recursion must be an integer") from exc
        if parsed < 1:
            raise KeyError("scan.max_recursion must be >= 1")
        cfg.scan.max_recursion = parsed
    elif key == "scan.max_files":
        try:
            parsed = int(value)
        except ValueError as exc:
            raise KeyError("scan.max_files must be an integer") from exc
        if parsed < 1:
            raise KeyError("scan.max_files must be >= 1")
        cfg.scan.max_files = parsed
    elif key == "scan.exclude_dirs":
        cfg.scan.exclude_dirs = _parse_exclude_dirs_csv(value)
    elif key == "scan.apply_limits_to":
        if value not in ("quick", "all"):
            raise KeyError("scan.apply_limits_to must be 'quick' or 'all'")
        cfg.scan.apply_limits_to = cast(ApplyLimitsTo, value)
    elif key == "clamav.ignore_sigs":
        names = _parse_csv(value)
        for name in names:
            if not _SIG_NAME_RE.match(name):
                raise KeyError(f"invalid signature name: {name}")
        cfg.clamav.ignore_sigs = names
    elif key == "fangfrisch.providers":
        providers = _parse_csv(value)
        for name in providers:
            if name not in KNOWN_FANGFRISCH_PROVIDERS:
                raise KeyError(
                    "fangfrisch.providers must be a subset of: "
                    + ", ".join(sorted(KNOWN_FANGFRISCH_PROVIDERS)),
                )
        cfg.fangfrisch.providers = providers
    elif key == "clamonacc.enabled":
        cfg.clamonacc.enabled = _parse_bool(value)
    elif key == "clamonacc.prevention":
        cfg.clamonacc.prevention = _parse_bool(value)
    elif key == "clamonacc.paths":
        cfg.clamonacc.paths = _parse_path_csv(value, key=key)
    elif key == "clamonacc.exclude_paths":
        cfg.clamonacc.exclude_paths = _parse_path_csv(value, key=key)
    elif key == "maldet_monitor.enabled":
        cfg.maldet_monitor.enabled = _parse_bool(value)
    elif key == "maldet_monitor.mode":
        if value not in ("users", "paths"):
            raise KeyError("maldet_monitor.mode must be 'users' or 'paths'")
        cfg.maldet_monitor.mode = value
    elif key == "maldet_monitor.paths":
        cfg.maldet_monitor.paths = _parse_path_csv(value, key=key)
    elif key == "setup.completed":
        cfg.setup.completed = _parse_bool(value)
        if cfg.setup.completed and not cfg.setup.completed_at:
            cfg.setup.completed_at = datetime.now(UTC).isoformat()
        if not cfg.setup.completed:
            cfg.setup.completed_at = None
    elif key == "setup.skipped_steps":
        cfg.setup.skipped_steps = _parse_csv(value)
    elif key == "rkhunter.skip_keypress":
        cfg.rkhunter.skip_keypress = _parse_bool(value)
    elif key == "rkhunter.disable_tests":
        tests = _parse_csv(value)
        for name in tests:
            if not _RKHUNTER_TEST_RE.match(name):
                raise KeyError(f"invalid rkhunter test name: {name}")
        cfg.rkhunter.disable_tests = tests
    elif key == "lynis.quick":
        cfg.lynis.quick = _parse_bool(value)
    elif key == "runtime.mode":
        if value not in ("full", "lite"):
            raise KeyError("runtime.mode must be 'full' or 'lite'")
        cfg.runtime.mode = cast(RuntimeMode, value)
    elif key == "schedule.enabled":
        cfg.schedule.enabled = _parse_bool(value)
    elif key == "schedule.profile":
        cfg.schedule.profile = value
    elif key == "schedule.packs":
        from oyst_core.schedule_validate import validate_packs

        try:
            cfg.schedule.packs = validate_packs(_parse_csv(value))
        except ValueError as exc:
            raise KeyError(str(exc)) from exc
    elif key == "schedule.paths":
        cfg.schedule.paths = _parse_path_csv(value, key=key)
    elif key == "schedule.frequency":
        if value not in ("hourly", "daily", "weekly", "custom"):
            raise KeyError("schedule.frequency must be hourly|daily|weekly|custom")
        cfg.schedule.frequency = cast(ScheduleFrequency, value)
    elif key == "schedule.time":
        from oyst_core.schedule_time import parse_schedule_time

        try:
            hour, minute = parse_schedule_time(value)
        except ValueError as exc:
            raise KeyError("schedule.time must be HH:MM (24-hour)") from exc
        cfg.schedule.time = f"{hour:02d}:{minute:02d}"
    elif key == "schedule.weekday":
        cfg.schedule.weekday = value
    elif key == "schedule.on_calendar":
        from oyst_core.schedule_time import sanitize_on_calendar

        cfg.schedule.on_calendar = sanitize_on_calendar(value)
    elif key == "schedule.persistent":
        cfg.schedule.persistent = _parse_bool(value)
    elif key == "schedule.quarantine":
        if value not in ("auto", "on", "off"):
            raise KeyError("schedule.quarantine must be auto|on|off")
        cfg.schedule.quarantine = cast(ScheduleQuarantine, value)
    elif key == "schedule.backend":
        if value not in ("inherit", "auto", "clamd", "clamscan"):
            raise KeyError("schedule.backend must be inherit|auto|clamd|clamscan")
        cfg.schedule.backend = cast(ScheduleBackend, value)
    elif key == "ui.run_at_startup":
        cfg.ui.run_at_startup = _parse_bool(value)
    elif key == "ui.start_minimized":
        cfg.ui.start_minimized = _parse_bool(value)
    elif key == "ui.minimize_to_tray":
        cfg.ui.minimize_to_tray = _parse_bool(value)
    elif key == "ui.security_news":
        cfg.ui.security_news = _parse_bool(value)
    elif key == "ui.security_news_sources":
        from oyst_core.security_news_sources import normalize_source_ids

        cfg.ui.security_news_sources = normalize_source_ids(_parse_csv(value))
    elif key == "ui.theme":
        if value not in UI_THEME_ID_SET:
            raise KeyError(
                "ui.theme must be one of: " + ", ".join(sorted(UI_THEME_ID_SET)),
            )
        cfg.ui.theme = cast(UiThemeId, value)
    else:
        raise KeyError(f"Unknown config key: {key}")
    save_config(cfg)

    # Side-effects for desktop integration (after persist).
    if key == "ui.run_at_startup":
        from oyst_core.desktop_util import sync_autostart_from_config

        sync_autostart_from_config()
    elif key == "ui.start_minimized":
        from oyst_core.desktop_util import rewrite_autostart_if_enabled

        rewrite_autostart_if_enabled()
    elif key == "clamav.ignore_sigs":
        from oyst_core.packs.clamav import ClamAVPack

        ClamAVPack().ensure_ignore_sigs()
    elif key == "rkhunter.disable_tests":
        from oyst_core.packs.rkhunter_resolve import ensure_disable_tests_overlay

        ensure_disable_tests_overlay(cfg.rkhunter.disable_tests)
    elif key == "fangfrisch.providers":
        from oyst_core.packs.fangfrisch import FangfrischPack

        FangfrischPack().ensure_config(force=True)

    from oyst_core.audit import SecurityAudit

    SecurityAudit().log("config.set", key, success=True, data={"old": old, "new": value})


def setup_status() -> dict[str, object]:
    from oyst_core.setup_workflow import assess_setup

    return assess_setup()
