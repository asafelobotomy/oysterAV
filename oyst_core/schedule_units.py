"""Systemd user timer install/status and scheduled scan execution."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from oyst_core.config import ScheduleConfig, load_config, save_config, set_config_value
from oyst_core.models import ScanProfile
from oyst_core.privileged.runner import CommandResult, run_command, which
from oyst_core.schedule_linger import (
    escape_systemd_exec_arg,
    get_linger_status,
    is_flatpak,
    resolve_oyst_cli_path,
)
from oyst_core.schedule_time import build_on_calendar as _build_on_calendar
from oyst_core.schedule_validate import validate_schedule_config

UNIT_SERVICE = "oyst-scan.service"
UNIT_TIMER = "oyst-scan.timer"
LEGACY_PROFILES = ("quick", "full", "integrity", "suite", "custom")


def _run_user_systemctl(args: list[str]) -> CommandResult:
    if is_flatpak():
        spawn = which("flatpak-spawn")
        if spawn:
            return run_command([spawn, "--host", "systemctl", "--user", *args], timeout=60)
    return run_command(["systemctl", "--user", *args], timeout=60)


def _user_systemd_dir() -> Path:
    path = Path.home() / ".config" / "systemd" / "user"
    path.mkdir(parents=True, exist_ok=True)
    return path


def build_on_calendar(cfg: ScheduleConfig | None = None) -> str:
    """Map ScheduleConfig to a systemd OnCalendar expression."""
    return _build_on_calendar(cfg or load_config().schedule)


def _remove_legacy_units() -> list[str]:
    removed: list[str] = []
    base = _user_systemd_dir()
    for profile in LEGACY_PROFILES:
        for kind in ("service", "timer"):
            path = base / f"oyst-scan-{profile}.{kind}"
            if path.is_file():
                unit = path.name
                if kind == "timer":
                    _run_user_systemctl(["disable", "--now", unit])
                path.unlink(missing_ok=True)
                removed.append(unit)
    return removed


def apply_schedule(*, smoke_test: bool = False) -> dict[str, object]:
    """Write oyst-scan units from ScheduleConfig and enable/disable per config."""
    try:
        sched = validate_schedule_config()
    except ValueError as exc:
        return {
            "ok": False,
            "message": str(exc),
            "service": "",
            "timer": "",
            "enabled": False,
            "active": False,
            "cli_path": "",
        }

    cli_path = resolve_oyst_cli_path()
    if cli_path is None:
        return {
            "ok": False,
            "service": "",
            "timer": "",
            "enabled": False,
            "active": False,
            "cli_path": "",
            "message": "oyst-cli not found in PATH; install or run from project venv first",
            "enable_hint": "Ensure oyst-cli is on PATH or reinstall oysterAV",
            "linger": get_linger_status(),
        }

    on_calendar = build_on_calendar(sched)
    base = _user_systemd_dir()
    service = base / UNIT_SERVICE
    timer = base / UNIT_TIMER
    persistent = "true" if sched.persistent else "false"
    try:
        exec_cli = escape_systemd_exec_arg(cli_path)
    except ValueError as exc:
        return {
            "ok": False,
            "service": "",
            "timer": "",
            "enabled": False,
            "active": False,
            "cli_path": cli_path,
            "message": str(exc),
            "linger": get_linger_status(),
        }
    service.write_text(
        f"""[Unit]
Description=oysterAV scheduled scan

[Service]
Type=oneshot
ExecStart={exec_cli} schedule run --json
""",
        encoding="utf-8",
    )
    timer.write_text(
        f"""[Unit]
Description=oysterAV scheduled scan timer

[Timer]
OnCalendar={on_calendar}
Persistent={persistent}

[Install]
WantedBy=timers.target
""",
        encoding="utf-8",
    )

    removed = _remove_legacy_units()
    result: dict[str, object] = {
        "service": str(service),
        "timer": str(timer),
        "cli_path": cli_path,
        "on_calendar": on_calendar,
        "installed": True,
        "enabled": False,
        "active": False,
        "ok": True,
        "message": "",
        "enable_hint": "",
        "linger": get_linger_status(),
        "config": sched.model_dump(),
        "legacy_removed": removed,
    }

    reload_res = _run_user_systemctl(["daemon-reload"])
    if reload_res.returncode != 0:
        result["ok"] = False
        result["message"] = (
            reload_res.stderr or reload_res.stdout or "daemon-reload failed"
        ).strip()
        result["enable_hint"] = (
            f"systemctl --user daemon-reload && systemctl --user enable --now {UNIT_TIMER}"
        )
        return result

    if sched.enabled:
        enable_res = _run_user_systemctl(["enable", "--now", UNIT_TIMER])
        if enable_res.returncode != 0:
            result["ok"] = False
            result["message"] = (enable_res.stderr or enable_res.stdout or "enable failed").strip()
            result["enable_hint"] = f"systemctl --user enable --now {UNIT_TIMER}"
            return result
        active_res = _run_user_systemctl(["is-active", UNIT_TIMER])
        result["enabled"] = True
        result["active"] = active_res.returncode == 0 and "active" in active_res.stdout
    else:
        _run_user_systemctl(["disable", "--now", UNIT_TIMER])
        result["enabled"] = False
        result["active"] = False
        result["message"] = "Timer units written; schedule.enabled=false (timer disabled)"

    if smoke_test and sched.enabled:
        start_res = _run_user_systemctl(["start", UNIT_SERVICE])
        if start_res.returncode != 0:
            result["ok"] = False
            detail = (start_res.stderr or start_res.stdout or "service start failed").strip()
            result["message"] = f"Timer enabled but service failed: {detail[:300]}"
        else:
            status_res = _run_user_systemctl(
                ["show", UNIT_SERVICE, "-p", "ExecMainStatus", "--value"],
            )
            exit_code = (status_res.stdout or "").strip()
            if exit_code and exit_code != "0":
                result["ok"] = False
                result["message"] = f"Service ran but exited with status {exit_code}"

    if result["ok"] and result.get("enabled") and result.get("active"):
        result["message"] = f"Scheduled scan timer enabled ({on_calendar})"
    elif result["ok"] and result.get("enabled"):
        result["message"] = f"Timer unit installed ({on_calendar}); verify with schedule status"

    linger = result.get("linger", {})
    if isinstance(linger, dict) and not linger.get("linger", True) and sched.enabled:
        result["linger_advisory"] = (
            "Timers stop when you log out. Enable linger for 24/7 scheduling."
        )

    from oyst_core.audit import SecurityAudit

    SecurityAudit().log(
        "schedule.install",
        sched.profile,
        success=bool(result.get("ok")),
        data={"on_calendar": on_calendar, "enabled": sched.enabled},
    )
    return result


def install_user_timer(
    profile: str = "quick",
    *,
    enable: bool = True,
    smoke_test: bool = False,
) -> dict[str, object]:
    """Compat: set schedule profile/enabled defaults and apply units."""
    try:
        ScanProfile(profile)
    except ValueError as exc:
        msg = f"invalid scan profile: {profile}"
        raise ValueError(msg) from exc
    set_config_value("schedule.profile", profile)
    set_config_value("schedule.enabled", "true" if enable else "false")
    cfg = load_config()
    # Keep daily 02:00 defaults when never customized
    if not cfg.schedule.time:
        set_config_value("schedule.time", "02:00")
    if cfg.schedule.frequency not in ("hourly", "daily", "weekly", "custom"):
        set_config_value("schedule.frequency", "daily")
    return apply_schedule(smoke_test=smoke_test)


def get_timer_status(profile: str = "quick") -> dict[str, object]:
    """Legacy status (profile hint ignored for unit names; prefers stable units)."""
    _ = profile
    status = get_schedule_status()
    config = status.get("config")
    profile_name = config.get("profile", profile) if isinstance(config, dict) else profile
    return {
        "profile": profile_name,
        "installed": status.get("installed", False),
        "enabled": status.get("enabled", False),
        "active": status.get("active", False),
        "timer": status.get("timer", ""),
        "cli_path": status.get("cli_path", ""),
        "on_calendar": status.get("on_calendar", ""),
        "next": status.get("next", ""),
    }


def _next_elapse() -> str:
    res = _run_user_systemctl(
        ["show", UNIT_TIMER, "-p", "NextElapseUSecRealtime", "--value"],
    )
    if res.returncode != 0:
        return ""
    return (res.stdout or "").strip()


def get_schedule_status() -> dict[str, object]:
    """Merged schedule config + systemd timer state."""
    cfg = load_config().schedule
    try:
        on_calendar = build_on_calendar(cfg)
        calendar_error = ""
    except ValueError as exc:
        on_calendar = ""
        calendar_error = str(exc)

    base = _user_systemd_dir()
    timer_path = base / UNIT_TIMER
    service_path = base / UNIT_SERVICE
    installed = timer_path.is_file() and service_path.is_file()
    enabled = False
    active = False
    if installed:
        enabled_res = _run_user_systemctl(["is-enabled", UNIT_TIMER])
        enabled = enabled_res.returncode == 0 and "enabled" in (enabled_res.stdout or "")
        active_res = _run_user_systemctl(["is-active", UNIT_TIMER])
        active = active_res.returncode == 0 and "active" in (active_res.stdout or "")

    return {
        "config": cfg.model_dump(),
        "on_calendar": on_calendar,
        "calendar_error": calendar_error,
        "installed": installed,
        "enabled": enabled,
        "active": active,
        "next": _next_elapse() if installed else "",
        "service": str(service_path),
        "timer": str(timer_path),
        "cli_path": resolve_oyst_cli_path() or "",
        "linger": get_linger_status(),
    }


def run_scheduled_scan() -> dict[str, Any]:
    """Execute a scan using ScheduleConfig (timer ExecStart target)."""
    from oyst_core.config import effective_schedule_backend
    from oyst_core.orchestrator import JobOrchestrator

    sched = validate_schedule_config()
    profile = ScanProfile(sched.profile)
    packs = list(sched.packs) if sched.packs else None
    paths = list(sched.paths) if sched.paths else None
    if sched.quarantine == "on":
        quarantine = True
    elif sched.quarantine == "off":
        quarantine = False
    else:
        quarantine = load_config().quarantine.auto

    orch = JobOrchestrator()
    result, code = orch.run_scan(
        profile=profile,
        paths=paths,
        packs=packs,
        backend=effective_schedule_backend(schedule=sched),
        quarantine=quarantine,
    )
    return {
        "ok": int(code) in (0, 1),
        "exit_code": int(code),
        "scan": result.model_dump(mode="json"),
        "schedule": sched.model_dump(),
    }


def update_schedule_settings(**kwargs: object) -> ScheduleConfig:
    """Patch schedule fields from CLI flags and persist."""
    cfg = load_config()
    sched = cfg.schedule
    if "enabled" in kwargs and kwargs["enabled"] is not None:
        sched.enabled = bool(kwargs["enabled"])
    if "profile" in kwargs and kwargs["profile"] is not None:
        sched.profile = str(kwargs["profile"])
    if "packs" in kwargs and kwargs["packs"] is not None:
        raw = kwargs["packs"]
        if isinstance(raw, str):
            sched.packs = [s.strip() for s in raw.split(",") if s.strip()]
        elif isinstance(raw, list):
            sched.packs = [str(s).strip() for s in raw if str(s).strip()]
    if "paths" in kwargs and kwargs["paths"] is not None:
        from oyst_core.config_access import _parse_path_csv

        raw = kwargs["paths"]
        if isinstance(raw, str):
            sched.paths = _parse_path_csv(raw, key="schedule.paths")
        elif isinstance(raw, list):
            joined = ",".join(str(s) for s in raw)
            sched.paths = _parse_path_csv(joined, key="schedule.paths")
    if "frequency" in kwargs and kwargs["frequency"] is not None:
        sched.frequency = kwargs["frequency"]  # type: ignore[assignment]
    if "time" in kwargs and kwargs["time"] is not None:
        sched.time = str(kwargs["time"])
    if "weekday" in kwargs and kwargs["weekday"] is not None:
        sched.weekday = str(kwargs["weekday"])
    if "on_calendar" in kwargs and kwargs["on_calendar"] is not None:
        sched.on_calendar = str(kwargs["on_calendar"])
    if "persistent" in kwargs and kwargs["persistent"] is not None:
        sched.persistent = bool(kwargs["persistent"])
    if "quarantine" in kwargs and kwargs["quarantine"] is not None:
        sched.quarantine = kwargs["quarantine"]  # type: ignore[assignment]
    if "backend" in kwargs and kwargs["backend"] is not None:
        backend = str(kwargs["backend"])
        if backend not in ("inherit", "auto", "clamd", "clamscan"):
            msg = "schedule.backend must be inherit|auto|clamd|clamscan"
            raise ValueError(msg)
        sched.backend = backend  # type: ignore[assignment]
    cfg.schedule = validate_schedule_config(sched)
    save_config(cfg)
    return cfg.schedule
