"""User timer that keeps full-mode private ClamAV signatures fresh.

Full mode scans with ``--database=<runtime db>``; the distro freshclam timer
only updates ``/var/lib/clamav``. This user-level timer (no polkit) runs
``oyst-cli freshclam update --fangfrisch`` every six hours. Lite mode keeps
using the distro timer (services ``freshclam-timer``).
"""

from __future__ import annotations

import contextlib
from typing import Any

from oyst_core.config import load_config, save_config
from oyst_core.schedule_linger import escape_systemd_exec_arg, resolve_oyst_cli_path
from oyst_core.schedule_units import _run_user_systemctl, _user_systemd_dir

UNIT_SERVICE = "oyst-signatures.service"
UNIT_TIMER = "oyst-signatures.timer"
# Four times a day with jitter: well inside ClamAV CDN rate limits.
ON_CALENDAR = "*-*-* 00/6:00:00"


def timer_wanted() -> bool:
    runtime = load_config().runtime
    return runtime.mode == "full" and runtime.auto_update_signatures


def _unit_text(cli: str) -> tuple[str, str]:
    service = f"""[Unit]
Description=oysterAV virus definition update
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart={cli} freshclam update --fangfrisch --json
"""
    timer = f"""[Unit]
Description=oysterAV virus definition update timer

[Timer]
OnCalendar={ON_CALENDAR}
RandomizedDelaySec=30m
Persistent=true

[Install]
WantedBy=timers.target
"""
    return service, timer


def signature_timer_status() -> dict[str, Any]:
    """Live user-timer state plus whether config wants it on."""
    installed = (_user_systemd_dir() / UNIT_TIMER).is_file()
    enabled = active = False
    if installed:
        enabled = _run_user_systemctl(["is-enabled", UNIT_TIMER]).stdout.strip() == "enabled"
        active = _run_user_systemctl(["is-active", UNIT_TIMER]).stdout.strip() == "active"
    return {
        "unit": UNIT_TIMER,
        "installed": installed,
        "enabled": enabled,
        "active": active,
        "wanted": timer_wanted(),
        "on_calendar": ON_CALENDAR,
    }


def _remove_units() -> None:
    base = _user_systemd_dir()
    for name in (UNIT_TIMER, UNIT_SERVICE):
        with contextlib.suppress(OSError):
            (base / name).unlink()


def apply_signature_timer() -> dict[str, Any]:
    """Reconcile the user timer with ``runtime.mode`` + ``runtime.auto_update_signatures``."""
    base = _user_systemd_dir()
    if not timer_wanted():
        if (base / UNIT_TIMER).is_file():
            _run_user_systemctl(["disable", "--now", UNIT_TIMER])
            _remove_units()
            _run_user_systemctl(["daemon-reload"])
        return {"ok": True, "message": "Automatic definition updates are off", "enabled": False}

    cli_path = resolve_oyst_cli_path()
    if not cli_path:
        return {"ok": False, "message": "oyst-cli not found on PATH", "enabled": False}
    try:
        service, timer = _unit_text(escape_systemd_exec_arg(cli_path))
    except ValueError as exc:
        return {"ok": False, "message": str(exc), "enabled": False}
    (base / UNIT_SERVICE).write_text(service, encoding="utf-8")
    (base / UNIT_TIMER).write_text(timer, encoding="utf-8")
    for args in (["daemon-reload"], ["enable", "--now", UNIT_TIMER]):
        res = _run_user_systemctl(args)
        if res.returncode != 0:
            detail = (res.stderr or res.stdout or "systemctl --user failed").strip()
            return {"ok": False, "message": detail[:300], "enabled": False}
    return {
        "ok": True,
        "message": "Virus definitions update automatically every 6 hours",
        "enabled": True,
    }


def set_auto_update(on: bool) -> dict[str, Any]:
    """Persist the preference, then reconcile the timer."""
    cfg = load_config()
    cfg.runtime.auto_update_signatures = on
    save_config(cfg)
    return apply_signature_timer()
