"""Schedule commands."""

from __future__ import annotations

import click

from oyst_cli.confirm import require_confirm
from oyst_cli.options import json_option
from oyst_cli.output import emit
from oyst_core.config import load_config
from oyst_core.schedule_util import (
    apply_schedule,
    build_on_calendar,
    enable_linger,
    get_linger_status,
    get_schedule_status,
    install_user_timer,
    run_scheduled_scan,
    update_schedule_settings,
)

_SCHEDULE_SET_EPILOG = """
Examples:
  oyst-cli schedule set --profile quick --frequency daily --time 02:00 --enabled --apply
  oyst-cli schedule set --packs clamav,rkhunter --paths ~/Downloads --apply --json

Structured API: set / apply / enable. Compat one-click: schedule install.
"""

_SCHEDULE_INSTALL_EPILOG = """
Examples:
  oyst-cli schedule install --profile quick --json
  oyst-cli schedule install --profile quick --no-smoke-test

Compat one-click (defaults + apply; smoke-test on by default). Prefer schedule set/apply/enable.
"""


@click.group("schedule")
def schedule_group() -> None:
    """Configure and manage the systemd user scan timer."""


@schedule_group.command("show")
@click.option("--json", "json_mode", is_flag=True)
def schedule_show(json_mode: bool) -> None:
    """Show schedule config and derived OnCalendar expression."""
    cfg = load_config().schedule
    try:
        on_calendar = build_on_calendar(cfg)
        err = ""
    except ValueError as exc:
        on_calendar = ""
        err = str(exc)
    payload = {
        "config": cfg.model_dump(),
        "on_calendar": on_calendar,
        "calendar_error": err,
    }
    if json_mode:
        emit(payload, json_mode=True)
        return
    click.echo(f"Enabled: {cfg.enabled}")
    click.echo(f"Profile: {cfg.profile}")
    click.echo(f"Packs: {', '.join(cfg.packs) or '(profile default)'}")
    click.echo(f"Paths: {', '.join(cfg.paths) or '(profile default)'}")
    click.echo(f"Frequency: {cfg.frequency}")
    click.echo(f"Time: {cfg.time}")
    click.echo(f"Weekday: {cfg.weekday}")
    if cfg.frequency == "custom":
        click.echo(f"OnCalendar (custom): {cfg.on_calendar}")
    click.echo(f"OnCalendar: {on_calendar or err}")
    click.echo(f"Quarantine: {cfg.quarantine}")
    click.echo(f"Backend: {cfg.backend}")


@schedule_group.command("template")
@click.option("--json", "json_mode", is_flag=True)
def schedule_template(json_mode: bool) -> None:
    """Print the timer unit that schedule apply would write."""
    cfg = load_config().schedule
    try:
        on_calendar = build_on_calendar(cfg)
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    persistent = "true" if cfg.persistent else "false"
    text = f"""# User timer: ~/.config/systemd/user/oyst-scan.timer
[Unit]
Description=oysterAV scheduled scan timer

[Timer]
OnCalendar={on_calendar}
Persistent={persistent}

[Install]
WantedBy=timers.target
"""
    if json_mode:
        emit({"on_calendar": on_calendar, "unit": text}, json_mode=True)
    else:
        click.echo(text)


@schedule_group.command("status")
@click.option("--json", "json_mode", is_flag=True)
def schedule_status(json_mode: bool) -> None:
    """Report schedule config plus live systemd timer state."""
    data = get_schedule_status()
    if json_mode:
        emit(data, json_mode=True)
        return
    config_raw = data.get("config")
    cfg = config_raw if isinstance(config_raw, dict) else {}
    click.echo(f"Profile: {cfg.get('profile', '')}")
    click.echo(f"Frequency: {cfg.get('frequency', '')} @ {cfg.get('time', '')}")
    click.echo(f"OnCalendar: {data.get('on_calendar', '') or data.get('calendar_error', '')}")
    click.echo(f"Timer unit: {data.get('timer', '')}")
    click.echo(f"Installed: {data.get('installed', False)}")
    click.echo(f"Enabled: {data.get('enabled', False)}")
    click.echo(f"Active: {data.get('active', False)}")
    if data.get("next"):
        click.echo(f"Next: {data['next']}")
    cli_path = data.get("cli_path")
    if cli_path:
        click.echo(f"oyst-cli path: {cli_path}")
    linger_raw = data.get("linger")
    linger = linger_raw if isinstance(linger_raw, dict) else {}
    if linger:
        click.echo(f"Linger: {'yes' if linger.get('linger') else 'no'}")


@schedule_group.command("set", epilog=_SCHEDULE_SET_EPILOG)
@click.option("--enabled/--disabled", "enabled", default=None)
@click.option("--profile", default=None)
@click.option("--packs", default=None, help="Comma-separated pack names")
@click.option("--paths", default=None, help="Comma-separated scan paths")
@click.option(
    "--frequency",
    type=click.Choice(["hourly", "daily", "weekly", "custom"]),
    default=None,
)
@click.option("--time", "at_time", default=None, help="Local HH:MM")
@click.option("--weekday", default=None, help="For weekly (mon..sun)")
@click.option("--on-calendar", default=None, help="Raw systemd calendar when frequency=custom")
@click.option("--persistent/--no-persistent", default=None)
@click.option(
    "--quarantine",
    type=click.Choice(["auto", "on", "off"]),
    default=None,
)
@click.option(
    "--backend",
    type=click.Choice(["auto", "clamd", "clamscan"]),
    default=None,
)
@click.option("--apply", "do_apply", is_flag=True, help="Apply systemd units after saving")
@json_option
def schedule_set(
    enabled: bool | None,
    profile: str | None,
    packs: str | None,
    paths: str | None,
    frequency: str | None,
    at_time: str | None,
    weekday: str | None,
    on_calendar: str | None,
    persistent: bool | None,
    quarantine: str | None,
    backend: str | None,
    do_apply: bool,
    json_mode: bool,
) -> None:
    """Update schedule.* settings (scan semantics; use --apply to refresh timer)."""
    try:
        sched = update_schedule_settings(
            enabled=enabled,
            profile=profile,
            packs=packs,
            paths=paths,
            frequency=frequency,
            time=at_time,
            weekday=weekday,
            on_calendar=on_calendar,
            persistent=persistent,
            quarantine=quarantine,
            backend=backend,
        )
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    payload: dict[str, object] = {"ok": True, "config": sched.model_dump()}
    if do_apply:
        applied = apply_schedule(smoke_test=False)
        payload["apply"] = applied
        if not applied.get("ok"):
            if json_mode:
                emit(payload, json_mode=True)
            else:
                click.echo(str(applied.get("message", "apply failed")))
            raise SystemExit(2)
    if json_mode:
        emit(payload, json_mode=True)
        return
    click.echo("Schedule settings updated.")
    if do_apply:
        apply_raw = payload.get("apply")
        apply_msg = (
            apply_raw.get("message", "applied") if isinstance(apply_raw, dict) else "applied"
        )
        click.echo(str(apply_msg))


@schedule_group.command("apply")
@click.option("--smoke-test", is_flag=True, help="Start the oneshot service once after enable")
@click.option("--json", "json_mode", is_flag=True)
def schedule_apply(smoke_test: bool, json_mode: bool) -> None:
    """Write/reload oyst-scan.timer from current schedule config."""
    result = apply_schedule(smoke_test=smoke_test)
    if json_mode:
        emit(result, json_mode=True)
        if not result.get("ok"):
            raise SystemExit(2)
        return
    if result.get("message"):
        click.echo(str(result["message"]))
    else:
        click.echo(f"Wrote {result.get('service')} and {result.get('timer')}")
    if result.get("enable_hint"):
        click.echo(f"Run: {result['enable_hint']}")
    if result.get("linger_advisory"):
        click.echo(f"Advisory: {result['linger_advisory']}")
    if not result.get("ok"):
        raise SystemExit(2)


@schedule_group.command("run")
@click.option("--json", "json_mode", is_flag=True)
def schedule_run(json_mode: bool) -> None:
    """Run one scan using schedule config (timer ExecStart target)."""
    try:
        result = run_scheduled_scan()
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    if json_mode:
        emit(result, json_mode=True)
    else:
        scan_raw = result.get("scan")
        scan = scan_raw if isinstance(scan_raw, dict) else {}
        click.echo(
            f"Scan {scan.get('job_id', '?')}: "
            f"{'clean' if scan.get('clean') else 'threats found'} "
            f"(exit {result.get('exit_code')})",
        )
    code = int(result.get("exit_code", 2))
    if code not in (0, 1):
        raise SystemExit(code if code else 2)
    if code == 1:
        raise SystemExit(1)


@schedule_group.command("enable")
@click.option("--json", "json_mode", is_flag=True)
def schedule_enable(json_mode: bool) -> None:
    """Enable schedule.enabled and apply the timer."""
    update_schedule_settings(enabled=True)
    result = apply_schedule(smoke_test=False)
    if json_mode:
        emit(result, json_mode=True)
        if not result.get("ok"):
            raise SystemExit(2)
        return
    click.echo(str(result.get("message", "enabled")))
    if not result.get("ok"):
        raise SystemExit(2)


@schedule_group.command(
    "disable",
    epilog="""
Examples:
  oyst-cli schedule disable --confirm --json
""",
)
@click.option("--confirm", is_flag=True)
@click.option("--json", "json_mode", is_flag=True)
def schedule_disable(confirm: bool, json_mode: bool) -> None:
    """Disable schedule.enabled and stop the timer."""
    require_confirm(confirm, message="--confirm required to disable the scan schedule")
    update_schedule_settings(enabled=False)
    result = apply_schedule(smoke_test=False)
    if json_mode:
        emit(result, json_mode=True)
        if not result.get("ok"):
            raise SystemExit(2)
        return
    click.echo(str(result.get("message", "disabled")))
    if not result.get("ok"):
        raise SystemExit(2)


@schedule_group.command("linger")
@click.option("--json", "json_mode", is_flag=True)
def schedule_linger(json_mode: bool) -> None:
    """Report whether user lingering is enabled for persistent timers."""
    data = get_linger_status()
    if json_mode:
        emit(data, json_mode=True)
        return
    click.echo(f"User: {data.get('user', '')}")
    click.echo(f"Linger: {'yes' if data.get('linger') else 'no'}")
    if not data.get("linger") and data.get("enable_hint"):
        click.echo(f"Enable: {data['enable_hint']}")


@schedule_group.command("enable-linger")
@click.option("--json", "json_mode", is_flag=True)
def schedule_enable_linger(json_mode: bool) -> None:
    """Enable user lingering so timers survive logout (requires root/polkit)."""
    data = enable_linger()
    if json_mode:
        emit(data, json_mode=True)
        if not data.get("ok"):
            raise SystemExit(2)
        return
    if data.get("message"):
        click.echo(str(data["message"]))
    click.echo(f"Linger: {'yes' if data.get('linger') else 'no'}")
    if not data.get("ok"):
        raise SystemExit(2)


@schedule_group.command("install", epilog=_SCHEDULE_INSTALL_EPILOG)
@click.option("--profile", default="quick")
@click.option("--smoke-test/--no-smoke-test", default=True)
@json_option
def schedule_install(
    profile: str,
    smoke_test: bool,
    json_mode: bool,
) -> None:
    """Compat one-click: defaults + apply (smoke-test on). Prefer set/apply/enable."""
    try:
        paths = install_user_timer(profile, smoke_test=smoke_test)
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    if json_mode:
        emit(paths, json_mode=True)
        if not paths.get("ok"):
            raise SystemExit(2)
        return
    if paths.get("ok") and paths.get("enabled"):
        click.echo(paths.get("message", f"Enabled oyst-scan.timer ({profile})"))
    else:
        click.echo(f"Wrote {paths.get('service')} and {paths.get('timer')}")
        if paths.get("message"):
            click.echo(str(paths["message"]))
    if paths.get("enable_hint"):
        click.echo(f"Run: {paths['enable_hint']}")
    if paths.get("linger_advisory"):
        click.echo(f"Advisory: {paths['linger_advisory']}")
    if not paths.get("ok"):
        raise SystemExit(2)
