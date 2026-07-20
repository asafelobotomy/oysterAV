"""Linux Malware Detect CLI commands."""

from __future__ import annotations

import click

from oyst_cli.confirm import require_confirm
from oyst_cli.options import json_option
from oyst_cli.output import emit
from oyst_core.packs.maldet import MaldetPack


@click.group("maldet")
def maldet_group() -> None:
    """Linux Malware Detect (optional)."""


@maldet_group.command("status")
@click.option("--json", "json_mode", is_flag=True)
def maldet_status(json_mode: bool) -> None:
    """Installation status."""
    emit(MaldetPack().doctor().model_dump(), json_mode=json_mode)


@maldet_group.command("scan")
@click.argument("path")
@click.option("--json", "json_mode", is_flag=True)
def maldet_scan(path: str, json_mode: bool) -> None:
    """Scan a path (upstream: maldet -a)."""
    pack = MaldetPack()
    ok, output = pack.scan(path)
    findings = pack.parse_findings(output)
    emit({"findings": [f.model_dump() for f in findings], "ok": ok}, json_mode=json_mode)
    raise SystemExit(1 if findings else (0 if ok else 2))


@maldet_group.command("update-sigs")
@click.option("--json", "json_mode", is_flag=True)
def maldet_update(json_mode: bool) -> None:
    """Update signatures (upstream: maldet -u)."""
    ok, msg = MaldetPack().update_sigs()
    if json_mode:
        emit({"ok": ok, "message": msg}, json_mode=True)
    else:
        click.echo(msg)
    raise SystemExit(0 if ok else 2)


@maldet_group.command("list")
@click.option("--json", "json_mode", is_flag=True)
def maldet_list(json_mode: bool) -> None:
    """List scan reports (upstream: maldet -l)."""
    ok, output = MaldetPack().list_scans()
    if json_mode:
        emit({"ok": ok, "reports": output.splitlines()}, json_mode=True)
    else:
        click.echo(output)
    raise SystemExit(0 if ok else 2)


@maldet_group.command("quarantine")
@click.option("--json", "json_mode", is_flag=True)
def maldet_quarantine(json_mode: bool) -> None:
    """List maldet quarantine (upstream: maldet -q)."""
    ok, output = MaldetPack().quarantine_list()
    if json_mode:
        emit({"ok": ok, "entries": output.splitlines()}, json_mode=True)
    else:
        click.echo(output)
    raise SystemExit(0 if ok else 2)


@maldet_group.group("monitor")
def maldet_monitor_group() -> None:
    """Real-time inotify monitoring (upstream: maldet -m / systemd maldet.service)."""


@maldet_monitor_group.command("status")
@click.option("--json", "json_mode", is_flag=True)
def maldet_monitor_status(json_mode: bool) -> None:
    """Monitor daemon and prerequisite status."""
    emit(MaldetPack().monitor_status(), json_mode=json_mode)


@maldet_monitor_group.command("start")
@click.option("--json", "json_mode", is_flag=True)
def maldet_monitor_start(json_mode: bool) -> None:
    """Configure and start maldet monitor via systemd."""
    ok, msg = MaldetPack().monitor_start()
    emit({"ok": ok, "message": msg}, json_mode=json_mode)
    raise SystemExit(0 if ok else 2)


@maldet_monitor_group.command("stop")
@click.option("--json", "json_mode", is_flag=True)
def maldet_monitor_stop(json_mode: bool) -> None:
    """Stop maldet monitor."""
    ok, msg = MaldetPack().monitor_stop()
    emit({"ok": ok, "message": msg}, json_mode=json_mode)
    raise SystemExit(0 if ok else 2)


@maldet_monitor_group.group("paths")
def maldet_monitor_paths() -> None:
    """Monitor path list (config: maldet_monitor.paths)."""


@maldet_monitor_paths.command("list")
@click.option("--json", "json_mode", is_flag=True)
def maldet_paths_list(json_mode: bool) -> None:
    """List configured monitor paths."""
    paths = MaldetPack().list_monitor_paths()
    emit(paths, json_mode=json_mode)


@maldet_monitor_paths.command("add")
@click.argument("path")
@json_option
def maldet_paths_add(path: str, json_mode: bool) -> None:
    """Add a monitor path."""
    MaldetPack().add_monitor_path(path)
    payload = {"ok": True, "path": path, "action": "add"}
    if json_mode:
        emit(payload, json_mode=True)
    else:
        click.echo(f"Added {path}")


@maldet_monitor_paths.command("remove")
@click.argument("path")
@click.option("--confirm", is_flag=True)
@json_option
def maldet_paths_remove(path: str, confirm: bool, json_mode: bool) -> None:
    """Remove a monitor path."""
    require_confirm(confirm, message="--confirm required to remove a maldet monitor path")
    removed = MaldetPack().remove_monitor_path(path)
    payload = {"ok": removed, "path": path, "action": "remove", "removed": removed}
    if json_mode:
        emit(payload, json_mode=True)
    elif removed:
        click.echo(f"Removed {path}")
    else:
        click.echo(f"Path not in list: {path}", err=True)
    if not removed:
        raise SystemExit(2)


@maldet_monitor_group.command("events")
@click.option("--tail", default=20, show_default=True)
@click.option("--json", "json_mode", is_flag=True)
def maldet_monitor_events(tail: int, json_mode: bool) -> None:
    """Tail maldet event log."""
    ok, output = MaldetPack().tail_events(lines=tail)
    if json_mode:
        emit({"ok": ok, "lines": output.splitlines()}, json_mode=True)
    else:
        click.echo(output)
    raise SystemExit(0 if ok else 2)
