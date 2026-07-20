"""clamonacc real-time protection CLI commands."""

from __future__ import annotations

import click

from oyst_cli.confirm import require_confirm
from oyst_cli.options import json_option
from oyst_cli.output import emit
from oyst_core.packs.clamd_ensure import ensure_fdpass, ensure_prevention
from oyst_core.packs.clamonacc import ClamonaccPack


@click.group("clamonacc")
def clamonacc_group() -> None:
    """Real-time protection via clamonacc."""


@clamonacc_group.command("start")
@click.option("--json", "json_mode", is_flag=True)
def clamonacc_start(json_mode: bool) -> None:
    """Start on-access scanner (upstream: clamonacc)."""
    ok, msg = ClamonaccPack().start()
    if json_mode:
        emit({"ok": ok, "message": msg}, json_mode=True)
    else:
        click.echo(msg)
    raise SystemExit(0 if ok else 2)


@clamonacc_group.command("stop")
@click.option("--json", "json_mode", is_flag=True)
def clamonacc_stop(json_mode: bool) -> None:
    """Stop on-access scanner."""
    ok, msg = ClamonaccPack().stop()
    if json_mode:
        emit({"ok": ok, "message": msg}, json_mode=True)
    else:
        click.echo(msg)
    raise SystemExit(0 if ok else 2)


@clamonacc_group.command("enable")
@click.option("--json", "json_mode", is_flag=True)
def clamonacc_enable(json_mode: bool) -> None:
    """Ensure clamd, start clamonacc, and persist enabled config."""
    ok, msg = ClamonaccPack().enable()
    if json_mode:
        emit({"ok": ok, "message": msg}, json_mode=True)
    else:
        click.echo(msg)
    raise SystemExit(0 if ok else 2)


@clamonacc_group.command("disable")
@click.option("--json", "json_mode", is_flag=True)
def clamonacc_disable(json_mode: bool) -> None:
    """Stop clamonacc and persist disabled config."""
    ok, msg = ClamonaccPack().disable()
    if json_mode:
        emit({"ok": ok, "message": msg}, json_mode=True)
    else:
        click.echo(msg)
    raise SystemExit(0 if ok else 2)


@clamonacc_group.command("status")
@click.option("--json", "json_mode", is_flag=True)
def clamonacc_status(json_mode: bool) -> None:
    """Daemon and path configuration status."""
    emit(ClamonaccPack().doctor().model_dump(), json_mode=json_mode)


@clamonacc_group.group("paths")
def clamonacc_paths() -> None:
    """Manage monitored paths."""


@clamonacc_paths.command("list")
@click.option("--json", "json_mode", is_flag=True)
def paths_list(json_mode: bool) -> None:
    """List watched paths (config: clamonacc.paths)."""
    paths = ClamonaccPack().list_paths()
    if json_mode:
        emit(paths, json_mode=True)
    else:
        for p in paths:
            click.echo(p)


@clamonacc_paths.command("add")
@click.argument("path")
@json_option
def paths_add(path: str, json_mode: bool) -> None:
    """Add a watched path."""
    ClamonaccPack().add_path(path)
    payload = {"ok": True, "path": path, "action": "add"}
    if json_mode:
        emit(payload, json_mode=True)
    else:
        click.echo(f"Added {path}")


@clamonacc_paths.command("remove")
@click.argument("path")
@click.option("--confirm", is_flag=True)
@json_option
def paths_remove(path: str, confirm: bool, json_mode: bool) -> None:
    """Remove a watched path."""
    require_confirm(confirm, message="--confirm required to remove a clamonacc path")
    removed = ClamonaccPack().remove_path(path)
    payload = {"ok": removed, "path": path, "action": "remove", "removed": removed}
    if json_mode:
        emit(payload, json_mode=True)
    elif removed:
        click.echo(f"Removed {path}")
    else:
        click.echo(f"Path not in list: {path}", err=True)
    if not removed:
        raise SystemExit(2)


@clamonacc_group.command("ensure-fdpass")
@click.option("--confirm", is_flag=True)
@json_option
def clamonacc_ensure_fdpass(confirm: bool, json_mode: bool) -> None:
    """Write systemd drop-in so distro clamonacc uses --fdpass (ADR-008 Phase 4)."""
    require_confirm(confirm, message="--confirm required to write systemd drop-in")
    result = ensure_fdpass(confirm=True)
    emit(result, json_mode=json_mode)
    if not result.get("ok"):
        raise SystemExit(2)


@clamonacc_group.command("ensure-prevention")
@click.option("--confirm", is_flag=True)
@json_option
def clamonacc_ensure_prevention(confirm: bool, json_mode: bool) -> None:
    """Surgical OnAccessPrevention ensure in host clamd.conf (ADR-008 Phase 4)."""
    require_confirm(confirm, message="--confirm required to edit host clamd.conf")
    result = ensure_prevention(confirm=True)
    emit(result, json_mode=json_mode)
    if not result.get("ok"):
        raise SystemExit(2)
