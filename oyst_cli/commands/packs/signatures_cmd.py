"""Signature update and small scanner pack CLI commands."""

from __future__ import annotations

import click

from oyst_cli.output import emit
from oyst_core.packs.chkrootkit import ChkrootkitPack
from oyst_core.packs.fangfrisch import FangfrischPack
from oyst_core.packs.freshclam import FreshclamPack
from oyst_core.packs.unhide import UnhidePack

UNHIDE_MODES = ("sys", "brute", "quick", "check", "fork", "proc", "reverse")


@click.group("freshclam")
def freshclam_group() -> None:
    """Signature updates."""


@freshclam_group.command("update")
@click.option("--json", "json_mode", is_flag=True)
def freshclam_update(json_mode: bool) -> None:
    """Update virus signatures (upstream: freshclam)."""
    ok, msg = FreshclamPack().update()
    payload = {"ok": ok, "message": msg}
    if json_mode:
        emit(payload, json_mode=True)
    else:
        click.echo(msg)
    raise SystemExit(0 if ok else 2)


@freshclam_group.command("status")
@click.option("--json", "json_mode", is_flag=True)
def freshclam_status(json_mode: bool) -> None:
    """Signature age and last update (upstream: freshclam log / db mtime)."""
    emit(FreshclamPack().status_text(), json_mode=json_mode)


@click.group("fangfrisch")
def fangfrisch_group() -> None:
    """Unofficial ClamAV signatures (complements freshclam)."""


@fangfrisch_group.command("status")
@click.option("--json", "json_mode", is_flag=True)
def fangfrisch_status(json_mode: bool) -> None:
    """Installation and config status."""
    emit(FangfrischPack().doctor().model_dump(), json_mode=json_mode)


@fangfrisch_group.command("ensure-config")
@click.option("--force", is_flag=True, help="Overwrite an existing fangfrisch.conf")
@click.option("--json", "json_mode", is_flag=True)
def fangfrisch_ensure_config(force: bool, json_mode: bool) -> None:
    """Write oysterAV-managed fangfrisch.conf for the active ClamAV DB dir."""
    ok, msg = FangfrischPack().ensure_config(force=force)
    emit({"ok": ok, "message": msg}, json_mode=json_mode)
    raise SystemExit(0 if ok else 2)


@fangfrisch_group.command("initdb")
@click.option("--force", is_flag=True)
@click.option("--json", "json_mode", is_flag=True)
def fangfrisch_initdb(force: bool, json_mode: bool) -> None:
    """Create fangfrisch SQLite schema (run once before refresh)."""
    ok, msg = FangfrischPack().initdb(force=force)
    emit({"ok": ok, "message": msg}, json_mode=json_mode)
    raise SystemExit(0 if ok else 2)


@fangfrisch_group.command("refresh")
@click.option("--json", "json_mode", is_flag=True)
def fangfrisch_refresh(json_mode: bool) -> None:
    """Download/update unofficial signatures into the ClamAV DB directory."""
    ok, msg = FangfrischPack().refresh()
    emit({"ok": ok, "message": msg}, json_mode=json_mode)
    raise SystemExit(0 if ok else 2)


@click.group("chkrootkit")
def chkrootkit_group() -> None:
    """chkrootkit scanner."""


@chkrootkit_group.command("status")
@click.option("--json", "json_mode", is_flag=True)
def chkrootkit_status(json_mode: bool) -> None:
    """Installation and version status."""
    emit(ChkrootkitPack().doctor().model_dump(), json_mode=json_mode)


@chkrootkit_group.command("scan")
@click.option("--json", "json_mode", is_flag=True)
def chkrootkit_scan(json_mode: bool) -> None:
    """Run rootkit scan (upstream: chkrootkit)."""
    pack = ChkrootkitPack()
    ok, output = pack.scan()
    findings = pack.parse_findings(output)
    emit({"findings": [f.model_dump() for f in findings], "ok": ok}, json_mode=json_mode)
    raise SystemExit(1 if findings else (0 if ok else 2))


@click.group("unhide")
def unhide_group() -> None:
    """Hidden process detection (optional)."""


@unhide_group.command("status")
@click.option("--json", "json_mode", is_flag=True)
def unhide_status(json_mode: bool) -> None:
    """Installation status."""
    emit(UnhidePack().doctor().model_dump(), json_mode=json_mode)


@unhide_group.command("scan")
@click.option(
    "--mode",
    type=click.Choice(UNHIDE_MODES),
    default="sys",
    show_default=True,
    help="Scan technique (upstream: unhide <mode>)",
)
@click.option("--json", "json_mode", is_flag=True)
def unhide_scan(mode: str, json_mode: bool) -> None:
    """Run hidden-process detection."""
    pack = UnhidePack()
    ok, output = pack.scan(mode=mode)
    findings = pack.parse_findings(output)
    emit(
        {"findings": [f.model_dump() for f in findings], "ok": ok, "mode": mode},
        json_mode=json_mode,
    )
    raise SystemExit(1 if findings else (0 if ok else 2))
