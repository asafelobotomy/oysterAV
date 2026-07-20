"""ClamAV and clamd CLI commands."""

from __future__ import annotations

import click

from oyst_cli.confirm import require_confirm
from oyst_cli.options import json_option
from oyst_cli.output import emit
from oyst_core.config import set_config_value
from oyst_core.packs.clamav import ClamAVPack


@click.group("clamav")
def clamav_group() -> None:
    """ClamAV operations."""


@clamav_group.command("status")
@click.option("--json", "json_mode", is_flag=True)
def clamav_status(json_mode: bool) -> None:
    """Installation and clamd status (upstream: clamscan --version, clamd probe)."""
    emit(ClamAVPack().doctor().model_dump(), json_mode=json_mode)


@clamav_group.command("scan")
@click.argument("path")
@click.option("--backend", default="auto")
@click.option("--json", "json_mode", is_flag=True)
def clamav_scan(path: str, backend: str, json_mode: bool) -> None:
    """Scan a path (upstream: clamscan/clamdscan -r)."""
    pack = ClamAVPack()
    res = pack.scan(path, backend=backend)
    findings = pack.parse_findings(res)
    payload = {
        "findings": [f.model_dump() for f in findings],
        "returncode": res.returncode,
    }
    emit(payload, json_mode=json_mode)
    if findings or res.returncode == 1:
        raise SystemExit(1)
    if res.returncode not in (0, 1):
        raise SystemExit(2)
    raise SystemExit(0)


@clamav_group.command("backend")
@click.argument("mode", type=click.Choice(["auto", "clamd", "clamscan"]))
@json_option
def clamav_backend(mode: str, json_mode: bool) -> None:
    """Set default scan backend (oyst-cli config: scan.backend)."""
    set_config_value("scan.backend", mode)
    payload = {"ok": True, "backend": mode}
    if json_mode:
        emit(payload, json_mode=True)
    else:
        click.echo(f"scan.backend={mode}")


@click.group("clamd")
def clamav_clamd_group() -> None:
    """ClamAV daemon (clamd) systemd control."""


@clamav_clamd_group.command("start")
@click.option("--json", "json_mode", is_flag=True)
def clamav_clamd_start(json_mode: bool) -> None:
    """Enable and start clamd (upstream: systemctl enable --now)."""
    ok, msg = ClamAVPack().clamd_start()
    emit({"ok": ok, "message": msg}, json_mode=json_mode)
    raise SystemExit(0 if ok else 2)


@clamav_clamd_group.command("stop")
@click.option("--confirm", is_flag=True)
@click.option("--json", "json_mode", is_flag=True)
def clamav_clamd_stop(confirm: bool, json_mode: bool) -> None:
    """Stop clamd."""
    require_confirm(confirm, message="--confirm required to stop clamd")
    ok, msg = ClamAVPack().clamd_stop()
    emit({"ok": ok, "message": msg}, json_mode=json_mode)
    raise SystemExit(0 if ok else 2)


@clamav_clamd_group.command("restart")
@click.option("--confirm", is_flag=True)
@click.option("--json", "json_mode", is_flag=True)
def clamav_clamd_restart(confirm: bool, json_mode: bool) -> None:
    """Restart clamd."""
    require_confirm(confirm, message="--confirm required to restart clamd")
    ok, msg = ClamAVPack().clamd_restart()
    emit({"ok": ok, "message": msg}, json_mode=json_mode)
    raise SystemExit(0 if ok else 2)


@clamav_clamd_group.command("status")
@click.option("--json", "json_mode", is_flag=True)
def clamav_clamd_status(json_mode: bool) -> None:
    """clamd unit and process status."""
    emit(ClamAVPack().clamd_status(), json_mode=json_mode)


@clamav_clamd_group.command("ensure")
@click.option("--json", "json_mode", is_flag=True)
def clamav_clamd_ensure(json_mode: bool) -> None:
    """Idempotent enable+start if clamd is not running."""
    ok, msg = ClamAVPack().clamd_ensure()
    emit({"ok": ok, "message": msg}, json_mode=json_mode)
    raise SystemExit(0 if ok else 2)


clamav_group.add_command(clamav_clamd_group, name="clamd")
