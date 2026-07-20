"""CLI for ClamAV VirusEvent bridge (ADR-008 Phase 3–4)."""

from __future__ import annotations

import click

from oyst_cli.confirm import require_confirm
from oyst_cli.output import emit
from oyst_core.packs.clamd_ensure import ensure_virusevent
from oyst_core.virusevent import handle_virusevent, install_wrapper, virusevent_status


@click.group("virusevent")
def virusevent_group() -> None:
    """On-access VirusEvent → quarantine / audit bridge."""


@virusevent_group.command("handle")
@click.option("--json", "json_mode", is_flag=True)
@click.option(
    "--no-quarantine",
    is_flag=True,
    help="Log/notify only (ignore quarantine.auto).",
)
def virusevent_handle_cmd(json_mode: bool, no_quarantine: bool) -> None:
    """Handle one event using CLAM_VIRUSEVENT_* env vars (called by clamd)."""
    result = handle_virusevent(quarantine=False if no_quarantine else None)
    emit(result, json_mode=json_mode)
    if not result.get("ok"):
        raise SystemExit(2)


@virusevent_group.command("status")
@click.option("--json", "json_mode", is_flag=True)
def virusevent_status_cmd(json_mode: bool) -> None:
    """Show whether host VirusEvent points at oysterAV."""
    emit(virusevent_status(), json_mode=json_mode)


@virusevent_group.command("install-wrapper")
@click.option("--force", is_flag=True, help="Overwrite existing wrapper.")
@click.option("--json", "json_mode", is_flag=True)
def virusevent_install_wrapper_cmd(force: bool, json_mode: bool) -> None:
    """Install ~/.local/share/oysterav/bin/oyst-virusevent for VirusEvent=."""
    result = install_wrapper(force=force)
    emit(result, json_mode=json_mode)
    if not result.get("ok"):
        raise SystemExit(2)


@virusevent_group.command("ensure")
@click.option("--confirm", is_flag=True)
@click.option("--force-wrapper", is_flag=True, help="Overwrite wrapper before ensure.")
@click.option("--json", "json_mode", is_flag=True)
def virusevent_ensure_cmd(confirm: bool, force_wrapper: bool, json_mode: bool) -> None:
    """Surgical VirusEvent ensure when unset or oysterAV-owned (ADR-008 Phase 4)."""
    require_confirm(confirm, message="--confirm required to edit host clamd.conf")
    result = ensure_virusevent(confirm=True, force_wrapper=force_wrapper)
    emit(result, json_mode=json_mode)
    if not result.get("ok"):
        raise SystemExit(2)
