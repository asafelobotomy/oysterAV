"""Lynis audit CLI commands."""

from __future__ import annotations

from pathlib import Path

import click

from oyst_cli.options import json_option
from oyst_cli.output import emit
from oyst_core.packs.lynis import LynisPack


@click.group("lynis")
def lynis_group() -> None:
    """Lynis security audit."""


@lynis_group.command("audit")
@click.option("--profile", default=None, help="Profile name or path")
@click.option(
    "--scope",
    type=click.Choice(["host", "container-host"]),
    default="host",
    show_default=True,
)
@click.option("--quick/--full", default=True, show_default=True)
@click.option("--json", "json_mode", is_flag=True)
def lynis_audit(
    profile: str | None,
    scope: str,
    quick: bool,
    json_mode: bool,
) -> None:
    """Run system audit (upstream: lynis audit system)."""
    ok, output, score = LynisPack().audit(profile=profile, scope=scope, quick=quick)
    emit(
        {
            "ok": ok,
            "hardening_index": score,
            "scope": scope,
            "profile": profile,
            "output_tail": output[-4000:],
        },
        json_mode=json_mode,
    )
    raise SystemExit(0 if ok else 2)


@lynis_group.group("profiles")
def lynis_profiles_group() -> None:
    """Available Lynis audit profiles."""


@lynis_profiles_group.command("list")
@click.option("--json", "json_mode", is_flag=True)
def lynis_profiles_list(json_mode: bool) -> None:
    """List bundled and system profiles."""
    emit(LynisPack().list_profiles(), json_mode=json_mode)


@lynis_group.group("container")
def lynis_container_group() -> None:
    """Audit a running container from the Docker host."""


@lynis_container_group.command("audit")
@click.argument("container_id")
@click.option("--quick/--full", default=True, show_default=True)
@click.option("--json", "json_mode", is_flag=True)
def lynis_container_audit(container_id: str, quick: bool, json_mode: bool) -> None:
    """Run lynis inside a container (upstream: docker exec ... lynis audit system)."""
    ok, output, score = LynisPack().audit_container(container_id, quick=quick)
    emit(
        {
            "ok": ok,
            "hardening_index": score,
            "container_id": container_id,
            "output_tail": output[-4000:],
        },
        json_mode=json_mode,
    )
    raise SystemExit(0 if ok else 2)


@lynis_group.command("status")
@click.option("--json", "json_mode", is_flag=True)
def lynis_status(json_mode: bool) -> None:
    """Last audit score and timestamp."""
    emit(LynisPack().status(), json_mode=json_mode)


@lynis_group.command("export")
@click.argument("dest")
@json_option
def lynis_export(dest: str, json_mode: bool) -> None:
    """Export last report (upstream: lynis report)."""
    p = Path(dest).expanduser()
    if p.suffix == ".html":
        LynisPack().export_html(p)
    else:
        LynisPack().export_json(p)
    payload = {"ok": True, "path": str(p)}
    if json_mode:
        emit(payload, json_mode=True)
    else:
        click.echo(f"Exported to {p}")
