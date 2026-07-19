"""Doctor command."""

from __future__ import annotations

import click

from oyst_cli.options import json_option
from oyst_cli.output import emit
from oyst_core.models import PackTier
from oyst_core.registry import get_registry


@click.command(
    "doctor",
    epilog="""
Examples:
  oyst-cli doctor --json
  oyst-cli doctor
""",
)
@json_option
def doctor_cmd(json_mode: bool) -> None:
    """Check all packs; print install hints per distro."""
    registry = get_registry()
    results = []
    for pack in registry.all():
        status = pack.doctor()
        results.append(status.model_dump())
        if not json_mode:
            tier = status.tier.value.upper()
            mark = "OK" if status.installed and status.version_ok else "MISSING"
            ver = status.version or "-"
            click.echo(f"[{tier:12}] {status.name:12} {mark:7} {ver}")
            if status.message:
                click.echo(f"             {status.message}")
            if not status.installed:
                click.echo(f"             install: {status.install_hint}")
    if json_mode:
        emit(results, json_mode=True)
    missing_required = [r for r in results if r["tier"] == PackTier.REQUIRED and not r["installed"]]
    if missing_required:
        raise SystemExit(5)
