"""Updates check and apply commands."""

from __future__ import annotations

import click

from oyst_cli.confirm import require_confirm
from oyst_cli.options import json_option
from oyst_cli.output import emit
from oyst_core.updates import apply_all_updates, check_available_updates


@click.group("updates")
def updates_group() -> None:
    """Check and apply pack/service package updates and definitions."""


@updates_group.command("check")
@json_option
def updates_check_cmd(json_mode: bool) -> None:
    """List package updates for installed packs / enabled related services."""
    result = check_available_updates()
    if json_mode:
        emit(result, json_mode=True)
        return
    updates = result.get("updates") or []
    if not updates:
        click.echo("No updates available")
        return
    for item in updates:
        if not isinstance(item, dict):
            continue
        click.echo(
            f"{item.get('name')}: {item.get('current')} > {item.get('available')} "
            f"({item.get('package')})"
        )


@updates_group.command("apply")
@click.option("--confirm", is_flag=True)
@json_option
def updates_apply_cmd(confirm: bool, json_mode: bool) -> None:
    """Upgrade tracked packages, refresh definitions, and run post-update baseline."""
    require_confirm(
        confirm,
        message="--confirm required (includes rkhunter --propupd baseline refresh)",
    )
    result = apply_all_updates()
    if json_mode:
        emit(result, json_mode=True)
    else:
        click.echo(str(result.get("message") or "Update all finished"))
        for step in result.get("steps") or []:
            if not isinstance(step, dict):
                continue
            name = step.get("step", "?")
            if step.get("skipped"):
                click.echo(f"  {name}: skipped")
            elif step.get("ok"):
                click.echo(f"  {name}: OK")
            else:
                click.echo(f"  {name}: FAILED — {step.get('message', '')}")
    steps = result.get("steps") or []
    failed = [s for s in steps if isinstance(s, dict) and not s.get("ok") and not s.get("skipped")]
    if failed or not result.get("ok", True):
        raise SystemExit(2)
