"""Maintenance workflows."""

from __future__ import annotations

import click

from oyst_cli.options import json_option
from oyst_cli.output import emit
from oyst_core.maintenance import run_bootstrap, run_post_update


def _exit_for_steps(steps: list[dict[str, object]]) -> None:
    """Exit 5 if required packs missing; 2 if any non-skipped step failed."""
    missing_required = [
        s for s in steps if str(s.get("step", "")).startswith("doctor-") and not s.get("ok")
    ]
    if missing_required:
        raise SystemExit(5)
    failed = [s for s in steps if not s.get("ok") and not s.get("skipped")]
    if failed:
        raise SystemExit(2)


def _print_steps(label: str, steps: list[dict[str, object]]) -> None:
    click.echo(f"{label}: {sum(1 for s in steps if s.get('ok'))}/{len(steps)} steps OK")
    for step in steps:
        name = step.get("step", "?")
        if step.get("skipped"):
            click.echo(f"  {name}: skipped")
        elif step.get("ok"):
            click.echo(f"  {name}: OK")
        else:
            click.echo(f"  {name}: FAILED — {step.get('message', '')}")


@click.group("maintenance")
def maintenance_group() -> None:
    """First-run and post-update maintenance."""


@maintenance_group.command(
    "bootstrap",
    epilog="""
Examples:
  oyst-cli maintenance bootstrap --json
  oyst-cli maintenance bootstrap --skip-lynis
""",
)
@click.option("--skip-lynis", is_flag=True, help="Skip Lynis audit (requires root)")
@json_option
def bootstrap(skip_lynis: bool, json_mode: bool) -> None:
    """Signatures/baseline only. First-run: setup run; full runtime: runtime bootstrap."""
    steps = run_bootstrap(skip_lynis=skip_lynis)
    if json_mode:
        emit({"bootstrap": steps}, json_mode=True)
    else:
        _print_steps("Bootstrap", steps)
        click.echo("Never run propupd on a suspect system.")
    _exit_for_steps(steps)


@maintenance_group.command("post-update")
@json_option
def post_update(json_mode: bool) -> None:
    """After OS updates: refresh signatures and rkhunter baseline."""
    steps = run_post_update()
    if json_mode:
        emit({"post_update": steps}, json_mode=True)
    else:
        _print_steps("Post-update", steps)
        click.echo("Consider: oyst-cli scan --profile integrity")
    _exit_for_steps(steps)
