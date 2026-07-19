"""Setup state and guided setup commands."""

from __future__ import annotations

import click

from oyst_cli.confirm import require_confirm
from oyst_cli.options import json_option
from oyst_cli.output import emit
from oyst_core.setup_workflow import assess_setup, reset_setup, run_setup

_CHECK_EPILOG = """
Examples:
  oyst-cli setup check --json
  # exit 1 when needs_attention is true (wizard gate)
"""

_RUN_EPILOG = """
Examples:
  oyst-cli setup run --json
  oyst-cli setup run --skip-packs --maintenance-only --json

Primary first-run path. See also: runtime bootstrap, maintenance bootstrap.
"""


@click.group("setup")
def setup_group() -> None:
    """First-run setup state (primary guided path: setup run)."""


@setup_group.command("status")
@json_option
def setup_status_cmd(json_mode: bool) -> None:
    """Report whether initial setup has been completed."""
    data = assess_setup()
    if json_mode:
        emit(data, json_mode=True)
        return
    click.echo(f"Completed: {data.get('completed', False)}")
    if data.get("completed_at"):
        click.echo(f"Completed at: {data['completed_at']}")
    skipped = data.get("skipped_steps")
    if skipped:
        click.echo(f"Skipped steps: {skipped}")
    if data.get("needs_attention"):
        click.echo("Needs attention: yes")
        missing = data.get("missing_required") or []
        if missing:
            click.echo(f"Missing required packs: {', '.join(missing)}")
        click.echo(f"Run: {data.get('recommended_action', 'oyst-cli setup run')}")


@setup_group.command("check", epilog=_CHECK_EPILOG)
@json_option
def setup_check_cmd(json_mode: bool) -> None:
    """Check if first-time setup still needs to run (wizard gate equivalent)."""
    data = assess_setup()
    if json_mode:
        emit(data, json_mode=True)
    elif data.get("needs_attention"):
        click.echo("Setup needs attention.")
    else:
        click.echo("Setup complete; no attention needed.")
    if data.get("needs_attention"):
        raise SystemExit(1)


@setup_group.command("reset")
@click.option("--confirm", is_flag=True)
@json_option
def setup_reset_cmd(confirm: bool, json_mode: bool) -> None:
    """Reset setup completion flag so setup can run again."""
    require_confirm(confirm, message="--confirm required to reset setup state")
    data = reset_setup()
    if json_mode:
        emit(data, json_mode=True)
    else:
        click.echo("Setup state reset.")


@setup_group.command("run", epilog=_RUN_EPILOG)
@click.option("--skip-packs", is_flag=True, help="Skip pack installation step")
@click.option("--skip-schedule", is_flag=True, help="Skip daily scan timer install")
@click.option("--skip-bootstrap", is_flag=True, help="Skip runtime/maintenance bootstrap")
@click.option("--confirm-aur", is_flag=True, help="Confirm AUR installs without prompting")
@click.option(
    "--auto-quarantine/--no-auto-quarantine",
    default=None,
    help="Set auto-quarantine default (current config kept if omitted)",
)
@click.option("--schedule-profile", default="quick", show_default=True)
@click.option(
    "--maintenance-only",
    is_flag=True,
    help="Skip runtime install; run maintenance bootstrap only",
)
@click.option(
    "--enable-linger",
    is_flag=True,
    help="Enable user lingering when schedule step reports it is off",
)
@click.option(
    "--no-mark-complete",
    is_flag=True,
    help="Run steps without marking setup.completed (dry orchestration)",
)
@json_option
def setup_run_cmd(
    skip_packs: bool,
    skip_schedule: bool,
    skip_bootstrap: bool,
    confirm_aur: bool,
    auto_quarantine: bool | None,
    schedule_profile: str,
    maintenance_only: bool,
    enable_linger: bool,
    no_mark_complete: bool,
    json_mode: bool,
) -> None:
    """Run guided first-time setup (wizard equivalent)."""
    result = run_setup(
        skip_packs=skip_packs,
        skip_schedule=skip_schedule,
        skip_bootstrap=skip_bootstrap,
        confirm_aur=confirm_aur,
        auto_quarantine=auto_quarantine,
        schedule_profile=schedule_profile,
        full_bootstrap=not maintenance_only,
        enable_linger=enable_linger,
        mark_complete=not no_mark_complete,
    )
    if json_mode:
        emit(result, json_mode=True)
    else:
        click.echo(f"Setup complete: {result.get('completed', False)}")
        if not result.get("marked_complete") and result.get("can_mark_complete") is False:
            click.echo("Setup not marked complete due to failed steps.")
        click.echo(f"Steps OK: {result.get('steps_ok', 0)}/{result.get('steps_total', 0)}")
        for step in result.get("steps", []):
            name = step.get("step", "?")
            if step.get("skipped"):
                click.echo(f"  {name}: skipped")
            elif step.get("ok"):
                click.echo(f"  {name}: OK")
            else:
                msg = step.get("message", "failed")
                click.echo(f"  {name}: FAILED — {msg}")
        if result.get("linger_advisory"):
            click.echo(f"Linger advisory: {result['linger_advisory']}")
            click.echo(f"Hint: {result.get('linger_hint', 'oyst-cli schedule enable-linger')}")
    if not result.get("ok"):
        raise SystemExit(2)
