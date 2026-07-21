"""Install privileged helper and polkit policy."""

from __future__ import annotations

import click

from oyst_cli.output import emit
from oyst_core.privileged.install_privileged_helper import helper_status, install_privileged_helper


@click.command("install-privileged-helper")
@click.option("--json", "json_mode", is_flag=True)
@click.option(
    "--dev",
    is_flag=True,
    help="Git checkout / uv dev install: embed user site root (not for production)",
)
def install_helper_cmd(json_mode: bool, dev: bool) -> None:
    """Install oyst-helper and polkit policy for GUI-driven privileged operations."""
    result = install_privileged_helper(dev_mode=dev)
    if json_mode:
        emit(result, json_mode=True)
    else:
        click.echo(result.get("message", ""))
        if result.get("helper_path"):
            click.echo(f"Helper: {result['helper_path']}")
        if result.get("polkit_path"):
            click.echo(f"Policy: {result['polkit_path']}")
    if not result.get("ok"):
        raise SystemExit(2)


@click.command("helper-status")
@click.option("--json", "json_mode", is_flag=True)
def helper_status_cmd(json_mode: bool) -> None:
    """Show whether oyst-helper is installed and polkit actions are current."""
    result = helper_status()
    if json_mode:
        emit(result, json_mode=True)
    elif result.get("installed") and result.get("policy_current"):
        click.echo(f"installed (policy v{result.get('policy_version')})")
    elif result.get("installed"):
        click.echo(
            f"installed but policy outdated — re-run: "
            f"sudo oyst-cli install-privileged-helper (v{result.get('policy_version')})"
        )
    else:
        click.echo("not installed")
