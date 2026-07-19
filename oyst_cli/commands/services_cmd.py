"""CLI: logical service status and lifecycle."""

from __future__ import annotations

import click

from oyst_cli.output import emit
from oyst_core.services import SERVICE_NAMES, services_status, set_service


@click.group("services")
def services_group() -> None:
    """Manage oysterAV-related system services (clamd, timers, monitors)."""


@services_group.command("status")
@click.option("--json", "json_mode", is_flag=True)
def services_status_cmd(json_mode: bool) -> None:
    """Show status of logical services."""
    emit(services_status(), json_mode=json_mode)


@services_group.command("set")
@click.argument("name", type=click.Choice(list(SERVICE_NAMES), case_sensitive=True))
@click.argument("state", type=click.Choice(["on", "off"], case_sensitive=True))
@click.option(
    "--boot/--no-boot",
    default=False,
    help="Also enable/disable at boot (systemctl enable-now / disable-now).",
)
@click.option("--json", "json_mode", is_flag=True)
def services_set_cmd(name: str, state: str, boot: bool, json_mode: bool) -> None:
    """Turn a service on or off (prompts via polkit / oyst-helper)."""
    result = set_service(name, state, boot=boot)  # type: ignore[arg-type]
    emit(result, json_mode=json_mode)
    if not result.get("ok"):
        raise SystemExit(2)
