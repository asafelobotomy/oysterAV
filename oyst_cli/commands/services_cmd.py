"""CLI: logical service status and lifecycle."""

from __future__ import annotations

import click

from oyst_cli.confirm import require_confirm
from oyst_cli.output import emit
from oyst_core.plan import change, plan_doc, refused
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
@click.option("--confirm", is_flag=True)
@click.option("--dry-run", is_flag=True, help="Print what would change; change nothing")
@click.option("--json", "json_mode", is_flag=True)
def services_set_cmd(
    name: str, state: str, boot: bool, confirm: bool, dry_run: bool, json_mode: bool
) -> None:
    """Turn a service on or off (prompts via polkit / oyst-helper)."""
    require_confirm(confirm, dry_run=dry_run, message="--confirm required to change service state")
    if dry_run:
        table = services_status().get("services")
        current = table.get(name) if isinstance(table, dict) else None
        running = bool(current.get("running")) if isinstance(current, dict) else False
        steps = [
            change(
                f"Turn {name} {state}",
                group="Services",
                detail="Asks for your password through oysterAV's helper",
                reversible=True,
            )
        ]
        if boot:
            steps.append(
                change(
                    f"{'Enable' if state == 'on' else 'Disable'} {name} at boot",
                    group="Services",
                    reversible=True,
                )
            )
        if (state == "on") == running:
            doc = refused(f"{name} is already {'on' if running else 'off'}.")
        else:
            doc = plan_doc(f"Turn {name} {state}", steps)
        if json_mode:
            emit({"ok": True, "dry_run": True, "name": name, "state": state, **doc}, json_mode=True)
        else:
            click.echo(doc["summary"])
        return
    result = set_service(name, state, boot=boot)  # type: ignore[arg-type]
    emit(result, json_mode=json_mode)
    if not result.get("ok"):
        raise SystemExit(2)
